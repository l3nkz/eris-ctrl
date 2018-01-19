#!/usr/bin/env python3

import logging
from enum import Enum
import collections

import requests


logger = logging.getLogger(__name__)


class ErisCtrlError(Exception):
    pass


class ErisBenchmarkMode(Enum):
    CLIENTS = 1
    TIMED = 2

class ErisBenchmark:
    """
    Wrapper class for a benchmark instance running on ERIS.
    """

    def __init__(self, ectrl, handle):
        self._ectrl = ectrl
        self._handle = handle

    @property
    def handle(self):
        return self._handle

    def status(self):
        """
        Get the current status of this benchmark instance.

        @returns:       The current status of the benchmark instance.
        @rtype:         str
        """
        data = self._ectrl._get("/benchmarking/status/{handle}".format(handle=self._handle))

        return data["state"]

    def stop(self):
        """
        Stop the benchmark instance.
        """
        self._ectrl._post("/benchmarking/stop/{handle}".format(handle=self._handle), rmode=ErisCtrl.RequstMode.BOOL)


ErisWorkerStatus = collections.namedtuple("ErisWorkerStatus", ["enabled", "suspending"])

class ErisWorker:
    """
    Wrapper class for a worker thread of ERIS.
    """

    def __init__(self, ectrl, cpuid, socketid):
        self._ectrl = ectrl
        self._cpuid = cpuid
        self._socketid = socketid

    @property
    def cpuid(self):
        return self._cpuid

    @property
    def socketid(self):
        return self._socketid

    def disable(self):
        """
        Disable this ERIS worker thread.

        @returns:       Whether the disabling was successful or not.
        @rtype:         bool
        """
        r = self._ectrl._post("/osctrl/lpv/{}/disable".format(self._cpuid), rmode=ErisCtrl.RequstMode.RAW)

        return r.status_code == 200

    def enable(self):
        """
        Enable this ERIS worker thread.

        @returns:       Whether the enabling was successful or not.
        @rtype:         bool
        """
        r = self._ectrl._post("/osctrl/lpv/{}/enable".format(self._cpuid), rmode=ErisCtrl.RequstMode.RAW)

        return r.status_code == 200

    def enabled(self):
        """
        Check whether this ERIS worker thread is enabled.

        @returns:       Whether the worker thread is enabled or not.
        @rtype:         bool
        """
        return self.status().enabled

    def suspending(self):
        """
        Check whether this ERIS working has a pending suspend request.

        @returns:       Whether there is a suspend request pending for this worker or not.
        @rtype:         bool
        """
        return self.status().suspending

    def status(self):
        """
        Get the current status of this ERIS worker thread.

        @returns:       The status of this worker thread.
        @rtype:         ErisWorkerStatus
        """
        data = self._ectrl._get("/osctrl/lpv/{}".format(self._cpuid))

        return ErisWorkerStatus(data["running"], data["suspendPending"])


class ErisCtrl:
    """
    The control interface to ERIS.

    This class handles all the general management requests to ERIS and is also the session manager.
    """

    class RequstMode(Enum):
        RAW = 1
        JSON = 2
        BOOL = 3

    def __init__(self, url, port, user, passwd):
        self._user = user
        self._passwd = passwd

        self._interface_url = "http://{}:{}".format(url, port)
        self._session = requests.Session()

        self._session_id = None

    def __enter__(self):
        self._login()
        return self

    def __exit__(self, type, value, traceback):
        self._logout()
        return True

    def _login(self):
        try:
            data = self._session.post(self._interface_url + "/session",
                    data={"login" : self._user, "password" : self._passwd}).json()
            if data["success"] == True:
                logger.debug("Successfully logged in to ERIS")
                self._session_id = data["id"]
            else:
                raise ErisCtrlError("Failed to login to ERIS -- wrong credentials?")
        except:
            raise ErisCtrlError("Couldn't connect to ERIS -- not running?")

    def _logout(self):
        pass

    def _is_logged_in(self):
        return self._session_id is not None

    def _post(self, sub_url, data={}, rmode=RequstMode.JSON):
        if not self._is_logged_in():
            raise ErisCtrlError("Not connected to ERIS")

        r = self._session.post(self._interface_url + sub_url,
                data=data, cookies={"id" : self._session_id})

        if rmode == ErisCtrl.RequstMode.RAW:
            return r

        if rmode == ErisCtrl.RequstMode.JSON:
            if r.status_code != 200:
                raise ErisCtrlError("Unable to make POST request to " + sub_url)

            return r.json()
        else:
            return r.status_code == 200

    def _get(self, sub_url, data={}, rmode=RequstMode.JSON):
        if not self._is_logged_in():
            raise ErisCtrlError("Not connected to ERIS")

        r = self._session.get(self._interface_url + sub_url,
                data=data, cookies={"id" : self._session_id})

        if rmode == ErisCtrl.RequstMode.RAW:
            return r

        if rmode == ErisCtrl.RequstMode.JSON:
            if r.status_code != 200:
                raise ErisCtrlError("Unable to make GET request to " + sub_url)

            return r.json()
        else:
            return r.status_code == 200


    # Functions for the benchmark interface of ERIS
    def benchmarks(self):
        """
        Get the list of all available benchmarks.

        @returns:       The names of all benchmarks that can be started.
        @rtype:         list(str)
        """
        data = self._get("/benchmarking/list")

        benchs = []
        for i in data["benchmarks"]:
            benchs.append(i["name"])

        return benchs

    def benchmark_start(self, bench, mode=ErisBenchmarkMode.CLIENTS, scale_factor=1, clients=1, interval=1000):
        """
        Start one specific benchmark instance on ERIS.

        @param bench:   The name of the benchmark that should be started.
        @type bench:    str
        @param mode:    The mode in with with the benchmark should be started.
        @type mode:     ErisBenchmarkMode
        @param scale_factor: TODO
        @type scale_factor: int
        @param clients: The number of clients that should be used when started in the 'clients' mode.
        @type clients:  int
        @param interval: TODO
        @type interval: int
        @returns:       A handle to the benchmark instance.
        @rtype:         ErisBenchmark
        """

        data = self._post("/benchmarking/start/{name}/{mode}/{scale_factor}/{clients}/{interval}".format(
            name=bench, mode=mode.name.lower(), scale_factor=scale_factor, clients=clients,
            interval=interval))

        return ErisBenchmark(self, data["handle"])


    # Functions for the worker thread interface of ERIS.
    def workers(self):
        """
        Get the list of all worker threads of ERIS.

        @returns:       The list of all worker threads of ERIS.
        @rtype:         list(ErisWorker)
        """
        data = self._get("/osctrl/status")

        workers = []
        for socket in data:
            for worker in socket["lpvs"]:
                workers.append(ErisWorker(self, worker["physicalId"], socket["physicalId"]))

        return workers
