#!/usr/bin/env python3

import logging
from enum import Enum
import collections

from datetime import timedelta, datetime

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
        self._ectrl._post("/benchmarking/stop/{handle}".format(handle=self._handle), rmode=ErisCtrl.RequestMode.BOOL)


class ErisCounterValue:
    def __init__(self, value, reltime, start_time):
        self._value = value
        self._reltime = reltime
        self._abstime = start_time + timedelta(milliseconds=reltime)

    def __str__(self):
        return "{}@{} (+{})".format(self._value, self._abstime, self._reltime)

    @property
    def value(self):
        return self._value

    @property
    def reltime(self):
        return self._reltime

    @property
    def abstime(self):
        return self._abstime


class ErisMonitoredCounter:
    def __init__(self, ectrl, ectr, ctr_id):
        self._ectrl = ectrl
        self._ectr = ectr
        self._ctr_id = ctr_id

        self._start = datetime.now()
        self._values = []

    def _push_values(self, reltime, values):
        for v in values:
            if v["type"] == "int64":
                v = int(v["value"])
            elif v["type"] == "double" or v["type"] == "float":
                v = float(v["value"])
            else:
                v = v["value"]

            self._values.append(ErisCounterValue(v, int(reltime), self._start))

    @property
    def counter(self):
        return self._ectr

    def values(self, refresh=True):
        if refresh:
            self._ectrl._pull_monitoring_data()

        return self._values

    def unmonitor(self):
        self._ectrl._unmonitor_counter(self._ctr_id)

    def clear(self, refresh=True):
        if refresh:
            self._ectrl._pull_monitoring_data()

        self._values.clear()


class ErisCounter:
    def __init__(self, ectrl, name, description, classes):
        self._ectrl = ectrl
        self._name = name
        self._description = description
        self._classes = classes

    @property
    def name(self):
        return self._name

    @property
    def description(self):
        return self._description

    @property
    def dist_name(self):
        return ".".join(self._classes) + "." + self._name

    def monitor(self):
        return self._ectrl._monitor_counter(self)


class ErisWorkerCounter(ErisCounter):
    def __init__(self, ectrl, name, description, classes, monitors=None):
        if monitors is not None and len(classes) != len(monitors):
            raise RuntimeError("there must be equally many monitors as classes")

        super().__init__(ectrl, name, description, classes)

        if monitors is None:
            self._monitors = [None for _ in classes]
        else:
            self._monitors = monitors

    @property
    def dist_name(self):
        return ".".join([c if m is None else c+"-"+m for c,m in zip(self._classes, self._monitors)]) + "." + self._name

    @property
    def ctr_name(self):
        return super().dist_name

    def monitor(self):
        return self._ectrl._monitor_worker_counter(self)


ErisWorkerStatus = collections.namedtuple("ErisWorkerStatus", ["enabled", "suspending"])

class ErisWorker:
    """
    Wrapper class for a worker thread of ERIS.
    """

    def __init__(self, ectrl, cpuid, localid, socketid):
        self._ectrl = ectrl
        self._cpuid = cpuid
        self._localid = localid
        self._socketid = socketid

    @property
    def cpuid(self):
        return self._cpuid

    @property
    def localid(self):
        return self._localid

    @property
    def socketid(self):
        return self._socketid

    def disable(self):
        """
        Disable this ERIS worker thread.

        @returns:       Whether the disabling was successful or not.
        @rtype:         bool
        """
        c = self._ectrl._post("/osctrl/lpv/{}/disable".format(self._cpuid), rmode=ErisCtrl.RequestMode.CODE)

        return c == 200

    def enable(self):
        """
        Enable this ERIS worker thread.

        @returns:       Whether the enabling was successful or not.
        @rtype:         bool
        """
        c = self._ectrl._post("/osctrl/lpv/{}/enable".format(self._cpuid), rmode=ErisCtrl.RequestMode.CODE)

        return c == 200

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

    def frequency(self, freq_khz):
        """
        Set the CPU frequency for this ERIS worker thread.

        @param freq_khz: The target frequency for the ERIS worker thread in kHz.
        @type freq_khz: int
        @returns:       Whether the setting of the frequency was successful or not.
        @rtype:         bool
        """
        c = self._ectrl._post("/osctrl/setfrequency/{}/{}".format(self._cpuid, freq_khz), rmode=ErisCtrl.RequestMode.CODE)

        return c == 200

    def counters(self):
        """
        Get the list of per-worker counters.

        @returns: The list of counters that are available per worker.
        @rtype: list(ErisCounter)
        """
        return [
                ErisWorkerCounter(self._ectrl, "Task Time", "The time the worker spends scheduling queries.",
                    ["Sockets", "LPVs"], [str(self._socketid), str(self._localid)]),
                ErisWorkerCounter(self._ectrl, "Buffer Time", "The time the worker spends processing queries.",
                    ["Sockets", "LPVs"], [str(self._socketid), str(self._localid)])
               ]


class ErisCtrl:
    """
    The control interface to ERIS.

    This class handles all the general management requests to ERIS and is also the session manager.
    """

    class RequestMode(Enum):
        JSON = 1
        CODE = 2
        BOOL = 3

    def __init__(self, url, port, user, passwd):
        self._user = user
        self._passwd = passwd

        if url.startswith("http"):
            self._interface_url = "{}:{}".format(url, port)
        else:
            self._interface_url = "http://{}:{}".format(url, port)
        self._session = requests.Session()

        self._session_id = None

        self._monitor_session_id = None
        self._monitored_counters = {}

    def __enter__(self):
        self._login()
        return self

    def __exit__(self, type, value, traceback):
        self._logout()

    def _login(self):
        try:
            with self._session.post(self._interface_url + "/session",
                    data={"login" : self._user, "password" : self._passwd}) as r:

                if r.status_code != 200:
                    raise ErisCtrlError("Failed to login to ERIS -- wrong credentials?")

                data = r.json()
                if data["success"] == True:
                    logger.debug("Successfully logged in to ERIS")
                    self._session_id = data["id"]
                else:
                    raise ErisCtrlError("Failed to login to ERIS -- wrong credentials?")
        except:
            raise ErisCtrlError("Couldn't connect to ERIS -- not running?")

        # Also create a monitoring session together with the login
        self._monitor_session_id = self._post("/monitoring/sessions", data={"interval" : 1000})["id"]

    def _logout(self):
        # Delete the monitoring session
        if self._monitor_session_id is not None:
            self._delete("/monitoring/session/{}".format(self._monitor_session_id))
            self._monitor_session_id = None

    def _is_logged_in(self):
        return self._session_id is not None

    def _delete(self, sub_url):
        if not self._is_logged_in():
            raise ErisCtrlError("Not connected to ERIS")

        while True:
            with self._session.delete(self._interface_url + sub_url,
                    cookies={"id" : self._session_id}) as r:

                if r.status_code == 501:
                    logger.debug("Got 501 response -- Retrying")
                    continue

                return r.status_code == 200

    def _post(self, sub_url, data={}, rmode=RequestMode.JSON):
        if not self._is_logged_in():
            raise ErisCtrlError("Not connected to ERIS")

        while True:
            with self._session.post(self._interface_url + sub_url,
                    json=data, cookies={"id" : self._session_id}) as r:

                if r.status_code == 501:
                    logger.debug("Got 501 response -- Retrying")
                    continue

                if rmode == ErisCtrl.RequestMode.CODE:
                    return r.status_code

                if rmode == ErisCtrl.RequestMode.JSON:
                    if r.status_code != 200:
                        raise ErisCtrlError("Unable to make POST request to {}.\nResponse: {}".format(sub_url, r))

                    return r.json()
                else:
                    return r.status_code == 200

    def _get(self, sub_url, data={}, rmode=RequestMode.JSON):
        if not self._is_logged_in():
            raise ErisCtrlError("Not connected to ERIS")

        while True:
            with self._session.get(self._interface_url + sub_url,
                    json=data, cookies={"id" : self._session_id}) as r:

                if r.status_code == 501:
                    continue

                if rmode == ErisCtrl.RequestMode.CODE:
                    return r.status_code

                if rmode == ErisCtrl.RequestMode.JSON:
                    if r.status_code != 200:
                        raise ErisCtrlError("Unable to make GET request to {}.\nResponse: {}".format(sub_url, r))

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

    def benchmark_start(self, bench, mode=ErisBenchmarkMode.CLIENTS, scale_factor=1, clients=1, interval=1000,
            requests=10):
        """
        Start one specific benchmark instance on ERIS.

        @param bench:   The name of the benchmark that should be started.
        @type bench:    str
        @param mode:    The mode in with with the benchmark should be started.
        @type mode:     ErisBenchmarkMode
        @param scale_factor: The number with which the benchmark base data size should be scaled.
        @type scale_factor: int
        @param clients: The number of clients that should be used when started in the 'clients' mode.
        @type clients:  int
        @param interval: The interval between individual requests in 'timed' mode.
        @type interval: int
        @param requests: The number of requests that should be started per transaction.
        @type requests: int
        @returns:       A handle to the benchmark instance.
        @rtype:         ErisBenchmark
        """
        data = self._post("/benchmarking/start/{name}/{mode}/{scale_factor}/{clients}/{interval}/{requests}".format(
            name=bench, mode=mode.name.lower(), scale_factor=scale_factor, clients=clients,
            interval=interval, requests=requests))

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
                workers.append(ErisWorker(self, worker["physicalId"], worker["localId"], socket["physicalId"]))

        return workers


    # Functions for the monitoring interface of ERIS.
    def counters(self):
        """
        Get the list of available monitoring counters.

        @returns:       The list of all available monitoring counters for ERIS.
        @rtype:         list(ErisCounters)
        """
        # Currently we hard-code a list of useful counters
        return [
                ErisCounter(self, "Started", "Number of started tasks.", ["Tasks"]),
                ErisCounter(self, "Active", "Number of active tasks.", ["Tasks"]),
                ErisCounter(self, "Finished", "Number of finished tasks.", ["Tasks"]),
                ErisCounter(self, "Latency Average", "Average latency of the tasks.", ["Tasks"])
               ]

    def _monitor_counter(self, ectr):
        """
        Add a counter to the list of monitored ones.

        @param ectr:    The ErisCounter instance that wraps the monitorable counter.
        @type ectr:     ErisCounter
        @return:        The counter wrapper that can be used to gather values.
        @rtype:         ErisMonitoredCounter
        """
        post_data = {"classes" : [], "counter" : ectr.name}
        for c in ectr._classes:
            post_data["classes"].append({"class" : c})

        data = self._post("/monitoring/session/{}/queries".format(self._monitor_session_id),
                data=post_data)

        ctr_id = data["id"]

        mctr = ErisMonitoredCounter(self, ectr, ctr_id)
        self._monitored_counters[ctr_id] = mctr

        return mctr

    def _monitor_worker_counter(self, wctr):
        """
        Add a worker counter to the list of monitored ones.

        @param wctr:    The ErisWorkerCounter instance that wraps the monitorable counter.
        @type wctr:     ErisWorkerCounter
        @return:        The counter wrapper that can be used to gather values.
        @rtype:         ErisMonitoredCounter
        """
        post_data = {"classes" : [], "counter" : wctr.name}
        for c, m in zip(wctr._classes, wctr._monitors):
            if m is None:
                post_data["classes"].append({"class" : c})
            else:
                post_data["classes"].append({"class" : c, "monitor" : m})

        data = self._post("/monitoring/session/{}/queries".format(self._monitor_session_id),
                data=post_data)

        ctr_id = data["id"]

        mctr = ErisMonitoredCounter(self, wctr, ctr_id)
        self._monitored_counters[ctr_id] = mctr

        return mctr

    def _unmonitor_counter(self, ctr_id):
        """
        Remove a counter from the list of monitored ones.
        """
        if not ctr_id in self._monitored_counters:
            raise ErisCtrlError("There is no such monitored counter with the id {}".format(ctr_id))

        self._delete("/monitoring/session/{}/queries/{}".format(self._monitor_session_id, ctr_id))
        del self._monitored_counters[ctr_id]

    def _pull_monitoring_data(self):
        """
        Get the latest counter values from ERIS.
        """
        try:
            data = self._get("/monitoring", rmode=ErisCtrl.RequestMode.JSON)
            for m in data["messages"]:
                if m["sessionId"] != self._monitor_session_id:
                    logger.debug("Found message for a different session.")
                    continue

                for q in m["queries"]:
                    qid = q["queryId"]

                    if not qid in self._monitored_counters:
                        logger.debug("Found non existing query")
                        continue

                    mctr = self._monitored_counters[qid]
                    mctr._push_values(q["relativeTime"], q["measurements"])

        except ErisCtrlError as e:
            logger.info("Failed to pull monitoring data.\nGot: {}".format(e))
            return

    def energy_management(self, ecl, autoadapt):
        """
        Enable/Disable the ECL and the auto-adapt features of ERIS

        @param  ecl:    Whether or not ERIS should use its ECL.
        @type ecl:      bool
        @param autoadapt: Whether or not ERIS should use its auto-adapt feature.
        @type autoadapt: bool
        @returns:       Whether or not changing this features was successful.
        @rtype:         bool
        """
        ecl_code = self._post("/osctrl/setcontrolstatus/eclon/{}".format("0" if not ecl else "1"),
                rmode=ErisCtrl.RequestMode.CODE)
        adapt_code = self._post("/osctrl/setcontrolstatus/adapton/{}".format("0" if not autoadapt else "1"),
                rmode=ErisCtrl.RequestMode.CODE)

        return ecl_code == 200 and adapt_code == 200
