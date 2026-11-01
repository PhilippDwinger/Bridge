"""BridgeAgent: learns from Bridge's own experience and estimates times.

It only learns from metadata - times, sizes, queue lengths - never from contents.
What it learns (one small model per key, see model.py):
    deliver:<route>               delivering a message: route "local", "remote:<server>" or "relay"
    s2s:<server>                  one server to server request
    pickup:<client_ip>            time until a client takes a message out of its mailbox (feature: messages ahead)
    process:<realm>|<cmd>|<host>  time from taking a task to the response - per host ...
    process:<realm>|<cmd>         ... and per command (all hosts)
    roundtrip:<realm>|<cmd>|<host> caller side: call -> response arrived
Every kind also has a general model "<kind>:*". It starts from baseline.json (made by tools/train_agent.py), learns
from every sample and is the start value for new keys. New samples count more, so the baseline slowly loses weight.

The learned state is part of the encrypted backup at the trusted servers (compressed), so it survives restarts.
Modes (server setting agent_mode): learn (default) | frozen (estimates, but does not learn) | off.
"""
import datetime
import json
import math
import os
import time

from bridge.core import metrics, protocol
from bridge.subservices.bridge_agent.model import Estimator, Rate

BASELINE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "baseline.json")
BASELINE_FORMAT = 1
MAX_ESTIMATORS = 5000
MAX_TRACKED_TASKS = 20000
# A specific model is used once it has this many samples, before that the more general one
MIN_SAMPLES = 3

# kind -> (features, start seconds if there is no baseline)
KINDS = {
    "deliver": (2, 0.005),
    "s2s": (1, 0.01),
    "pickup": (2, 0.5),
    "process": (2, 0.5),
    "roundtrip": (1, 1.0),
}
# Allowed range of the second weight: time grows at most about linearly with size / queue (power 0 ... 1.5)
BOUNDS = {"deliver": [[0.0, 1.5]], "pickup": [[0.0, 1.5]], "process": [[0.0, 1.5]]}

estimators = {}
_last_used = {}
reliability = {}
# Calls per hour of the day (UTC) - the load profile
load_profile = [0.0] * 24
# In-flight tasks (monotonic clock, not part of the backup)
host_tasks = {}
caller_tasks = {}
baseline_info = {"loaded": False}
# Samples the general models had in baseline.json (more = this server learned something itself)
_baseline_samples = {}


def _now():
    return time.monotonic()

def mode():
    return getattr(protocol, "agent_mode", "learn")

def enabled():
    return mode() != "off"

def learning():
    return mode() == "learn"

def kib(size_bytes):
    return max(0.0, (size_bytes or 0) / 1024)


# region models
def _general(kind):
    name = f"{kind}:*"
    estimator = estimators.get(name)
    if estimator is None:
        features, start = KINDS[kind]
        estimator = Estimator(features=features, start_seconds=start, start_spread=1.0, forgetting=0.995,
                              bounds=BOUNDS.get(kind))
        estimators[name] = estimator
    return estimator

def _get(name, create=True):
    estimator = estimators.get(name)
    if estimator is None and create:
        _evict()
        kind = name.split(":", 1)[0]
        estimator = _general(kind).as_prior()
        estimator.forgetting = 0.98
        estimators[name] = estimator
    if estimator is not None:
        _last_used[name] = time.time()
    return estimator

def _evict():
    if len(estimators) < MAX_ESTIMATORS:
        return
    specific = [name for name in estimators if not name.endswith(":*")]
    specific.sort(key=lambda name: _last_used.get(name, 0))
    for name in specific[:max(1, len(specific) // 10)]:
        estimators.pop(name, None)
        _last_used.pop(name, None)

def _learn(kind, names, x, seconds):
    if not learning() or seconds is None or seconds < 0:
        return
    _general(kind).update(x, seconds)
    for name in names:
        _get(name).update(x, seconds)

def _pick(names, kind):
    """The most specific model with enough samples (names from specific to general) and how specific it is."""
    for index, name in enumerate(names):
        estimator = estimators.get(name)
        if estimator is not None and estimator.samples >= MIN_SAMPLES:
            # own: exactly this host / client / route - command: all hosts of the command
            return estimator, name, "own" if index == 0 else "command"
    general = _general(kind)
    # general: the experience of this server - baseline: nothing learned yet, start values from baseline.json
    return general, f"{kind}:*", "general" if general.samples > _baseline_samples.get(kind, 0) else "baseline"

def _describe(picked, x):
    estimator, name, based_on = picked
    typical, worst = estimator.estimate(x)
    return {"typical_s": round(typical, 4), "worst_s": round(worst, 4), "samples": estimator.samples,
            "based_on": based_on, "model": name}
# endregion models


# region measuring (hooks called by Bridge)
def message_arrived(message, ahead):
    """A message was put into a mailbox."""
    if enabled():
        message._agent_arrived = _now()
        message._agent_ahead = ahead

def message_taken(client_ip, message):
    """A client took a message out of its mailbox (poll)."""
    if not enabled() or getattr(message, "_agent_taken", False):
        return
    message._agent_taken = True
    arrived = getattr(message, "_agent_arrived", None)
    if arrived is not None:
        ahead = getattr(message, "_agent_ahead", 0)
        waited = _now() - arrived
        metrics.timing("pickup", waited)
        _learn("pickup", [f"pickup:{client_ip}"], [1.0, math.log1p(ahead)], waited)
    if str(getattr(message, "content_type", "")) == "task":
        task_taken(message.message_id)

def task_arrived(task_id, host_ip, realm_address, command_name, ahead, size_bytes):
    if not enabled():
        return
    if len(host_tasks) >= MAX_TRACKED_TASKS:
        host_tasks.pop(next(iter(host_tasks)))
    host_tasks[task_id] = {"arrived": _now(), "taken": None, "host": host_ip, "realm": realm_address,
                           "command": command_name, "ahead": ahead, "kib": kib(size_bytes)}

def task_taken(task_id):
    entry = host_tasks.get(task_id)
    if entry is not None and entry["taken"] is None:
        entry["taken"] = _now()

def task_answered(task_id):
    entry = host_tasks.pop(task_id, None)
    if entry is None or not enabled():
        return
    reliability.setdefault(entry["host"], Rate()).add(True)
    if entry["taken"] is not None:
        key = f"{entry['realm']}|{entry['command']}"
        _learn("process", [f"process:{key}|{entry['host']}", f"process:{key}"], [1.0, math.log1p(entry["kib"])],
               _now() - entry["taken"])

def task_expired(task_id, host_ip):
    """The host never answered the task."""
    host_tasks.pop(task_id, None)
    if enabled() and learning():
        reliability.setdefault(host_ip, Rate()).add(False)

def call_sent(task_id, realm_address, command_name, host_ip, route, size_bytes, deliver_seconds):
    if not enabled():
        return
    if len(caller_tasks) >= MAX_TRACKED_TASKS:
        caller_tasks.pop(next(iter(caller_tasks)))
    caller_tasks[task_id] = {"sent": _now() - deliver_seconds, "realm": realm_address, "command": command_name,
                             "host": host_ip}
    delivered(route, size_bytes, deliver_seconds)
    hour = datetime.datetime.now(datetime.timezone.utc).hour
    load_profile[hour] += 1

def response_arrived(task_id):
    entry = caller_tasks.pop(task_id, None)
    if entry is None or not enabled():
        return
    _learn("roundtrip", [f"roundtrip:{entry['realm']}|{entry['command']}|{entry['host']}"], [1.0], _now() - entry["sent"])

def delivered(route, size_bytes, seconds):
    if enabled():
        _learn("deliver", [f"deliver:{route}"], [1.0, math.log1p(kib(size_bytes))], seconds)

def s2s_sample(peer_url, seconds):
    if enabled():
        _learn("s2s", [f"s2s:{peer_url}"], [1.0], seconds)
# endregion measuring


# region estimates (only local knowledge - service.py combines servers)
def process_estimate(realm_address, command_name, host_ip, size_bytes=0):
    key = f"{realm_address}|{command_name}"
    x = [1.0, math.log1p(kib(size_bytes))]
    return _describe(_pick([f"process:{key}|{host_ip}", f"process:{key}"], "process"), x)

def pickup_estimate(client_ip, ahead=0):
    x = [1.0, math.log1p(max(0, ahead))]
    return _describe(_pick([f"pickup:{client_ip}"], "pickup"), x)

def deliver_estimate(route, size_bytes=0):
    x = [1.0, math.log1p(kib(size_bytes))]
    return _describe(_pick([f"deliver:{route}"], "deliver"), x)

def roundtrip_observed(realm_address, command_name, host_ip):
    name = f"roundtrip:{realm_address}|{command_name}|{host_ip}"
    estimator = estimators.get(name)
    if estimator is None or estimator.samples < MIN_SAMPLES:
        return None
    return _describe((estimator, name, "own"), [1.0])

def host_reliability(host_ip):
    rate = reliability.get(host_ip)
    return round(rate.value(), 3) if rate else 1.0

def anomalies(limit=20):
    """Commands/clients that are much slower (or faster) than they usually are."""
    found = []
    for name, estimator in estimators.items():
        if name.endswith(":*") or estimator.samples < 10 or not name.startswith(("process:", "pickup:")):
            continue
        if abs(estimator.recent_error) >= math.log(3):
            factor = math.exp(estimator.recent_error)
            found.append({"model": name, "factor": round(factor, 2),
                          "text": f"{'slower' if factor > 1 else 'faster'} than usual (x{factor:.1f})"})
    found.sort(key=lambda entry: -abs(math.log(entry["factor"])))
    return found[:limit]

def accuracy():
    """How good the estimates are: share of samples below the worst case (target ~90 %) and the typical error."""
    result = {}
    for kind in KINDS:
        estimator = _general(kind)
        rate = estimator.hit_rate()
        result[kind] = {"samples": estimator.samples,
                        "within_worst_case": round(rate, 3) if rate is not None else None,
                        "typical_error_factor": round(math.exp(estimator.mean_error), 2)}
    return result
# endregion estimates


# region state (backup, baseline, reset)
def to_state():
    return {
        "format": BASELINE_FORMAT,
        "estimators": {name: estimator.to_state() for name, estimator in estimators.items()},
        "reliability": {ip: rate.to_state() for ip, rate in reliability.items()},
        "load_profile": list(load_profile),
        "baseline": dict(baseline_info),
    }

def load_state(state):
    if not isinstance(state, dict) or state.get("format") != BASELINE_FORMAT:
        return False
    estimators.clear()
    _last_used.clear()
    for name, data in (state.get("estimators") or {}).items():
        try:
            estimators[name] = Estimator.from_state(data)
        except (KeyError, TypeError, ValueError):
            continue
    reliability.clear()
    for ip, data in (state.get("reliability") or {}).items():
        reliability[ip] = Rate.from_state(data)
    profile = state.get("load_profile") or []
    load_profile[:] = [float(value) for value in profile][:24] + [0.0] * max(0, 24 - len(profile))
    baseline_info.update(state.get("baseline") or {})
    return True

def export_baseline():
    """The general models as a new baseline.json (e.g. after a long run on the real server)."""
    return {
        "format": BASELINE_FORMAT,
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "note": "Start values of the BridgeAgent. Made by tools/train_agent.py or /admin/agent export.",
        "kinds": {kind: _general(kind).to_state() for kind in KINDS},
    }

def load_baseline(data=None):
    """Loads baseline.json (or the given data). Specific models stay as they are."""
    if data is None:
        try:
            with open(BASELINE_PATH, encoding="utf-8") as file:
                data = json.load(file)
        except (OSError, ValueError):
            baseline_info.update(loaded=False, reason="no baseline.json")
            return False
    if not isinstance(data, dict) or data.get("format") != BASELINE_FORMAT:
        baseline_info.update(loaded=False, reason="unknown format")
        return False
    for kind, state in (data.get("kinds") or {}).items():
        if kind in KINDS:
            state = dict(state, bounds=BOUNDS.get(kind, []))
            estimator = Estimator.from_state(state)
            _baseline_samples[kind] = estimator.samples
            # The baseline is a start value: keep its knowledge, but let the server's own samples count fast
            estimator.p = [[min(value, 0.25) if i == j else value for j, value in enumerate(row)]
                           for i, row in enumerate(estimator.p)]
            estimators[f"{kind}:*"] = estimator
    baseline_info.update(loaded=True, created_at=data.get("created_at"), reason=None)
    return True

def reset():
    """Forgets everything the server learned and starts again from the baseline."""
    estimators.clear()
    _last_used.clear()
    reliability.clear()
    host_tasks.clear()
    caller_tasks.clear()
    load_profile[:] = [0.0] * 24
    load_baseline()

def status():
    kinds = {}
    for name, estimator in estimators.items():
        kind = name.split(":", 1)[0]
        entry = kinds.setdefault(kind, {"models": 0, "samples": 0})
        entry["models"] += 1
        entry["samples"] += estimator.samples
    unreliable = sorted(((ip, rate.value()) for ip, rate in reliability.items() if rate.value() < 0.9), key=lambda item: item[1])
    return {
        "mode": mode(),
        "baseline": dict(baseline_info),
        "models": kinds,
        "accuracy": accuracy(),
        "anomalies": anomalies(),
        "unreliable_hosts": [{"host_ip": ip, "reliability": round(value, 3)} for ip, value in unreliable[:20]],
        "load_profile_utc": [round(value, 1) for value in load_profile],
        "tracked_tasks": {"as_host_server": len(host_tasks), "as_caller_server": len(caller_tasks)},
    }
# endregion state


load_baseline()
