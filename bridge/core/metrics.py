"""Analysis: counters and timings of the server - last minute, last hour and since the start.

Cheap enough to run always: counters use 60 one-second and 60 one-minute buckets, timings keep the last 2000 values.
Shown by /admin/analysis (together with links, mailboxes, conversations, ...).
"""
import collections
import time

_counters = {}
_timings = {}
# Paths of the app's endpoints - everything else is counted as "other" (unknown paths must not create new counters)
known_paths = set()
started_at = time.time()
TIMING_SAMPLES = 2000


class Counter:
    __slots__ = ("total", "seconds", "second_stamps", "minutes", "minute_stamps")

    def __init__(self):
        self.total = 0
        self.seconds = [0] * 60
        self.second_stamps = [0] * 60
        self.minutes = [0] * 60
        self.minute_stamps = [0] * 60

    def add(self, value=1, now=None):
        now = int(now or time.time())
        self.total += value
        index = now % 60
        if self.second_stamps[index] != now:
            self.second_stamps[index], self.seconds[index] = now, 0
        self.seconds[index] += value
        minute = now // 60
        index = minute % 60
        if self.minute_stamps[index] != minute:
            self.minute_stamps[index], self.minutes[index] = minute, 0
        self.minutes[index] += value

    def last_minute(self, now):
        now = int(now)
        return sum(value for value, stamp in zip(self.seconds, self.second_stamps) if now - stamp < 60)

    def last_hour(self, now):
        minute = int(now) // 60
        return sum(value for value, stamp in zip(self.minutes, self.minute_stamps) if minute - stamp < 60)


def count(name, value=1):
    counter = _counters.get(name)
    if counter is None:
        counter = _counters[name] = Counter()
    counter.add(value)


def timing(name, seconds):
    values = _timings.get(name)
    if values is None:
        values = _timings[name] = collections.deque(maxlen=TIMING_SAMPLES)
    values.append(seconds)


def _percentile(sorted_values, share):
    if not sorted_values:
        return None
    index = min(len(sorted_values) - 1, max(0, int(round(share * (len(sorted_values) - 1)))))
    return round(sorted_values[index], 5)


def report():
    now = time.time()
    counters = {}
    for name, counter in sorted(_counters.items()):
        counters[name] = {"last_minute": counter.last_minute(now), "last_hour": counter.last_hour(now), "total": counter.total}
    timings = {}
    for name, values in sorted(_timings.items()):
        ordered = sorted(values)
        timings[name] = {"samples": len(ordered), "p50_s": _percentile(ordered, 0.5), "p90_s": _percentile(ordered, 0.9),
                         "p99_s": _percentile(ordered, 0.99), "max_s": round(ordered[-1], 5) if ordered else None}
    return {"uptime_s": round(now - started_at, 1), "counters": counters, "timings": timings}


def reset():
    _counters.clear()
    _timings.clear()


class RequestMetricsMiddleware:
    """Counts every HTTP request per endpoint group (e.g. /message/send) with duration and errors."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "/")
        group = path if path in known_paths else "other"
        started = time.monotonic()
        status_holder = {"status": 500}

        async def counting_send(message):
            if message["type"] == "http.response.start":
                status_holder["status"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, counting_send)
        finally:
            # Long polls wait on purpose - their duration says nothing about the speed of Bridge
            if not group.endswith(("/poll", "/stream")):
                timing(f"http {group}", time.monotonic() - started)
            count(f"http {group}")
            if status_holder["status"] >= 400:
                count(f"http errors {status_holder['status']}")
