"""The small learning model of the BridgeAgent.

Estimator: online linear regression (recursive least squares) on the logarithm of a duration.
- log, because durations are always positive and spread a lot (2 ms ... 20 s) - errors are factors, not seconds.
- "forgetting": new samples count more than old ones, so the baseline (start values) slowly loses weight.
- worst case: a learned 90 % bound of the error, so "worst" is the time 9 out of 10 cases stay below.
Everything is plain numbers, so it fits into the backup and into baseline.json.
"""
import math

MIN_SECONDS = 0.0005
MAX_SECONDS = 24 * 3600
# Cap of the uncertainty, so the model does not "wind up" when a feature never changes
MAX_P = 25.0
MIN_P = 1e-6
WORST_QUANTILE = 0.9
MIN_LOG = math.log(MIN_SECONDS)
MAX_LOG = math.log(MAX_SECONDS)


def to_log(seconds):
    return math.log(min(max(seconds, MIN_SECONDS), MAX_SECONDS))


def _finite(value, default):
    return value if isinstance(value, (int, float)) and math.isfinite(value) else default


class Estimator:
    def __init__(self, features=1, start_seconds=0.5, start_spread=1.0, prior_strength=4.0, forgetting=0.995,
                 bounds=None):
        self.w = [to_log(start_seconds)] + [0.0] * (features - 1)
        # Allowed range of each weight after the first (e.g. "time grows at most about linearly with the queue"),
        # so the model never extrapolates to absurd values
        self.bounds = [list(bound) for bound in (bounds or [])]
        # Uncertainty of the weights: small = strong prior (baseline), it grows back with forgetting
        self.p = [[(1.0 / prior_strength) if i == j else 0.0 for j in range(features)] for i in range(features)]
        self.forgetting = forgetting
        # log(worst / typical) - learned 90 % bound of the error
        self.spread = start_spread
        self.samples = 0
        # How good the estimates are: share of samples below the worst case, mean error (log)
        self.hits = 0.0
        self.checked = 0.0
        self.mean_error = start_spread / 2
        # Short-term average error - detects changes (and anomalies: much slower than usual)
        self.recent_error = 0.0
        self.drift_up = 0.0
        self.drift_down = 0.0
        self.changes = 0

    @property
    def features(self):
        return len(self.w)

    def _x(self, x):
        x = list(x)[:self.features]
        return x + [0.0] * (self.features - len(x))

    def predict_log(self, x=(1.0,)):
        x = self._x(x)
        return sum(w * value for w, value in zip(self.w, x))

    def estimate(self, x=(1.0,)):
        """(typical seconds, worst seconds) - always finite and in [MIN_SECONDS, MAX_SECONDS]"""
        log_value = min(max(_finite(self.predict_log(x), MAX_LOG), MIN_LOG), MAX_LOG)
        spread = min(max(_finite(self.spread, 1.0), 0.05), 5.0)
        return math.exp(log_value), math.exp(min(log_value + spread, MAX_LOG))

    def update(self, x, seconds):
        x = self._x(x)
        y = to_log(seconds)
        error = y - self.predict_log(x)
        # Quality before learning from the sample
        self.checked = self.checked * 0.995 + 1
        self.hits = self.hits * 0.995 + (1 if error <= self.spread else 0)
        self.recent_error += 0.3 * (error - self.recent_error)
        # Change detection (CUSUM): errors in one direction add up, normal noise cancels out
        scale = max(self.mean_error * 1.25, 0.05)
        self.drift_up = max(0.0, self.drift_up + error / scale - 1.0)
        self.drift_down = max(0.0, self.drift_down - error / scale - 1.0)
        if self.samples >= 10 and (self.drift_up > 5 or self.drift_down > 5):
            # Something changed (e.g. a host got much slower): be unsure again, so the model learns the new
            # situation within a few samples instead of slowly averaging it in
            self.p = [[min(MAX_P, value * 20) if i == j else value for j, value in enumerate(row)]
                      for i, row in enumerate(self.p)]
            self.drift_up = self.drift_down = 0.0
            self.changes += 1
        self.mean_error += 0.05 * (abs(error) - self.mean_error)
        # Recursive least squares with forgetting
        px = [sum(self.p[i][j] * x[j] for j in range(self.features)) for i in range(self.features)]
        denominator = self.forgetting + sum(x[i] * px[i] for i in range(self.features))
        if math.isfinite(denominator) and denominator > 1e-9 and math.isfinite(error):
            gain = [value / denominator for value in px]
            self.w = [w + g * error for w, g in zip(self.w, gain)]
            self._clip()
            self.p = [[(self.p[i][j] - gain[i] * px[j]) / self.forgetting for j in range(self.features)]
                      for i in range(self.features)]
        self._stabilize()
        # 90 % bound of the error (stochastic quantile estimate, fast at first, then calmer)
        step = max(0.02, 1.5 / (self.samples + 10))
        self.spread += step * ((1 if error > self.spread else 0) - (1 - WORST_QUANTILE)) * 2
        self.spread = min(max(self.spread, 0.05), 5.0)
        self.samples += 1

    def _stabilize(self):
        """Keeps the model healthy: P symmetric and positive, uncertainty capped, weights finite.
        Rounding errors otherwise make P drift apart in directions that hardly change (e.g. a queue that is almost
        always empty) until the weights jump and finally become NaN."""
        n = self.features
        for i in range(n):
            self.p[i][i] = min(max(_finite(self.p[i][i], MAX_P), MIN_P), MAX_P)
        for i in range(n):
            for j in range(i + 1, n):
                value = _finite((self.p[i][j] + self.p[j][i]) / 2, 0.0)
                limit = math.sqrt(self.p[i][i] * self.p[j][j]) * 0.999
                value = min(max(value, -limit), limit)
                self.p[i][j] = self.p[j][i] = value
        if not all(math.isfinite(w) for w in self.w):
            # Should never happen any more - start again from a neutral, unsure state instead of answering NaN
            self.w = [to_log(0.5)] + [0.0] * (n - 1)
            self.p = [[MAX_P if i == j else 0.0 for j in range(n)] for i in range(n)]
        self.w[0] = min(max(self.w[0], MIN_LOG - 5), MAX_LOG + 5)
        self._clip()

    def _clip(self):
        for index, bound in enumerate(self.bounds, start=1):
            if index < len(self.w) and bound:
                self.w[index] = min(max(self.w[index], bound[0]), bound[1])

    def hit_rate(self):
        return self.hits / self.checked if self.checked else None

    def to_state(self):
        return {"w": list(self.w), "p": [list(row) for row in self.p], "forgetting": self.forgetting,
                "spread": self.spread, "samples": self.samples, "hits": self.hits, "checked": self.checked,
                "mean_error": self.mean_error, "recent_error": self.recent_error, "changes": self.changes,
                "drift_up": self.drift_up, "drift_down": self.drift_down, "bounds": [list(b) for b in self.bounds]}

    @classmethod
    def from_state(cls, state):
        estimator = cls(features=len(state["w"]))
        estimator.w = [float(value) for value in state["w"]]
        estimator.p = [[float(value) for value in row] for row in state["p"]]
        estimator.forgetting = float(state.get("forgetting", 0.995))
        estimator.spread = float(state.get("spread", 1.0))
        estimator.samples = int(state.get("samples", 0))
        estimator.hits = float(state.get("hits", 0.0))
        estimator.checked = float(state.get("checked", 0.0))
        estimator.mean_error = float(state.get("mean_error", 0.5))
        estimator.recent_error = float(state.get("recent_error", 0.0))
        estimator.changes = int(state.get("changes", 0))
        estimator.drift_up = float(state.get("drift_up", 0.0))
        estimator.drift_down = float(state.get("drift_down", 0.0))
        estimator.bounds = [list(bound) for bound in state.get("bounds") or []]
        # A state with NaN / Infinity (e.g. from an older version) is repaired instead of spreading
        estimator.spread = min(max(_finite(estimator.spread, 1.0), 0.05), 5.0)
        estimator.mean_error = _finite(estimator.mean_error, 0.5)
        estimator.recent_error = _finite(estimator.recent_error, 0.0)
        estimator.drift_up = _finite(estimator.drift_up, 0.0)
        estimator.drift_down = _finite(estimator.drift_down, 0.0)
        estimator._stabilize()
        return estimator

    def as_prior(self, prior_strength=1.0):
        """A new estimator that starts from this one (e.g. a new host starts from the general experience).
        prior_strength 1 = the start value counts like one sample - own samples take over quickly."""
        estimator = Estimator.from_state(self.to_state())
        estimator.p = [[(1.0 / prior_strength) if i == j else 0.0 for j in range(self.features)] for i in range(self.features)]
        estimator.samples = 0
        estimator.hits = estimator.checked = 0.0
        estimator.recent_error = estimator.drift_up = estimator.drift_down = 0.0
        return estimator


class Rate:
    """Decaying counter of good / bad outcomes (e.g. answered / expired tasks of a host)."""

    def __init__(self, good=4.0, bad=0.0):
        # Start: 4 good ones, so a new host counts as reliable until it proves otherwise
        self.good = good
        self.bad = bad

    def add(self, ok):
        self.good *= 0.98
        self.bad *= 0.98
        if ok:
            self.good += 1
        else:
            self.bad += 1

    def value(self):
        total = self.good + self.bad
        return self.good / total if total else 1.0

    def to_state(self):
        return {"good": self.good, "bad": self.bad}

    @classmethod
    def from_state(cls, state):
        return cls(float(state.get("good", 4.0)), float(state.get("bad", 0.0)))
