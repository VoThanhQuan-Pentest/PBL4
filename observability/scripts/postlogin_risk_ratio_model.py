"""Recipe6 research: one continuous, before-action request/history ratio.

No cutoff, labels, OTP evidence or identity enters the feature calculation.
Raw input remains the Java-audited schema6/65; model input is schema7/66.
"""
import numpy as np
from postlogin_risk_model import ObservableContextScorer


def relative_volume(values):
    values = np.asarray(values, dtype=np.float64)
    if values.ndim != 2 or values.shape[1] != 65 or not np.isfinite(values).all():
        raise ValueError("finite Java-audited schema6/65 input required")
    history, available = values[:, 63], values[:, 64]
    if np.any(history < 0) or np.any(~np.isin(available, [0, 1])):
        raise ValueError("explicit nonnegative observed history required")
    ratio = np.zeros(len(values))
    np.divide(values[:, 57], history, out=ratio, where=(available == 1) & (history > 0))
    if not np.isfinite(ratio).all() or np.any(ratio < 0):
        raise ValueError("finite nonnegative ratio required")
    return ratio


class RelativeVolumeScorer(ObservableContextScorer):
    recipe_version = 6
    feature_schema_version = 7

    def __init__(self, representation):
        if representation not in ("baseline", "candidate"):
            raise ValueError("fixed baseline65 or candidate66 required")
        super().__init__("candidate")
        self.representation = representation

    def values(self, values):
        raw = super().values(values)
        if self.representation == "baseline":
            return raw
        return np.column_stack((raw, relative_volume(raw)))
