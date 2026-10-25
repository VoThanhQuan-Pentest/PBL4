"""Versioned schema6 context scorer; serving/fit admission is separate from risk."""
from dataclasses import asdict
import numpy as np
from scipy.special import logsumexp
from sklearn.ensemble import HistGradientBoostingClassifier
from .contract import feature_array
from .hybrid_incident import HybridResearchConfig, training_labels, MAX_LABELED_ROWS
from .normal_support import NormalSupportScorer, _signed_log, MAX_REFERENCE_ROWS, MAX_SCORE_ROWS
from .postlogin_contract import FEATURE_NAMES, LABELS, EVALUATION_UNIT, require_campaign_admission


def features(rows, maximum):
    raw=np.asarray(rows,dtype=np.float64)
    if raw.ndim!=2 or raw.shape[1]!=65 or not 1<=len(raw)<=maximum or not np.isfinite(raw).all():
        raise ValueError("bounded finite65 pre-attempt matrix required")
    feature_array(raw[:,:37].tolist(),maximum,4)
    if (raw[:,57:65]<0).any() or not np.isin(raw[:,64],(0,1)).all():
        raise ValueError("observed rolling history required")
    return raw


def projection(raw):
    ratio=np.zeros(len(raw));np.divide(raw[:,57],raw[:,63],out=ratio,where=(raw[:,64]==1)&(raw[:,63]>0))
    rates=[]
    for column in (59,60):
        result=np.zeros(len(raw));np.divide(raw[:,column],raw[:,57],out=result,where=raw[:,57]>0);rates.append(result)
    return np.column_stack((raw[:,57:65],ratio,*rates))


class PostLoginContextScorer:
    def __init__(self, config=None):
        self._config=config if config is not None else HybridResearchConfig(100,15,0,42)
        if type(self._config) is not HybridResearchConfig:raise ValueError("typed predeclared configuration required")
        self._normal=self._classifier=None;self.normal_fit_count=self.labeled_fit_count=0

    @property
    def config(self):return self._config

    def parameters(self):
        return {"model_kind":"normal_plus_incident_research","recipe_version":2,
            "feature_schema_version":6,"evaluation_unit":EVALUATION_UNIT,"feature_names":list(FEATURE_NAMES),
            "config":asdict(self.config),"normal_width":37,"classifier_width":11,"class_names":list(LABELS),
            "projection":"ROLLING8_REQUEST_HISTORY_RATIO_AND_HTTP4XX_5XX_RATES",
            "normal_recipe":NormalSupportScorer(8,256,"euclidean",self.config.random_state).parameters(),
            "fusion":"MAX_LOG_POSITIVE_ODDS_MARGIN_AND_LOG_SUPPORT_DISTANCE_PLUS_EPSILON",
            "calibration_used_in_fit":False,"actor_role_is_ml_target":False}

    def fit(self, normal, labeled, labels, *, protocol, approval, reserve_component):
        require_campaign_admission(protocol,approval)
        if self._classifier is not None:raise ValueError("already fitted")
        normal=features(normal,MAX_REFERENCE_ROWS);labeled=features(labeled,MAX_LABELED_ROWS)
        targets=training_labels(labels,len(labeled))
        if len(normal)!=50000 or len(labeled)!=81500 or not np.array_equal(normal,labeled[:50000]) or np.any(targets[:50000]!=0):
            raise ValueError("strict matching-fold50000normal/81500labeled source required; benchmark is never training")
        reserve_component("normal")
        self._normal=NormalSupportScorer(8,256,"euclidean",self.config.random_state).fit(normal[:,:37])
        reserve_component("classifier")
        self._classifier=HistGradientBoostingClassifier(**asdict(self.config),learning_rate=.1,
            min_samples_leaf=20,max_bins=255,early_stopping=False,categorical_features=None,class_weight=None).fit(_signed_log(projection(labeled)),targets)
        if not np.array_equal(self._classifier.classes_,[0,1,2]):raise ValueError("three context classes required")
        self.normal_fit_count=len(normal);self.labeled_fit_count=len(labeled);return self

    def score_components(self, rows):
        if self._classifier is None:raise ValueError("not fitted")
        raw=features(rows,MAX_SCORE_ROWS)
        logits=self._classifier._raw_predict(_signed_log(projection(raw)))
        if logits.shape!=(len(raw),3) or not np.isfinite(logits).all():raise ValueError("invalid learned logits")
        margin=logsumexp(logits[:,1:],axis=1)-logits[:,0]
        distance=self._normal.anomaly_scores(raw[:,:37]);novelty=np.log(distance+1e-12)
        fused=np.maximum(margin,novelty)
        if not np.isfinite(fused).all():raise ValueError("invalid fused score")
        return {"raw_anomaly_score":fused,"incident_margin":margin,"normal_support_distance":distance,
                "normal_novelty_log_score":novelty,"uncalibrated_context_probabilities":np.exp(logits-logsumexp(logits,axis=1,keepdims=True))}

    def anomaly_scores(self, rows):return self.score_components(rows)["raw_anomaly_score"]
    def score_samples(self, rows):return -self.anomaly_scores(rows)
