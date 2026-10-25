"""Research classifier projection to the observable rubric's sufficient inputs.

Retains the genuine37-wide normal component, fusion and calibration policy.
No zero padding, hand-coded target cutoff, identity or outcome features.
"""
import numpy as np
from scipy.special import logsumexp
from sklearn.ensemble import HistGradientBoostingClassifier
from app.hybrid_incident import training_labels
from app.normal_support import NormalSupportScorer, _signed_log
from postlogin_risk_model import PARAMETERS
from postlogin_risk_ratio_model import relative_volume


def projection(values):
    raw=np.asarray(values,dtype=np.float64)
    ratio=relative_volume(raw)
    rates=[]
    for column in (59,60):
        result=np.zeros(len(raw))
        np.divide(raw[:,column],raw[:,57],out=result,where=raw[:,57]>0)
        rates.append(result)
    return np.column_stack((raw[:,57:65],ratio,*rates))


class SufficientContextScorer:
    recipe_version=8
    feature_schema_version=8
    applicability="PILOT_ONLY_RULE_DISTILLATION"

    def __init__(self):self.normal=None;self.classifier=None

    def fit(self,normal,labeled,labels,reserve_component):
        if self.normal is not None or self.classifier is not None:raise ValueError("already fitted")
        normal=np.asarray(normal,dtype=np.float64);labeled=np.asarray(labeled,dtype=np.float64)
        projection(normal);transformed=projection(labeled)
        targets=training_labels(labels,len(labeled))
        reserve_component("normal");self.normal=NormalSupportScorer(8,256,"euclidean",42).fit(normal[:,:37])
        reserve_component("classifier");self.classifier=HistGradientBoostingClassifier(**PARAMETERS).fit(_signed_log(transformed),targets)
        return self

    def anomaly_scores(self,rows):
        raw=np.asarray(rows,dtype=np.float64)
        logits=self.classifier._raw_predict(_signed_log(projection(raw)))
        margin=logsumexp(logits[:,1:],axis=1)-logits[:,0]
        novelty=np.log(self.normal.anomaly_scores(raw[:,:37])+1e-12)
        return np.maximum(margin,novelty)

    def contexts(self,rows):return np.argmax(self.classifier._raw_predict(_signed_log(projection(rows))),axis=1)
