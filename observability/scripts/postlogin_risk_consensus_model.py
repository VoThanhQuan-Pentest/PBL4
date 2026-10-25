"""Two learned context views must agree before emitting a risk-context score.

Score is a monotone bounded index, never an account-takeover probability.
This uses fitted classifiers, not hand-coded request/error cutoffs.
"""
import numpy as np
from scipy.special import expit


class ConsensusContextScorer:
    recipe_version=9
    feature_schema_version=9
    applicability="PILOT_ONLY_RULE_DISTILLATION"

    def __init__(self,full_view,sufficient_view):
        self.full_view=full_view;self.sufficient_view=sufficient_view

    def contexts(self,rows):
        full=self.full_view.contexts(rows);sufficient=self.sufficient_view.contexts(rows)
        return np.where((full!=0)&(sufficient!=0),sufficient,0)

    def anomaly_scores(self,rows):
        agreement=self.contexts(rows)!=0
        score=expit(self.full_view.anomaly_scores(rows))
        return np.where(agreement,score,0.)
