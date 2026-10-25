"""PILOT_ONLY schema7; never accepted by the frozen schema6 guard or strict admission."""
from datetime import datetime, timezone
import math
from .postlogin_contract import FEATURE_NAMES as BASE_NAMES, validate_snapshot

SCHEMA_VERSION=7
NEW_NAMES=(
    'prior_failed_logins_same_source_target_10m','prior_distinct_login_targets_same_source_10m',
    'prior_login_failure_ratio_same_source_10m','current_session_login_after_failures',
    'seconds_last_failure_to_current_session_login','source_changed_since_session_login',
    'ua_family_changed_since_session_login','distinct_sources_current_session_15m',
    'distinct_ua_families_current_session_15m','account_session_switches_15m',
    'account_active_session_context_pairs_15m','reset_preceded_current_session_login_30m',
    'prior_otp_failures_session_operation_15m','prior_distinct_challenges_session_operation_15m',
    'prior_sensitive_rejections_same_session_15m','seconds_since_last_session_operation_otp_failure')
FEATURE_NAMES=BASE_NAMES+NEW_NAMES
COVERAGE={'auth_source_window','session_context','otp_history'}
MAX_SNAPSHOTS=100_000
RECIPES=({'name':'A','max_iter':100,'max_leaf_nodes':15},{'name':'B','max_iter':200,'max_leaf_nodes':31})
SEEDS=(42,43)

def validate(value, *, require_ready=True):
    if type(value) is not dict or value.get('feature_schema_version')!=7 or value.get('feature_names')!=list(FEATURE_NAMES):
        raise ValueError('explicit schema7 ordered81 snapshot required; never pad96')
    coverage=value.get('coverage')
    if type(coverage) is not dict or set(coverage)!=COVERAGE or any(type(v) is not bool or not v for v in coverage.values()):
        raise ValueError('complete independently observed coverage required')
    features=value.get('features')
    if type(features) is not list or len(features)!=81 or any(type(v) not in (int,float) or not math.isfinite(v) for v in features):
        raise ValueError('finite observed81 features required')
    baseline={key:v for key,v in value.items() if key!='coverage'}
    baseline.update(feature_schema_version=6,feature_names=list(BASE_NAMES),features=features[:65])
    validate_snapshot(baseline)
    if require_ready and not value['baseline_established']:raise ValueError('COLD is undetermined; no candidate score')
    extra=features[65:]
    if any(v<0 for v in extra) or not 0<=extra[2]<=1 or any(extra[i] not in (0,1) for i in (3,5,6,11)):
        raise ValueError('invalid observed auth values')
    if any(extra[i]!=int(extra[i]) for i in (0,1,7,8,9,10,12,13,14)) or any(extra[i]>900 for i in (4,15)):
        raise ValueError('invalid count or capped elapsed time')
    return tuple(float(v) for v in features)

def pilot_protocol():
    return {'format':'AUTH_CONTEXT_PILOT_V1','scope':'PILOT_ONLY','evaluation_mode':'SHADOW',
        'feature_schema_version':7,'feature_names':list(FEATURE_NAMES),'evaluation_unit':'SENSITIVE_ACTION_ATTEMPT',
        'maximum_snapshots':100_000,'maximum_classifier_fits':4,'maximum_normal_fits':0,
        'recipes':list(RECIPES),'seeds':list(SEEDS),'data_provenance':'CONTROLLED_CLOCK_LAB',
        'strict_adoption_eligible':False,'automatic_hold_eligible':False,
        'dataset_splits':{'train':40000,'calibration':15000,'development':10000,'evaluation':25000,'controls':10000},
        'maximum_artifact_bytes':4*1024**3,'maximum_training_memory_bytes':2*1024**3,'maximum_cpus':2}
