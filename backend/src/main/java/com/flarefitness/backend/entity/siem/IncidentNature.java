package com.flarefitness.backend.entity.siem;

/** Server-authored incident domain; distinct from triage/noise classification and analyst verdict. */
public enum IncidentNature {
    SECURITY_DETECTION,
    ELASTIC_DETECTION,
    ACCOUNT_BEHAVIOR_ANOMALY,
    OPERATIONAL_ANOMALY,
    MIXED_ANOMALY,
    UNKNOWN
}
