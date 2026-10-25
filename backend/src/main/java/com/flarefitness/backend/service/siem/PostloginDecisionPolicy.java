package com.flarefitness.backend.service.siem;

import java.util.List;

/** Application response policy, never a label generator or actor-ownership verdict. */
public final class PostloginDecisionPolicy {
    public static final String ID = "postlogin-project-limited-v1";
    public static final String MODEL = "postlogin-legacy-f3-project-v1";
    public enum Decision { NORMAL, STEP_UP, TEMP_HOLD, OPS_ALERT, UNDETERMINED }
    public record Input(boolean covered, boolean baselineEstablished, int trustedWindows,
                        boolean modelAvailable, boolean aboveThreshold, String context,
                        int requests, int serverErrors, int priorOtpFailures,
                        boolean sameSourceScan, boolean freshHighAbuse) { }
    public record Result(Decision decision, List<String> reasons) {
        public Result { reasons = List.copyOf(reasons); }
    }

    private PostloginDecisionPolicy() { }

    public static Result assess(Input input) {
        if (!input.covered()) return result(Decision.UNDETERMINED, "MISSING_OBSERVED_COVERAGE");
        if (!input.modelAvailable()) return result(Decision.UNDETERMINED, "MODEL_UNAVAILABLE_KEEP_OTP");
        if ("SERVICE_DEGRADATION_CONTEXT".equals(input.context())
                || input.requests() >= 40 && input.serverErrors() >= .35 * input.requests()
                && input.priorOtpFailures() < 3 && !input.sameSourceScan()) {
            return result(Decision.OPS_ALERT, "SERVICE_DEGRADATION_NOT_ACCOUNT_COMPROMISE");
        }
        if (!input.aboveThreshold()) return result(Decision.NORMAL, "BELOW_FROZEN_MODEL_THRESHOLD", "EXISTING_OTP_STILL_REQUIRED");
        if (!input.baselineEstablished() || input.trustedWindows() < AccountBaselinePolicy.REQUIRED_WINDOWS) {
            return result(Decision.STEP_UP, "INSUFFICIENT_HISTORY_NO_AUTOMATIC_ML_HOLD");
        }
        if (!"BEHAVIOR_REVIEW_CONTEXT".equals(input.context())) {
            return result(Decision.STEP_UP, "MODEL_NOVELTY_REQUIRES_REVIEW_NOT_HOLD");
        }
        if (input.priorOtpFailures() >= 3) return result(Decision.TEMP_HOLD, "MODEL_HIGH_AND_THREE_SESSION_OTP_FAILURES");
        if (input.sameSourceScan() && input.freshHighAbuse()) {
            return result(Decision.TEMP_HOLD, "MODEL_HIGH_AND_SAME_SOURCE_SCAN_CORROBORATED_BY_REAL_ABUSE");
        }
        return result(Decision.STEP_UP, "MODEL_HIGH_WITHOUT_HOLD_CORROBORATION");
    }

    private static Result result(Decision decision, String... reasons) {
        return new Result(decision, List.of(reasons));
    }
}
