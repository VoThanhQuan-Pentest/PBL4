package com.flarefitness.backend.integration;

import java.util.List;

/** External scenario oracle; these fields must never enter the numeric feature vector. */
final class ActionProofCapturePlan {
    record Plan(String caseId, String pairId, String action, String role, String capability, String proofMode) { }
    private ActionProofCapturePlan() { }

    static List<Plan> initialSignalCases() {
        return List.of(
                new Plan("case-0", "pair-email", "EMAIL_CHANGE", "OWNER", "OWNER_SESSION_AND_FIXED_MAILBOX", "VERIFIED"),
                new Plan("case-1", "pair-email", "EMAIL_CHANGE", "NONOWNER", "COPIED_SESSION_AND_NEW_MAILBOX_ONLY", "NOT_OBSERVED"),
                new Plan("case-2", "pair-password", "PASSWORD_CHANGE", "OWNER", "OWNER_CREDENTIAL_AND_FIXED_MAILBOX", "VERIFIED"),
                new Plan("case-3", "pair-password", "PASSWORD_CHANGE", "NONOWNER", "COPIED_PASSWORD_WITHOUT_FIXED_MAILBOX", "INVALID"));
    }

    static List<Plan> coverageControls() {
        return List.of(
                new Plan("case-0", "pair-email", "EMAIL_CHANGE", "OWNER", "OWNER_WITHOUT_OPTIONAL_PROOF", "NOT_OBSERVED"),
                new Plan("case-1", "pair-email", "EMAIL_CHANGE", "NONOWNER", "COPIED_SESSION_WITHOUT_OPTIONAL_PROOF", "NOT_OBSERVED"),
                new Plan("case-2", "pair-password", "PASSWORD_CHANGE", "OWNER", "OWNER_CREDENTIAL_AND_FIXED_MAILBOX", "VERIFIED"),
                new Plan("case-3", "pair-password", "PASSWORD_CHANGE", "NONOWNER", "COPIED_PASSWORD_AND_FIXED_MAILBOX", "VERIFIED"));
    }
}
