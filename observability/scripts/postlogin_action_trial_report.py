#!/usr/bin/env python3
"""Audit finite OTP lab denominators; never infer population safety from fixtures."""
import argparse
from collections import Counter
import json
from pathlib import Path

from ueba_research_artifacts import commit, digest, private_directory


def summarize(document):
    if document["status"] != "CONTROLLED_TRIALS_COMPLETE" or document["smtp_verified"] is not False:
        raise ValueError("complete mock-transport lab evidence required")
    owners, invalid = document["planned_eligible_owners_per_operation"], document["planned_invalid_proofs_per_operation"]
    if type(owners) is not int or type(invalid) is not int or not 1 <= owners <= 5000 or not 1 <= invalid <= 2000:
        raise ValueError("bounded predeclared counts required")
    rows = document["outcomes"]
    if len(rows) != 2 * (owners + invalid + 2):
        raise ValueError("missing or extra operation trials")
    result = {}
    for operation in ("EMAIL_CHANGE", "PASSWORD_CHANGE"):
        selected = [r for r in rows if r["operation"] == operation]
        if {r["ordinal"] for r in selected} != set(range(owners + invalid + 2)) or len(selected) != owners + invalid + 2:
            raise ValueError("duplicate or missing account/scenario ordinal")
        for row in selected:
            i = row["ordinal"]
            expected = "OWNER_VALID_PROOF" if i < owners else (
                ("WRONG_CODE", "OTHER_SESSION", "EXPIRED", "AUTH_VERSION_CHANGED")[(i - owners) % 4]
                if i < owners + invalid else "OWNER_WITHOUT_PROOF_CONTROL" if i == owners + invalid
                else "SESSION_AND_MAILBOX_COMPROMISED_CONTROL")
            if (row["scenario"] != expected or row["correct"] is not True or row["replay_safe"] is not True
                    or type(row["committed"]) is not bool or type(row["http_status"]) is not int):
                raise ValueError("trial failed or scenario changed after its outcome")
            expected_commit = expected in ("OWNER_VALID_PROOF", "SESSION_AND_MAILBOX_COMPROMISED_CONTROL")
            expected_status = 200 if expected_commit else 401 if expected == "AUTH_VERSION_CHANGED" else (
                409 if expected in ("OTHER_SESSION", "EXPIRED") else 400)
            if row["committed"] != expected_commit or row["http_status"] != expected_status:
                raise ValueError("observed commit disagrees with declared scenario")
        result[operation] = {
            "eligible_owner_operations": owners, "eligible_owner_completion_failures": 0,
            "invalid_proof_operations": invalid, "unauthorized_mutations": 0,
            "replayed_owner_operations": owners, "additional_replay_mutations": 0,
            "invalid_scenarios": dict(Counter(r["scenario"] for r in selected if r["scenario"] in
                                             ("WRONG_CODE", "OTHER_SESSION", "EXPIRED", "AUTH_VERSION_CHANGED"))),
            "missing_proof_owner_control": "DENIED_AS_EXPECTED_NOT_EVIDENCE_OF_ATTACK",
            "compromised_mailbox_control": "ACCEPTED_OUTSIDE_EMAIL_PROTECTION_ASSUMPTION",
            "conditional_iid_zero_error_upper_bounds_familywise_95_six_comparisons": {
                "eligible_owner_failure": 1 - (.05 / 6) ** (1 / owners),
                "invalid_proof_mutation": 1 - (.05 / 6) ** (1 / invalid),
                "replay_mutation": 1 - (.05 / 6) ** (1 / owners)},
        }
    return {"status": "CONTROLLED_ACTION_TRIAL_AUDIT_PASS", "operations": result,
            "planned_count_screen_complete": owners == 5000 and invalid == 2000,
            "confidence_limit": "The formula assumes IID Bernoulli sampling. Synthetic fixed scenarios do not establish this assumption or real-user error rates.",
            "action_false_block_population_gate": "INCONCLUSIVE_WITHOUT_INDEPENDENT_REAL_USAGE_EVIDENCE",
            "real_smtp_gate": "PENDING_CONFIGURATION_AND_LIVE_SMOKE", "global_activation": False,
            "execution_latency_excludes_smtp_and_human": document["execution_latency_excludes_smtp_and_human"]}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--phase", required=True)
    a = p.parse_args()
    path = a.input.absolute()
    private_directory(path.parent)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 16 * 1024**2 or path.stat().st_mode & 0o077:
        raise ValueError("bounded owner-private trial evidence required")
    report = summarize(json.loads(path.read_text()))
    report["trial_evidence_sha256"] = digest(path)
    proof = commit(private_directory(a.output), report, phase=a.phase)
    print(json.dumps({"status": report["status"], "receipt": proof}), flush=True)
