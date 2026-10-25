package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.assertThat;
import org.junit.jupiter.api.Test;

class PostloginDecisionPolicyTest {
    private PostloginDecisionPolicy.Decision decision(boolean covered,boolean ready,int count,boolean model,
            boolean high,String context,int requests,int errors,int failures,boolean scan,boolean real) {
        return PostloginDecisionPolicy.assess(new PostloginDecisionPolicy.Input(covered,ready,count,model,high,
                context,requests,errors,failures,scan,real)).decision();
    }
    @Test void missingEvidenceAndWorkerFailureCannotCreateHold() {
        assertThat(decision(false,true,30,true,true,"BEHAVIOR_REVIEW_CONTEXT",100,0,3,true,true))
                .isEqualTo(PostloginDecisionPolicy.Decision.UNDETERMINED);
        assertThat(decision(true,true,30,false,true,"BEHAVIOR_REVIEW_CONTEXT",100,0,3,true,true))
                .isEqualTo(PostloginDecisionPolicy.Decision.UNDETERMINED);
    }
    @Test void historyAndModelCorroborationAreAllRequired() {
        assertThat(decision(true,false,29,true,true,"BEHAVIOR_REVIEW_CONTEXT",100,0,3,true,true))
                .isEqualTo(PostloginDecisionPolicy.Decision.STEP_UP);
        assertThat(decision(true,true,30,true,false,"BEHAVIOR_REVIEW_CONTEXT",100,0,3,true,true))
                .isEqualTo(PostloginDecisionPolicy.Decision.NORMAL);
        assertThat(decision(true,true,30,true,true,"ROUTINE_CONTEXT",100,0,3,true,true))
                .isEqualTo(PostloginDecisionPolicy.Decision.STEP_UP);
        assertThat(decision(true,true,30,true,true,"BEHAVIOR_REVIEW_CONTEXT",100,0,2,false,false))
                .isEqualTo(PostloginDecisionPolicy.Decision.STEP_UP);
    }
    @Test void onlySameSourceRealFreshIntelligenceOrThreeFailuresCanHold() {
        assertThat(decision(true,true,30,true,true,"BEHAVIOR_REVIEW_CONTEXT",100,0,3,false,false))
                .isEqualTo(PostloginDecisionPolicy.Decision.TEMP_HOLD);
        assertThat(decision(true,true,30,true,true,"BEHAVIOR_REVIEW_CONTEXT",100,0,0,true,true))
                .isEqualTo(PostloginDecisionPolicy.Decision.TEMP_HOLD);
        assertThat(decision(true,true,30,true,true,"BEHAVIOR_REVIEW_CONTEXT",100,0,0,true,false))
                .isEqualTo(PostloginDecisionPolicy.Decision.STEP_UP);
        assertThat(decision(true,true,30,true,true,"BEHAVIOR_REVIEW_CONTEXT",100,0,0,false,true))
                .isEqualTo(PostloginDecisionPolicy.Decision.STEP_UP);
    }
    @Test void serviceDegradationAloneNeverPunishesCustomer() {
        assertThat(decision(true,true,30,true,true,"SERVICE_DEGRADATION_CONTEXT",100,90,0,false,false))
                .isEqualTo(PostloginDecisionPolicy.Decision.OPS_ALERT);
        assertThat(decision(true,true,30,true,true,"BEHAVIOR_REVIEW_CONTEXT",100,40,0,false,false))
                .isEqualTo(PostloginDecisionPolicy.Decision.OPS_ALERT);
    }
}
