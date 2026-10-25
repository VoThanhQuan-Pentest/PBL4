package com.flarefitness.backend.service.siem;

import static org.assertj.core.api.Assertions.*;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.Test;

class AuthInvestigationRulesTest {
    final LocalDateTime at=LocalDateTime.of(2026,10,24,10,0);
    final AuthInvestigationRules.Novelty none=new AuthInvestigationRules.Novelty(false,false,false);
    AuthInvestigationRules.Event event(String id,String target,String action,String outcome){return new AuthInvestigationRules.Event(id,id,at,"AUTH",action,outcome,"SUCCESS".equals(outcome)?target:null,target,null,null,"192.0.2.25","Firefox","SUCCESS".equals(outcome)?"session":null,"PASSWORD_CHANGE",null);}
    @Test void fiveIndependentFailuresCreateOneSignalAndSuccessIsLinked(){
        List<AuthInvestigationRules.Event> failures=new ArrayList<>();for(int i=0;i<5;i++)failures.add(event("f"+i,"customer","LOGIN","FAILURE"));
        var duplicate=new ArrayList<>(failures);duplicate.addAll(failures);
        assertThat(AuthInvestigationRules.assess(failures.getLast(),duplicate,true,none)).extracting(AuthInvestigationRules.Signal::rule).containsExactly("AUTH_BRUTE_TARGET");
        var success=event("success","customer","LOGIN","SUCCESS");var result=AuthInvestigationRules.assess(success,duplicate,true,none);
        assertThat(result.getFirst().severity()).isEqualTo("HIGH");assertThat(result.getFirst().evidence()).hasSize(6);
    }
    @Test void rateLimitedRequestsAreNotCredentialFailuresAndMissingCoverageCannotAlert(){
        var limited=event("limited","customer","LOGIN","RATE_LIMITED");
        assertThat(AuthInvestigationRules.assess(limited,List.of(limited),true,none)).isEmpty();
        var failures=new ArrayList<AuthInvestigationRules.Event>();for(int i=0;i<10;i++)failures.add(event("f"+i,"customer","LOGIN","FAILURE"));
        assertThat(AuthInvestigationRules.assess(failures.getLast(),failures,false,none)).isEmpty();
    }
    @Test void sprayingRequiresTenIndependentTargets(){
        var failures=new ArrayList<AuthInvestigationRules.Event>();for(int i=0;i<10;i++)failures.add(event("f"+i,"target"+i,"LOGIN","FAILURE"));
        assertThat(AuthInvestigationRules.assess(failures.getLast(),failures,true,none)).extracting(AuthInvestigationRules.Signal::rule).containsExactly("AUTH_PASSWORD_SPRAY");
        assertThat(AuthInvestigationRules.assess(failures.get(8),failures.subList(0,9),true,none)).isEmpty();
    }
    @Test void aSingleLegitimateLoginOrMobileIpChangeIsNotAnIncident(){
        var login=event("login","customer","LOGIN","SUCCESS");
        assertThat(AuthInvestigationRules.assess(login,List.of(login),true,none)).isEmpty();
        var mobile=new AuthInvestigationRules.Event("mobile","mobile",at.plusMinutes(1),"HTTP_REQUEST","GET","SUCCESS","customer","customer",null,null,"192.0.2.26","Firefox","session",null,null);
        assertThat(AuthInvestigationRules.assess(mobile,List.of(login,mobile),true,none)).isEmpty();
    }
    @Test void sensitiveChainNeedsTwoObservedFlagsAndNoFutureEvidence(){
        var login=event("login","customer","LOGIN","SUCCESS");
        var attempt=new AuthInvestigationRules.Event("attempt","attempt",at.plusMinutes(1),"SENSITIVE_ACTION_ATTEMPT","PASSWORD_CHANGE","ATTEMPT","customer","customer",null,null,"192.0.2.25","Firefox","session","PASSWORD_CHANGE",null);
        assertThat(AuthInvestigationRules.assess(attempt,List.of(login),true,new AuthInvestigationRules.Novelty(true,true,false))).isEmpty();
        assertThat(AuthInvestigationRules.assess(attempt,List.of(login),true,new AuthInvestigationRules.Novelty(true,true,true))).extracting(AuthInvestigationRules.Signal::rule).contains("AUTH_LOGIN_SENSITIVE_CHAIN");
    }
    @Test void otpFailuresAndRevocationAreInvestigationOnly(){
        var failures=new ArrayList<AuthInvestigationRules.Event>();
        for(int i=0;i<3;i++)failures.add(new AuthInvestigationRules.Event("otp"+i,"otp"+i,at,"AUTH","OTP_CHECK","FAILURE","customer","customer",null,null,"192.0.2.25","Firefox","session","PASSWORD_CHANGE","OTP_INVALID"));
        assertThat(AuthInvestigationRules.assess(failures.getLast(),failures,true,none)).extracting(AuthInvestigationRules.Signal::rule).containsExactly("AUTH_OTP_SENSITIVE_ABUSE");
        var denial=new AuthInvestigationRules.Event("denied","denied",at,"AUTH","SESSION_DENIED","DENIED",null,"customer",null,null,"192.0.2.25","Firefox",null,null,"AUTH_VERSION_REVOKED");
        assertThat(AuthInvestigationRules.assess(denial,List.of(),true,none)).extracting(AuthInvestigationRules.Signal::rule).containsExactly("AUTH_REVOKED_SESSION_REUSE");
    }
    @Test void interleavedDistinctSessionContextsCreateAnInvestigationSignal(){
        List<AuthInvestigationRules.Event> observations=new ArrayList<>();
        for(int i=0;i<4;i++)observations.add(new AuthInvestigationRules.Event("http"+i,"request"+i,at.plusSeconds(i),"HTTP_REQUEST","READ","SUCCESS","customer","customer",null,null,i%2==0?"192.0.2.25":"192.0.2.26",i%2==0?"CHROMIUM":"FIREFOX",i%2==0?"first-session":"second-session",null,null));
        assertThat(AuthInvestigationRules.assess(observations.getLast(),observations,true,none)).extracting(AuthInvestigationRules.Signal::rule).containsExactly("AUTH_SESSION_CONTEXT");
    }
    @Test void fingerprintKeyRotationDoesNotTurnFiveUnknownTargetsIntoTen(){
        List<AuthInvestigationRules.Event> failures=new ArrayList<>();
        for(int i=0;i<10;i++)failures.add(new AuthInvestigationRules.Event("failure"+i,"request"+i,at,"AUTH","LOGIN","FAILURE",null,null,String.format("%064x",i),i<5?"key-before":"key-after","192.0.2.25","CHROMIUM",null,null,null));
        assertThat(AuthInvestigationRules.assess(failures.getLast(),failures,true,none)).isEmpty();
    }

}
