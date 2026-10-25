package com.flarefitness.backend.service.siem;

import java.time.*;
import java.util.*;

/** Schema7 appends observed auth context; the accepted first65 values are copied without modification. */
public final class PostloginShadowFeatures {
    public static final List<String> NAMES=List.of(
        "prior_failed_logins_same_source_target_10m","prior_distinct_login_targets_same_source_10m",
        "prior_login_failure_ratio_same_source_10m","current_session_login_after_failures",
        "seconds_last_failure_to_current_session_login","source_changed_since_session_login",
        "ua_family_changed_since_session_login","distinct_sources_current_session_15m",
        "distinct_ua_families_current_session_15m","account_session_switches_15m",
        "account_active_session_context_pairs_15m","reset_preceded_current_session_login_30m",
        "prior_otp_failures_session_operation_15m","prior_distinct_challenges_session_operation_15m",
        "prior_sensitive_rejections_same_session_15m","seconds_since_last_session_operation_otp_failure");
    public record Observation(AuthInvestigationRules.Event event,String challengeReference) { }
    public record Result(Map<String,Object> packet,boolean covered,String reason) { }
    private PostloginShadowFeatures() { }
    public static Result build(Map<String,Object> baseline,AuthInvestigationRules.Event current,List<Observation> observations,boolean complete) {
        if(!complete||!Integer.valueOf(6).equals(baseline.get("feature_schema_version"))||current.actor()==null||current.session()==null||current.source()==null||current.ua()==null)
            return new Result(Map.of(),false,"MISSING_OBSERVED_COVERAGE");
        if(!(baseline.get("features") instanceof List<?> prefix)||prefix.size()!=65||!(baseline.get("feature_names") instanceof List<?> baseNames)||baseNames.size()!=65)
            return new Result(Map.of(),false,"BASELINE_CONTRACT_MISMATCH");
        var before=observations.stream().filter(o->o.event().requestId()!=null&&o.event().at().isBefore(current.at())).sorted(Comparator.comparing((Observation o)->o.event().at()).thenComparing(o->o.event().id())).toList();
        var prior=before.stream().filter(o->!o.event().at().isBefore(current.at().minusMinutes(30))).toList();
        var login=before.stream().map(Observation::event).filter(e->current.actor().equals(e.actor())&&current.session().equals(e.session())&&"LOGIN".equals(e.action())&&"SUCCESS".equals(e.outcome())).min(Comparator.comparing(AuthInvestigationRules.Event::at));
        if(login.isEmpty()||login.get().source()==null||login.get().ua()==null)return new Result(Map.of(),false,"LOGIN_CONTEXT_NOT_OBSERVED");
        var ten=prior.stream().map(Observation::event).filter(e->!e.at().isBefore(current.at().minusMinutes(10))).toList();
        var source=ten.stream().filter(e->current.source().equals(e.source())&&"LOGIN".equals(e.action())&&Set.of("SUCCESS","FAILURE").contains(e.outcome())).toList();
        var failures=source.stream().filter(e->"FAILURE".equals(e.outcome())).toList();
        var precursor=prior.stream().map(Observation::event).filter(e->"LOGIN".equals(e.action())&&"FAILURE".equals(e.outcome())&&current.actor().equals(e.target())&&e.at().isBefore(login.get().at())&&!e.at().isBefore(login.get().at().minusMinutes(10))).sorted(Comparator.comparing(AuthInvestigationRules.Event::at)).toList();
        var account=prior.stream().map(Observation::event).filter(e->current.actor().equals(e.actor())&&!e.at().isBefore(current.at().minusMinutes(15))).sorted(Comparator.comparing(AuthInvestigationRules.Event::at).thenComparing(AuthInvestigationRules.Event::id)).toList();
        var session=account.stream().filter(e->current.session().equals(e.session())).toList();
        int switches=0;String previous=null;for(var e:account)if(e.session()!=null&&("HTTP_REQUEST".equals(e.type())||"LOGIN".equals(e.action()))){if(previous!=null&&!previous.equals(e.session()))switches++;previous=e.session();}
        var otp=session.stream().filter(e->"OTP_CHECK".equals(e.action())&&"FAILURE".equals(e.outcome())&&Objects.equals(current.operation(),e.operation())).toList();
        boolean reset=prior.stream().map(Observation::event).anyMatch(e->current.actor().equals(e.target())&&"PASSWORD_RESET".equals(e.action())&&"SUCCESS".equals(e.outcome())&&e.at().isBefore(login.get().at()));
        List<Double> extra=List.of(
            (double)failures.stream().filter(e->current.actor().equals(e.target())).count(),
            (double)source.stream().map(AuthInvestigationRules.Event::targetKey).filter(Objects::nonNull).distinct().count(),
            source.isEmpty()?0d:(double)failures.size()/source.size(),precursor.isEmpty()?0d:1d,
            precursor.isEmpty()?0d:(double)Math.min(900,Duration.between(precursor.getLast().at(),login.get().at()).getSeconds()),
            current.source().equals(login.get().source())?0d:1d,current.ua().equals(login.get().ua())?0d:1d,
            (double)session.stream().map(AuthInvestigationRules.Event::source).filter(Objects::nonNull).distinct().count(),
            (double)session.stream().map(AuthInvestigationRules.Event::ua).filter(Objects::nonNull).distinct().count(),(double)switches,
            (double)account.stream().filter(e->e.session()!=null&&e.source()!=null&&e.ua()!=null).map(e->e.session()+"|"+e.source()+"|"+e.ua()).distinct().count(),reset?1d:0d,
            (double)otp.size(),(double)prior.stream().filter(o->current.actor().equals(o.event().actor())&&current.session().equals(o.event().session())&&Objects.equals(current.operation(),o.event().operation())&&o.challengeReference()!=null&&!o.event().at().isBefore(current.at().minusMinutes(15))).map(Observation::challengeReference).distinct().count(),
            (double)session.stream().filter(e->"SENSITIVE_REJECTED".equals(e.action())).count(),
            otp.isEmpty()?0d:(double)Math.min(900,Duration.between(otp.getLast().at(),current.at()).getSeconds()));
        List<Object> values=new ArrayList<>(prefix);values.addAll(extra);List<Object> names=new ArrayList<>(baseNames);names.addAll(NAMES);
        var packet=new LinkedHashMap<String,Object>(baseline);packet.put("feature_schema_version",7);packet.put("features",List.copyOf(values));packet.put("feature_names",List.copyOf(names));
        packet.put("coverage",Map.of("auth_source_window",true,"session_context",true,"otp_history",true));
        return new Result(Collections.unmodifiableMap(packet),true,"OBSERVED");
    }
}
