package com.flarefitness.backend.service.siem;

import java.time.*;
import java.util.*;

/** Versioned investigation signals. No response side effects or signature strikes. */
public final class AuthInvestigationRules {
    public static final String VERSION="AUTH_INVESTIGATION_V1";
    public record Event(String id,String requestId,LocalDateTime at,String type,String action,String outcome,
            String actor,String target,String fingerprint,String keyId,String source,String ua,String session,String operation,String reason) {
        public String targetKey(){return target!=null?"user:"+target:fingerprint!=null&&keyId!=null?"fp:"+keyId+":"+fingerprint:null;}
        boolean failure(){return "LOGIN".equals(action)&&"FAILURE".equals(outcome);}
    }
    public record Novelty(boolean ready,boolean sourceNew,boolean uaNew) { }
    public record Signal(String rule,String group,String severity,List<Event> evidence) { }
    private AuthInvestigationRules() { }
    public static List<Signal> assess(Event current,List<Event> observations,boolean complete,Novelty novelty) {
        if(!complete||current.requestId()==null)return List.of();
        Map<String,Event> distinct=new LinkedHashMap<>();
        observations.stream().filter(e->e.requestId()!=null&&!e.at().isAfter(current.at())&& !e.at().isBefore(current.at().minusMinutes(30)))
                .forEach(e->distinct.putIfAbsent(e.requestId()+"|"+e.type()+"|"+e.action(),e));
        distinct.putIfAbsent(current.requestId()+"|"+current.type()+"|"+current.action(),current);
        var events=distinct.values().stream().sorted(Comparator.comparing(Event::at).thenComparing(Event::id)).toList();
        var ten=events.stream().filter(e->!e.at().isBefore(current.at().minusMinutes(10))).toList();
        var fifteen=events.stream().filter(e->!e.at().isBefore(current.at().minusMinutes(15))).toList();
        List<Signal> signals=new ArrayList<>();String target=current.targetKey();
        if(target!=null&&"LOGIN".equals(current.action())){
            var failures=ten.stream().filter(e->e.failure()&&target.equals(e.targetKey())).toList();
            if(failures.size()>=5)signals.add(signal("AUTH_BRUTE_TARGET",target,"SUCCESS".equals(current.outcome())?"HIGH":"MEDIUM",failures,current));
        }
        if(current.source()!=null&&current.failure()){
            var failures=ten.stream().filter(e->e.failure()&&current.source().equals(e.source())&&e.targetKey()!=null&&(e.target()!=null||current.keyId()!=null&&current.keyId().equals(e.keyId()))).toList();
            if(failures.size()>=10&&failures.stream().map(Event::targetKey).distinct().count()>=10)
                signals.add(signal("AUTH_PASSWORD_SPRAY",current.source(),"MEDIUM",failures,current));
        }
        if(current.actor()!=null&&current.session()!=null){
            var session=fifteen.stream().filter(e->current.actor().equals(e.actor())&&current.session().equals(e.session())).toList();
            var login=session.stream().filter(e->"LOGIN".equals(e.action())&&"SUCCESS".equals(e.outcome())).findFirst();
            if(("SENSITIVE_ACTION_ATTEMPT".equals(current.type())||"SENSITIVE_EXECUTE".equals(current.action()))&&login.isPresent()){
                var failures=ten.stream().filter(e->e.failure()&&Objects.equals(e.target(),current.actor())&&e.at().isBefore(login.get().at())).toList();
                boolean reset=events.stream().anyMatch(e->"PASSWORD_RESET".equals(e.action())&&"SUCCESS".equals(e.outcome())&&current.actor().equals(e.target())&&e.at().isBefore(login.get().at()));
                int flags=(novelty.ready()&&novelty.sourceNew()?1:0)+(novelty.ready()&&novelty.uaNew()?1:0)+(failures.size()>=3?1:0)+(reset?1:0);
                if(flags>=2)signals.add(signal("AUTH_LOGIN_SENSITIVE_CHAIN",current.actor()+":"+current.session(),"MEDIUM",events.stream().filter(e->Objects.equals(e.actor(),current.actor())||Objects.equals(e.target(),current.actor())).toList(),current));
            }
            var account=fifteen.stream().filter(e->current.actor().equals(e.actor())&&e.session()!=null&&e.source()!=null&&e.ua()!=null&&("HTTP_REQUEST".equals(e.type())||"LOGIN".equals(e.action()))).toList();
            int switches=0;for(int i=1;i<account.size();i++)if(!account.get(i-1).session().equals(account.get(i).session()))switches++;
            boolean changed=login.isPresent()&&current.source()!=null&&current.ua()!=null&&login.get().source()!=null&&login.get().ua()!=null
                    &&!current.source().equals(login.get().source())&&!current.ua().equals(login.get().ua());
            boolean interleaved=switches>=3&&account.stream().map(Event::session).distinct().count()>=2
                    &&account.stream().map(e->e.source()+"|"+e.ua()).distinct().count()>=2;
            if(changed||interleaved)signals.add(signal("AUTH_SESSION_CONTEXT",current.actor(),"MEDIUM",account,current));
            var otp=session.stream().filter(e->"OTP_CHECK".equals(e.action())&&"FAILURE".equals(e.outcome())&&Objects.equals(current.operation(),e.operation())).toList();
            var attempts=session.stream().filter(e->"SENSITIVE_EXECUTE".equals(e.action())&&Objects.equals(current.operation(),e.operation())).toList();
            if(otp.size()>=3||attempts.size()>=5){List<Event> refs=new ArrayList<>(otp);refs.addAll(attempts);signals.add(signal("AUTH_OTP_SENSITIVE_ABUSE",current.actor()+":"+current.session()+":"+current.operation(),"MEDIUM",refs,current));}
        }
        if("SESSION_DENIED".equals(current.action())&&current.target()!=null&&Set.of("ACCOUNT_ISOLATED","AUTH_VERSION_REVOKED","SESSION_REVOKED").contains(current.reason()))
            signals.add(signal("AUTH_REVOKED_SESSION_REUSE",current.target(),"HIGH",List.of(current),current));
        return List.copyOf(signals);
    }
    private static Signal signal(String rule,String group,String severity,List<Event> evidence,Event current){
        Map<String,Event> unique=new LinkedHashMap<>();evidence.forEach(e->unique.put(e.id(),e));unique.put(current.id(),current);
        return new Signal(rule,group,severity,List.copyOf(unique.values()));
    }
}
