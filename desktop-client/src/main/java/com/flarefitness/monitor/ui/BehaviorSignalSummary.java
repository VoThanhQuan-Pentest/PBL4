package com.flarefitness.monitor.ui;

import com.flarefitness.monitor.model.SiemModels;
import java.util.List;
import java.util.Map;

/** Presentation-only telemetry context; never changes scores, workflow or analyst conclusions. */
public final class BehaviorSignalSummary {
    public static final String CAUTION = "UEBA detects abnormal behavior, including possible operational faults. "
            + "A score or signal is not proof of compromise; analysts must determine the cause.";

    private BehaviorSignalSummary() { }

    public static String describe(SiemModels.BehaviorWindow window) {
        return describe(window == null ? List.of() : List.of(window), List.of());
    }

    public static String describe(List<SiemModels.BehaviorWindow> windows,
                                  List<SiemModels.SecurityEventEvidence> events) {
        boolean serviceErrors = false;
        boolean failedLogins = false;
        boolean unfamiliarSource = false;
        if (windows != null) for (var window : windows) {
            if (window == null) continue;
            serviceErrors |= positiveCount(window.features(), "http_5xx_count");
            failedLogins |= positiveCount(window.features(), "failed_login_count");
            unfamiliarSource |= window.baselineEstablished()
                    && (flag(window.features(), "new_ip_flag") || flag(window.features(), "new_user_agent_flag"));
        }
        if (events != null) for (var event : events) {
            if (event == null) continue;
            serviceErrors |= "HTTP_REQUEST".equals(event.eventType()) && event.httpStatus() != null
                    && event.httpStatus() >= 500 && event.httpStatus() < 600;
            failedLogins |= "AUTH".equals(event.eventType()) && "LOGIN".equals(event.action())
                    && "FAILURE".equals(event.outcome());
        }
        boolean securityContext = failedLogins || unfamiliarSource;
        String signal = serviceErrors && securityContext ? "Mixed service-error and security-context signals"
                : serviceErrors ? "Service-error signal (possible operational fault)"
                : securityContext ? "Security-context signal (needs investigation)" : "Cause undetermined";
        String observed = (serviceErrors ? " HTTP 5xx observed." : "")
                + (failedLogins ? " Failed logins observed." : "")
                + (unfamiliarSource ? " New IP or agent relative to an established baseline." : "");
        return signal + "." + (observed.isEmpty()
                ? " Available HTTP/auth/source telemetry does not establish the cause." : observed)
                + " Evidence context only, not attack confirmation.";
    }

    private static boolean positiveCount(Map<String, Double> features, String name) {
        Double value = features == null ? null : features.get(name);
        return value != null && Double.isFinite(value) && value > 0 && value == Math.rint(value);
    }

    private static boolean flag(Map<String, Double> features, String name) {
        return features != null && Double.valueOf(1).equals(features.get(name));
    }
}
