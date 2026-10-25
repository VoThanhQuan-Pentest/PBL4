package com.flarefitness.monitor.model;

import java.util.List;
import java.util.Map;

/** Typed display projection. Derive rates from counters; never turn undefined into 100%. */
public final class UebaQualityMetrics {
    private UebaQualityMetrics() { }
    public record Counts(long tp, long fn, long fp, long tn) {
        public long normal() { return Math.addExact(fp, tn); }
        public long positive() { return Math.addExact(tp, fn); }
        public Double precision() { return ratio(tp, Math.addExact(tp, fp)); }
        public Double recall() { return ratio(tp, positive()); }
        public Double fpr() { return ratio(fp, normal()); }
        public Double accuracy() { return ratio(Math.addExact(tp, tn), Math.addExact(normal(), positive())); }
    }
    public record Bounds(double lower, double upper, boolean available) { }
    public record Scope(String name, Counts counts, String qualityGate,
                        Bounds precision, Bounds recall, Bounds falsePositiveRate) { }

    public static List<Scope> from(Map<String, Object> summary) {
        if (summary == null || summary.isEmpty()) return List.of();
        if (summary.get("scopes") instanceof Map<?, ?> scopes) {
            if (!scopes.keySet().equals(java.util.Set.of("MODEL_ONLY", "SIEM_FINAL"))) throw invalid();
            return List.of(scope("MODEL_ONLY", object(scopes.get("MODEL_ONLY"))), scope("SIEM_FINAL", object(scopes.get("SIEM_FINAL"))));
        }
        return summary.containsKey("tp") ? List.of(scope("MODEL_ONLY", summary)) : List.of();
    }
    private static Scope scope(String name, Map<?, ?> values) {
        Counts counts = new Counts(count(values.get("tp")), count(values.get("fn")), count(values.get("fp")), count(values.get("tn")));
        counts.accuracy(); // Check overflow even if the caller only displays another metric.
        Map<?, ?> confidence = values.get("confidence") instanceof Map<?, ?> map ? map : Map.of();
        Map<?, ?> conservative = confidence.get("conservative") instanceof Map<?, ?> map ? map : Map.of();
        return new Scope(name, counts, values.containsKey("quality_gate") ? String.valueOf(values.get("quality_gate")) : "NOT_RUN",
                bounds(conservative.get("precision")), bounds(conservative.get("recall")), bounds(conservative.get("false_positive_rate")));
    }
    private static Bounds bounds(Object value) {
        if (!(value instanceof Map<?, ?> map) || !Boolean.TRUE.equals(map.get("available"))) return new Bounds(0, 1, false);
        double lower = probability(map.get("lower")), upper = probability(map.get("upper"));
        if (lower > upper) throw invalid();
        return new Bounds(lower, upper, true);
    }
    private static long count(Object value) {
        if (!(value instanceof Number number) || !Double.isFinite(number.doubleValue()) || number.doubleValue() < 0
                || number.doubleValue() >= Long.MAX_VALUE || number.doubleValue() != number.longValue()) throw invalid();
        return number.longValue();
    }
    private static double probability(Object value) {
        if (!(value instanceof Number number) || !Double.isFinite(number.doubleValue()) || number.doubleValue() < 0 || number.doubleValue() > 1) throw invalid();
        return number.doubleValue();
    }
    private static Map<?, ?> object(Object value) { if (value instanceof Map<?, ?> map) return map; throw invalid(); }
    private static Double ratio(long value, long total) { return total == 0 ? null : (double) value / total; }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid UEBA evaluation counters or confidence bounds."); }
}
