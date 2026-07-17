package com.tda.core.json;

import java.util.List;
import java.util.Map;

/**
 * Minimal dependency-free JSON writer. Serializes the usual tree shape:
 * {@code Map<String,Object>}, {@code List<Object>}, String, Number, Boolean, null.
 * Keeping this in-house keeps the shaded jar tiny and the dependency surface auditable
 * (this tool processes sensitive production dumps and must stay fully offline).
 */
public final class Json {

    private Json() {}

    public static String write(Object value) {
        StringBuilder sb = new StringBuilder(1 << 12);
        writeValue(sb, value);
        return sb.toString();
    }

    private static void writeValue(StringBuilder sb, Object v) {
        if (v == null) { sb.append("null"); return; }
        if (v instanceof String s) { writeString(sb, s); return; }
        if (v instanceof Double d) {
            if (d.isNaN() || d.isInfinite()) { sb.append("null"); return; }
            sb.append(stripTrailingZero(d)); return;
        }
        if (v instanceof Float f) { writeValue(sb, f.doubleValue()); return; }
        if (v instanceof Number || v instanceof Boolean) { sb.append(v); return; }
        if (v instanceof Map<?, ?> m) { writeMap(sb, m); return; }
        if (v instanceof List<?> l) { writeList(sb, l); return; }
        if (v instanceof Object[] a) { writeList(sb, List.of(a)); return; }
        if (v instanceof Enum<?> e) { writeString(sb, e.name()); return; }
        writeString(sb, String.valueOf(v));
    }

    private static String stripTrailingZero(double d) {
        if (d == Math.rint(d) && Math.abs(d) < 1e15) return Long.toString((long) d);
        return Double.toString(d);
    }

    private static void writeMap(StringBuilder sb, Map<?, ?> m) {
        sb.append('{');
        boolean first = true;
        for (Map.Entry<?, ?> e : m.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            writeString(sb, String.valueOf(e.getKey()));
            sb.append(':');
            writeValue(sb, e.getValue());
        }
        sb.append('}');
    }

    private static void writeList(StringBuilder sb, List<?> l) {
        sb.append('[');
        for (int i = 0; i < l.size(); i++) {
            if (i > 0) sb.append(',');
            writeValue(sb, l.get(i));
        }
        sb.append(']');
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                // </script> inside inlined report data must not terminate the script tag
                case '<' -> sb.append("\\u003c");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        sb.append('"');
    }
}
