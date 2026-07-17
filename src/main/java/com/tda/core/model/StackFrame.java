package com.tda.core.model;

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** One "at ..." line of a stack trace. */
public final class StackFrame {
    private static final Pattern AT = Pattern.compile(
            "^\\s*at\\s+(?<sig>[^(]+)\\((?<loc>[^)]*)\\)\\s*(~\\[.*)?$");

    private final String raw;        // trimmed original line without leading "at "
    private final String classFqn;   // fully qualified class (may include module prefix stripped)
    private final String method;
    private final String location;   // "Foo.java:42", "Native Method", "Unknown Source"

    public StackFrame(String raw, String classFqn, String method, String location) {
        this.raw = raw;
        this.classFqn = classFqn;
        this.method = method;
        this.location = location;
    }

    /** Parses a "	at com.foo.Bar.baz(Bar.java:42)" line; returns null if it is not a frame. */
    public static StackFrame parse(String line) {
        Matcher m = AT.matcher(line);
        if (!m.matches()) return null;
        String sig = m.group("sig").trim();
        // JDK9+ frames may be "java.base@11.0.2/java.lang.Thread.sleep" - strip module prefix
        int slash = sig.indexOf('/');
        if (slash > 0 && sig.lastIndexOf('@', slash) > 0) sig = sig.substring(slash + 1);
        int dot = sig.lastIndexOf('.');
        String cls = dot > 0 ? sig.substring(0, dot) : sig;
        String method = dot > 0 ? sig.substring(dot + 1) : "";
        return new StackFrame(sig + "(" + m.group("loc") + ")", cls, method, m.group("loc").trim());
    }

    public String raw() { return raw; }
    public String classFqn() { return classFqn; }
    public String method() { return method; }
    public String location() { return location; }
    public boolean isNative() { return "Native Method".equals(location); }
    /** class.method - the identity used for fingerprints and pattern matching. */
    public String signature() { return classFqn + "." + method; }

    @Override public boolean equals(Object o) {
        return o instanceof StackFrame f && f.raw.equals(raw);
    }
    @Override public int hashCode() { return Objects.hash(raw); }
    @Override public String toString() { return raw; }
}
