package com.tda.core.model;

/** java.lang.Thread.State plus UNKNOWN for VM/native threads that carry no Java state line. */
public enum ThreadState {
    NEW, RUNNABLE, BLOCKED, WAITING, TIMED_WAITING, TERMINATED, UNKNOWN;

    public static ThreadState parse(String s) {
        if (s == null) return UNKNOWN;
        String norm = s.trim().toUpperCase();
        for (ThreadState st : values()) {
            if (norm.startsWith(st.name())) return st;
        }
        return UNKNOWN;
    }
}
