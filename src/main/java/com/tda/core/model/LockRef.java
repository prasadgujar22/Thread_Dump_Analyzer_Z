package com.tda.core.model;

/** A lock-related annotation attached to a thread (from stack "- ..." lines or the synchronizers section). */
public final class LockRef {

    public enum Kind {
        /** "- locked &lt;0x...&gt; (a Foo)" - intrinsic monitor held */
        LOCKED_MONITOR,
        /** "- waiting to lock &lt;0x...&gt;" - BLOCKED entering a synchronized block */
        WAITING_TO_LOCK,
        /** "- waiting on &lt;0x...&gt;" / "- waiting to re-lock ..." - Object.wait() */
        WAITING_ON,
        /** "- parking to wait for &lt;0x...&gt;" - LockSupport.park on a j.u.c. synchronizer */
        PARKING_TO_WAIT_FOR,
        /** entry under "Locked ownable synchronizers:" (jstack -l) - j.u.c. lock held */
        LOCKED_SYNCHRONIZER,
        /** "- eliminated &lt;owner is scalar replaced&gt;" - lock elided by JIT */
        ELIMINATED
    }

    private final Kind kind;
    private final String address;    // "0x00000000d6a08c50" or null (eliminated)
    private final String className;  // "java.lang.Object", "java.util.concurrent.locks.ReentrantLock$NonfairSync"
    private final int frameIndex;    // index of the stack frame the annotation follows, -1 for synchronizer section

    public LockRef(Kind kind, String address, String className, int frameIndex) {
        this.kind = kind;
        this.address = address;
        this.className = className;
        this.frameIndex = frameIndex;
    }

    public Kind kind() { return kind; }
    public String address() { return address; }
    public String className() { return className; }
    public int frameIndex() { return frameIndex; }

    public boolean isHold() { return kind == Kind.LOCKED_MONITOR || kind == Kind.LOCKED_SYNCHRONIZER; }
    public boolean isWait() {
        return kind == Kind.WAITING_TO_LOCK || kind == Kind.PARKING_TO_WAIT_FOR || kind == Kind.WAITING_ON;
    }

    @Override public String toString() { return kind + " <" + address + "> (a " + className + ")"; }
}
