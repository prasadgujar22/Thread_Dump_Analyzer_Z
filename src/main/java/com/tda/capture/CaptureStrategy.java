package com.tda.capture;

import java.util.Optional;

/**
 * One way of extracting a thread dump from a live JVM. Strategies are tried in order
 * (see {@link CaptureSession}) because cross-version attach is unreliable: our 17+ jar
 * routinely captures from JDK 8 WebLogic/WebSphere processes.
 */
public interface CaptureStrategy {

    String name();

    /** The dump text, or empty when this strategy is unavailable or failed for this pid. */
    Optional<String> tryCapture(long pid);
}
