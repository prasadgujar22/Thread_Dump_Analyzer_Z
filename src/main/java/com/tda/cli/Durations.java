package com.tda.cli;

import java.time.Duration;

/** Parses human-style durations: "10s", "5m", "1h", "500ms", bare seconds. */
final class Durations {

    private Durations() {}

    static Duration parse(String s) {
        String t = s.trim().toLowerCase();
        try {
            if (t.endsWith("ms")) return Duration.ofMillis(Long.parseLong(t.substring(0, t.length() - 2)));
            if (t.endsWith("s")) return Duration.ofSeconds(Long.parseLong(t.substring(0, t.length() - 1)));
            if (t.endsWith("m")) return Duration.ofMinutes(Long.parseLong(t.substring(0, t.length() - 1)));
            if (t.endsWith("h")) return Duration.ofHours(Long.parseLong(t.substring(0, t.length() - 1)));
            return Duration.ofSeconds(Long.parseLong(t));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("cannot parse duration \"" + s + "\" (use e.g. 10s, 5m, 1h)");
        }
    }
}
