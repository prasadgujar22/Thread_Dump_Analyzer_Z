package com.tda.core.model;

/** One row of `top -H -p <pid>` output; pid equals the JVM thread nid in decimal. */
public record TopHSample(long pid, double cpuPercent, double memPercent, String command) {}
