package com.tda.core.model;

/** A non-fatal problem found while parsing (truncated section, unrecognized line run, ...). */
public record ParseIssue(String where, String message) {
    @Override public String toString() { return where + ": " + message; }
}
