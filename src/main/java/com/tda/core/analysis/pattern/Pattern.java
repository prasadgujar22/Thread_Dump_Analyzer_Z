package com.tda.core.analysis.pattern;

import java.util.List;

/** A detection heuristic producing severity-ranked findings. Implementations must be stateless. */
public interface Pattern {
    List<Finding> detect(PatternContext ctx);
}
