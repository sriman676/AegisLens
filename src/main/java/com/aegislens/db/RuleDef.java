package com.aegislens.db;

import com.aegislens.core.Severity;

/**
 * One detection rule as stored in the rule table: its id (for example NET-001), module, name, optional regex pattern,
 * optional numeric threshold, severity and on/off switch.
 */
public record RuleDef(String id, String module, String name, String pattern, Double threshold, Severity severity, boolean enabled) {
}
