package com.tda.report;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Redaction mode ({@code --redact}): scrubs hostnames, IPs, and email-like tokens from every
 * string in the analysis tree - thread names, frames, lock strings - replacing them with
 * deterministic first-seen pseudonyms ({@code host-1}, {@code ip-2}, {@code user-1@redacted})
 * so cross-references still line up. Applied before the HTML report, the JSON output, and
 * any webhook payload.
 *
 * <p>Hostname matching is deliberately conservative: a dotted token only counts as a host
 * when its last label is a TLD-ish/internal suffix, so Java class names
 * ({@code com.acme.orders.LedgerService}) are never touched.
 */
public final class Redactor {

    private static final Pattern EMAIL = Pattern.compile(
            "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)+\\b");
    private static final Pattern IPV4 = Pattern.compile(
            "\\b(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}"
            + "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\b");
    // last label must look like a TLD or internal-network suffix; boundaries reject tokens
    // embedded in longer dotted runs (package/class names)
    private static final Pattern HOSTNAME = Pattern.compile(
            "(?<![\\w.@])(?:[A-Za-z0-9][A-Za-z0-9-]*\\.)+"
            + "(?:com|net|org|io|co|de|uk|in|corp|internal|local|lan|intra|cloud|svc|cluster)"
            + "(?![\\w.])");

    private final Map<String, String> hosts = new LinkedHashMap<>();
    private final Map<String, String> ips = new LinkedHashMap<>();
    private final Map<String, String> emails = new LinkedHashMap<>();

    /** Redacts the whole JSON-shaped tree in place-order (returns a new tree). */
    @SuppressWarnings("unchecked")
    public Object redactTree(Object node) {
        if (node instanceof String s) return redact(s);
        if (node instanceof Map<?, ?> m) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : m.entrySet()) {
                out.put(String.valueOf(e.getKey()), redactTree(e.getValue()));
            }
            return out;
        }
        if (node instanceof List<?> l) {
            List<Object> out = new java.util.ArrayList<>(l.size());
            for (Object o : l) out.add(redactTree(o));
            return out;
        }
        return node;
    }

    public String redact(String s) {
        // emails first (they contain a hostname); the domain still routes through the host
        // table so thread@host tokens and bare host tokens share one pseudonym
        String out = replace(s, EMAIL, emails, raw -> {
            int at = raw.lastIndexOf('@');
            String domain = raw.substring(at + 1);
            String hostPseudo = hosts.computeIfAbsent(domain, k -> "host-" + (hosts.size() + 1));
            return "user-" + (emails.size() + 1) + "@" + hostPseudo;
        });
        out = replace(out, IPV4, ips, v -> "ip-" + (ips.size() + 1));
        out = replace(out, HOSTNAME, hosts, this::hostPseudonym);
        return out;
    }

    /**
     * The greedy first label can swallow a prefix glued on with a hyphen
     * ("replica-app01.prod.acme.com"). When a known host is a hyphen-separated suffix of the
     * candidate, reuse its pseudonym so cross-references line up.
     */
    private String hostPseudonym(String candidate) {
        for (Map.Entry<String, String> e : hosts.entrySet()) {
            String known = e.getKey();
            if (candidate.length() > known.length() && candidate.endsWith(known)
                    && candidate.charAt(candidate.length() - known.length() - 1) == '-') {
                return candidate.substring(0, candidate.length() - known.length()) + e.getValue();
            }
        }
        return "host-" + (hosts.size() + 1);
    }

    /** The mapping tables (for tests and for an operator to keep locally if needed). */
    public Map<String, Map<String, String>> mappings() {
        return Map.of("hosts", hosts, "ips", ips, "emails", emails);
    }

    private String replace(String s, Pattern p, Map<String, String> table,
                           java.util.function.Function<String, String> next) {
        Matcher m = p.matcher(s);
        if (!m.find()) return s;
        StringBuilder sb = new StringBuilder();
        m.reset();
        while (m.find()) {
            String raw = m.group();
            String pseudo = table.computeIfAbsent(raw, k -> next.apply(k));
            m.appendReplacement(sb, Matcher.quoteReplacement(pseudo));
        }
        m.appendTail(sb);
        return sb.toString();
    }
}
