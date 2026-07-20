package com.tda.core.analysis.classify;

import java.io.BufferedReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Dependency-free parser for the strict YAML subset TDA's data files use: one top-level
 * key holding a list of items, where each field is a scalar, a list of scalars, or one
 * nested map of scalars/lists (two-space indentation, {@code #} comments). Values are
 * String / List&lt;String&gt; / Map&lt;String,Object&gt;. Shared by frame-meanings and
 * rules files so user overrides behave identically everywhere.
 */
public final class YamlMini {

    private YamlMini() {}

    public static List<Map<String, Object>> parseItems(BufferedReader reader, String topKey)
            throws IOException {
        List<Map<String, Object>> items = new ArrayList<>();
        Map<String, Object> item = null;    // current "- ..." item
        Map<String, Object> nested = null;  // one-level nested map inside the item
        // where "- value" lines currently append: [owner map, field name], or null
        Object[] openList = null;

        String line;
        int no = 0;
        while ((line = reader.readLine()) != null) {
            no++;
            String raw = stripComment(line);
            String t = raw.trim();
            if (t.isEmpty()) continue;
            int indent = indentOf(raw);

            if (indent == 0) {
                if (!t.equals(topKey + ":")) {
                    throw new IOException("line " + no + ": expected top-level \"" + topKey
                            + ":\", got \"" + t + "\"");
                }
            } else if (indent == 2 && t.startsWith("- ")) {           // new item
                item = new LinkedHashMap<>();
                items.add(item);
                nested = null;
                openList = null;
                openList = scalarOrOpen(item, t.substring(2), no);
            } else if (item == null) {
                throw new IOException("line " + no + ": content before the first list item");
            } else if (indent == 4 && !t.startsWith("- ")) {          // item-level field
                nested = null;
                openList = scalarOrOpen(item, t, no);
            } else if (indent == 6 && t.startsWith("- ")) {           // item-level list entry
                requireOpen(openList, item, no);
                append(openList, t.substring(2).trim());
            } else if (indent == 6 && !t.startsWith("- ")) {          // nested-map field
                if (nested == null) nested = materializeNested(item, openList, no);
                openList = scalarOrOpen(nested, t, no);
            } else if (indent == 8 && t.startsWith("- ")) {           // nested-level list entry
                requireOpen(openList, nested, no);
                append(openList, t.substring(2).trim());
            } else {
                throw new IOException("line " + no + ": unexpected structure: \"" + t + "\"");
            }
        }
        return items;
    }

    /** "key: value" -> scalar put (returns null); "key:" -> opens a list/nested slot. */
    private static Object[] scalarOrOpen(Map<String, Object> target, String kv, int no)
            throws IOException {
        int colon = kv.indexOf(':');
        if (colon <= 0) {
            throw new IOException("line " + no + ": expected \"key: value\", got \"" + kv + "\"");
        }
        String key = kv.substring(0, colon).trim();
        String value = kv.substring(colon + 1).trim();
        if (!value.isEmpty()) {
            target.put(key, unquote(value));
            return null;
        }
        return new Object[]{target, key}; // list entries or a nested map will follow
    }

    /** The last "key:" on the item becomes the nested map the indent-6 fields write into. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> materializeNested(Map<String, Object> item,
                                                         Object[] openList, int no) throws IOException {
        if (openList == null || openList[0] != item) {
            throw new IOException("line " + no + ": nested field without an opening \"key:\" line");
        }
        String key = (String) openList[1];
        Object existing = item.get(key);
        if (existing instanceof Map) return (Map<String, Object>) existing;
        Map<String, Object> nested = new LinkedHashMap<>();
        item.put(key, nested);
        return nested;
    }

    private static void requireOpen(Object[] openList, Map<String, Object> owner, int no)
            throws IOException {
        if (openList == null || openList[0] != owner) {
            throw new IOException("line " + no + ": list entry without an opening \"key:\" line");
        }
    }

    @SuppressWarnings("unchecked")
    private static void append(Object[] openList, String value) {
        Map<String, Object> owner = (Map<String, Object>) openList[0];
        String key = (String) openList[1];
        Object cur = owner.get(key);
        if (!(cur instanceof List)) {
            cur = new ArrayList<String>();
            owner.put(key, cur);
        }
        ((List<String>) cur).add(unquote(value));
    }

    private static int indentOf(String raw) {
        int i = 0;
        while (i < raw.length() && raw.charAt(i) == ' ') i++;
        return i;
    }

    private static String stripComment(String s) {
        int i = s.indexOf('#');
        return i >= 0 ? s.substring(0, i) : s;
    }

    private static String unquote(String s) {
        if (s.length() >= 2 && (s.startsWith("\"") && s.endsWith("\"")
                || s.startsWith("'") && s.endsWith("'"))) {
            return s.substring(1, s.length() - 1);
        }
        return s;
    }
}
