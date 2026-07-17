package com.tda.core.json;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal recursive-descent JSON parser (the mirror of {@link Json}); used for the web API
 * request body and for reading saved baseline files. Produces Map/List/String/Double/Boolean/null.
 */
public final class JsonParser {

    private final String s;
    private int i;

    private JsonParser(String s) { this.s = s; }

    public static Object parse(String text) {
        JsonParser p = new JsonParser(text);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i != text.length()) throw p.err("trailing characters");
        return v;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) {
        Object o = parse(text);
        if (!(o instanceof Map)) throw new IllegalArgumentException("expected JSON object");
        return (Map<String, Object>) o;
    }

    private Object value() {
        char c = peek();
        return switch (c) {
            case '{' -> object();
            case '[' -> array();
            case '"' -> string();
            case 't' -> lit("true", Boolean.TRUE);
            case 'f' -> lit("false", Boolean.FALSE);
            case 'n' -> lit("null", null);
            default -> number();
        };
    }

    private Map<String, Object> object() {
        expect('{');
        Map<String, Object> m = new LinkedHashMap<>();
        ws();
        if (peek() == '}') { i++; return m; }
        while (true) {
            ws();
            String k = string();
            ws();
            expect(':');
            ws();
            m.put(k, value());
            ws();
            char c = next();
            if (c == '}') return m;
            if (c != ',') throw err("expected , or }");
        }
    }

    private List<Object> array() {
        expect('[');
        List<Object> l = new ArrayList<>();
        ws();
        if (peek() == ']') { i++; return l; }
        while (true) {
            ws();
            l.add(value());
            ws();
            char c = next();
            if (c == ']') return l;
            if (c != ',') throw err("expected , or ]");
        }
    }

    private String string() {
        expect('"');
        StringBuilder sb = new StringBuilder();
        while (true) {
            char c = next();
            if (c == '"') return sb.toString();
            if (c == '\\') {
                char e = next();
                switch (e) {
                    case '"' -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case '/' -> sb.append('/');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'u' -> {
                        sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                    }
                    default -> throw err("bad escape \\" + e);
                }
            } else {
                sb.append(c);
            }
        }
    }

    private Object number() {
        int start = i;
        while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) i++;
        if (start == i) throw err("unexpected character '" + peek() + "'");
        return Double.parseDouble(s.substring(start, i));
    }

    private Object lit(String word, Object v) {
        if (!s.startsWith(word, i)) throw err("expected " + word);
        i += word.length();
        return v;
    }

    private void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }
    private char peek() { if (i >= s.length()) throw err("unexpected end"); return s.charAt(i); }
    private char next() { if (i >= s.length()) throw err("unexpected end"); return s.charAt(i++); }
    private void expect(char c) { if (next() != c) throw err("expected '" + c + "'"); }
    private IllegalArgumentException err(String msg) {
        return new IllegalArgumentException("JSON error at offset " + i + ": " + msg);
    }
}
