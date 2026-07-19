package com.tda.core.parse;

import com.tda.core.json.JsonParser;
import com.tda.core.model.StackFrame;
import com.tda.core.model.ThreadDump;
import com.tda.core.model.ThreadInfo;
import com.tda.core.model.ThreadState;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

/**
 * Parses the JDK 21+ JSON dump format ({@code jcmd <pid> Thread.dump_to_file -format=json})
 * - the only dump format that includes virtual threads. Tolerant across JDK 21/22+ field
 * evolution: {@code state} and {@code carrier} are read when present, absent fields degrade
 * to UNKNOWN/none. A thread with an empty name (or {@code "virtual": true}) is virtual.
 */
public final class JsonDumpParser {

    public static boolean looksLikeJsonDump(String content) {
        int i = 0;
        while (i < content.length() && Character.isWhitespace(content.charAt(i))) i++;
        return i < content.length() && content.charAt(i) == '{' && content.contains("\"threadDump\"");
    }

    @SuppressWarnings("unchecked")
    public ThreadDump parse(String content, String sourceName) {
        Map<String, Object> root = JsonParser.parseObject(content);
        Map<String, Object> td = (Map<String, Object>) root.get("threadDump");
        if (td == null) throw new IllegalArgumentException(sourceName + ": no \"threadDump\" object");

        ThreadDump dump = new ThreadDump();
        dump.setSourceName(sourceName);
        dump.setJvmBanner("JSON thread dump (Thread.dump_to_file), runtime "
                + td.getOrDefault("runtimeVersion", "?"));
        dump.markSynchronizerSection(); // the JSON format has no -l concept; skip that quality note
        Object time = td.get("time");
        if (time != null) {
            try {
                dump.setTimestamp(OffsetDateTime.parse(String.valueOf(time)).toInstant());
            } catch (Exception e) {
                try {
                    dump.setTimestamp(Instant.parse(String.valueOf(time)));
                } catch (Exception ignored) { /* keep null */ }
            }
        }

        for (Object co : (List<Object>) td.getOrDefault("threadContainers", List.of())) {
            Map<String, Object> container = (Map<String, Object>) co;
            String containerName = String.valueOf(container.getOrDefault("container", ""));
            for (Object to : (List<Object>) container.getOrDefault("threads", List.of())) {
                dump.threads().add(parseThread((Map<String, Object>) to, containerName));
            }
        }
        return dump;
    }

    private ThreadInfo parseThread(Map<String, Object> t, String container) {
        ThreadInfo ti = new ThreadInfo();
        String tid = String.valueOf(t.getOrDefault("tid", "?"));
        String name = String.valueOf(t.getOrDefault("name", ""));
        boolean virtual = name.isEmpty() || Boolean.TRUE.equals(t.get("virtual"))
                || "true".equals(String.valueOf(t.get("virtual")));
        ti.setVirtual(virtual);
        ti.setName(name.isEmpty() ? "virtual-" + tid : name);
        try {
            ti.setJavaId(Long.parseLong(tid));
        } catch (NumberFormatException ignored) { }
        ti.setTidHex(null); // JSON format has no native tid; matchKey falls back to name
        Object carrier = t.get("carrier");
        if (carrier != null) ti.setCarrierTid(String.valueOf(carrier));
        Object state = t.get("state");
        ti.setState(state != null ? ThreadState.parse(String.valueOf(state)) : ThreadState.UNKNOWN);
        ti.setStateDetail(state != null ? String.valueOf(state)
                : (virtual ? "virtual (state not in this format)" : container));
        ti.setDaemon(Boolean.TRUE.equals(t.get("daemon")));

        Object stack = t.get("stack");
        if (stack instanceof List<?> frames) {
            for (Object fo : frames) {
                if (ti.frames().size() >= 60) break;
                String f = String.valueOf(fo).trim();
                // "java.base/java.lang.VirtualThread.run(VirtualThread.java:311)" - strip module
                int slash = f.indexOf('/');
                if (slash > 0 && f.lastIndexOf('.', slash) >= 0 && !f.substring(0, slash).contains("(")) {
                    f = f.substring(slash + 1);
                }
                StackFrame sf = StackFrame.parse("\tat " + f);
                if (sf != null) ti.frames().add(sf);
            }
        }
        return ti;
    }
}
