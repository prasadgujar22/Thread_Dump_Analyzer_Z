package com.tda.history;

import com.tda.core.json.Json;
import com.tda.core.json.JsonParser;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Incident memory: an embedded H2 database (default {@code ~/.tda/history.db}) storing, per
 * analysis, the recurring-stack fingerprint set, a findings summary, and a distilled
 * baseline. Similarity between incidents is Jaccard overlap of the fingerprint sets.
 *
 * <p>Strictly local. The database contains stack frames and must be treated with the same
 * sensitivity as the dumps themselves (documented in the README).
 */
public final class HistoryStore implements AutoCloseable {

    /** Overlap at or above this is reported as a similar past incident. */
    public static final double SIMILARITY_THRESHOLD = 0.3;

    public record Entry(long id, Instant ts, String label, Map<String, Object> summary) {}
    public record Similar(long id, Instant ts, String label, double overlap, List<String> sharedHashes) {}

    private final Connection conn;

    public static Path defaultPath() {
        return Path.of(System.getProperty("user.home"), ".tda", "history.db");
    }

    public HistoryStore(Path dbPath) throws SQLException {
        try {
            Files.createDirectories(dbPath.toAbsolutePath().getParent());
        } catch (Exception ignored) { }
        // H2 appends .mv.db itself; strip a user-supplied suffix so paths round-trip
        String base = dbPath.toAbsolutePath().toString().replaceAll("\\.(mv\\.)?db$", "");
        conn = DriverManager.getConnection("jdbc:h2:" + base + ";DB_CLOSE_ON_EXIT=FALSE");
        try (Statement st = conn.createStatement()) {
            st.execute("CREATE TABLE IF NOT EXISTS analysis(" +
                    "id IDENTITY PRIMARY KEY, ts TIMESTAMP NOT NULL, label VARCHAR(200), " +
                    "summary CLOB NOT NULL, baseline CLOB)");
            st.execute("CREATE TABLE IF NOT EXISTS stack(" +
                    "analysis_id BIGINT NOT NULL, hash VARCHAR(32) NOT NULL)");
            st.execute("CREATE INDEX IF NOT EXISTS idx_stack_analysis ON stack(analysis_id)");
        }
    }

    public long record(String label, Set<String> stackHashes,
                       Map<String, Object> summary, Map<String, Object> baseline) throws SQLException {
        long id;
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO analysis(ts, label, summary, baseline) VALUES (?, ?, ?, ?)",
                Statement.RETURN_GENERATED_KEYS)) {
            ps.setTimestamp(1, Timestamp.from(Instant.now()));
            ps.setString(2, label);
            ps.setString(3, Json.write(summary));
            ps.setString(4, baseline != null ? Json.write(baseline) : null);
            ps.executeUpdate();
            try (ResultSet rs = ps.getGeneratedKeys()) {
                rs.next();
                id = rs.getLong(1);
            }
        }
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO stack(analysis_id, hash) VALUES (?, ?)")) {
            for (String h : stackHashes) {
                ps.setLong(1, id);
                ps.setString(2, h);
                ps.addBatch();
            }
            ps.executeBatch();
        }
        return id;
    }

    /** Past analyses whose fingerprint sets overlap the given set by >= threshold. */
    public List<Similar> similar(Set<String> stackHashes, double threshold) throws SQLException {
        if (stackHashes.isEmpty()) return List.of();
        List<Similar> out = new ArrayList<>();
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery("SELECT id, ts, label FROM analysis ORDER BY ts DESC")) {
            while (rs.next()) {
                long id = rs.getLong(1);
                Set<String> theirs = stacksOf(id);
                if (theirs.isEmpty()) continue;
                Set<String> shared = new HashSet<>(theirs);
                shared.retainAll(stackHashes);
                Set<String> union = new HashSet<>(theirs);
                union.addAll(stackHashes);
                double overlap = (double) shared.size() / union.size();
                if (overlap >= threshold) {
                    out.add(new Similar(id, rs.getTimestamp(2).toInstant(), rs.getString(3),
                            Math.round(overlap * 1000) / 1000.0,
                            new ArrayList<>(shared).subList(0, Math.min(10, shared.size()))));
                }
            }
        }
        out.sort((a, b) -> Double.compare(b.overlap(), a.overlap()));
        return out;
    }

    public List<Entry> list(int limit) throws SQLException {
        List<Entry> out = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id, ts, label, summary FROM analysis ORDER BY ts DESC LIMIT ?")) {
            ps.setInt(1, limit);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.add(entry(rs));
            }
        }
        return out;
    }

    public List<Entry> search(String text) throws SQLException {
        List<Entry> out = new ArrayList<>();
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id, ts, label, summary FROM analysis WHERE LOWER(label) LIKE ? " +
                "OR LOWER(summary) LIKE ? ORDER BY ts DESC LIMIT 50")) {
            String needle = "%" + text.toLowerCase() + "%";
            ps.setString(1, needle);
            ps.setString(2, needle);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.add(entry(rs));
            }
        }
        return out;
    }

    public Entry show(long id) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT id, ts, label, summary FROM analysis WHERE id = ?")) {
            ps.setLong(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? entry(rs) : null;
            }
        }
    }

    /** The stored distilled baseline of the most recent analysis with this label, or null. */
    public Map<String, Object> baselineForLabel(String label) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT baseline FROM analysis WHERE label = ? AND baseline IS NOT NULL " +
                "ORDER BY ts DESC LIMIT 1")) {
            ps.setString(1, label);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return null;
                return JsonParser.parseObject(rs.getString(1));
            }
        }
    }

    public Set<String> stacksOf(long analysisId) throws SQLException {
        Set<String> out = new HashSet<>();
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT hash FROM stack WHERE analysis_id = ?")) {
            ps.setLong(1, analysisId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) out.add(rs.getString(1));
            }
        }
        return out;
    }

    private Entry entry(ResultSet rs) throws SQLException {
        Map<String, Object> summary;
        try {
            summary = JsonParser.parseObject(rs.getString(4));
        } catch (Exception e) {
            summary = new LinkedHashMap<>();
        }
        return new Entry(rs.getLong(1), rs.getTimestamp(2).toInstant(), rs.getString(3), summary);
    }

    @Override
    public void close() throws SQLException {
        conn.close();
    }
}
