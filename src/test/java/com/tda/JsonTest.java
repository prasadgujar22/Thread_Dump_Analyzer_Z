package com.tda;

import com.tda.core.json.Json;
import com.tda.core.json.JsonParser;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JsonTest {

    @Test
    void writesAndEscapes() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("s", "a\"b\\c\nd\te</script>");
        m.put("i", 42);
        m.put("d", 4.5);
        m.put("b", true);
        m.put("n", null);
        m.put("l", List.of(1, 2));
        String json = Json.write(m);
        assertEquals("{\"s\":\"a\\\"b\\\\c\\nd\\te\\u003c/script>\",\"i\":42,\"d\":4.5,"
                + "\"b\":true,\"n\":null,\"l\":[1,2]}", json);
        assertFalse(json.contains("</script>"), "must be safe to inline into a <script> tag");
    }

    @Test
    void roundTrips() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", "ExecuteThread: '12' for queue: 'x'");
        m.put("counts", List.of(3.0, 5.0, 7.0));
        m.put("nested", Map.of("deep", "value with ünicode"));
        Object back = JsonParser.parse(Json.write(m));
        assertEquals(m.get("name"), ((Map<?, ?>) back).get("name"));
        assertEquals(m.get("counts"), ((Map<?, ?>) back).get("counts"));
    }

    @Test
    void rejectsGarbage() {
        assertThrows(IllegalArgumentException.class, () -> JsonParser.parse("{\"a\":}"));
        assertThrows(IllegalArgumentException.class, () -> JsonParser.parse("{} trailing"));
    }
}
