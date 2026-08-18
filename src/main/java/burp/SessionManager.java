package burp;

import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpHeader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class SessionManager {

    public static class SessionData {
        private final Map<String, String> headers = new ConcurrentHashMap<>();
        private long lastUpdated;

        public SessionData() {
            this.lastUpdated = System.currentTimeMillis();
        }

        public void setHeader(String name, String value) {
            headers.put(name.toLowerCase(), value);
            this.lastUpdated = System.currentTimeMillis();
        }

        public String getHeader(String name) {
            return headers.get(name.toLowerCase());
        }

        public Map<String, String> getHeaders() {
            return headers;
        }

        public long getLastUpdated() {
            return lastUpdated;
        }
    }

    private final Map<HighlightColor, SessionData> sessions = new ConcurrentHashMap<>();

    public SessionManager() {
        // Initialize sessions for all possible HighlightColors
        for (HighlightColor color : HighlightColor.values()) {
            if (color != HighlightColor.NONE) {
                sessions.put(color, new SessionData());
            }
        }
    }

    public void updateSession(HighlightColor color, List<HttpHeader> headers) {
        if (color == HighlightColor.NONE) {
            return;
        }
        SessionData data = sessions.computeIfAbsent(color, k -> new SessionData());
        boolean updated = false;
        for (HttpHeader header : headers) {
            String name = header.name().toLowerCase();
            if (name.equals("authorization") || name.equals("cookie")) {
                data.setHeader(header.name(), header.value());
                updated = true;
            }
        }
        if (updated) {
            data.lastUpdated = System.currentTimeMillis();
        }
    }

    public SessionData getSession(HighlightColor color) {
        return sessions.get(color);
    }

    public String getAuthorization(HighlightColor color) {
        SessionData data = sessions.get(color);
        return data != null ? data.getHeader("authorization") : null;
    }

    public String getCookie(HighlightColor color) {
        SessionData data = sessions.get(color);
        return data != null ? data.getHeader("cookie") : null;
    }

    public boolean hasToken(HighlightColor color) {
        SessionData data = sessions.get(color);
        return data != null && (data.getHeader("authorization") != null || data.getHeader("cookie") != null);
    }

    public HighlightColor fromColorName(String colorName) {
        if (colorName == null) return HighlightColor.NONE;
        switch (colorName.toLowerCase().trim()) {
            case "red": return HighlightColor.RED;
            case "orange": return HighlightColor.ORANGE;
            case "yellow": return HighlightColor.YELLOW;
            case "green": return HighlightColor.GREEN;
            case "cyan": return HighlightColor.CYAN;
            case "blue": return HighlightColor.BLUE;
            case "purple":
            case "magenta": return HighlightColor.MAGENTA;
            case "pink": return HighlightColor.PINK;
            default: return HighlightColor.NONE;
        }
    }

    public String toColorName(HighlightColor color) {
        if (color == null) return "none";
        switch (color) {
            case RED: return "red";
            case ORANGE: return "orange";
            case YELLOW: return "yellow";
            case GREEN: return "green";
            case CYAN: return "cyan";
            case BLUE: return "blue";
            case MAGENTA: return "magenta";
            case PINK: return "pink";
            default: return "none";
        }
    }
}
