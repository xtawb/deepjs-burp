package deepjs.burp;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The credentials the browser last sent to each host through the proxy.
 * "Send to Repeater" borrows them, so that a request built from a finding is
 * not an anonymous one that the application turns away before anything can be
 * tested.
 *
 * Kept in memory, per host, for as long as the extension is loaded: never
 * written anywhere, never logged, and only ever offered back to the host they
 * were sent to.
 */
final class Sessions {

    private static final int MAX_HOSTS = 300, MAX_HEADERS = 12, MAX_VALUE = 16_384;
    private static final Pattern CARRIES_A_SESSION = Pattern.compile(
            "^(cookie|authorization)$|csrf|xsrf|token|api[-_]?key|^x-.*auth|session", Pattern.CASE_INSENSITIVE);

    // host → lower-case header name → {name as sent, value}; the host used longest ago goes first
    private final Map<String, Map<String, String[]>> byHost = new LinkedHashMap<>(64, 0.75f, true) {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Map<String, String[]>> eldest) {
            return size() > MAX_HOSTS;
        }
    };

    /** A header the browser sent to `host` ({@link Traffic#hostOf}). Remembered if it carries a session. */
    synchronized void note(String host, String name, String value) {
        if (host.isEmpty() || name == null || value == null || value.isEmpty() || value.length() > MAX_VALUE
                || !CARRIES_A_SESSION.matcher(name).find()) {
            return;
        }
        Map<String, String[]> headers = byHost.computeIfAbsent(host, h -> new LinkedHashMap<>());
        String id = name.toLowerCase(Locale.ROOT);
        if (headers.size() < MAX_HEADERS || headers.containsKey(id)) {
            headers.put(id, new String[]{name, value});
        }
    }

    /** {name, value} of every session header last seen for that host; empty when there is none. */
    synchronized List<String[]> headersFor(String host) {
        Map<String, String[]> headers = byHost.get(host);
        return headers == null ? List.of() : new ArrayList<>(headers.values());
    }

    synchronized void clear() {
        byHost.clear();
    }
}
