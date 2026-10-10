package deepjs.burp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * What Burp has already requested, and which of the endpoints the code names
 * that covers.
 *
 * A request is remembered as host, path and method. An endpoint counts as
 * requested once a request with its method has gone to a path its URL matches:
 * {@code /users/{id}/roles} matches {@code /users/42/roles}. The endpoints
 * that stay unrequested are the ones the application's own pages never led
 * the tester to.
 *
 * Only request lines are kept, never more than {@link #MAX_PATHS} of them, and
 * nothing here outlives the extension.
 */
final class Traffic {

    static final int MAX_PATHS = 100_000;

    private static final Pattern URL = Pattern.compile("^([a-zA-Z][a-zA-Z0-9+.\\-]*)://([^/?#]*)([^?#]*)");
    private static final Pattern PLACEHOLDER = Pattern.compile("\\{[^{}/]*\\}");
    private static final List<String> METHODS = List.of("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS");
    private static final int ANY_METHOD = 0, OTHER_METHOD = 1 << METHODS.size();

    /** An endpoint waiting for its first request. */
    private static final class Watch {
        final String key, url, host, path, prefix;
        final int methods, segments;
        final Pattern shape;                // null when the path holds no placeholder
        boolean requested;

        Watch(String key, String method, String url, String host, String path) {
            this.key = key;
            this.url = url;
            this.host = host;
            this.path = path;
            this.methods = method.isEmpty() || method.equals("?") ? ANY_METHOD : bit(method);
            this.segments = segments(path);
            Matcher hole = PLACEHOLDER.matcher(path);
            if (!hole.find()) {
                this.prefix = path;
                this.shape = null;
                return;
            }
            this.prefix = path.substring(0, hole.start());
            StringBuilder regex = new StringBuilder();
            int from = 0;
            do {
                regex.append(Pattern.quote(path.substring(from, hole.start()))).append("[^/]+");
                from = hole.end();
            } while (hole.find());
            this.shape = Pattern.compile(regex.append(Pattern.quote(path.substring(from))).toString());
        }

        boolean matches(int method, int segmentCount, String requested) {
            return (methods == ANY_METHOD || (methods & method) != 0) && segments == segmentCount
                    && (shape == null ? path.equals(requested) : requested.startsWith(prefix) && shape.matcher(requested).matches());
        }
    }

    // host → number of path segments → path → the methods it was requested with
    private final Map<String, Map<Integer, Map<String, Integer>>> requests = new HashMap<>();
    private final Map<String, Watch> watches = new HashMap<>();
    private final Map<String, List<Watch>> waiting = new HashMap<>();      // by host; "" = whatever the host
    private int stored;

    /** {host[:port], path} of an absolute URL — default port and one trailing slash dropped — or null. */
    static String[] locate(String url) {
        Matcher m = URL.matcher(url == null ? "" : url);
        if (!m.find()) {
            return null;
        }
        String scheme = m.group(1).toLowerCase(Locale.ROOT), host = m.group(2).toLowerCase(Locale.ROOT), path = m.group(3);
        host = host.substring(host.lastIndexOf('@') + 1);
        String standard = scheme.equals("https") || scheme.equals("wss") ? ":443" : scheme.equals("http") || scheme.equals("ws") ? ":80" : null;
        if (standard != null && host.endsWith(standard)) {
            host = host.substring(0, host.length() - standard.length());
        }
        if (host.isEmpty() || host.indexOf('{') >= 0) {
            return null;                                    // `{apiUrl}/users`: no host is known
        }
        if (path.length() > 1 && path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return new String[]{host, path.isEmpty() ? "/" : path};
    }

    /** The host[:port] part of {@link #locate}, or "". */
    static String hostOf(String url) {
        String[] at = locate(url);
        return at == null ? "" : at[0];
    }

    private static int bit(String method) {
        int i = METHODS.indexOf(method.toUpperCase(Locale.ROOT));
        return i < 0 ? OTHER_METHOD : 1 << i;
    }

    private static int segments(String path) {
        int n = 0;
        for (int i = path.indexOf('/'); i >= 0; i = path.indexOf('/', i + 1)) {
            n++;
        }
        return n;
    }

    /** Burp requested this. Returns the keys of the endpoints it is the first request for. */
    synchronized List<String> saw(String method, String url) {
        String[] at = locate(url);
        if (at == null || method == null) {
            return List.of();
        }
        int bit = bit(method), count = segments(at[1]);
        Map<Integer, Map<String, Integer>> host = requests.get(at[0]);
        Map<String, Integer> paths = host == null ? null : host.get(count);
        Integer known = paths == null ? null : paths.get(at[1]);
        if (known != null && (known & bit) != 0) {
            return List.of();                               // nothing new: the common case, two lookups
        }
        if (known != null || stored < MAX_PATHS) {
            requests.computeIfAbsent(at[0], h -> new HashMap<>()).computeIfAbsent(count, n -> new HashMap<>())
                    .merge(at[1], bit, (a, b) -> a | b);
            stored += known == null ? 1 : 0;
        }
        List<String> first = new ArrayList<>();
        for (String where : new String[]{at[0], ""}) {
            List<Watch> candidates = waiting.get(where);
            if (candidates == null) {
                continue;
            }
            for (Iterator<Watch> it = candidates.iterator(); it.hasNext(); ) {
                Watch w = it.next();
                if (w.matches(bit, count, at[1])) {
                    w.requested = true;
                    first.add(w.key);
                    it.remove();
                }
            }
        }
        return first;
    }

    /**
     * Follow an endpoint; returns whether a request for it has been seen already.
     * `anyHost`: the URL's host is a guess (the code builds it on a base nobody has revealed),
     * so the path is what identifies it.
     */
    synchronized boolean watch(String key, String method, String url, boolean anyHost) {
        Watch old = watches.get(key);
        if (old != null && old.url.equals(url)) {
            return old.requested;
        }
        forget(key);                                        // the same endpoint, now known under a better URL
        String[] at = locate(url);
        if (at == null) {
            return false;
        }
        Watch w = new Watch(key, method, url, anyHost ? "" : at[0], at[1]);
        watches.put(key, w);
        for (Map.Entry<String, Map<Integer, Map<String, Integer>>> host : requests.entrySet()) {
            if (!anyHost && !host.getKey().equals(at[0])) {
                continue;
            }
            Map<String, Integer> paths = host.getValue().get(w.segments);
            if (paths == null) {
                continue;
            }
            if (w.shape == null) {
                Integer methods = paths.get(w.path);
                w.requested = methods != null && (w.methods == ANY_METHOD || (w.methods & methods) != 0);
            } else {
                for (Map.Entry<String, Integer> seen : paths.entrySet()) {
                    if (w.matches(seen.getValue(), w.segments, seen.getKey())) {
                        w.requested = true;
                        break;
                    }
                }
            }
            if (w.requested) {
                return true;
            }
        }
        waiting.computeIfAbsent(w.host, h -> new ArrayList<>()).add(w);
        return false;
    }

    /** The engine withdrew this endpoint. */
    synchronized void forget(String key) {
        Watch w = watches.remove(key);
        if (w != null && !w.requested) {
            List<Watch> list = waiting.get(w.host);
            if (list != null) {
                list.remove(w);
            }
        }
    }

    /** Findings were cleared. What Burp has requested stays true. */
    synchronized void forgetEndpoints() {
        watches.clear();
        waiting.clear();
    }

    synchronized int paths() {
        return stored;
    }
}
