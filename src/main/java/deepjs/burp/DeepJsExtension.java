package deepjs.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import deepjs.engine.Json;
import deepjs.engine.Serve;
import java.awt.Component;
import java.awt.Desktop;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import javax.swing.JMenuItem;
import javax.swing.Timer;

/**
 * DeepJS for Burp Suite.
 *
 * Every JavaScript / HTML response that passes through Burp is handed to the
 * analysis engine ({@link deepjs.engine.Engine}). What it finds appears in the
 * "DeepJS" tab: API calls with method, parameters and body fields; secrets;
 * hosts; and the scripts and source maps the code names but no page has
 * loaded — which the extension can then request through Burp, so they land in
 * the site map and are analysed too. Each call is set against what Burp has
 * actually requested ({@link Traffic}): the ones nobody has made yet are the
 * part of the API the application's pages did not show.
 *
 * The engine never touches the network: every request is made here, through
 * Burp, and only when the user has left "Fetch hidden scripts" / "Fetch source
 * maps" on. Analysis runs on its own thread; Burp's threads only queue work.
 */
public final class DeepJsExtension implements BurpExtension, HttpHandler, ContextMenuItemsProvider,
        DeepJsTab.Actions, Analyzer.Listener {

    static final String VERSION = Serve.VERSION;
    private static final int MAX_BODY = 20 * 1024 * 1024;
    private static final int MAX_FETCHES = 400;                 // per "Clear" — a ceiling on extension-made requests
    static final String RELEASES_API = "https://api.github.com/repos/xtawb/deepjs-burp/releases/latest";
    static final String RELEASES_PAGE = "https://github.com/xtawb/deepjs-burp/releases/latest";
    private static final int MAX_QUEUED = 32;                   // responses waiting for analysis during a history pass
    private static final int MAX_NOTES_LINES = 40;
    private static final String DISMISSED = "deepjs.dismissed";    // the preference that holds what the user ruled out
    private static final Pattern VERSION_SHAPE = Pattern.compile("\\d{1,9}(\\.\\d{1,9}){0,5}");

    private MontoyaApi api;
    private Preferences prefs;
    DeepJsTab tab;               // package-private: the harness inspects these
    Analyzer analyzer;
    private ExecutorService fetchPool;
    private Timer statusTimer;

    private final Set<String> analysed = ConcurrentHashMap.newKeySet();       // url + body fingerprint
    private final Set<String> analysedHosts = ConcurrentHashMap.newKeySet();  // hosts a script was seen on
    private final Map<String, String> pendingFetch = Collections.synchronizedMap(new LinkedHashMap<>());   // url → kind
    private final Set<String> fetched = ConcurrentHashMap.newKeySet();
    private final Set<String> reportedSecrets = ConcurrentHashMap.newKeySet();
    private final Traffic traffic = new Traffic();
    private final Sessions sessions = new Sessions();
    private final AtomicInteger fetchCount = new AtomicInteger();
    private final AtomicInteger analysedCount = new AtomicInteger();
    private volatile String notice = "";              // shown in the status line: "update available: 0.5.0"
    Consumer<String> browser = this::openInBrowser;   // the harness has no desktop to open a page on

    // ── BurpExtension ────────────────────────────────────────────────────────

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.prefs = api.persistence().preferences();
        api.extension().setName("DeepJS");

        tab = new DeepJsTab(this);
        loadSettings();
        fetchPool = Executors.newFixedThreadPool(4, r -> {
            Thread t = new Thread(r, "deepjs-fetch");
            t.setDaemon(true);
            return t;
        });
        analyzer = new Analyzer(this);

        api.userInterface().registerSuiteTab("DeepJS", tab);
        api.userInterface().registerContextMenuItemsProvider(this);
        api.http().registerHttpHandler(this);
        api.extension().registerUnloadingHandler(this::unload);

        statusTimer = new Timer(1000, e -> refreshStatus());
        statusTimer.start();
        if (api.extension().isBapp()) {
            tab.updatesComeFromTheStore();
        } else if (tab.updateCheck.isSelected()) {
            background("deepjs-update", this::checkForUpdate);
        }
        api.logging().logToOutput("DeepJS " + VERSION + " loaded.");
    }

    /** Run `body` on a daemon thread; whatever it throws goes to the extension's error stream. */
    private void background(String name, Runnable body) {
        Thread t = new Thread(() -> {
            try {
                body.run();
            } catch (RuntimeException e) {
                api.logging().logToError("DeepJS (" + name + "): " + e);
            }
        }, name);
        t.setDaemon(true);
        t.start();
    }

    private void unload() {
        if (statusTimer != null) {
            statusTimer.stop();
        }
        fetchPool.shutdownNow();
        analyzer.shutdown();
        sessions.clear();
    }

    // ── settings ─────────────────────────────────────────────────────────────

    private void loadSettings() {
        tab.forEachOption(box -> {
            Boolean v = prefs.getBoolean("deepjs." + box.getText());
            if (v != null) {
                box.setSelected(v);
            }
        });
        String dismissed = prefs.getString(DISMISSED);
        if (dismissed != null && !dismissed.isEmpty()) {
            tab.setDismissed(Arrays.asList(dismissed.split("\n")));
        }
        tab.settingsLoaded();
    }

    @Override
    public void dismissalsChanged() {
        // the type and fingerprint of each value, never the value: a preferences file is no place for a credential
        prefs.setString(DISMISSED, String.join("\n", tab.dismissedIds()));
    }

    @Override
    public void settingsChanged() {
        tab.forEachOption(box -> prefs.setBoolean("deepjs." + box.getText(), box.isSelected()));
        if (tab.fetchHidden.isSelected() || tab.fetchMaps.isSelected()) {
            drainPending(false);
        }
    }

    // ── passive analysis ─────────────────────────────────────────────────────

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        try {
            noteRequest(request, request.toolSource().isFromTool(ToolType.PROXY));
        } catch (RuntimeException e) {
            api.logging().logToError("DeepJS: " + e);
        }
        return RequestToBeSentAction.continueWith(request);
    }

    /**
     * A request Burp is sending, or sent before the extension was loaded. Its method and path say
     * which endpoints have been requested; when the browser made it, its headers say what a
     * session with that host looks like.
     */
    private void noteRequest(HttpRequest request, boolean fromBrowser) {
        String url = request.url();
        synchronized (traffic) {                            // with onMessage: a row and the mark on it arrive in order
            List<String> first = traffic.saw(request.method(), url);
            if (!first.isEmpty()) {
                tab.markRequested(first);
            }
        }
        if (fromBrowser) {
            String host = Traffic.hostOf(url);
            for (HttpHeader header : request.headers()) {
                sessions.note(host, header.name(), header.value());
            }
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            // our own fetches are analysed where they are made; do not loop through here
            if (tab.enabled.isSelected() && !response.toolSource().isFromTool(ToolType.EXTENSIONS)) {
                consider(response.initiatingRequest(), response);
            }
        } catch (RuntimeException e) {
            api.logging().logToError("DeepJS: " + e);
        }
        return ResponseReceivedAction.continueWith(response);
    }

    /** Decide whether a response is worth analysing, and queue it if so. Returns true when queued. */
    private boolean consider(HttpRequest request, HttpResponse response) {
        if (request == null || response == null || response.statusCode() != 200) {
            return false;
        }
        String url = request.url();
        if (tab.scopeOnly.isSelected() && !request.isInScope()) {
            return false;
        }
        String kind = kindOf(url, response);
        if (kind == null) {
            return false;
        }
        byte[] body = response.body().getBytes();
        if (body.length == 0 || body.length > MAX_BODY) {
            return false;
        }
        return analyse(kind, url, body);
    }

    private static String kindOf(String url, HttpResponse response) {
        String path = url.split("[?#]", 2)[0].toLowerCase(Locale.ROOT);
        if (path.endsWith(".js") || path.endsWith(".mjs")) {
            return "script";
        }
        if (path.endsWith(".map")) {
            return "map";
        }
        MimeType stated = response.statedMimeType();
        MimeType inferred = response.inferredMimeType();
        if (stated == MimeType.SCRIPT || inferred == MimeType.SCRIPT) {
            return "script";
        }
        if (stated == MimeType.HTML || inferred == MimeType.HTML) {
            return "html";
        }
        return null;
    }

    private boolean analyse(String kind, String url, byte[] body) {
        String clean = url.split("#", 2)[0];
        String fingerprint = clean + "|" + body.length + "|" + Arrays.hashCode(body);
        if (!analysed.add(fingerprint)) {
            return false;                                   // this exact response was analysed already
        }
        if (analysed.size() > 100_000) {
            analysed.clear();
        }
        if (!analyzer.submit(kind, clean, body)) {
            analysed.remove(fingerprint);                   // unloading
            return false;
        }
        String host = hostOf(clean);
        if (!host.isEmpty()) {
            analysedHosts.add(host);
        }
        fetched.add(clean);
        return true;
    }

    private static String hostOf(String url) {
        try {
            String h = URI.create(url).getHost();
            return h == null ? "" : h.toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            return "";
        }
    }

    // ── results from the engine ──────────────────────────────────────────────

    @Override
    public void onMessage(String[] f) {
        switch (f[0]) {
            case "E" -> {
                if (f.length >= 10) {
                    // E method full url kind query body headers file line confidence [before span after]
                    String key = f[1] + " " + f[3];
                    synchronized (traffic) {
                        // `{apiUrl}/users`: the host shown is a guess, so a request is matched on the path alone
                        boolean requested = traffic.watch(key, f[1], f[2], f[3].startsWith("{"));
                        tab.putEndpoint(key, new String[]{f[1].isEmpty() ? "?" : f[1], f[2], f[5], f[6], f[7], f[4], f[8] + ":" + f[9],
                                requested ? "yes" : "no", field(f, 11), field(f, 12), field(f, 13)});
                    }
                }
            }
            case "W" -> {
                // the engine replaced this endpoint with a better one (base URL resolved, string → call)
                if (f.length >= 3) {
                    synchronized (traffic) {
                        traffic.forget(f[1] + " " + f[2]);
                        tab.removeEndpoint(f[1] + " " + f[2]);
                    }
                }
            }
            case "S" -> {
                if (f.length >= 10) {
                    // S severity kind value key file line note fingerprint public [before span after]
                    String id = f[2] + " " + f[8];
                    tab.putSecret(id, new String[]{f[1], f[2], f[3], f[4], f[5] + ":" + f[6], f[7],
                            field(f, 10), field(f, 11), field(f, 12)});
                    if (!"1".equals(f[9]) && tab.raiseIssues.isSelected() && !tab.isDismissed(id) && reportedSecrets.add(id)) {
                        raiseIssue(f);
                    }
                }
            }
            case "C" -> offer(f[1], "script");
            case "M" -> {
                if (f.length >= 3) {
                    offer(f[1], "1".equals(f[2]) ? "source map" : "source map (guess)");
                }
            }
            case "H" -> {
                if (f.length >= 5) {
                    tab.putHost(new String[]{f[1], f[2], f[3], "1".equals(f[4]) ? "yes" : ""});
                }
            }
            case "R" -> tab.putOther("Client routes", f[1]);
            case "G" -> tab.putOther("GraphQL operations", f.length >= 3 ? f[1] + " " + f[2] : f[1]);
            case "B" -> tab.putOther("API base URLs", f[1]);
            case "P" -> tab.putOther("npm packages (from source maps)", f[1]);
            case "X" -> tab.log("engine: " + (f.length > 1 ? f[1] : ""));
            case "D" -> analysedCount.incrementAndGet();
            default -> { }
        }
    }

    private static String field(String[] record, int i) {
        return i < record.length ? record[i] : "";
    }

    // ── update notice ────────────────────────────────────────────────────────

    /**
     * One request to GitHub's API, through Burp, when the extension loads. Silent when offline.
     *
     * A newer release is announced, with what it changed, and the tab offers its download page.
     * That is as far as this goes: an extension cannot replace the jar Burp has loaded it from,
     * and a build installed from the BApp Store is updated by Burp, which is why it never asks.
     */
    private void checkForUpdate() {
        HttpRequest request = HttpRequest.httpRequestFromUrl(RELEASES_API)
                .withAddedHeader("Accept", "application/vnd.github+json")
                .withAddedHeader("User-Agent", "DeepJS-Burp/" + VERSION);
        HttpResponse response = api.http().sendRequest(request).response();
        if (response == null || response.statusCode() != 200) {
            return;
        }
        Release latest = Release.read(response.bodyToString());
        if (!isNewer(latest.version(), VERSION)) {
            return;
        }
        notice = "update available: " + latest.version();
        String headline = "DeepJS " + latest.version() + " is available (this is " + VERSION + "): " + RELEASES_PAGE;
        StringBuilder text = new StringBuilder(headline);
        if (!latest.notes().isEmpty()) {
            text.append("\nWhat changed:");
            for (String line : latest.notes()) {
                text.append("\n  ").append(line);
            }
        }
        text.append("\nTo update: download deepjs-burp.jar from that page, then under Extensions > Installed"
                + " remove DeepJS and add the new file.");
        tab.log(text.toString());
        tab.offerUpdate(latest.version());
        api.logging().logToOutput(headline);
        refreshStatus();
    }

    /** The latest release as GitHub describes it: its version ("" when the tag is not one) and its notes, by line. */
    record Release(String version, List<String> notes) {

        static Release read(String json) {
            try {
                Map<String, Object> doc = Json.object(Json.parse(json == null ? "" : json));
                if (doc != null && doc.get("tag_name") instanceof String tag) {
                    String version = tag.startsWith("v") ? tag.substring(1) : tag;
                    String notes = doc.get("body") instanceof String body ? body : "";
                    return new Release(VERSION_SHAPE.matcher(version).matches() ? version : "", readable(notes));
                }
            } catch (Json.Malformed e) {
                // an error page, a captive portal, a rate-limit message: not a release
            }
            return new Release("", List.of());
        }
    }

    /** Release notes as lines fit for the log: no control characters, a bounded number of bounded lines. */
    static List<String> readable(String notes) {
        List<String> lines = new ArrayList<>();
        for (String raw : notes.split("\r\n|\r|\n", -1)) {
            StringBuilder line = new StringBuilder();
            for (int i = 0; i < raw.length() && line.length() < 300; i++) {
                char c = raw.charAt(i);
                if (c == '\t' || !Character.isISOControl(c)) {
                    line.append(c);
                }
            }
            lines.add(line.toString());
        }
        while (!lines.isEmpty() && lines.get(lines.size() - 1).isBlank()) {
            lines.remove(lines.size() - 1);
        }
        if (lines.size() > MAX_NOTES_LINES) {
            lines = new ArrayList<>(lines.subList(0, MAX_NOTES_LINES));
            lines.add("…");
        }
        return lines;
    }

    @Override
    public void openReleasePage() {
        background("deepjs-browser", () -> browser.accept(RELEASES_PAGE));
    }

    /** Hand a page to the desktop's browser; where there is none to hand it to, the address goes to the log. */
    private void openInBrowser(String url) {
        try {
            Desktop.getDesktop().browse(URI.create(url));
        } catch (IOException | RuntimeException e) {
            tab.log("No browser could be opened from here (" + e.getClass().getSimpleName() + "). The page is " + url);
        }
    }

    /** Is version `candidate` ("0.10.1") later than `current`? Unparseable input is never newer. */
    static boolean isNewer(String candidate, String current) {
        if (candidate == null || current == null
                || !VERSION_SHAPE.matcher(candidate).matches() || !VERSION_SHAPE.matcher(current).matches()) {
            return false;
        }
        String[] a = candidate.split("\\."), b = current.split("\\.");
        for (int i = 0; i < Math.max(a.length, b.length); i++) {
            long x = i < a.length ? Long.parseLong(a[i]) : 0, y = i < b.length ? Long.parseLong(b[i]) : 0;
            if (x != y) {
                return x > y;
            }
        }
        return false;
    }

    @Override
    public void onLog(String text) {
        tab.log(text);
    }

    private void refreshStatus() {
        int waiting = analyzer == null ? 0 : analyzer.pending();
        tab.setStatus("DeepJS " + VERSION + "  ·  " + analysedCount.get() + " response(s) analysed"
                + (waiting > 0 ? ", " + waiting + " queued" : "")
                + (fetchCount.get() > 0 ? ", " + fetchCount.get() + " fetched by DeepJS" : "")
                + (notice.isEmpty() ? "" : "  ·  " + notice), true);
    }

    private void raiseIssue(String[] f) {
        try {
            String file = f[5];
            String base = file.startsWith("map:") || !file.startsWith("http") ? "" : file;
            AuditIssueSeverity sev = switch (f[1]) {
                case "critical", "high" -> AuditIssueSeverity.HIGH;
                case "medium" -> AuditIssueSeverity.MEDIUM;
                case "low" -> AuditIssueSeverity.LOW;
                default -> AuditIssueSeverity.INFORMATION;
            };
            if (base.isEmpty()) {
                return;                                     // an issue needs a URL to hang on
            }
            String detail = "<p>DeepJS found a credential in front-end code.</p><ul>"
                    + "<li><b>Type:</b> " + html(f[2]) + "</li><li><b>Value:</b> " + html(tab.maskValues.isSelected() ? DeepJsTab.mask(f[3]) : f[3]) + "</li>"
                    + (f[4].isEmpty() ? "" : "<li><b>Assigned to:</b> " + html(f[4]) + "</li>")
                    + "<li><b>Location:</b> " + html(f[5]) + ":" + html(f[6]) + "</li></ul><p>" + html(f[7]) + "</p>";
            api.siteMap().add(AuditIssue.auditIssue(
                    "Secret in JavaScript: " + f[2], detail,
                    "Remove the value from client-side code, rotate it, and serve it from the back end only.",
                    base, sev, AuditIssueConfidence.FIRM, null, null, sev, new ArrayList<HttpRequestResponse>()));
        } catch (RuntimeException e) {
            // editions without an issue store: the Secrets table already shows it
            tab.log("could not add an issue (" + e.getClass().getSimpleName() + ") — see the Secrets table instead");
        }
    }

    private static String html(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    // ── fetching what the code refers to ─────────────────────────────────────

    /** The engine named a script / source map nobody has loaded. */
    private void offer(String url, String kind) {
        if (fetched.contains(url) || pendingFetch.containsKey(url)) {
            return;
        }
        pendingFetch.put(url, kind);
        tab.putScript(url, kind, "not fetched");
        drainPending(false);
    }

    @Override
    public void fetchHiddenNow() {
        drainPending(true);
    }

    private void drainPending(boolean force) {
        List<Map.Entry<String, String>> todo;
        synchronized (pendingFetch) {
            todo = new ArrayList<>(pendingFetch.entrySet());
        }
        for (Map.Entry<String, String> e : todo) {
            String url = e.getKey();
            String kind = e.getValue();
            boolean isMap = kind.startsWith("source map");
            boolean wanted = force || (isMap ? tab.fetchMaps.isSelected() : tab.fetchHidden.isSelected());
            if (!wanted) {
                continue;
            }
            String reason = refusal(url);
            if (reason != null) {
                pendingFetch.remove(url);
                tab.putScript(url, kind, reason);
                continue;
            }
            if (fetchCount.get() >= MAX_FETCHES) {
                tab.putScript(url, kind, "not fetched (limit of " + MAX_FETCHES + " reached — press Clear to reset)");
                continue;
            }
            if (pendingFetch.remove(url) != null && fetched.add(url)) {
                fetchCount.incrementAndGet();
                tab.putScript(url, kind, "queued");
                fetchPool.execute(() -> fetch(url, kind));
            }
        }
    }

    /** Why DeepJS will not request this URL, or null if it may. */
    private String refusal(String url) {
        String host = hostOf(url);
        if (host.isEmpty()) {
            return "skipped (not a valid URL)";
        }
        if (tab.scopeOnly.isSelected() && !api.scope().isInScope(url)) {
            return "skipped (out of scope)";
        }
        // Only hosts the application itself has already served a script from —
        // the same thing a browser would do when it lazy-loads a chunk.
        if (!analysedHosts.contains(host)) {
            return "skipped (no script seen from this host)";
        }
        return null;
    }

    private void fetch(String url, String kind) {
        try {
            HttpRequestResponse rr = api.http().sendRequest(HttpRequest.httpRequestFromUrl(url));
            HttpResponse resp = rr.response();
            if (resp == null) {
                tab.putScript(url, kind, "no response");
                return;
            }
            int code = resp.statusCode();
            byte[] body = resp.body().getBytes();
            String head = new String(body, 0, Math.min(body.length, 200)).trim().toLowerCase(Locale.ROOT);
            if (code != 200 || body.length == 0) {
                tab.putScript(url, kind, "HTTP " + code);
            } else if (head.startsWith("<!doctype") || head.startsWith("<html")) {
                tab.putScript(url, kind, "not there (the server answered with a page)");
            } else if (body.length > MAX_BODY) {
                tab.putScript(url, kind, "too large");
            } else {
                boolean isMap = kind.startsWith("source map");
                analysed.add(url + "|" + body.length + "|" + Arrays.hashCode(body));
                analyzer.submit(isMap ? "map" : "script", url, body);
                tab.putScript(url, kind, "fetched (" + (body.length / 1024) + " KB)");
                try {
                    api.siteMap().add(rr);                  // so it is visible in Target like any other response
                } catch (RuntimeException ignored) {
                    // not essential
                }
            }
        } catch (RuntimeException e) {
            tab.putScript(url, kind, "failed: " + e.getClass().getSimpleName());
        }
    }

    // ── tab actions ──────────────────────────────────────────────────────────

    @Override
    public void analyseProxyHistory() {
        background("deepjs-history", () -> {
            int queued = 0, noted = 0;
            for (ProxyHttpRequestResponse item : api.proxy().history()) {
                try {
                    HttpRequest sent = item.finalRequest();
                    noteRequest(sent, true);                // what the browser asked for before DeepJS was listening
                    noted++;
                    if (consider(sent, item.originalResponse())) {
                        queued++;
                        // a large history must not be copied into memory all at once: keep pace with the analysis
                        while (analyzer.pending() > MAX_QUEUED) {
                            Thread.sleep(20);
                        }
                    }
                } catch (InterruptedException unloading) {
                    Thread.currentThread().interrupt();
                    return;
                } catch (RuntimeException ignored) {
                    // one odd history entry must not stop the pass
                }
            }
            tab.log("proxy history: " + queued + " response(s) queued for analysis, " + noted + " request(s) noted as made");
        });
    }

    @Override
    public void clearAll() {
        analysed.clear();
        analysedHosts.clear();
        pendingFetch.clear();
        fetched.clear();
        reportedSecrets.clear();
        fetchCount.set(0);
        analysedCount.set(0);
        analyzer.reset();
        synchronized (traffic) {
            traffic.forgetEndpoints();                      // the findings go; what Burp has requested stays true
            tab.clearTables();
        }
    }

    @Override
    public void sendToRepeater(List<String[]> rows) {
        int sent = 0, signedIn = 0;
        for (String[] row : rows) {
            try {
                HttpRequest req = buildRequest(row);
                if (req != null) {
                    String path = row[DeepJsTab.E_URL].replaceFirst("^[a-z]+://[^/]+", "");
                    api.repeater().sendToRepeater(req, "DeepJS " + row[DeepJsTab.E_METHOD] + " " + shorten(path));
                    sent++;
                    signedIn += sessionFor(row[DeepJsTab.E_URL]).isEmpty() ? 0 : 1;
                }
            } catch (RuntimeException e) {
                tab.log("could not build a request for " + row[DeepJsTab.E_URL] + ": " + e.getMessage());
            }
        }
        tab.log(sent + " request(s) sent to Repeater"
                + (signedIn > 0 ? ", " + signedIn + " with the session your browser last used on that host" : "")
                + (sent < rows.size() ? " — " + (rows.size() - sent) + " skipped (no absolute URL is known for them)" : ""));
    }

    /** The session headers to add to a request for `url`: none unless the user wants them and the host has been seen. */
    private List<String[]> sessionFor(String url) {
        return tab.withSession.isSelected() ? sessions.headersFor(Traffic.hostOf(url)) : List.of();
    }

    private static String shorten(String s) {
        return s.length() > 40 ? s.substring(0, 37) + "…" : s;
    }

    /** Turn an endpoint row into a request skeleton: method, query names, JSON body field names. */
    static String requestUrl(String[] row) {
        String url = row[DeepJsTab.E_URL];
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return null;
        }
        // {id} → :id — a placeholder the tester can see and replace
        url = url.replaceAll("\\{([^{}]*)\\}", ":$1");
        String query = row[DeepJsTab.E_QUERY];
        if (!query.isEmpty()) {
            StringBuilder q = new StringBuilder();
            for (String name : query.split(",")) {
                q.append(q.length() == 0 ? (url.contains("?") ? "&" : "?") : "&").append(name.trim()).append('=');
            }
            url += q;
        }
        return url;
    }

    static String requestBody(String[] row) {
        String fields = row[DeepJsTab.E_BODY];
        if (fields.isEmpty()) {
            return null;
        }
        StringBuilder b = new StringBuilder("{");
        for (String name : fields.split(",")) {
            b.append(b.length() > 1 ? ", " : "").append('"').append(name.trim().replace("\"", "")).append("\": \"\"");
        }
        return b.append('}').toString();
    }

    private HttpRequest buildRequest(String[] row) {
        String url = requestUrl(row);
        if (url == null) {
            return null;
        }
        String method = row[DeepJsTab.E_METHOD];
        HttpRequest req = HttpRequest.httpRequestFromUrl(url);
        if (!method.equals("?") && !method.equals("GET")) {
            req = req.withMethod(method);
        }
        String body = requestBody(row);
        if (body != null && !method.equals("GET") && !method.equals("?")) {
            req = req.withAddedHeader("Content-Type", "application/json").withBody(body);
        }
        for (String[] header : sessionFor(url)) {
            req = req.withAddedHeader(header[0], header[1]);
        }
        return req;
    }

    // ── context menu: "Analyse with DeepJS" ──────────────────────────────────

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = new ArrayList<>(event.selectedRequestResponses());
        event.messageEditorRequestResponse().ifPresent(m -> selected.add(m.requestResponse()));
        if (selected.isEmpty()) {
            return List.of();
        }
        JMenuItem item = new JMenuItem("Analyse with DeepJS");
        item.addActionListener(e -> background("deepjs-menu", () -> {
            int queued = 0;
            for (HttpRequestResponse rr : selected) {
                try {
                    HttpResponse resp = rr.response();
                    if (resp == null) {
                        continue;
                    }
                    byte[] body = resp.body().getBytes();
                    String kind = kindOf(rr.request().url(), resp);
                    // an explicit request from the user: analyse it even if it does not look like a script
                    if (body.length > 0 && body.length <= MAX_BODY && analyse(kind == null ? "auto" : kind, rr.request().url(), body)) {
                        queued++;
                    }
                } catch (RuntimeException ignored) {
                    // skip the item
                }
            }
            tab.log("context menu: " + queued + " response(s) queued for analysis");
        }));
        return List.of(item);
    }
}
