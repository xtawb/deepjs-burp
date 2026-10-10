package deepjs.burp;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.SwingUtilities;

/**
 * Exercises the extension without Burp: the analysis thread and the engine
 * behind it, hostile input, the tab and its models, the request skeletons
 * sent to Repeater, and the extension class itself against a mocked Burp API.
 *
 *   java -cp <classes>:<test-classes>:<montoya-api.jar> deepjs.burp.Harness
 *
 * Exits non-zero on the first failed check.
 */
public final class Harness {

    private static int checks;

    private static void check(boolean ok, String what) {
        checks++;
        if (!ok) {
            System.err.println("FAILED: " + what);
            System.exit(1);
        }
    }

    public static void main(String[] args) throws Exception {
        // ── update notice ────────────────────────────────────────────────────
        DeepJsExtension.Release release = DeepJsExtension.Release.read("{\"url\":\"x\",\"tag_name\": \"v1.12.0\",\"name\":\"n\","
                + "\"body\":\"## Fixes\\r\\n- one\\u001b[2J\\u0007\\n- two\\n\\n\"}");
        check(release.version().equals("1.12.0"), "tag is read");
        check(release.notes().equals(List.of("## Fixes", "- one[2J", "- two")), "release notes are read, minus control characters: " + release.notes());
        check(DeepJsExtension.Release.read("<html>rate limited</html>").version().isEmpty()
                && DeepJsExtension.Release.read(null).version().isEmpty()
                && DeepJsExtension.Release.read("{\"tag_name\":7}").version().isEmpty()
                && DeepJsExtension.Release.read("{\"tag_name\":\"v1.0 beta\"}").version().isEmpty(), "what is not a release has no version");
        List<String> cut = DeepJsExtension.readable("x".repeat(5000) + "\nline".repeat(500));
        check(cut.size() == 41 && cut.get(0).length() == 300 && cut.get(40).equals("…"), "long release notes are cut");
        check(DeepJsExtension.isNewer("0.10.0", "0.9.9") && DeepJsExtension.isNewer("1.0", "0.99.99")
                && !DeepJsExtension.isNewer("0.3.0", "0.3.0") && !DeepJsExtension.isNewer("0.2.9", "0.3.0")
                && !DeepJsExtension.isNewer("", "0.3.0") && !DeepJsExtension.isNewer("nightly", "0.3.0")
                && !DeepJsExtension.isNewer("99999999999999999999999.0", "0.3.0"), "version comparison");
        check(DeepJsExtension.VERSION.matches("\\d+\\.\\d+\\.\\d+"), "the extension has a version: " + DeepJsExtension.VERSION);

        // ── the analysis thread and the engine behind it ─────────────────────
        List<String[]> messages = Collections.synchronizedList(new ArrayList<>());
        List<String> logged = Collections.synchronizedList(new ArrayList<>());
        Analyzer analyzer = new Analyzer(new Analyzer.Listener() {
            public void onMessage(String[] f) { messages.add(f); }
            public void onLog(String text) { logged.add(text); }
        });
        String base = "https://app.acme.io";
        String runtime = "(()=>{var r={};r.p=\"/\";r.u=e=>\"static/js/\"+({3:\"admin\"}[e]||e)+\".\"+"
                + "{3:\"9f1c2a\",7:\"02ab3c\"}[e]+\".chunk.js\";})();";
        String main = "const API=\"/api/v1\";function login(e,t){return fetch(API+\"/auth/login\",{method:\"POST\","
                + "body:JSON.stringify({email:e,password:t})})}"
                + "const cfg={clientSecret:\"Zx9Qm2Lk8Pz4Rt6V\"+\"\",apiKey:\"YOUR_API_KEY\"};"
                + "var k=\"AKIA\"+\"\";function del(id){return axios.delete(`/api/v1/users/${id}`)}"
                + "\n//# sourceMappingURL=main.js.map\n";
        long began = System.nanoTime();
        check(analyzer.submit("script", base + "/static/js/runtime.js", runtime.getBytes(StandardCharsets.UTF_8)), "work is accepted");
        analyzer.submit("script", base + "/static/js/main.js", main.getBytes(StandardCharsets.UTF_8));
        analyzer.submit("script", base + "/static/js/junk.js", new byte[]{0, 1, 2, '{', '{', '{'});
        check(analyzer.awaitIdle(30_000), "everything submitted is analysed");
        check(messages.stream().anyMatch(f -> f[0].equals("E") && f[3].equals("/api/v1/auth/login") && f.length == 14
                        && f[12].equals("fetch") && main.contains(f[11] + f[12] + f[13]) && f[13].startsWith("(API+\"/auth/login\"")),
                "an endpoint comes with the code it was read from");
        check(messages.stream().anyMatch(f -> f[0].equals("S") && f.length == 13 && f[11].equals(f[3])
                        && main.contains(f[10] + f[11] + f[12])), "a secret comes with the code around its value");
        System.out.println("DeepJS " + DeepJsExtension.VERSION + " (engine in process, first three files in "
                + (System.nanoTime() - began) / 1_000_000 + " ms)");

        boolean login = false, delete = false, chunk = false, map = false;
        int done = 0;
        for (String[] f : messages) {
            switch (f[0]) {
                case "E" -> {
                    login |= f[1].equals("POST") && f[2].equals(base + "/api/v1/auth/login") && f[6].equals("email,password");
                    delete |= f[1].equals("DELETE") && f[3].equals("/api/v1/users/{id}");
                }
                case "C" -> chunk |= f[1].equals(base + "/static/js/admin.9f1c2a.chunk.js");
                case "M" -> map |= f[1].equals(base + "/static/js/main.js.map") && f[2].equals("1");
                case "D" -> done++;
                default -> { }
            }
        }
        check(login, "POST /api/v1/auth/login with body fields arrives");
        check(delete, "DELETE /api/v1/users/{id} arrives");
        check(chunk, "the hidden admin chunk is named");
        check(map, "the source map is named as referenced");
        check(done == 3, "one completion marker per response: " + done);

        int before = messages.size();
        analyzer.submit("script", base + "/static/js/main.js", main.getBytes(StandardCharsets.UTF_8));
        check(analyzer.awaitIdle(30_000), "second pass completes");
        long repeated = messages.subList(before, messages.size()).stream().filter(f -> !f[0].equals("D")).count();
        check(repeated == 0, "nothing is reported twice");

        // ── input written to break a parser ──────────────────────────────────
        String deep = "(".repeat(200_000) + "[".repeat(200_000) + "{".repeat(200_000);
        String longToken = "var t=\"xoxb-" + "a1-".repeat(120_000) + "zzzzzz\";var u=\"" + "\\u".repeat(50_000) + "\";";
        String nested = "`${`${`${`".repeat(5_000) + "x" + "`}`}`}`".repeat(5_000);
        String operators = "a" + "+b.c(d)[e]".repeat(60_000) + ";fetch(" + "(".repeat(5_000) + "\"/api/v1/deep\"" + ")".repeat(5_000) + ")";
        String html = "<script>" + "<script src=".repeat(40_000) + "<form action=".repeat(40_000) + "<base href='" + "/".repeat(40_000);
        byte[] binary = new byte[400_000];
        new java.util.Random(7).nextBytes(binary);
        int marker = messages.size();
        for (String hostile : new String[]{deep, longToken, nested, operators}) {
            analyzer.submit("script", base + "/static/js/hostile" + hostile.length() + ".js", hostile.getBytes(StandardCharsets.UTF_8));
        }
        analyzer.submit("html", base + "/hostile.html", html.getBytes(StandardCharsets.UTF_8));
        analyzer.submit("auto", base + "/static/js/binary.js", binary);
        analyzer.submit("map", base + "/static/js/hostile.js.map", ("{\"sources\":" + "[".repeat(100_000)).getBytes(StandardCharsets.UTF_8));
        analyzer.submit("script", base + "/static/js/after.js", "fetch(\"/api/v1/still-working\")".getBytes(StandardCharsets.UTF_8));
        began = System.nanoTime();
        check(analyzer.awaitIdle(120_000), "hostile input is analysed or rejected, never hung on");
        boolean survived = messages.subList(marker, messages.size()).stream()
                .anyMatch(f -> f[0].equals("E") && f[3].equals("/api/v1/still-working"));
        check(survived, "the engine keeps working after hostile input (log: " + logged + ")");
        System.out.println("hostile input: 8 files in " + (System.nanoTime() - began) / 1_000_000 + " ms, "
                + logged.size() + " rejected");

        // ── reported from a real Burp session: four findings, none of them a secret ──
        String grammar = "var rules={start:[{token:\"xml-pe.doctype.xml\",regex:\"(<!)(DOCTYPE)\",next:\"doctype\"}]};";
        String visitorTokens = "<html><script>boot({ajaxpipe_token:\"AXk6Zr9Qm2Lk8Pz4GM\",token:\"AdTLUvdWw1Yb5Nc7uJZY\","
                + "clientSecret:\"Zx9Qm2Lk8Pz4Rt6Vw1Yb5Nc7Hf0Jg3Ua\"})</script></html>";
        marker = messages.size();
        analyzer.submit("script", base + "/static/lib/ace/mode-xml.js", grammar.getBytes(StandardCharsets.UTF_8));
        analyzer.submit("html", "https://www.instagram.com/shop/embed", visitorTokens.getBytes(StandardCharsets.UTF_8));
        analyzer.submit("html", base + "/account", visitorTokens.getBytes(StandardCharsets.UTF_8));
        check(analyzer.awaitIdle(30_000), "the reported cases are analysed");
        List<String[]> secrets = messages.subList(marker, messages.size()).stream().filter(f -> f[0].equals("S")).toList();
        check(secrets.stream().noneMatch(f -> f[5].contains("mode-xml") || f[5].contains("instagram")),
                "a highlighter's token types and a third-party embed are not findings");
        check(secrets.stream().filter(f -> f[2].equals("PAGE_TOKEN") && f[1].equals("info") && f[9].equals("1")).count() == 2,
                "tokens written into the application's own page are labelled as the visitor's, not as leaks");
        check(secrets.stream().anyMatch(f -> f[2].equals("HARDCODED_SECRET") && f[4].equals("clientSecret")
                        && f[3].equals("Zx9Qm2Lk8Pz4Rt6Vw1Yb5Nc7Hf0Jg3Ua") && f[9].equals("0")),
                "a client secret in the same page is still a finding, with its value");

        analyzer.reset();
        analyzer.submit("script", base + "/static/js/main.js", main.getBytes(StandardCharsets.UTF_8));
        check(analyzer.awaitIdle(30_000) && messages.stream().filter(f -> f[0].equals("E") && f[3].equals("/api/v1/auth/login")).count() == 2,
                "after a reset the same file is reported again");
        analyzer.shutdown();
        check(!analyzer.submit("script", base + "/x.js", new byte[]{'1'}), "no work is accepted after shutdown");

        // ── the tab and its models (no Burp, no display) ─────────────────────
        List<List<String[]>> toRepeater = new ArrayList<>();
        int[] dismissals = {0};
        DeepJsTab[] holder = new DeepJsTab[1];
        SwingUtilities.invokeAndWait(() -> holder[0] = new DeepJsTab(new DeepJsTab.Actions() {
            public void sendToRepeater(List<String[]> rows) { toRepeater.add(rows); }
            public void fetchHiddenNow() { }
            public void analyseProxyHistory() { }
            public void clearAll() { }
            public void settingsChanged() { }
            public void dismissalsChanged() { dismissals[0]++; }
            public void openReleasePage() { }
        }));
        DeepJsTab tab = holder[0];
        String[] row = {"POST", base + "/api/v1/users/{id}/roles", "expand,fields", "role,reason", "X-CSRF", "fetch", "main.js:1"};
        tab.putEndpoint("POST /api/v1/users/{id}/roles", row);
        tab.putEndpoint("POST /api/v1/users/{id}/roles", row);                 // same key → still one row
        tab.putEndpoint(" /other", new String[]{"?", "/other", "", "", "", "string", "x.js:2"});
        tab.putSecret("AWS x", new String[]{"critical", "AWS_ACCESS_KEY", "AKIA…6N", "k", "a.js:1", "note"});
        tab.putScript(base + "/a.chunk.js", "script", "not fetched");
        tab.putScript(base + "/a.chunk.js", "script", "fetched (12 KB)");
        tab.putHost(new String[]{"api.acme.io", "in-scope", "", ""});
        tab.putOther("Client routes", "/admin");
        tab.log("hello");
        tab.setStatus("ok", true);
        boolean offeredTooEarly = tab.updateButton.isVisible();
        tab.offerUpdate("9.9.9");
        SwingUtilities.invokeAndWait(() -> { });
        check(!offeredTooEarly && tab.updateButton.isVisible() && tab.updateButton.getText().equals("Get DeepJS 9.9.9"),
                "the download button appears only when there is something to download");
        check(tab.endpoints.getRowCount() == 2, "endpoint rows are keyed (2 rows, got " + tab.endpoints.getRowCount() + ")");

        // what is listed: calls only until strings are asked for, one host, not yet requested
        tab.putEndpoint("GET /v2/x", new String[]{"GET", "https://api.other.io/v2/x", "", "", "", "fetch", "m.js:1", "no",
                "return ", "fetch", "(\"/v2/x\")\r\n"});
        int[] seen = new int[6];
        String[] shown = new String[3];
        SwingUtilities.invokeAndWait(() -> {
            seen[0] = tab.endpointTable.getRowCount();                          // the bare string "/other" is not listed
            tab.showStrings.doClick();
            seen[1] = tab.endpointTable.getRowCount();
            tab.hostFilter.setSelectedItem("api.other.io");
            seen[2] = tab.endpointTable.getRowCount();
            tab.endpointTable.setRowSelectionInterval(0, 0);
            shown[0] = tab.endpointCode.text();
            shown[1] = tab.endpointCode.highlighted();
            tab.onlyUnrequested.doClick();
            seen[3] = tab.endpointTable.getRowCount();
        });
        tab.markRequested(List.of("GET /v2/x", "no such row"));
        SwingUtilities.invokeAndWait(() -> {
            seen[4] = tab.endpointTable.getRowCount();
            shown[2] = String.valueOf(tab.endpoints.getValueAt(2, DeepJsTab.E_SEEN));
            tab.onlyUnrequested.doClick();
            tab.hostFilter.setSelectedItem(DeepJsTab.ALL_HOSTS);
            seen[5] = tab.endpointTable.getRowCount();
        });
        check(seen[0] == 2 && seen[1] == 3, "string-only paths are listed when asked for: " + seen[0] + " → " + seen[1]);
        check(tab.hostFilter.getItemCount() == 3 && tab.hostFilter.getItemAt(1).equals("api.other.io")
                && tab.hostFilter.getItemAt(2).equals("app.acme.io") && seen[2] == 1, "the calls can be narrowed to one host");
        check(shown[0].equals("return fetch(\"/v2/x\")\n") && shown[1].equals("fetch"),
                "selecting a call shows its code, the call highlighted: " + shown[0] + " / " + shown[1]);
        check(seen[3] == 1 && seen[4] == 0 && shown[2].equals("yes") && seen[5] == 3,
                "a call disappears from \"not requested yet\" once it is requested: " + java.util.Arrays.toString(seen) + " " + shown[2]);

        // "Mask values": no value of the Secrets table is readable in a code view, whole or cut
        String value = "Zx9Qm2Lk8Pz4Rt6Vw1Yb5Nc7Hf0Jg3Ua";
        StringBuilder excerpt = new StringBuilder("key=\"" + value + "\"; again=\"" + value.substring(0, 20));
        int[] mark = CodeView.conceal(excerpt, 5, 5 + value.length(), List.of(value));
        check(excerpt.toString().equals("key=\"Zx9Qm2Lk…g3Ua\"; again=\"Zx…") && excerpt.substring(mark[0], mark[1]).equals("Zx9Qm2Lk…g3Ua"),
                "a concealed value is masked wherever the excerpt shows it: " + excerpt);
        excerpt = new StringBuilder(value.substring(12) + "\" }; fetch(u)");
        mark = CodeView.conceal(excerpt, 25, 30, List.of(value));
        check(excerpt.toString().equals("…\" }; fetch(u)") && excerpt.substring(mark[0], mark[1]).equals("fetch"),
                "…also where the excerpt begins inside it: " + excerpt);
        check(CodeView.printable("a\r\nb\u0000c\td").equals("a\nb·c\td"), "source is made printable");
        check(tab.scripts.getRowCount() == 1 && tab.scripts.getValueAt(0, 2).equals("fetched (12 KB)"), "script status updates in place");
        check(tab.secrets.getRowCount() == 1 && tab.hosts.getRowCount() == 1, "secrets and hosts tables fill");

        // "Not a secret": gone from the list, remembered, and reversible
        int[] listed = new int[4];
        SwingUtilities.invokeAndWait(() -> {
            tab.secretTable.setRowSelectionInterval(0, 0);
            ((javax.swing.JMenuItem) tab.secretTable.getComponentPopupMenu().getComponent(1)).doClick();
            listed[0] = tab.secretTable.getRowCount();
            tab.showDismissed.doClick();
            listed[1] = tab.secretTable.getRowCount();
            tab.secretTable.setRowSelectionInterval(0, 0);
            listed[2] = tab.isDismissed("AWS x") ? 1 : 0;
            ((javax.swing.JMenuItem) tab.secretTable.getComponentPopupMenu().getComponent(2)).doClick();
            tab.showDismissed.doClick();
            listed[3] = tab.secretTable.getRowCount();
        });
        check(listed[0] == 0 && listed[1] == 1 && listed[2] == 1 && tab.secrets.getRowCount() == 1,
                "a dismissed secret leaves the list and can be shown again");
        check(listed[3] == 1 && !tab.isDismissed("AWS x") && dismissals[0] == 2, "and brought back; each change is reported to be saved");
        SwingUtilities.invokeAndWait(tab::clearTables);
        SwingUtilities.invokeAndWait(() -> { });
        check(tab.endpoints.getRowCount() == 0, "clear empties the tables");

        // ── request skeletons for Repeater ───────────────────────────────────
        check((base + "/api/v1/users/:id/roles?expand=&fields=").equals(DeepJsExtension.requestUrl(row)),
                "placeholders and query names become a URL: " + DeepJsExtension.requestUrl(row));
        check("{\"role\": \"\", \"reason\": \"\"}".equals(DeepJsExtension.requestBody(row)), "body fields become JSON");
        check(DeepJsExtension.requestUrl(new String[]{"GET", "{base}/users", "", "", "", "fetch", ""}) == null,
                "an endpoint with no known host is not sent");

        // ── what Burp has requested, and the session it was requested with ───
        Traffic traffic = new Traffic();
        String roles = base + "/api/users/{id}/roles";
        check(!traffic.watch("roles", "GET", roles, false) && traffic.saw("POST", base + "/api/users/42/roles").isEmpty(),
                "a request with another method is another request");
        check(traffic.saw("GET", "HTTPS://App.Acme.io:443/api/users/42/roles/?x=1#top").equals(List.of("roles")),
                "a request to a path the endpoint's URL matches is its first request");
        check(traffic.saw("GET", base + "/api/users/42/roles").isEmpty() && traffic.watch("roles", "GET", roles, false), "…and is counted once");
        check(traffic.watch("literal", "", base + "/api/users/42/roles", false) && !traffic.watch("delete", "DELETE", roles, false)
                && !traffic.watch("shorter", "GET", base + "/api/users/{id}", false), "method and depth both have to match");
        check(!traffic.watch("elsewhere", "GET", "https://api.acme.io/api/users/{id}/roles", false)
                && traffic.watch("guessed", "GET", "https://guess.example/api/users/{id}/roles", true),
                "another host is another API, unless the host was only a guess");
        traffic.forget("delete");
        check(traffic.saw("DELETE", base + "/api/users/9/roles").isEmpty() && !traffic.watch("nowhere", "GET", "{base}/users", false)
                && Traffic.hostOf("{base}/users").isEmpty() && Traffic.hostOf("http://localhost:3000/").equals("localhost:3000"),
                "a withdrawn endpoint is no longer followed; one without a host cannot be");
        check(traffic.paths() == 2, "one path per host is one entry, whatever the methods: " + traffic.paths());

        Sessions sessions = new Sessions();
        sessions.note("app.acme.io", "Cookie", "sid=1");
        sessions.note("app.acme.io", "Accept", "*/*");
        sessions.note("app.acme.io", "X-CSRF-Token", "t1");
        sessions.note("app.acme.io", "cookie", "sid=2");                          // a later request: the newer value
        StringBuilder kept = new StringBuilder();
        sessions.headersFor("app.acme.io").forEach(h -> kept.append(h[0]).append('=').append(h[1]).append(' '));
        check(kept.toString().equals("cookie=sid=2 X-CSRF-Token=t1 ") && sessions.headersFor("api.acme.io").isEmpty(),
                "session headers are kept per host, the latest value of each: " + kept);

        extensionAgainstMockedBurp();

        System.out.println("harness: " + checks + " checks passed");
        System.exit(0);
    }

    private static String column(DeepJsTab.KeyedModel model, int col) {
        StringBuilder b = new StringBuilder();
        for (int r = 0; r < model.getRowCount(); r++) {
            b.append(model.getValueAt(r, col)).append('\n');
        }
        return b.toString();
    }

    private static void settle(DeepJsExtension ext, MockBurp fake, int expectRequests) throws Exception {
        long end = System.currentTimeMillis() + 30_000;
        while (System.currentTimeMillis() < end) {
            Thread.sleep(150);
            SwingUtilities.invokeAndWait(() -> { });
            if (ext.analyzer.pending() == 0 && fake.requested.size() >= expectRequests) {
                Thread.sleep(300);                           // let the last answers reach the tables
                SwingUtilities.invokeAndWait(() -> { });
                if (ext.analyzer.pending() == 0) {
                    return;
                }
            }
        }
    }

    /**
     * Load the real extension class against a mocked Burp API and push traffic
     * through it: the handler, the engine, the fetching of hidden chunks and
     * source maps "through Burp", Repeater, history, context menu.
     */
    private static void extensionAgainstMockedBurp() throws Exception {
        String base = "https://app.acme.io";
        MockBurp fake = new MockBurp();
        fake.site.put(DeepJsExtension.RELEASES_API, "{\"tag_name\":\"v99.1.0\",\"name\":\"DeepJS 99.1.0\","
                + "\"body\":\"## Secrets\\r\\n- Fewer false positives.\\r\\n\"}");
        fake.site.put(base + "/static/js/admin.9f1c2a.chunk.js",
                "function del(e){return fetch(\"/api/v1/admin/users/\"+e,{method:\"DELETE\"})}");
        fake.site.put(base + "/static/js/main.js.map",
                "{\"version\":3,\"sources\":[\"webpack:///./src/audit.ts\",\"webpack:///./node_modules/@acme-internal/kit/i.js\"],"
                        + "\"sourcesContent\":[\"export const a = () => http.get(`/api/v1/audit/${id}`)\",\"x\"]}");

        DeepJsExtension ext = new DeepJsExtension();
        List<String> opened = Collections.synchronizedList(new ArrayList<>());
        ext.browser = opened::add;
        check(burp.api.montoya.BurpExtension.class.isAssignableFrom(DeepJsExtension.class), "implements BurpExtension");
        ext.initialize(fake.api());
        check(fake.suiteTab == ext.tab && fake.unloadHandler != null, "registers its tab and an unload handler");
        long end = System.currentTimeMillis() + 10_000;
        while (fake.output.stream().noneMatch(line -> line.contains("99.1.0 is available")) && System.currentTimeMillis() < end) {
            Thread.sleep(100);
        }
        check(fake.output.stream().anyMatch(line -> line.contains("DeepJS 99.1.0 is available")),
                "a newer release is announced: " + fake.output);
        String[] log = new String[1];
        SwingUtilities.invokeAndWait(() -> log[0] = ext.tab.logText());
        check(log[0].contains("What changed:\n  ## Secrets\n  - Fewer false positives.\n"), "with what it changed:\n" + log[0]);
        check(fake.releaseChecks.size() == 1 && fake.requested.isEmpty(), "one request, to GitHub's API: " + fake.releaseChecks);
        check(ext.tab.updateButton.isVisible() && opened.isEmpty(), "the download page is offered, not opened");
        SwingUtilities.invokeAndWait(ext.tab.updateButton::doClick);
        for (int i = 0; i < 50 && opened.isEmpty(); i++) {
            Thread.sleep(100);
        }
        check(opened.equals(List.of(DeepJsExtension.RELEASES_PAGE)), "the button opens the release page: " + opened);
        check(fake.releaseChecks.size() == 1 && fake.requested.isEmpty(), "and downloads nothing itself");

        // 1. the browser loads the runtime and the main bundle through the proxy
        String runtime = "(()=>{var r={};r.p=\"/\";r.u=e=>\"static/js/\"+({3:\"admin\"}[e]||e)+\".\"+"
                + "{3:\"9f1c2a\",7:\"02ab3c\"}[e]+\".chunk.js\";})();";
        String main = "function login(e,t){return fetch(\"/api/v1/auth/login\",{method:\"POST\","
                + "body:JSON.stringify({email:e,password:t})})}var k=\"AKIA\"+\"\";const c={clientSecret:\"Zx9Qm2Lk8Pz4Rt6Vw1Yb5Nc7Hf0Jg3Ua\"};"
                + "\n//# sourceMappingURL=main.js.map\n";
        ext.handleHttpResponseReceived(fake.proxied(base + "/static/js/runtime.js", runtime, burp.api.montoya.http.message.MimeType.SCRIPT));
        ext.handleHttpResponseReceived(fake.proxied(base + "/static/js/main.js", main, burp.api.montoya.http.message.MimeType.SCRIPT));
        ext.handleHttpResponseReceived(fake.proxied(base + "/static/js/main.js", main, burp.api.montoya.http.message.MimeType.SCRIPT));   // again
        ext.handleHttpResponseReceived(fake.proxied(base + "/logo.png", "\u0089PNG", burp.api.montoya.http.message.MimeType.IMAGE_PNG));
        settle(ext, fake, 3);

        String urls = column(ext.tab.endpoints, DeepJsTab.E_URL);
        String methods = column(ext.tab.endpoints, DeepJsTab.E_METHOD);
        check(urls.contains(base + "/api/v1/auth/login") && methods.contains("POST"), "proxied bundle → API call in the tab");

        // 2. the extension fetched, through Burp, what the code named but the browser never loaded
        check(fake.requested.contains(base + "/static/js/admin.9f1c2a.chunk.js"), "hidden chunk requested through Burp: " + fake.requested);
        check(fake.requested.contains(base + "/static/js/main.js.map"), "source map requested through Burp");
        check(urls.contains(base + "/api/v1/admin/users/{param}") && methods.contains("DELETE"),
                "endpoint that exists only in the hidden chunk appears:\n" + urls);
        check(urls.contains("/api/v1/audit/{id}"), "endpoint that exists only in the recovered source appears:\n" + urls);
        String scriptStates = column(ext.tab.scripts, 2);
        check(scriptStates.contains("fetched (") && scriptStates.contains("HTTP 404"),
                "each hidden script shows what happened to it:\n" + scriptStates);
        check(fake.siteMapAdds.size() >= 2, "fetched files are added to Burp's site map");
        // two chunks the runtime names + one map per script seen (3) — and nothing that is not a script or a map
        check(fake.requested.stream().allMatch(u -> u.startsWith(base + "/static/js/") && (u.endsWith(".js") || u.endsWith(".js.map")))
                && fake.requested.size() == 5 && new java.util.HashSet<>(fake.requested).size() == 5,
                "only scripts and maps were requested, each once: " + fake.requested);

        // 3. secrets: listed, masked, and raised as an issue
        String secretValues = column(ext.tab.secrets, 2);
        check(column(ext.tab.secrets, 1).contains("HARDCODED_SECRET"), "secret listed");
        String found = "Zx9Qm2Lk8Pz4Rt6Vw1Yb5Nc7Hf0Jg3Ua";
        check(secretValues.contains(found), "the tester sees the value that was found: " + secretValues);
        check(DeepJsTab.mask(found).equals("Zx9Qm2Lk…g3Ua") && DeepJsTab.mask("hunter2").equals("hu…")
                && DeepJsTab.mask("0123456789abcdef").equals("0123…ef"), "\"Mask values\" hides the middle of a value");
        check(fake.siteMapAdds.stream().anyMatch(o -> String.valueOf(o).contains("AuditIssue")), "an issue is raised for the secret");

        // 4. Repeater skeleton
        int loginRow = -1, adminRow = -1;
        for (int r = 0; r < ext.tab.endpoints.getRowCount(); r++) {
            Object url = ext.tab.endpoints.getValueAt(r, DeepJsTab.E_URL);
            loginRow = url.equals(base + "/api/v1/auth/login") ? r : loginRow;
            adminRow = url.equals(base + "/api/v1/admin/users/{param}") ? r : adminRow;
        }
        final int login = loginRow, admin = adminRow;
        ext.sendToRepeater(java.util.Collections.singletonList(ext.tab.endpoints.row(login)));
        check(fake.repeater.size() == 1 && fake.repeater.get(0).startsWith("POST " + base + "/api/v1/auth/login")
                && fake.repeater.get(0).contains("\"email\": \"\""), "Repeater receives a POST with the body fields: " + fake.repeater);
        check(!fake.repeater.get(0).contains("Cookie"), "with no session seen for the host, none is invented");

        // 4a. the code a call was read from
        String[] code = new String[2];
        SwingUtilities.invokeAndWait(() -> {
            int viewRow = ext.tab.endpointTable.convertRowIndexToView(login);
            ext.tab.endpointTable.setRowSelectionInterval(viewRow, viewRow);
            code[0] = ext.tab.endpointCode.text();
            code[1] = ext.tab.endpointCode.highlighted();
        });
        check(code[1].equals("fetch") && code[0].contains("function login(e,t){return fetch(\"/api/v1/auth/login\",{method:\"POST\""),
                "a call is shown in its code: " + code[0]);

        // 4b. which calls Burp has made: the browser logs in, someone tries the admin call from Repeater
        check(ext.tab.endpoints.getValueAt(login, DeepJsTab.E_SEEN).equals("no") && ext.tab.endpoints.getValueAt(admin, DeepJsTab.E_SEEN).equals("no"),
                "nothing has been requested yet");
        ext.handleHttpRequestToBeSent(fake.sent("GET", base + "/api/v1/auth/login", true));
        ext.handleHttpRequestToBeSent(fake.sent("POST", base + "/api/v1/auth/login?next=%2F", true,
                "Cookie", "sid=abc123", "Authorization", "Bearer tok-1", "Accept", "*/*", "X-CSRF-Token", "c5"));
        ext.handleHttpRequestToBeSent(fake.sent("DELETE", "https://app.acme.io:443/api/v1/admin/users/17", false, "Cookie", "sid=from-repeater"));
        SwingUtilities.invokeAndWait(() -> { });
        check(ext.tab.endpoints.getValueAt(login, DeepJsTab.E_SEEN).equals("yes"), "a request with the call's method and path marks it requested");
        check(ext.tab.endpoints.getValueAt(admin, DeepJsTab.E_SEEN).equals("yes"), "/users/17 is a request for /users/{param}");
        check(column(ext.tab.endpoints, DeepJsTab.E_SEEN).contains("no"), "what nobody has requested stays marked");

        // 4c. the session the browser used is offered to Repeater, for that host only and only if wanted
        ext.sendToRepeater(java.util.Collections.singletonList(ext.tab.endpoints.row(login)));
        String borrowed = fake.repeater.get(1);
        check(borrowed.contains("Cookie: sid=abc123") && borrowed.contains("Authorization: Bearer tok-1") && borrowed.contains("X-CSRF-Token: c5")
                && !borrowed.contains("Accept") && !borrowed.contains("from-repeater"), "Repeater gets the session the browser used: " + borrowed);
        String[] elsewhere = ext.tab.endpoints.row(login).clone();
        elsewhere[DeepJsTab.E_URL] = "https://api.other.io/api/v1/auth/login";
        ext.sendToRepeater(java.util.Collections.singletonList(elsewhere));
        check(!fake.repeater.get(2).contains("sid="), "a session is never sent to another host: " + fake.repeater.get(2));
        SwingUtilities.invokeAndWait(ext.tab.withSession::doClick);
        ext.sendToRepeater(java.util.Collections.singletonList(ext.tab.endpoints.row(login)));
        check(!fake.repeater.get(3).contains("sid="), "nor at all once the option is off");
        SwingUtilities.invokeAndWait(ext.tab.withSession::doClick);
        fake.repeater.subList(1, fake.repeater.size()).clear();

        // 4d. "Not a secret" is remembered — as a fingerprint, not as the value
        SwingUtilities.invokeAndWait(() -> {
            for (int r = 0; r < ext.tab.secretTable.getRowCount(); r++) {
                if (ext.tab.secretTable.getValueAt(r, 1).equals("HARDCODED_SECRET")) {
                    ext.tab.secretTable.setRowSelectionInterval(r, r);
                }
            }
            ((javax.swing.JMenuItem) ext.tab.secretTable.getComponentPopupMenu().getComponent(1)).doClick();
        });
        String remembered = String.valueOf(fake.savedStrings.get("deepjs.dismissed"));
        check(remembered.startsWith("HARDCODED_SECRET ") && !remembered.contains(found),
                "the choice is saved without the value: " + remembered);

        // 5. proxy history + context menu + clear
        fake.history.add(fake.pair(base + "/static/js/extra.js", "fetch(\"/api/v1/from-history\")", burp.api.montoya.http.message.MimeType.SCRIPT));
        ext.analyseProxyHistory();
        settle(ext, fake, 3);
        Thread.sleep(500);
        settle(ext, fake, 3);
        check(column(ext.tab.endpoints, DeepJsTab.E_URL).contains("/api/v1/from-history"), "proxy history is analysed on request");

        List<burp.api.montoya.http.message.HttpRequestResponse> selection =
                List.of(fake.pair(base + "/static/js/menu.js", "fetch(\"/api/v1/from-menu\")", burp.api.montoya.http.message.MimeType.SCRIPT));
        burp.api.montoya.ui.contextmenu.ContextMenuEvent event = MockBurp.mock(
                burp.api.montoya.ui.contextmenu.ContextMenuEvent.class, java.util.Map.of("selectedRequestResponses", a -> selection));
        List<java.awt.Component> items = ext.provideMenuItems(event);
        check(items.size() == 1, "context menu offers \"Analyse with DeepJS\"");
        ((javax.swing.JMenuItem) items.get(0)).doClick();
        Thread.sleep(500);
        settle(ext, fake, 3);
        check(column(ext.tab.endpoints, DeepJsTab.E_URL).contains("/api/v1/from-menu"), "context-menu analysis works");

        ext.clearAll();
        SwingUtilities.invokeAndWait(() -> { });
        Thread.sleep(200);
        SwingUtilities.invokeAndWait(() -> { });
        check(ext.tab.endpoints.getRowCount() == 0 && ext.tab.secrets.getRowCount() == 0, "Clear empties everything");

        // 6. "In-scope only" + a host no script came from: never requested
        int before = fake.requested.size();
        ext.handleHttpResponseReceived(fake.proxied(base + "/static/js/loader.js",
                "const s=document.createElement(\"script\");s.src=\"https://cdn.unrelated-host.io/lib/other.js\";",
                burp.api.montoya.http.message.MimeType.SCRIPT));
        settle(ext, fake, before);
        check(fake.requested.stream().noneMatch(u -> u.contains("unrelated-host")), "a host that never served a script is not contacted");

        // 7. a base URL revealed by a later chunk replaces the placeholder row instead of adding a second one
        ext.handleHttpResponseReceived(fake.proxied(base + "/static/js/svc.js",
                "class S{http=inject(H);root=env.gatewayRoot;host=this.root+`/rest/wallet`;"
                        + "get(){return this.http.get(this.host+`/balance`)}}",
                burp.api.montoya.http.message.MimeType.SCRIPT));
        settle(ext, fake, fake.requested.size());
        check(column(ext.tab.endpoints, DeepJsTab.E_URL).contains(base + "/rest/wallet/balance"),
                "class service with an unknown base is listed against the site:\n" + column(ext.tab.endpoints, DeepJsTab.E_URL));
        ext.handleHttpResponseReceived(fake.proxied(base + "/static/js/env.js",
                "const env={production:!0,gatewayRoot:\"/gw/v2\"};",
                burp.api.montoya.http.message.MimeType.SCRIPT));
        settle(ext, fake, fake.requested.size());
        String resolved = column(ext.tab.endpoints, DeepJsTab.E_URL);
        check(resolved.contains(base + "/gw/v2/rest/wallet/balance") && !resolved.contains(base + "/rest/wallet/balance"),
                "the row is replaced once another chunk reveals the base:\n" + resolved);

        fake.unloadHandler.extensionUnloaded();
        check(!ext.analyzer.submit("script", base + "/late.js", new byte[]{'1'}), "unloading the extension stops the analysis thread");

        // a copy installed from the BApp Store is updated by Burp: it has nothing to ask GitHub
        MockBurp store = new MockBurp();
        store.bapp = true;
        store.site.put(DeepJsExtension.RELEASES_API, "{\"tag_name\":\"v99.1.0\"}");
        DeepJsExtension fromStore = new DeepJsExtension();
        fromStore.initialize(store.api());
        Thread.sleep(500);
        SwingUtilities.invokeAndWait(() -> { });
        check(store.releaseChecks.isEmpty() && !fromStore.tab.updateCheck.isEnabled() && !fromStore.tab.updateButton.isVisible(),
                "installed from the BApp Store: no update check");
        if (java.awt.GraphicsEnvironment.isHeadless()) {        // with a desktop this would open a real browser
            fromStore.openReleasePage();
            String[] said = {""};
            for (int i = 0; i < 50 && !said[0].contains("The page is " + DeepJsExtension.RELEASES_PAGE); i++) {
                Thread.sleep(100);
                SwingUtilities.invokeAndWait(() -> said[0] = fromStore.tab.logText());
            }
            check(said[0].contains("The page is " + DeepJsExtension.RELEASES_PAGE), "without a desktop the address goes to the log: " + said[0]);
        }
        store.unloadHandler.extensionUnloaded();

        // another Burp session, the same preferences: what was ruled out is neither listed nor raised again
        MockBurp later = new MockBurp();
        later.savedStrings.putAll(fake.savedStrings);
        later.savedBooleans.put("deepjs.Show string-only paths", true);
        DeepJsExtension again = new DeepJsExtension();
        again.browser = opened::add;
        again.initialize(later.api());
        SwingUtilities.invokeAndWait(() -> {
            again.tab.fetchHidden.setSelected(false);
            again.tab.fetchMaps.setSelected(false);
        });
        again.handleHttpResponseReceived(later.proxied(base + "/static/js/main.js", main + "var help=\"/api/v1/only-a-string\";",
                burp.api.montoya.http.message.MimeType.SCRIPT));
        settle(again, later, 0);
        int[] rows = new int[2];
        SwingUtilities.invokeAndWait(() -> {
            rows[0] = again.tab.secretTable.getRowCount();
            rows[1] = again.tab.endpointTable.getRowCount();
        });
        check(again.tab.showStrings.isSelected() && column(again.tab.endpoints, DeepJsTab.E_KIND).contains("string")
                && rows[1] == again.tab.endpoints.getRowCount(), "a saved option is in force from the start: " + rows[1] + " call(s) listed");
        check(column(again.tab.secrets, 1).contains("HARDCODED_SECRET") && rows[0] == again.tab.secrets.getRowCount() - 1
                        && later.siteMapAdds.stream().noneMatch(o -> String.valueOf(o).contains("AuditIssue")),
                "a value ruled out once stays out: " + rows[0] + " of " + again.tab.secrets.getRowCount() + " listed");
        later.unloadHandler.extensionUnloaded();
        System.out.println("extension against mocked Burp: ok (" + fake.requested.size() + " request(s) made through Burp)");
    }
}
