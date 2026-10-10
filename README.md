# DeepJS for Burp Suite

A Burp Suite extension that reads the JavaScript passing through Burp and
reports the API a front end talks to — each request with its **method, path,
query-parameter names, body field names and header names** — along with the
secrets, hosts and hidden scripts it finds on the way.

It does not search the text for quoted paths. It tokenizes the code and
evaluates the expressions that build URLs, so a call like

```js
class ReviewService {
  host = this.hostServer + "/rest/products";
  get(id) { return this.http.get(`${this.host}/${id}/reviews`); }
}
```

is reported as `GET /rest/products/{id}/reviews`, and
`"/articles" + (feed ? "/feed" : "")` as two endpoints.

One jar, no dependencies, Burp Suite Community and Professional.

## Install

Download `deepjs-burp.jar` from the
[latest release](https://github.com/xtawb/deepjs-burp/releases/latest), then in
Burp: **Extensions → Add → Extension type: Java →** select the file.

Browse the target through Burp; findings appear in the **DeepJS** tab as
responses arrive.

## The tab

| | |
|---|---|
| **API calls** | Method, URL, query names, body fields, headers, where it was found. Filter, select rows, *Send to Repeater*: a request skeleton is built from the finding (`{id}` becomes `:id`, body fields become a JSON object). Paths that only appear as strings are listed too and can be hidden. |
| **Secrets** | 35 credential formats, and credible values under secret-bearing names. Values are shown as found — you need them to check a finding — and *Mask values* hides the middle of each one for screenshots. Keys that are public by design (Stripe publishable keys, Firebase web configuration, Supabase anon keys, Algolia search keys) and tokens the server writes into a page for the current visitor are labelled as such, not reported as leaks; the rest are also raised as issues. |
| **Hidden scripts** | Chunks and source maps the code names but no page has loaded. The chunk-name function of webpack, Next.js and Vite builds is evaluated, so the lazy parts of an application — the admin panel included — are listed without visiting them. |
| **Hosts** | Every host the code mentions: in scope, cloud storage, internal, third party; non-production names flagged. |
| **Routes · GraphQL · packages** | Client-side routes, GraphQL operation names, API base URLs, npm package names recovered from source maps. |

*Analyse proxy history* covers traffic captured before the extension was
loaded; *Analyse with DeepJS* is in the context menu of any message.

## What it requests, and when

Analysis is passive: the engine works on responses Burp already has and makes
no request of its own.

With *Fetch hidden scripts* / *Fetch source maps* on (the default), the
extension requests the scripts and maps the analysed code refers to — through
Burp, so upstream proxies and session handling apply and the responses land in
the site map. It asks only hosts that have already served a script to the
browser, never more than 400 requests until *Clear* is pressed, and with
*In-scope only* nothing outside the target scope. Turn the two options off for
a fully passive extension.

When Burp starts, one request goes to GitHub's API, through Burp, to see
whether a newer release exists. If one does, the status line says so, the
*Log / settings* tab lists what it changed, and a button there opens its
download page in your browser. *Check for updates when Burp starts* turns the
check off; without network access it is silent.

That is deliberately all: the extension never downloads or installs a jar. An
extension cannot replace the file Burp has loaded it from, and code that
fetched and ran its own replacement would be code nobody had reviewed. A copy
installed from the BApp Store does not check at all — Burp updates it.

## How it is verified

- **Against a mocked Burp API.** `./gradlew harness` loads the real extension
  class against dynamic proxies of the Montoya interfaces and pushes traffic
  through it: the HTTP handler, the fetching of hidden chunks and source maps,
  Repeater, proxy history, the context menu, unloading.
- **Against input written to break a parser.** Responses come from sites the
  user does not trust. The harness feeds the extension megabytes of unclosed
  tags, 200,000 nested brackets, a 120,000-term token, thousands of nested
  template literals, random bytes — and requires that the engine is still
  answering afterwards. HTML is read by a single-pass tag scanner, nesting is
  followed to a fixed depth, and every regular expression that meets untrusted
  text runs on a bounded length.
- **Against a second implementation.** The engine is a port of the Python
  analysis in [xtawb/deepjs](https://github.com/xtawb/deepjs), a command-line
  tool with the same rules. `tools/parity.py` feeds identical input to both and
  compares every record they produce. They agree on that project's accuracy
  corpus, its end-to-end fixture, a generated set of credential / HTML /
  source-map shapes, seven real applications and nineteen well-known libraries
  (26 MB of JavaScript, 2,247 records). CI runs the built-in sets on every push
  and once a week.

- **In Burp.** 0.4.0 was loaded and used in Burp Suite Community 2026.9.1. That
  first real session reported four secrets and all four were false positives —
  the token types of a syntax highlighter's grammar, and the page tokens of a
  third-party embed. Both are fixed and are now tests; later versions have been
  through the harness, which CI runs, but CI cannot load the jar into Burp.

## Compared with the JavaScript extensions in the BApp Store

JS Miner and JS Link Finder match regular expressions against the response
text. That works where an application writes `client.get("/literal")`, and
finds nothing when the request is made through `fetch`, a request-config
object, Babel's `"".concat()` output or a URL built from class properties.

Measured on seven open-source applications whose real routes are known, same
script files for each tool, counting routes identified with method and path:
JS Miner 1.16 identified 43 of 254; DeepJS identified 156 on its first run
against each application and 194 after the gaps those runs exposed were fixed.
JS Miner was ahead on two of the seven first runs. The per-application table,
the method and its limits — JS Miner's patterns were re-run outside Burp, the
sample is small — are in the
[deepjs README](https://github.com/xtawb/deepjs#compared-with-js-miner).

## Build

JDK 17 or newer.

```bash
./gradlew jar          # build/libs/deepjs-burp.jar
./gradlew harness      # the extension against a mocked Burp API
python tools/parity.py --classpath build/libs/deepjs-burp.jar --engine ../deepjs    # needs a checkout of xtawb/deepjs
```

`python tools/build.py --test` does the first two with nothing but a JDK.

| Package | Role |
|---|---|
| `deepjs.burp` | the extension: Montoya API glue (`DeepJsExtension`), the Swing tab (`DeepJsTab`), the analysis thread (`Analyzer`) |
| `deepjs.engine` | the analysis: tokenizer, expression evaluation, endpoints, secrets, hosts, chunk discovery, source maps |

The engine has no knowledge of Burp and can be driven on its own:
`java -cp deepjs-burp.jar deepjs.engine.Serve` speaks a line protocol on
stdin / stdout.

## Limits

- **Static only.** URLs computed at run time from server responses, or built
  by code the evaluator does not model, are missed or left with a
  `{placeholder}`. For an endpoint whose base URL is not known, the full URL
  shown is a best guess (the site the script came from).
- **It analyses what Burp sees.** It does not crawl.
- **Obfuscated bundles** (string-array rotation, control-flow flattening)
  defeat this kind of analysis.
- Secrets are found by format and by name. A finding is a lead to check, not a
  verified credential: nothing found is ever sent anywhere or tried. Expect
  some false positives, and report them — each one so far has become a test.

## License

MIT
