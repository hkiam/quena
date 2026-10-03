# Diagnostics in CI

Functional tests rarely notice network regressions: the page still works, but it now makes
50 requests instead of 5, signs in twice or retries a failing call in a loop. `quena-cli`
runs Quena's [Diagnostics](diagnostics.md) on the HAR files your end-to-end tests record and
turns the report into a **quality gate**: the build fails when the traffic got worse.

It is the same analyzer and the same redaction as in the app, without a window: no proxy, no
certificate, no settings of the desktop app are used or changed.

## Quick start

=== "GitHub Actions"

    ```yaml
    - run: npx playwright test            # records captures/*.har
    - uses: hkiam/quena/diagnose@v0.1.5
      with:
        files: captures/*.har
        fail-on: critical
    ```

    The action downloads `quena-cli` of the release it is used from (`@v0.1.5` → quena-cli
    0.1.5), writes the report to the job summary, marks the findings as annotations and
    leaves `report.json`, `junit.xml` and `report.md` for later steps (outputs `report`,
    `junit`, `markdown`, `passed`). The outputs are set when the gate fails, too.

    | Input | Effect |
    |---|---|
    | `files` | captures, separated by spaces or new lines; glob patterns (`captures/**/*.har`) are expanded. A pattern that matches nothing is a warning, nothing at all an error |
    | `config` | settings file (see below) |
    | `profile`, `lang`, `fail-on` | override the settings file; empty (the default) leaves the file's value, else `full`, `en`, `critical` |
    | `baseline` | baseline report; leave it empty when there is none yet |
    | `budgets`, `ignore` | added to those of the settings file (budgets separated by spaces, ignore entries by new lines) |
    | `args` | further `quena-cli diagnose` arguments (split at spaces, not glob-expanded) |
    | `version` | `0.1.5`, or `latest`: the newest published release, prereleases included. Default: the release of the action ref; for other refs (`@main`) `latest` |
    | `bin` | an existing `quena-cli` instead of a download |
    | `summary` | `"false"`: no job summary |

    The action can only download from a **published** release: drafts are invisible to it.
    quena-cli is part of the releases from v0.1.3 on.

=== "Docker (GitLab CI, Jenkins …)"

    ```bash
    docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" ghcr.io/hkiam/quena-cli \
      diagnose captures/*.har --fail-on critical -o junit=quena-junit.xml
    ```

    `--user` makes the reports belong to you; any user id works. Compiled plugins are cached
    inside the container, so a new container compiles them again (a few seconds). To keep
    them, mount a volume: `-v quena-cache:/tmp/quena-cache`.

    GitLab CI:

    ```yaml
    network-gate:
      image: { name: ghcr.io/hkiam/quena-cli:0.1.5, entrypoint: [""] }
      script:
        - quena-cli diagnose captures/*.har --baseline baseline.json -o junit=quena-junit.xml -o json=report.json
      artifacts:
        when: always
        paths: [report.json]
        reports: { junit: quena-junit.xml }
    ```

    `latest` is the newest release that is not a prerelease; pin a version for reproducible
    builds.

=== "Program"

    Download `quena-cli-<version>-<platform>` from the
    [releases](https://github.com/hkiam/quena/releases) (Windows, macOS, Linux x64/arm64),
    unpack it and keep the `plugins` folder next to the program:

    ```bash
    quena-cli diagnose captures/*.har --fail-on critical
    ```

## Recording the captures

Any HAR file works: Playwright, Cypress, browser developer tools, Quena itself (*File →
Export Sessions → HTTP Archive (HAR)…*), and SAZ archives.

* **Playwright:** `recordHar` in the context options, one file per test — see the
  [example](https://github.com/hkiam/quena/tree/main/examples/ci-playwright).
  `content: "omit"` is enough: the diagnostics need timings, sizes and headers. With
  `"embed"` the character encoding of textual bodies is checked as well.
* **Cypress:** `@neuralegion/cypress-har-generator` (Chromium-based browsers), one file per
  test — see the [example](https://github.com/hkiam/quena/tree/main/examples/ci-cypress).

All files of one call are analysed together, as one capture. Passing the same file twice is
an error.

## The quality gate

| Option | Effect |
|---|---|
| `--fail-on critical` | fail on critical findings (the default); `warning`, `info`, or `none` to never fail on findings |
| `--baseline main.json` | compare with an earlier report: only **new** findings and findings that got **more severe** count |
| `--fail-on-existing` | with a baseline, known findings count too |
| `--no-fail-on-existing` | only new and worse findings, even if the settings file says `"failOnExisting": true` |
| `--budget requests=+10%` | a key figure may grow by at most 10 % against the baseline |
| `--budget errors=0` | an absolute limit, with or without a baseline |
| `--ignore OAUTH-FLOW` | never fail on a rule — or on one finding, by its key |
| `--config quena-gate.json` | the settings above in a file under version control |

### Budgets

The key figures for budgets are those of the report:

| Key | Figure |
|---|---|
| `requests` | HTTP requests |
| `bytes` | transferred bytes |
| `errors` | errors and failures |
| `span` | duration of the capture (milliseconds) |
| `hosts` | hosts |
| `operations` | user operations |
| `rate` | requests per second — missing when the capture has no duration (span 0) |
| `open` | requests still open at the end of the capture — only when there are any |
| `notAnalysed` | sessions beyond the analyzer's limit — only when there are any |

Limits are plain numbers in the unit of the figure (bytes, milliseconds), e.g.
`bytes=5000000`. A budget for a key the report does not contain (a typo, or one of the
figures above that is missing in this report) is an error (exit code 2); the message lists
the keys of the report.

**Relative budgets** (`requests=+10%`) need a baseline. Without one they are skipped with a
note in the report — so the very first run, before there is a baseline, passes on them and
provides the baseline for the next. Absolute budgets always apply.

### The settings file

A settings file holds the gate and the analysis settings:

```json
{
  "profile": "performance",
  "lang": "en",
  "options": { "slowMs": 1500 },
  "hosts": ["*.example.com"],
  "failOn": "critical",
  "failOnExisting": false,
  "budgets": ["requests=+10%", "bytes=+20%", "errors=0"],
  "ignore": ["OAUTH-FLOW"]
}
```

Both `diagnose` and `compare` accept it; `compare` uses only the gate part (`failOn`,
`failOnExisting`, `budgets`, `ignore`) and ignores `profile`, `lang`, `options`, `hosts` and
`processes`.

For single values — profile, language, `failOn`, `failOnExisting`, hosts, processes — the
command line wins over the file. Budgets and ignore entries of the file and of the command
line are combined.

### Baselines

The JSON report of a run is the baseline of the next one. A typical setup keeps the report
of the last successful run on `main` as a build artifact and compares every pull request
with it (the Playwright example contains the workflow). To accept a change on purpose, merge
it: its report becomes the new baseline.

On the first run there is no baseline yet: leave `--baseline` out (in the GitHub Action:
leave the `baseline` input empty, e.g. with `hashFiles`, as in the example). Then all
findings count and relative budgets are skipped.

Findings are matched by their **key** (rule and subject, e.g. the endpoint), so they stay
the same across captures as long as the endpoint does. `quena-cli compare before.json
after.json` compares two saved reports without a new analysis.

## Outputs

| Format | Use |
|---|---|
| `md` | readable report with the verdict and the comparison — stdout by default, or the job summary |
| `json` | the complete report plus `gate` and `comparison`; the next baseline |
| `junit` | JUnit XML: one test case per finding, failures for what breaks the gate, and a suite `budgets` with one test case per budget; for the test report of GitLab, Jenkins, Azure DevOps |
| `github` | GitHub Actions annotations |

`--format` chooses what goes to stdout, `-o FORMAT=PATH` writes further files (repeatable).

stderr shows the progress (importing, analysing), then the verdict: the counts, the
comparison with the baseline, the reasons of the gate and the findings that break it (the
first ten). `--quiet` suppresses all of it; errors are still printed.

## Other options

| Option | Effect |
|---|---|
| `--profile` | `full`, `performance`, `troubleshooting`, `auth`, `resilience`, `modernization` (`quena-cli profiles` lists them) |
| `--lang de` | report texts in German |
| `--set slowMs=1500` | an analyzer option (thresholds, network profiles); not `lang` or `profile` — use `--lang` and `--profile` |
| `--host api.example.com`, `--process chrome` | analyse only part of the traffic |
| `--plugins DIR` | use the plugins of this folder only (instead of the `plugins` folder next to the program and `QUENA_PLUGIN_DIR`) |
| `--timeout 600` | give up when the whole run (import and analysis) takes longer than this many seconds |

### Plugin cache

Compiled plugins are cached, so only the first run of a version takes a few seconds longer:

| System | Cache |
|---|---|
| Linux | `~/.cache/quena/plugin-cache` (`$XDG_CACHE_HOME/quena/plugin-cache`) |
| macOS | `~/Library/Caches/quena/plugin-cache` |
| Windows | `%LOCALAPPDATA%\quena\plugin-cache` |
| `QUENA_CACHE_DIR=/x` | `/x/plugin-cache` |
| Docker image | `/tmp/quena-cache/plugin-cache` inside the container; mount a volume at `/tmp/quena-cache` to keep it |

To keep it between CI jobs, cache that folder with your CI's cache feature. Several
processes can share it.

!!! warning "Only trusted users may write to the cache"
    The cache holds compiled machine code that `quena-cli` loads as it is. Share a cache
    folder or volume only between jobs you trust, and never make it writable for everyone.

## Sanitize and mocks

Two more commands take captures as input:

```sh
# A copy for a vendor or support team (see Archives → Sanitized export).
quena-cli sanitize captures/*.har -o shared.har --preset gdpr --log redaction.json

# Mocks for frontend tests without the backend (see Mocks from a capture).
quena-cli mock captures/*.har --wiremock wiremock/ --sequence
quena-cli mock captures/*.har --package shop.quena-mocks --host api.example.com
```

| `sanitize` option | Effect |
|---|---|
| `-o PATH` | the sanitized archive, `.saz` or `.har` |
| `--preset` | `support` (default: credentials, tokens, e-mail addresses, IBANs and card numbers), `gdpr` (also phone numbers, IP addresses, personal fields, national ids, process names; bodies cut), or `credentials` (only credentials and tokens) |
| `--config FILE` | sanitize options as JSON — the options object, or the app's saved `{"options": …, "format": …}` — instead of a preset |
| `--log PATH` | also write the redaction log (`.json`, or text) |
| `-q`, `--quiet` | no progress messages on stderr (errors only) |
| `--timeout SECONDS` | give up when the whole run (imports, sanitizing, writing) takes longer (default 600); exit code 3, and a half-written archive is removed |

| `mock` option | Effect |
|---|---|
| `--wiremock PATH` | WireMock mappings and `__files`: a folder (its old `mappings` and `__files` are replaced), or a `.zip`. An existing file that is not a `.zip` is rejected |
| `--package PATH` | a Quena mock package; the name must end in `.quena-mocks` |
| `--host HOST` | only these hosts (repeatable; subdomains included) |
| `--sequence` | several recordings of a request answer in recorded order |
| `--exact-query` | match the query string exactly |
| `--include-static`, `--latency` | include static resources; answer after the recorded latency |
| `--sanitize PRESET` | `credentials` (default: credentials and tokens), `support`, `gdpr` or `none` (as recorded) |
| `--config FILE` | mock options as JSON (`hosts`, `includeStatic`, `query`, `ignoreParams`, `repeats`, `matchBody`, `latency`, `includePreflight`, `includeErrors`, `sanitize`, `keepSetCookie`; `sanitize` is a preset name, `null` or full sanitize options); flags win |
| `-q`, `--quiet` | no progress messages on stderr (errors only) |
| `--timeout SECONDS` | give up when the whole run (imports, building and writing the mocks) takes longer (default 600); exit code 3 |

Neither needs plugins. `.http` request collections run headless as well (see
[Request collections](change-replay.md#request-collections-http-files)), e.g. as smoke tests
after a deployment:

```sh
quena-cli http run smoke.http --env staging --save smoke.har   # exit code 1 on a failure or a status >= 400
quena-cli http from-har captures/login.har -o login.http       # captured requests as a collection
```

| `http run` option | Effect |
|---|---|
| `--env NAME` | environment from `http-client.env.json` / `http-client.private.env.json` next to the file |
| `--name NAME` | only these requests (`# @name`, `### title` or `line:N`; repeatable) |
| `--save PATH` | also save the requests with their responses (`.har`, `.saz`) |
| `--timeout SECONDS` | wait at most this long for each response (default 30) |

Config files of `sanitize` and `mock` are read strictly: an unknown key (a typo such as
`"repeat"` or `"emials"`) is an error that names it, instead of being ignored. No output may
overwrite a capture or another output — `-o`, `--log`, `--package` and `--wiremock` are
compared by their real path (also for files that do not exist yet), and a WireMock folder
may not hold a capture in its `mappings` or `__files`. Exit code 2 for these, for
unreadable captures, a wrong output type or an invalid pattern; 3 for a timeout and other
failures.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | gate passed |
| 1 | gate failed |
| 2 | usage or input error: unknown option, unreadable capture, baseline or settings file, the same capture twice, a budget for a key the report does not contain, `--set lang`/`--set profile`, the plugins folder or the diagnostics plugin not found |
| 3 | analysis error: a plugin failed to load, the analysis failed or timed out |

## Privacy

Tokens, cookie values and secret URL parameters are removed before the analyzer sees the
traffic ([details](diagnostics.md#privacy)). Reports still contain URLs and host names —
mind that when you publish them, e.g. as artifacts of a public repository.
