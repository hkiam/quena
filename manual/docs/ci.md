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
    - uses: hkiam/quena/diagnose@v0.2.0
      with:
        files: captures/*.har
        fail-on: critical
    ```

    The action downloads `quena-cli` of the same release, writes the report to the job
    summary, marks the findings as annotations and leaves `report.json`, `junit.xml` and
    `report.md` for later steps (outputs `report`, `junit`, `markdown`, `passed`).

=== "Docker (GitLab CI, Jenkins …)"

    ```bash
    docker run --rm -v "$PWD:/work" ghcr.io/hkiam/quena-cli \
      diagnose captures/*.har --fail-on critical -o junit=quena-junit.xml
    ```

    GitLab CI:

    ```yaml
    network-gate:
      image: { name: ghcr.io/hkiam/quena-cli:0.2.0, entrypoint: [""] }
      script:
        - quena-cli diagnose captures/*.har --baseline baseline.json -o junit=quena-junit.xml -o json=report.json
      artifacts:
        when: always
        paths: [report.json]
        reports: { junit: quena-junit.xml }
    ```

=== "Program"

    Download `quena-cli-<version>-<platform>` from the
    [releases](https://github.com/hkiam/quena/releases) (Windows, macOS, Linux x64/arm64),
    unpack it and keep the `plugins` folder next to the program:

    ```bash
    quena-cli diagnose captures/*.har --fail-on critical
    ```

## Recording the captures

Any HAR file works: Playwright, Cypress, browser developer tools, Quena itself (*File → Save
as HAR*), and SAZ archives.

* **Playwright:** `recordHar` in the browser context, one file per test — see the
  [example](https://github.com/hkiam/quena/tree/main/examples/ci-playwright).
  `content: "omit"` is enough: the diagnostics need timings, sizes and headers. With
  `"embed"` the character encoding of textual bodies is checked as well.
* **Cypress:** `@neuralegion/cypress-har-generator` (Chromium-based browsers) — see the
  [example](https://github.com/hkiam/quena/tree/main/examples/ci-cypress).

All files of one call are analysed together, as one capture.

## The quality gate

| Option | Effect |
|---|---|
| `--fail-on critical` | fail on critical findings (the default); `warning`, `info`, or `none` to never fail on findings |
| `--baseline main.json` | compare with an earlier report: only **new** findings and findings that got **more severe** count |
| `--fail-on-existing` | with a baseline, known findings count too |
| `--budget requests=+10%` | a key figure may grow by at most 10 % against the baseline |
| `--budget errors=0` | an absolute limit, with or without a baseline |
| `--ignore OAUTH-FLOW` | never fail on a rule — or on one finding, by its key |
| `--config quena-gate.json` | the settings above in a file under version control |

The key figures for budgets are those of the report: `requests`, `bytes`, `errors`, `span`
(duration of the capture), `hosts`, `operations`, `rate`. Limits are plain numbers in the
unit of the figure (bytes, milliseconds), e.g. `bytes=5000000`.

A settings file holds the same and the analysis settings:

```json
{
  "profile": "performance",
  "lang": "en",
  "options": { "slowMs": 1500 },
  "hosts": ["*.example.com"],
  "failOn": "critical",
  "budgets": ["requests=+10%", "bytes=+20%", "errors=0"],
  "ignore": ["OAUTH-FLOW"]
}
```

Command line arguments override the file.

### Baselines

The JSON report of a run is the baseline of the next one. A typical setup keeps the report
of the last successful run on `main` as a build artifact and compares every pull request
with it (the Playwright example contains the workflow). To accept a change on purpose, merge
it: its report becomes the new baseline.

Findings are matched by their **key** (rule and subject, e.g. the endpoint), so they stay
the same across captures as long as the endpoint does. `quena-cli compare before.json
after.json` compares two saved reports without a new analysis.

## Outputs

| Format | Use |
|---|---|
| `md` | readable report with the verdict and the comparison — stdout by default, or the job summary |
| `json` | the complete report plus `gate` and `comparison`; the next baseline |
| `junit` | JUnit XML: one test case per finding, failures for what breaks the gate; for the test report of GitLab, Jenkins, Azure DevOps |
| `github` | GitHub Actions annotations |

`--format` chooses what goes to stdout, `-o FORMAT=PATH` writes further files (repeatable).
A one-line verdict goes to stderr (`--quiet` suppresses it).

## Other options

| Option | Effect |
|---|---|
| `--profile` | `full`, `performance`, `troubleshooting`, `auth`, `resilience`, `modernization` (`quena-cli profiles` lists them) |
| `--lang de` | report texts in German |
| `--set slowMs=1500` | an analyzer option (thresholds, network profiles) |
| `--host api.example.com`, `--process chrome` | analyse only part of the traffic |
| `--plugins DIR` | the plugins folder, if not next to the program |
| `--timeout 600` | give up after this many seconds |

Compiled plugins are cached (`~/.cache/quena`, `QUENA_CACHE_DIR`); the first run of a version
takes a few seconds longer.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | gate passed |
| 1 | gate failed |
| 2 | usage or input error (unknown option, unreadable capture or baseline) |
| 3 | analysis error |

## Privacy

Tokens, cookie values and secret URL parameters are removed before the analyzer sees the
traffic ([details](diagnostics.md#privacy)). Reports still contain URLs and host names —
mind that when you publish them, e.g. as artifacts of a public repository.
