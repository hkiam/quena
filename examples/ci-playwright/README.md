# Quena as a quality gate after Playwright tests

Every test records a HAR file (`tests/fixtures.ts`); `quena-cli` analyses them after the run
and fails the build when the traffic got worse than on `main`: new critical findings
(N+1 requests, retry storms, failing sign-ins …) or a metric over its budget
(`quena-gate.json`).

```bash
npm ci && npx playwright install --with-deps chromium
npx playwright test
quena-cli diagnose captures/*.har --config quena-gate.json --baseline baseline.json
```

Without a baseline (the first run) leave out `--baseline`: all findings count and the
relative budgets (`requests=+10%`) are skipped.

`workflow.yml` shows the whole loop for GitHub Actions: on `main` the report of a green run
becomes the baseline artifact, pull requests are compared with it. Copy it to
`.github/workflows/network-gate.yml`.
