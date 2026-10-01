# Quena as a quality gate after Playwright tests

The tests record HAR files (`tests/fixtures.ts`); `quena-cli` analyses them after the run
and fails the build when the traffic got worse than on `main`: new critical findings
(N+1 requests, retry storms, failing sign-ins …) or a metric over its budget
(`quena-gate.json`).

```bash
npm ci && npx playwright install --with-deps chromium
npx playwright test
quena-cli diagnose captures/*.har --config quena-gate.json --baseline baseline.json
```

`workflow.yml` shows the whole loop for GitHub Actions: on `main` the report becomes the
baseline artifact, pull requests are compared with it. Copy it to `.github/workflows/`.
