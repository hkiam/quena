# Quena as a quality gate after Cypress tests

`@neuralegion/cypress-har-generator` records a HAR file per spec (`cypress/support/e2e.js`,
Chromium-based browsers); `quena-cli` analyses them after the run:

```bash
npm ci
npx cypress run --browser chrome
quena-cli diagnose captures/*.har --config quena-gate.json --baseline baseline.json -o junit=quena-junit.xml
```

For GitHub Actions use the workflow of the Playwright example with `npx cypress run` as the
test step; for GitLab CI or Jenkins the Docker image:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/hkiam/quena-cli diagnose captures/*.har --config quena-gate.json
```
