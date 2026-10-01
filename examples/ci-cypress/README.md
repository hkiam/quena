# Quena as a quality gate after Cypress tests

`@neuralegion/cypress-har-generator` records a HAR file per test (`cypress/support/e2e.js`,
Chromium-based browsers); `quena-cli` analyses them after the run:

```bash
npm ci
npx cypress run --browser chrome
quena-cli diagnose captures/*.har --config quena-gate.json --baseline baseline.json -o junit=quena-junit.xml
```

Without a baseline (the first run) leave out `--baseline`: all findings count and the
relative budgets of `quena-gate.json` (`requests=+10%`) are skipped.

Cypress is pinned to version 13: the HAR generator plugin (version 5) was written for it.
Check the plugin's notes before you move to a newer Cypress.

For GitHub Actions use the workflow of the Playwright example with `npx cypress run` as the
test step; for GitLab CI or Jenkins the Docker image:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work" ghcr.io/hkiam/quena-cli \
  diagnose captures/*.har --config quena-gate.json
```

`--user` makes the reports belong to you. Compiled plugins are cached inside the container;
add `-v quena-cache:/tmp/quena-cache` to keep them between runs.
