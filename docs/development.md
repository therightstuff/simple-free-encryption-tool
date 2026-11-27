# Local verification

Use the Node.js version in `.nvmrc` and install the locked dependencies:

```sh
npm ci
```

Run the complete definition-of-done check:

```sh
npm run verify
```

This runs lint, unit tests with coverage, the browser bundle build, and the real-browser checks. Unit tests run once through `npm run build`. The browser checks then exercise the freshly built bundle and the demo. Failures stop verification with a nonzero exit status.

The browser runner needs an installed Chromium-compatible browser. It defaults to `/usr/bin/google-chrome`, as used in CI. On another system, set `CHROME_BIN` to the browser executable. For example, with Brave installed on macOS:

```sh
CHROME_BIN='/Applications/Brave Browser.app/Contents/MacOS/Brave Browser' npm run verify
```

Playwright launches a separate headless browser with a temporary profile and closes it after the checks. No personal browser profile is used.

## Local quality rules

```sh
npm run lint
```

ESLint and SonarJS run locally without a Sonar account, server, token or paid license. After dependencies are installed, lint needs no network access. Configuration lives in `eslint.config.mjs`; the lockfile records exact dependency versions.

Lint covers authored JavaScript, including test and automation scripts and inline JavaScript in `dist/index.html`. Generated bundles, vendor scripts and coverage output are excluded. The configuration enables ESLint and SonarJS recommended rules, `no-await-in-loop`, and a property restriction for deprecated `execCommand`. The latter detects the clipboard API without requiring a type-aware analyzer.

Fix findings before calling work complete. Only use narrow, explained exceptions where changing the code would undermine correctness or supported compatibility. Read-only browser assertions can run together; operations changing a shared page's viewport or AES mode must stay sequential.

These checks are not an exact replica of SonarCloud analysis, and do not update its dashboard. The GitHub Test and Build workflow runs the same `npm run verify` command and checks for generated-file drift. Repository administrators can require that job in branch rules to enforce verification before merging.
