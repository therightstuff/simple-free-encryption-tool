# Repository checks

- Before declaring implementation work complete, run `npm run verify`: local lint, unit tests, browser bundle build, then real-browser interoperability checks. See [development setup](docs/development.md) for browser configuration.
- Fix failures and rerun affected checks. Missing prerequisites or interrupted checks mean verification is incomplete; report them explicitly.
- `eslint.config.mjs` defines the local quality rules: ESLint and SonarJS recommended rules, sequential-await checks, and a restriction on deprecated `execCommand` use. Lint allows zero warnings.
- Do not weaken rules, exclude authored code, or remove assertions to obtain a pass. Any necessary exception must be narrowly scoped with an adjacent explanation of why the alternative is incorrect. Preserve sequential operations that mutate shared browser state.
- Keep Node and browser behavior aligned. Edit source and rebuild generated bundles; do not edit generated or vendor JavaScript directly.

<!-- CODEGRAPH_START -->
## CodeGraph

If a `.codegraph/` directory exists at the repository root, use CodeGraph before text search or file reads to locate or understand code. Otherwise use ordinary repository tools; do not create an index unless requested.
<!-- CODEGRAPH_END -->
