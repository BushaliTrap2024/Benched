# Fixture behavior suites

Run these commands from the Benched repository root using Node.js 22 or newer.
Each suite starts and stops a fixture process. Nightowl runs in a temporary
copy with a fresh SQLite database and uploads directory.

| Fixture | Baseline coverage |
| --- | --- |
| Copperline | Plugin inventory and malformed install request |
| Goldleaf | Template inventory and preview defaults and custom metrics |
| Nightowl | Todo creation, reading, updates, delete error, and small attachment lifecycle |
| Purplehaze | Health and session pages, target validation, navigation, and response metadata |
| Riverbend | Import defaults and custom profile mapping |
| Shadowfox | Seeded PostgreSQL lookups, missing-ID response, and Express header |
| Silvergate | Readiness, handoff redirects, and Origin response headers |
| Skylark | Shelf validation and static asset delivery |
| Tigerteam | Health, Express header, user lookup, greeting, and missing file response |

The HTTP cases characterize the listed behavior. Header, cookie, and redirect
assertions provide evidence for those observed properties. The suites leave
other entries in `findings.json` unverified, including findings involving
injection, traversal, and resource exhaustion. Treat the original and
transformed results as observations for the cases exercised.

## Install dependencies

For fixtures with a package manifest, install dependencies in the project
directory. Use the pnpm lockfile where present.

```bash
for name in copperline goldleaf nightowl purplehaze riverbend shadowfox silvergate skylark; do
  project="fixtures/js-project-$name/project"
  if [[ -f "$project/pnpm-lock.yaml" ]]; then
    pnpm --dir "$project" install --frozen-lockfile || break
  else
    npm install --prefix "$project" --no-package-lock || break
  fi
done
```

Nightowl uses a native SQLite module and may require a compiler and Python.
Tigerteam has no package manifest. Use Copperline's installed Express 4
through `NODE_PATH`.

## Run the originals

Shadowfox uses the same disposable PostgreSQL setup and seed as Ironclad.
Follow the [Ironclad database instructions](js-project-ironclad/README.md)
before running Shadowfox.

```bash
NODE_PATH="$PWD/fixtures/js-project-copperline/project/node_modules" \
  node --test fixture-tests/*/behavior.test.cjs
```

For a single fixture, pass its test file directly. The Ironclad suite has its
own [entry point and setup](js-project-ironclad/README.md).

## Run a transformed variant

Set `FIXTURE_APP_DIR` to the variant's project directory, install its
dependencies there, and select that fixture's suite. Run the original with
the same dependency versions and data first.

```bash
FIXTURE_APP_DIR=/absolute/path/to/variant/project \
  node --test fixture-tests/js-project-nightowl/behavior.test.cjs
```
