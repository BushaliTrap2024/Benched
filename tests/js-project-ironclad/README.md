# Ironclad tests

Run these commands from the workspace root. The seven checks use a running
Ironclad app and inspect the source tree selected by `IRONCLAD_APP_DIR`.

## Original fixture

Install the test and app dependencies.

```sh
npm ci --prefix tests/js-project-ironclad
pnpm --dir fixtures/js-project-ironclad/project install --frozen-lockfile
```

Start a disposable PostgreSQL database. Ironclad expects port 5432.

```sh
docker run --rm -d --name ironclad-test-db -p 127.0.0.1:5432:5432 \
  -e POSTGRES_USER=your_database_user \
  -e POSTGRES_PASSWORD=your_database_password \
  -e POSTGRES_DB=myapp_test postgres:16-alpine
```

Once PostgreSQL is ready, seed the database.

```sh
docker exec -i ironclad-test-db psql -h 127.0.0.1 \
  -U your_database_user -d myapp_test -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE users (id integer PRIMARY KEY, name text NOT NULL);
INSERT INTO users VALUES (1, 'Ada'), (2, 'Grace');
SQL
```

Start the app in one terminal and run the suite in another.

```sh
node fixtures/js-project-ironclad/project/app.js
```

```sh
node --test tests/js-project-ironclad/users.test.cjs
```

Stop the app and run `docker stop ironclad-test-db` when finished.

## Transformed copies

Keep transformed copies under `fixtures/js-project-ironclad/variants/`.
For each run, start the selected variant against the same seed data and set
both `IRONCLAD_APP_DIR` and `APP_URL` for that copy.

```sh
IRONCLAD_APP_DIR=fixtures/js-project-ironclad/variants/variant-01/project \
APP_URL=http://127.0.0.1:3001 \
node --test tests/js-project-ironclad/users.test.cjs
```

The source checks cover Ironclad's fixture structure. An inconclusive result
requires source review to determine the status of the finding.
