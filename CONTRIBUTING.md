# Contributing to AegisLens

Thanks for your interest! Bug reports, new detection ideas, false-alarm reports and pull requests are all welcome.

## Getting started

1. Install **JDK 26** and **Maven 3.9+**.
2. Fork and clone the repository, then build and run every test:
   ```bash
   mvn clean verify
   ```
3. Start the desktop app with `mvn javafx:run` and try the files in `sample-data/`.

## Reporting a bug or a false alarm

Open an issue with the version, your operating system and the steps to reproduce. For detection problems attach a
**small synthetic** log line, export or file that shows the issue. Never attach real logs from other people, real
malware or anything containing secrets. Security problems go through [SECURITY.md](SECURITY.md), not public issues.

## Making a change

- Branch from `main` (`feature/<topic>` or `fix/<topic>`), keep each pull request about one thing.
- Write the test first or together with the change; `mvn clean verify` must stay green, including the coverage check
  (70 % per logic package).
- Commit messages: `<module>: <what changed>`, for example `intrusion: detect Kerberos password spraying`.

## Code rules

These keep AegisLens safe and easy to read; CI checks several of them.

- **Never run analysed input.** Only the `sandbox` package may start processes; no `Runtime.exec`, `ProcessBuilder`,
  class loading or native loading anywhere else.
- **SQL:** PreparedStatement only, writes through `Database.locked`/`transaction`, never `getGeneratedKeys`
  (use `Database.lastInsertId`).
- **Untrusted text:** cap sizes, avoid regexes with nested quantifiers, keep XML parsing hardened, show text in the UI
  as plain text only, and send AI prompts through `Sanitizer` and `PromptBuilder`.
- **Secrets** come only from environment variables; never commit keys, `.db` files, real logs or real malware.
- **Platform independent:** `java.nio.file.Path`, no hard-coded `/` or `C:\`.
- **Readable code:** small methods, a Javadoc line on every public class, numbers as named constants.
- **New detection rules:** add the rule to `schema.sql` (seed), a detector with tests (one positive, near-misses that must
  stay quiet), an offline explanation in `src/main/resources/templates/<RULE>.txt`, sample data that really triggers it,
  and a row in the README rule table.

## Project structure

See the "Project layout" section of the [README](README.md). Shared contracts live in `core` (`Finding`,
`Analyzer<T>`, `Detector<T>`, `AlertBus`); please discuss changes to them in an issue first.

By contributing you agree that your work is released under the [MIT License](LICENSE).
