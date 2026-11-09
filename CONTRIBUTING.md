# Contributing to seethru

<div align="center">

English | [한국어](CONTRIBUTING_KR.md)

</div>

First of all, thanks for helping. seethru checks apps for security problems, so a change has to keep users and their data safe as well as work. Please read this page before you open a pull request.

## Ground rules

- Every feature follows the [safety rules](README.md#safety-by-design). A change that lets seethru check a target without proof of ownership, leave the verified scope, change data or send bulk requests is not merged.
- Static analysis does not use the network. The analyzer, the fix prompts and the HTML report never connect to it. Only `seethru-guard` may depend on an HTTP client, and `deny.toml` enforces that.
- Do not commit real secrets, or even strings that look like them. Neither secret scanners nor people can tell strings shaped like Stripe keys, AWS access keys or JWTs apart from real ones. Tests build fake values at runtime from fragments, as `crates/seethru-analyzer/tests/secrets.rs` does.
- Make fixtures yourself. Projects in `fixtures/` are written by hand. Never copy files from a real project, even a public one, because it may contain leaked keys.
- Secrets leave seethru only in masked form. Findings, fix prompts and reports carry only the masked value, never the raw one.
- Explanations need to be easy. Users are not security experts. Every message they see should be fairly simple, in both English and Korean. Use `LocalizedText` in Rust and `web/src/messages.ts` in the web UI, and write Korean text in the friendly polite "~해요" style of the existing strings.

## Setup

| Tool       | Version                                                                        |
|------------|--------------------------------------------------------------------------------|
| Rust       | 1.99.1 with clippy and rustfmt, installed by rustup from `rust-toolchain.toml` |
| Node.js    | 22.12 or newer                                                                 |
| pnpm       | 11.20.0, set in the `packageManager` field of `package.json`                   |
| cargo-deny | Needed when you change Rust dependencies                                       |

```bash
$ pnpm install
$ pnpm build
$ cargo build
$ cargo run -p seethru-cli -- scan fixtures/supabase-vite
```

Build the web UI before the Rust crates. `crates/seethru-report/build.rs` inlines `web/dist/app.js` and `web/dist/app.css` into the binary and pins them with CSP hashes. Without them the build only prints a warning, and the binary cannot write HTML reports.

`pnpm dev` runs the web UI on its own. Open a report made with `seethru scan --json` in it.

## Checks

There is no CI yet, so run all of these yourself before you open a pull request. Every one of them must pass.

```bash
$ cargo fmt --all --check
$ cargo clippy --workspace --all-targets -- -D warnings
$ cargo test --workspace
$ pnpm typecheck
$ pnpm test
```

Also run `cargo deny check` when you change Rust dependencies.

The workspace forbids `unsafe` and denies `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!` and `dbg!` everywhere, tests included. Return a `Result` or use `let ... else` instead.

The code has almost no comments. Prefer clear names and small functions, and write a comment only when the reason behind the code is not obvious from the code itself. That said, the lack of comments in the existing code can be seen as a problem of its own, so feel free to add comments if you want to.

## Dependencies

- Pin exact versions, such as `=1.2.3` in `Cargo.toml`. pnpm is already set to save exact versions.
- Use only releases that have been public for at least 14 days, including every new transitive dependency. pnpm enforces this through `minimumReleaseAge` in `pnpm-workspace.yaml`. For Rust, check the publish dates on crates.io and pin older releases with `cargo update -p <crate> --precise <version>`.
- Licenses must be on the allow list in `deny.toml`.
- Keep the dependency tree small. Turn off default features you do not need, and explain in the pull request why a new dependency is needed.

## Report schema

The scan report in `crates/seethru-core/src/report.rs` is a format that the web UI and other tools read.

- When you change its shape, bump `SCHEMA_VERSION` in both `crates/seethru-core/src/report.rs` and `web/src/model.ts`, and update the parser in `web/src/model.ts`.
- Regenerate the JSON Schema with `cargo run -p seethru-cli -- schema > schema/scan-report.schema.json`. The `committed_schema_matches_the_model` test fails if you forget.

## Adding a rule

1. Check the change against the [safety rules](README.md#safety-by-design).
2. Add a variant to `RuleId` in `crates/seethru-core/src/report.rs`, give it a kebab-case ID in `as_str` and list its CWE numbers in `cwe`. Users write this ID in `seethru.toml`, so never change it after a release.
3. Write the title and the explanation in English and Korean in `crates/seethru-analyzer/src/rules.rs`, and add them to `every_text()` in its tests. The test checks that both languages are there and that they name the same things in backticks.
4. Raise the finding from the analyzer with `Graph::add_finding`. Always give it a location so that `path` in `[[accept]]` can match it, a confidence (`certain` for a fact read directly, `likely` for an interpreted path, `review` when a person has to check) and the evidence steps that lead from the code to the node.
5. Pick the severity by what an attacker could do. Use `Info` only for what cannot be confirmed from the repository alone.
6. Write the fix prompt in English and Korean in `crates/seethru-fix/src/lib.rs`.
7. Add unit tests next to the code and an integration test in `crates/seethru-analyzer/tests`. Add or extend a fixture when the rule needs a whole project.
8. Regenerate the schema, and add the rule to the check table and the rule ID table in both `README.md` and `README_KR.md`.

## Commits and pull requests

- Write commit messages in English and follow the style of recent `git log`. Start with a short title line, then add `-` bullets when more detail helps.
- Keep one feature per commit, and split unrelated changes.
- Do not use type prefixes such as `feat` or `chore`. Leave colons, periods, em dashes and middle dots out of the message.
- In the pull request, say what changed and why, and list the checks you ran. For a new rule, show the finding it raises on a fixture.

## Reporting a security problem

Report a security problem in seethru itself privately with **Report a vulnerability** on the **Security** tab at the top of the repository, not in a public issue. You can also contact <qtfelix@qu4nt.space> directly.

## License

By contributing, you agree that your work is licensed under the [Apache License 2.0](LICENSE), the same license as the project.
