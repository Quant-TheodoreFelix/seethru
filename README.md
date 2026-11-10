# seethru

<div align="center">

**"_See through_ your app before attackers do."**

English | [한국어](README_KR.md)

</div>

seethru is a **defensive security checker** that lets you see the security problems in your vibe-coded app and fix them yourself with the AI tools you already use. It belongs to the same category as DAST (Dynamic Application Security Testing) tools such as OWASP ZAP and Burp Suite. What sets it apart is **how it shows** the results and **how it fixes** them.

> [!WARNING]
> Early stage of development. Only offline static analysis (Security Map) and fix prompts (Fix Prompt) work today. Dynamic checks (Proof Replay) are not implemented yet.

## Why

- Many AI-built apps ship with **basic problems** such as exposed secrets and missing authorization checks.
- The people who build them often don't know how to protect their apps, and they don't fix the code themselves. It's always the AI that does the fixing.
- So instead of a list of warnings, seethru gives you **visualizations**, **reproduction recordings**, and **fix prompts to hand to your AI**.

## Usage

```sh
pnpm install && pnpm build
cargo run -p seethru-cli -- scan <project path>
```

The report is written to `<project path>/.seethru/report.html`, and that directory is ignored by git automatically. The report opens as a single file without any outside requests, and every secret it finds is masked so the raw value never appears.

| Option               | What it does                                                                       |
|----------------------|------------------------------------------------------------------------------------|
| `--out FILE`         | Write the HTML report to `FILE` instead                                            |
| `--json`             | Print the scan report as JSON instead of writing HTML                              |
| `--lang ko`          | Show the summary and the report in Korean (default is `en`)                        |
| `--no-config`        | Ignore `seethru.toml` in the scanned project (see [Configuration](#configuration)) |
| `--build-output DIR` | Read the Vite or Next build output in DIR, a folder inside the project             |
| `--sarif FILE`       | Add the results another scanner wrote to FILE in SARIF 2.1.0. Up to 8 files       |
| `--sarif-out FILE`   | Also write what seethru found to FILE in SARIF 2.1.0                               |
| `--compile-commands FILE` | Read `compile_commands.json` from FILE, a file inside the project, to learn which C and C++ files are built |
| `--llvm-ir PATH`     | Read compiled output of a Rust project from PATH, a `.ll` file or a folder of them. Can be given more than once (see [Rust](#rust)) |


| Check                     | What it finds                                                                                                        |
|---------------------------|----------------------------------------------------------------------------------------------------------------------|
| Supabase RLS              | Tables with RLS off and policies that open every row, from migration SQL                                             |
| Supabase functions        | `security definer` functions that anyone or any signed-in user can call through `rpc()`, which skip RLS              |
| Supabase views            | Views that skip RLS and that anyone or any signed-in user can read                                                   |
| Supabase Storage          | Storage policies that open every file in a bucket to anyone or any signed-in user                                    |
| service_role key exposure | Browser code that reads the service_role key from a public env variable                                              |
| Unguarded service_role    | Routes, server actions and Edge Functions that reach code using the service_role key without checking who is calling |
| Exposed secrets           | API keys and database URLs in code, build output and env files                                                       |
| Firmware settings         | Test-only firmware settings left on, updates over plain HTTP and skipped certificate checks in ESP-IDF and Zephyr config files |
| Open firmware update      | An HTTP route of an ESP-IDF device that writes a firmware update without checking who sends it                       |
| Secret-dependent division | In compiled Rust code, a division of a value the code wipes after use, which leaks the value through timing          |
| Cargo dependencies        | Git and `*` dependencies that are not fixed to one version in a project with no `Cargo.lock`                         |
| Missing table schema      | Tables the code queries that no SQL file in the repo creates, so their RLS cannot be checked                         |

## Configuration

To skip paths or accept findings you meant to have, put a `seethru.toml` in the root of the project you scan. The file is optional.

```toml
exclude = ["legacy", "**/*.test.ts", "supabase/seed.sql"]

[[accept]]
rule = "supabase-policy-unrestricted"
path = "supabase/migrations/*_products.sql"
reason = "Products are public on purpose"

[[accept]]
id = "supabase-table-schema-missing:table:public.orders"
reason = "orders was made in the dashboard and has RLS on there"
```

**`exclude`** lists files and folders that seethru does not read at all.

- Patterns support `*`, `?` and `**`. A pattern without `/` matches a name at any depth, so `legacy` skips every `legacy` folder. A pattern with `/` is matched from the project root, so begin it with `**/` to match at any depth.
- Patterns must stay inside the project. `..`, a leading `/` and `\` are rejected.
- `.git`, `node_modules`, `.pnpm-store`, `.yarn` and `.seethru` are always skipped, so there is no need to list them.
- Problems in excluded files never show up. To keep a known problem in sight, use `[[accept]]` instead.

**`[[accept]]`** marks matching findings as accepted. Each entry needs a `reason` of 1 to 500 characters and at least one of the keys below. When an entry has more than one, all of them must match.

| Key    | Matches                                                                 |
|--------|-------------------------------------------------------------------------|
| `id`   | One finding, by the ID shown in the report's fix panel and in `--json`  |
| `rule` | Every finding of a rule, by the rule ID in the table below              |
| `path` | Findings reported in files that match a pattern, written like `exclude` |
| `engine` | Results from one outside scanner, by the name seethru shows for it, such as `semgrep` |
| `external-rule` | Results of one rule of an outside scanner, by the rule name shown in the report |

| Rule ID                                | Severity        | Finding                                                                                                                      |
|----------------------------------------|-----------------|------------------------------------------------------------------------------------------------------------------------------|
| `supabase-rls-disabled`                | Critical        | A table in the `public` schema has RLS off                                                                                   |
| `supabase-policy-unrestricted`         | Low to Critical | A policy lets anyone, or any signed-in user, reach every row                                                                 |
| `supabase-function-bypasses-rls`       | Low to High     | A `security definer` function that anon or signed-in users can call through `rpc()` runs without RLS                         |
| `supabase-view-bypasses-rls`           | Low to Critical | A view in the `public` schema skips RLS and can be read by anon or signed-in users                                           |
| `supabase-storage-policy-unrestricted` | Low to Critical | A `storage.objects` policy lets anyone, or any signed-in user, reach every file in a bucket                                  |
| `supabase-service-role-in-browser`     | Critical        | Browser code reads the service_role key from a public env variable                                                           |
| `supabase-service-role-unguarded`      | Medium to High  | A route, server action or Edge Function reaches code that uses the service_role key, and nothing checks who is calling first |
| `secret-in-browser-code`               | Critical        | A secret in code or files that reach the browser                                                                             |
| `secret-in-public-env-var`             | Critical        | A secret in an env variable with a public prefix such as `VITE_`                                                             |
| `secret-in-source-code`                | High            | A secret in a file that does not reach the browser, such as server code or an env file                                       |
| `supabase-table-schema-missing`        | Info            | The code queries a table that no SQL file in the repo creates                                                                |
| `external`                             | Info to High    | A result another scanner reported in a SARIF file. seethru did not check it itself                                          |
| `firmware-insecure-option-on`          | Medium to High  | A firmware setting meant only for testing is turned on in a config file                                                      |
| `firmware-ota-over-http`               | High            | A config file lets firmware updates download over plain HTTP                                                                 |
| `firmware-tls-verification-off`        | High            | A config file lets the device skip checking the server certificate                                                           |
| `firmware-ota-unguarded`               | High            | An HTTP route of the device writes a firmware update and no check of the caller was found                                    |
| `secret-in-native-code`                | High            | A secret value is in C or C++ code or in a firmware config file                                                              |
| `secret-dependent-division`            | Medium          | Compiled code divides a value that comes from memory the program wipes after use                                             |
| `cargo-dependency-not-pinned`          | Low             | A Cargo dependency from git has no `rev`, or its version is `*`, and the project has no `Cargo.lock`                         |

- A finding ID is the rule ID followed by the graph node, such as `supabase-rls-disabled:table:public.orders`.
- The ID of a `secret-dependent-division` finding names the file and the order of the finding in that file, such as `secret-dependent-division:file:mldsa/src/sign.rs:2`. It does not carry the line number.
- The ID of a secret finding names the file, the kind of secret and its order among secrets of that kind in the file, such as `secret-in-source-code:secret:src/pay.ts:stripeSecretKey:1`. It stays the same when other code in the file moves.
- Accepted findings stay in the report and the CLI summary under their own heading, with the reason. They do not count toward the totals or color the graph.
- If `seethru.toml` cannot be used, the scan stops and names the line instead of ignoring it. That covers unknown keys, a missing reason, an unknown rule ID and invalid patterns. The file must be a regular file of up to 64 KB, with at most 256 `exclude` patterns and 1,000 `[[accept]]` entries.
- `--no-config` ignores the file. Use it when you review a project someone else wrote, so its config cannot hide anything from you.

## Entry points

seethru follows each entry point to the code it runs and checks whether something verifies the caller before that code uses the service_role key.

- Entry points are Next route handlers (`app/**/route.ts` and `pages/api/**`), the exported functions of `"use server"` files, and Supabase Edge Functions.
- A check counts when the code stops early with `return`, `throw` or `redirect()` if there is no user. It can sit in the handler or in a helper that the handler calls first.
- Recognized checks are `supabase.auth.getUser()`, `getClaims()` and `getSession()` (a weak check on the server), next-auth `getServerSession()`, Clerk `auth()`, `currentUser()` and `auth.protect()`, Stripe webhook signatures, Firebase `verifyIdToken()`, JWT checks with jose or jsonwebtoken, and comparing a request value with a secret env variable.
- When seethru cannot tell, for example a middleware that checks users, an auth library it does not know, or a 401 response after a check it cannot read, it reports nothing for that entry point instead of guessing.
- A Supabase client passed to another function as an argument is not followed yet.

## Build output

seethru never runs your build. Build the project yourself, then pass the output folder.

```bash
$ seethru scan . --build-output dist
$ seethru scan . --build-output .next
```

- The folder must be inside the scanned project and must not be a symbolic link. It is read even when an `exclude` pattern matches it.
- **Vite**: turn on `build.manifest` and `build.sourcemap` in `vite.config` so seethru can see every file in the bundle. With source maps for every chunk, files that the bundle leaves out are no longer treated as browser code.
- **Next**: seethru reads `.next`. The `"use client"` files are confirmed from the build manifests. To confirm every file that reaches the browser, set `productionBrowserSourceMaps: true` in `next.config`. Routes in the build manifests also appear as entry points, even when seethru cannot find their handler in the source.
- Findings on files that the build output confirms are no longer marked as likely. A secret found in a bundle points back to its source line through the source map.
- If any source file is newer than the build output by more than 2 seconds, the build output is not used and the report says so under "Not checked". Build again and rerun.
- Even without the option, files under `.next/server` and `.next/standalone` are treated as server code, `.next/static` as browser code and `.next/cache` as build cache.

## C, C++ and firmware

seethru reads C and C++ sources and firmware config files without building them. This part is new and narrow on purpose.

- Firmware projects are recognized by `sdkconfig` files (ESP-IDF), `prj.conf` (Zephyr), `platformio.ini` and `.ino` sketches.
- Config files read: `sdkconfig`, `sdkconfig.defaults` and its variants, `prj.conf` and `prj_*.conf`. Only settings that are written as turned on are reported. A setting that is missing from the files says nothing, so seethru never reports "secure boot is off". Files for CI and files under `test`, `tests` or `examples` folders are skipped.
- Entry points: routes of the ESP-IDF HTTP server that are written as `httpd_uri_t` values with `.uri` and `.handler`. seethru follows calls by function name from the handler, and reports the route when it reaches `esp_ota_write` or `esp_https_ota` and no function on the way looks like it checks the caller.
- Anything that looks like a caller check keeps the route silent: a call or a text with words such as `auth`, `password`, `token`, `session` or `verify`, a handler swapped for a wrapper that does so, or a handler that cannot be found.
- Macros, function pointers, C++ overloads and generated code are not followed. Memory safety bugs are not looked for. Use another scanner for those and pass its results with `--sarif`.
- Secrets found in C or C++ files and firmware config files get the rule `secret-in-native-code`. A private key is reported only when its body is there, so parser code that only names the key header is not flagged.
- `--compile-commands` reads `compile_commands.json` as data. Its commands are never run. A finding in a source file that the build does not list is marked "needs review".
- A root `build` or `out` folder next to a `CMakeLists.txt`, `platformio.ini` or `sdkconfig` file is not read, and `.pio`, `managed_components` and `CMakeFiles` folders are always skipped.

## Rust

seethru reads a Cargo project from its root `Cargo.toml` and draws each crate and the crates it depends on. The checks that matter for Rust run on compiled output, because the compiler rewrites code after you write it.

- Crates come from the root manifest: the root package, `[workspace] members` (with `exclude`), and every crate they reach through a `path` dependency. A `target` folder next to a `Cargo.toml` is not read as source.
- A git dependency with no `rev`, or a version of `*`, is reported only when the project has no `Cargo.lock`.
- seethru never runs `cargo`. To check compiled code, build it yourself and pass the output:

```bash
RUSTFLAGS="--emit=llvm-ir,asm -C debuginfo=line-tables-only" cargo build --release
seethru scan . --llvm-ir target/release/deps
```

- With `--target` or a `build.target` setting, the files are in `target/<triple>/release/deps`.
- seethru cannot tell whether the compiled output is older than the source. Build again after every change before you scan.

- `--llvm-ir` takes a `.ll` file or a folder, which may be outside the project. For each `.ll` file, a `.s` file with the same name next to it is read as its machine code. Up to 64 files of 64 MB each.
- **What counts as secret.** Memory that the code wipes with a volatile write on purpose, such as a call to `zeroize()`. Values read from that memory are followed through function calls, copies and returned pointers. Memory that a type wipes by itself when it is dropped does not count, because a hash state wipes itself even when it only held public data.
- **What is reported.** A division or remainder of such a value (`secret-dependent-division`). The time a division takes depends on its operands on most processors. With a `.s` file, the finding is `likely` when the machine code has a division instruction for that source line, and it is dropped when the compiler turned a division by a constant into a multiplication. Without one it is `review`.
- **What is not checked yet.** Branches and table lookups that depend on a secret, and whether a wipe survives the compiler. Both were tried and gave too many wrong results to ship. The report says so every time.
- A secret that is only wiped by a caller outside the compiled files, or that sits behind a pointer stored in memory, is not followed. The output of a library is from before the final link. No finding does not mean constant time.
- Paths in the compiled output must point into the scanned project, so build from the same checkout or use `--remap-path-prefix` to make them relative.

## Results from other scanners

seethru can show what another scanner found next to its own findings. Run the scanner yourself, save its results as SARIF 2.1.0, and pass the file.

```bash
$ seethru scan . --sarif semgrep.sarif --sarif clang.sarif
$ seethru scan . --sarif-out seethru.sarif
```

- seethru never runs a scanner. It only reads the file you pass, and it never looks for SARIF files inside the project.
- Each result becomes a finding with the rule `external`, marked "needs review". Its severity is at most High, because seethru did not check the result itself.
- The scanner's own text is not copied. Messages, code snippets and help text can hold secrets or instructions aimed at an AI tool, so the report keeps only the scanner name, the rule name, CWE numbers, the file and the line. Titles, explanations and fix prompts are written by seethru.
- A result is kept only when its file exists inside the scanned project. Results on other paths, on excluded files, on remote addresses, or without a usable location are left out, and the report says how many.
- To accept results, use `engine`, `external-rule` and `path` in `[[accept]]`. `rule = "external"` alone is rejected, because it would hide every scanner at once.
- `--sarif-out` writes seethru's own findings as SARIF, for example for GitHub code scanning. Accepted findings are marked as suppressed. Results that came from another scanner are not written again.
- Joern's `joern-scan` prints text and has no SARIF option. Joern exports SARIF from a script that calls `cpg.finding.toSarifJson()`. The `tests/test-sarif.sc` file in the Joern repository shows how.

## Agent skill

This repository is also a Claude Code plugin marketplace. The `seethru` plugin adds a skill that lets a coding agent run a scan, read the report, fix the findings in order and rescan to prove the fix.

Install it inside Claude Code:

```
/plugin install seethru --marketplace Quant-TheodoreFelix/seethru
```

On older versions, add the marketplace first:

```
/plugin marketplace add Quant-TheodoreFelix/seethru
/plugin install seethru@seethru
```

Update it:

```
/plugin marketplace update seethru
/plugin update seethru@seethru
```

The same commands work from a terminal as `claude plugin marketplace add`, `claude plugin install`, `claude plugin marketplace update` and `claude plugin update`. Restart Claude Code after an update. Remove it with `/plugin uninstall seethru@seethru`.

- Use it by asking the agent to scan a project with seethru, or with `/seethru:seethru`.
- The skill does not ship the scanner. Build seethru as shown in [Usage](#usage), then set `SEETHRU_BIN` to `target/release/seethru`, or put that file on your `PATH`.
- To use the skill without the plugin system, copy `plugins/seethru/skills/seethru` into `~/.claude/skills/`.

## Safety by design

**seethru is not an attack tool.** The principles below are not optional. They are required for *every feature*.

1. **No dynamic checks without proof of ownership**: Only domains whose ownership has been verified through a DNS TXT record or a file such as `/.well-known/` are checked, and verification is repeated periodically.
2. **Scope lock**: No request is sent outside the verified domain. If a redirect reaches an external domain, the check stops immediately.
3. **Non-destructive checks only**: No deleting or modifying data, no denial of service, no bulk requests. Only test accounts created by the user are used.
4. **Rate limiting**: Request rates are limited so the target server is never overloaded.
5. **No collection of real user data**: Real data exposed during a reproduction is masked and never stored.
6. **Audit log**: Every check request is logged and can be reviewed by the user.
7. **Staging first**: Checking production requires explicit confirmation.

## Tech stack

Designed for Zero-Trust and Air-Gapped environments, favoring a single binary and a small dependency tree.

| Area   | Choice                                              |
|--------|-----------------------------------------------------|
| Engine | Rust single binary, oxc (JS/TS parser)              |
| Web UI | React, React Flow, ELK.js, Motion, Vite, TypeScript |

## Repository layout

| Path                      | Role                                                                  |
|---------------------------|-----------------------------------------------------------------------|
| `crates/seethru-core`     | Shared types and graph model                                          |
| `crates/seethru-analyzer` | Static analysis (Security Map)                                        |
| `crates/seethru-guard`    | Ownership verification, scope lock, rate limiting, audit log, masking |
| `crates/seethru-probe`    | Dynamic checks (Proof Replay)                                         |
| `crates/seethru-fix`      | Fix prompt generation (Fix Prompt)                                    |
| `crates/seethru-report`   | Local HTML report                                                     |
| `crates/seethru-mcp`      | MCP server                                                            |
| `crates/seethru-cli`      | `seethru` executable                                                  |
| `web`                     | Web UI for Security Map and Proof Replay                              |
| `schema`                  | JSON Schema of the scan report                                        |
| `fixtures`                | Deliberately vulnerable sample projects for tests (no real keys)      |
| `plugins`                 | Agent skill, published through `.claude-plugin/marketplace.json`      |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, checks and how to add a new rule.

## Responsible use

Only use seethru on apps you own or are authorized to test. seethru does not run dynamic checks against any target that has not passed ownership verification.

## License

Licensed under the [Apache License 2.0](LICENSE).
