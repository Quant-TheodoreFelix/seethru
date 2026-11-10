# seethru usage

English | [한국어](USAGE_KR.md)

This page explains how to run seethru, what every option does, how to configure it, and what to know for each kind of project it reads. For what seethru is and why it exists, see the [README](README.md).

- [Build and run](#build-and-run)
- [Commands](#commands)
- [Options](#options)
- [Exit codes](#exit-codes)
- [Configuration](#configuration)
- [Entry points](#entry-points)
- [Build output](#build-output)
- [C, C++ and firmware](#c-c-and-firmware)
- [Rust](#rust)
- [Results from other scanners](#results-from-other-scanners)
- [Agent skill](#agent-skill)

## Build and run

```sh
pnpm install && pnpm build
cargo run -p seethru-cli -- scan <project path>
```

The report is written to `<project path>/.seethru/report.html`, and that directory is ignored by git automatically. The report opens as a single file without any outside requests, and every secret it finds is masked so the raw value never appears.

`pnpm build` builds the web UI that is placed inside the HTML report. Without it, HTML reports are unavailable.

For a release binary at `target/release/seethru`, run `cargo build --release -p seethru-cli` after `pnpm build`.

## Commands

| Command                  | What it does                                                          |
|--------------------------|-----------------------------------------------------------------------|
| `seethru scan [PATH]`    | Analyze a project directory (default is the current directory)        |
| `seethru schema`         | Print the JSON Schema of the scan report                              |
| `seethru --version`      | Print the version                                                     |
| `seethru --help`         | Print the usage text. Running `seethru` with no arguments does the same |

The full form of the scan command is:

```sh
seethru scan [PATH] [--out FILE] [--json] [--lang LANG] [--no-config]
             [--build-output DIR] [--sarif FILE]... [--sarif-out FILE]
             [--compile-commands FILE] [--llvm-ir PATH]... [--build]
```

## Options

| Option               | What it does                                                                       |
|----------------------|------------------------------------------------------------------------------------|
| `--out FILE`         | Write the HTML report to `FILE` instead (default is `PATH/.seethru/report.html`)   |
| `--json`             | Print the scan report as JSON instead of writing HTML                              |
| `--lang ko`          | Show the summary and the report in Korean (default is `en`)                        |
| `--no-config`        | Ignore `seethru.toml` in the scanned project (see [Configuration](#configuration)) |
| `--build-output DIR` | Read the Vite or Next build output in DIR, a folder inside the project (see [Build output](#build-output)) |
| `--sarif FILE`       | Add the results another scanner wrote to FILE in SARIF 2.1.0. Up to 8 files (see [Results from other scanners](#results-from-other-scanners)) |
| `--sarif-out FILE`   | Also write what seethru found to FILE in SARIF 2.1.0                               |
| `--compile-commands FILE` | Read `compile_commands.json` from FILE, a file inside the project, to learn which C and C++ files are built (see [C, C++ and firmware](#c-c-and-firmware)) |
| `--llvm-ir PATH`     | Read compiled output of a Rust project from PATH, a `.ll` file or a folder of them. Can be given more than once (see [Rust](#rust)) |
| `--build`            | Build a Rust project with cargo and read what it built. Runs the project's build scripts and macros, so use it only on code you trust (see [Rust](#rust)) |

- `--lang` takes `en` or `ko`. Any other value is an error.
- `--json` and `--out` cannot be used together.
- `--sarif-out` must be a different file from every `--sarif` file and from `--out`.
- `--json` prints the report to the terminal. Without it, seethru prints a short summary and then the path of the report it wrote.

## Exit codes

| Code | Meaning                                                                                     |
|------|---------------------------------------------------------------------------------------------|
| `0`  | The scan finished. Findings do not change the exit code                                     |
| `1`  | The scan could not run. The one-line `error:` on stderr names the input to fix              |
| `2`  | The arguments were wrong. seethru prints the error and the usage text                       |

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
| `stop-on-outside-input`                | Low             | Compiled code keeps a check that panics, and the value it tests comes from an exported entry point such as a system call handler |
| `cargo-dependency-not-pinned`          | Low             | A Cargo dependency from git has no `rev`, or its version is `*`, and the project has no `Cargo.lock`                         |

### Finding IDs

- A finding ID is the rule ID followed by the graph node, such as `supabase-rls-disabled:table:public.orders`.
- The ID of a `secret-dependent-division` or `stop-on-outside-input` finding names the file and the order of the finding in that file, such as `secret-dependent-division:file:mldsa/src/sign.rs:2`. It does not carry the line number.
- The ID of a secret finding names the file, the kind of secret and its order among secrets of that kind in the file, such as `secret-in-source-code:secret:src/pay.ts:stripeSecretKey:1`. It stays the same when other code in the file moves.

### Accepted findings and errors

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
- seethru does not run `cargo` unless you ask. To check compiled code, either let seethru build it with `--build` (below), or build it yourself and pass the output:

```bash
RUSTFLAGS="--emit=llvm-ir,asm -C debuginfo=line-tables-only" cargo build --release
seethru scan . --llvm-ir target/release/deps
```

- With `--target` or a `build.target` setting, the files are in `target/<triple>/release/deps`.
- seethru cannot tell whether the compiled output is older than the source. Build again after every change before you scan.

- `--llvm-ir` takes a `.ll` file or a folder, which may be outside the project. For each `.ll` file, a `.s` file with the same name next to it is read as its machine code. Up to 1,024 files of 1 GB each, 2 GB in total. Reading that much can take a few gigabytes of memory.
- **What counts as secret.** Memory that the code wipes with a volatile write on purpose, such as a call to `zeroize()`. Values read from that memory are followed through function calls, copies and returned pointers. Memory that a type wipes by itself when it is dropped does not count, because a hash state wipes itself even when it only held public data.
- **What is reported.** A division or remainder of such a value (`secret-dependent-division`). The time a division takes depends on its operands on most processors. With a `.s` file, the finding is `likely` when the machine code has a division instruction for that source line, and it is dropped when the compiler turned a division by a constant into a multiplication. Without one it is `review`.
- **Checks that can stop the program (`stop-on-outside-input`).** For kernels, firmware and libraries called from other languages. seethru treats the arguments of exported functions with unmangled names (`#[no_mangle]`, `extern "C"`), and the memory they point to, as values from outside. It reports a check that is still in the compiled code, panics when it fails and tests such a value: an index or slice range, an arithmetic overflow, `unwrap`, `expect`. A panic stops the program, and in a kernel it stops the whole system. The compiler already removed every check it could prove safe, so what is left is what it could not prove. An earlier check or a rule of your design may still make it impossible, which seethru cannot see, so these findings are always `review` and severity Low. Values that the outside value only selects, such as an entry of a kernel table picked by a caller's index, are not followed. Without such an entry point the report says the check did not run.
- A volatile write to an address made from a number is a device register write and does not count as a wipe.
- **What is not checked yet.** Branches and table lookups that depend on a secret, and whether a wipe survives the compiler. Both were tried and gave too many wrong results to ship. The report says so every time.
- A secret that is only wiped by a caller outside the compiled files, or that sits behind a pointer stored in memory, is not followed. The output of a library is from before the final link. No finding does not mean constant time.
- Paths in the compiled output must point into the scanned project, so build from the same checkout or use `--remap-path-prefix` to make them relative.

### Letting seethru build

```bash
seethru scan . --build
```

`--build` is the only case where seethru runs anything from your project. It is off unless you pass it.

- **Use it only on code you trust.** A cargo build runs the project's `build.rs` scripts and macros on your computer, and those of its dependencies. seethru cannot stop or sandbox that. For a repository you do not trust, scan without `--build`.
- It runs `cargo build --release --locked --offline --target-dir PATH/.seethru/build/<project>` from the folder that holds the `Cargo.toml` and prints that command first. The project's own settings in `.cargo/config.toml`, such as the target and compiler flags, apply as usual.
- Nothing is downloaded. The project needs a `Cargo.lock`, and its dependencies and toolchain must already be on the computer. If something is missing the build fails instead of fetching it, and seethru tells you what to run yourself: `cargo generate-lockfile` for a missing lock file, `cargo fetch` for missing dependencies, `rustup toolchain install` for a missing toolchain.
- The output goes to a folder per project under `PATH/.seethru/build`. Your `target` folder is not touched. The folder can grow large. Delete it whenever you like.
- seethru adds the output it needs by putting itself in front of the compiler (`RUSTC_WRAPPER`) for this one build. Your own compiler flags are kept. If the project uses its own wrapper such as sccache, it is not used for this build.
- Each run builds again, so the result always matches the source. When the build settings, dependencies or toolchain change, seethru throws the folder away and builds from scratch once.
- If the build fails, seethru stops with an error and writes no report.
- A program that compiles but cannot be linked still counts, because the checks read compiled code and do not need the linked file. This is common for kernels, firmware and test programs without a `main`. seethru says so when it happens.
- seethru builds every Cargo project it finds in `PATH` that is not inside another one, so a project in a subfolder such as `core/` or `apps/desktop/src-tauri/` works. Each needs its own `Cargo.lock`. If one of them fails, the scan stops. With more than 8 such projects, scan one folder at a time.
- For a workspace, pass the workspace root, not a member folder.
- Compiled output is kept only for crates whose source is inside `PATH`. Dependencies from a registry or from git are built as usual but not read, so a secret is not followed into them.
- There is no time limit. Stop it with Ctrl-C if a build hangs.
- `--build` and `--llvm-ir` can be used together.

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
- The skill does not ship the scanner. Build seethru as shown in [Build and run](#build-and-run), then set `SEETHRU_BIN` to `target/release/seethru`, or put that file on your `PATH`.
- To use the skill without the plugin system, copy `plugins/seethru/skills/seethru` into `~/.claude/skills/`.
