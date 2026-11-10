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
- [Checking that memory wipes are still in the built program](#checking-that-memory-wipes-are-still-in-the-built-program)
- [Checking a running app](#checking-a-running-app)
- [Results from other scanners](#results-from-other-scanners)
- [Using seethru from a coding agent (MCP)](#using-seethru-from-a-coding-agent-mcp)
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
| `seethru own URL [PATH]` | Print the address and the one line a running app must serve before seethru will check it. Sends nothing (see [Checking a running app](#checking-a-running-app)) |
| `seethru mcp`            | Run as an MCP server for a coding agent, over standard input and output (see [Using seethru from a coding agent (MCP)](#using-seethru-from-a-coding-agent-mcp)) |
| `seethru schema`         | Print the JSON Schema of the scan report                              |
| `seethru --version`      | Print the version                                                     |
| `seethru --help`         | Print the usage text. Running `seethru` with no arguments does the same |

The full form of the scan command is:

```sh
seethru scan [PATH] [--out FILE] [--json] [--lang LANG] [--no-config]
             [--build-output DIR] [--sarif FILE]... [--sarif-out FILE]
             [--compile-commands FILE] [--llvm-ir PATH]... [--build]
             [--binary FILE]... [--tool NAME[=PATH]]...
             [--probe URL (--staging | --production --confirm-production)]
seethru own URL [PATH] [--lang LANG]
seethru mcp [--root DIR]... [--allow-build] [--tool NAME[=PATH]]...
```

By default seethru only reads files. It runs something or sends something only when you name it with an option: `--build` runs a cargo build, `--tool` allows one outside tool, and `--probe` together with `--tool curl` sends requests to an app you proved is yours.

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
| `--binary FILE`      | A linked program (ELF or Mach-O) that you built from this project, to check that memory wipes are still in it. Up to 16 times. Reading it needs `--tool` (see [Checking that memory wipes are still in the built program](#checking-that-memory-wipes-are-still-in-the-built-program)) |
| `--tool NAME[=PATH]` | Allow seethru to run one outside tool on this computer. `NAME` is `objdump`, `dwarfdump` or `curl`. Nothing outside is run without it. `PATH` is the full path of the tool when it is not on `PATH` |
| `--probe URL`        | Also check the running app at `URL`, such as `https://staging.example.com`. Needs `--tool curl` and one of `--staging` or `--production` (see [Checking a running app](#checking-a-running-app)) |
| `--staging`          | The app at `URL` is a test copy. Prefer this                                       |
| `--production`       | The app at `URL` is the one real users use. Also needs `--confirm-production`      |
| `--confirm-production` | Say a second time that you mean the app real users use                           |

- `--lang` takes `en` or `ko`. Any other value is an error.
- `--json` and `--out` cannot be used together.
- `--sarif-out` must be a different file from every `--sarif` file and from `--out`.
- `--json` prints the report to the terminal. Without it, seethru prints a short summary and then the path of the report it wrote.
- `--tool objdump` and `--tool dwarfdump` need something to read, so they need `--binary` or `--build`. `--tool curl` needs `--probe`. The same tool cannot be named twice, and a `PATH` must be a full path.
- `--probe` needs exactly one of `--staging` and `--production`. `--production` without `--confirm-production` is an error, and nothing is sent.
- Before it runs an outside tool, seethru prints the full command on stderr.

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
| `memory-wipe-removed`                  | Low             | A line that fills memory with zeros is in the Rust source, and the built program has no code for it. Needs `--tool objdump --tool dwarfdump` |
| `security-header-missing`              | Low             | The first page of the running app answers without a security header. One finding per header. Needs `--probe`                 |
| `cors-allows-any-origin-with-credentials` | Low to Medium | The running app tells browsers that any site may read its answers together with the visitor's cookies. Needs `--probe`      |

### Finding IDs

- A finding ID is the rule ID followed by the graph node, such as `supabase-rls-disabled:table:public.orders`.
- The ID of a `secret-dependent-division` or `stop-on-outside-input` finding names the file and the order of the finding in that file, such as `secret-dependent-division:file:mldsa/src/sign.rs:2`. It does not carry the line number.
- The ID of a secret finding names the file, the kind of secret and its order among secrets of that kind in the file, such as `secret-in-source-code:secret:src/pay.ts:stripeSecretKey:1`. It stays the same when other code in the file moves.
- The ID of a `memory-wipe-removed` finding names the file and the position of that wipe among the wipes seethru recognizes in the file, such as `memory-wipe-removed:file:src/main.rs:1`. It does not carry the line number. Adding or removing such a wipe earlier in the same file changes the numbers after it.
- Findings on a running app do not name the address. They are `security-header-missing:header:<name>`, where the name is `content-security-policy`, `x-content-type-options`, `frame-protection` or `strict-transport-security`, and `cors-allows-any-origin-with-credentials:app`. The same app gets the same IDs on staging and on production, so one `[[accept]]` entry covers both.

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
- **What is not checked yet.** Branches and table lookups that depend on a secret. This was tried and gave too many wrong results to ship. The report says so every time.
- **Whether a wipe survives the compiler** cannot be seen in `.ll` and `.s` files. It is checked in the linked program, and only when you allow the tools that read it (see [Checking that memory wipes are still in the built program](#checking-that-memory-wipes-are-still-in-the-built-program)).
- A secret that is only wiped by a caller outside the compiled files, or that sits behind a pointer stored in memory, is not followed. The output of a library is from before the final link. No finding does not mean constant time.
- Paths in the compiled output must point into the scanned project, so build from the same checkout or use `--remap-path-prefix` to make them relative.

### Letting seethru build

```bash
seethru scan . --build
```

`--build` is the only option that runs code from your project. It is off unless you pass it. Outside tools are a separate permission, given with `--tool`.

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
- When the build makes a program and you did not pass `--tool objdump --tool dwarfdump`, the report says under "Not checked" that the program was there and was not read.

## Checking that memory wipes are still in the built program

Code that handles a key or a password often fills that memory with zeros when it is done, so the secret does not stay behind. A compiler is allowed to delete a write that nothing reads afterwards, and it often does. The source still shows the wipe. The program you ship does not have it. Only the finished program tells you which.

seethru can check this for Rust, if you let it run two tools that read a built program:

```bash
seethru scan . --build --tool objdump --tool dwarfdump
```

Or, for a program you built yourself:

```bash
seethru scan . --binary target/release/myapp --tool objdump --tool dwarfdump
```

- **What you need.** The LLVM versions of `objdump` and `dwarfdump`. On macOS they come with the Xcode command line tools. seethru goes through the folders on your `PATH` in order, and in each one looks for `llvm-objdump` and `llvm-dwarfdump` first, then for `objdump` and `dwarfdump`. If they are somewhere else, give the full path: `--tool objdump=/full/path/to/llvm-objdump`. Both tools are needed, because one shows which source line each instruction came from and the other shows where a function was copied into its caller.
- **What seethru looks for in the source.** Lines that fill memory with zeros and are the last use of that memory in the function: `x.fill(0)`, `write_bytes` and `memset` with zero, and `x = [0; N];`. Wipes the compiler must keep, such as `zeroize()` and `write_volatile`, are used to make sure the method works on your program. They are never reported.
- **What is reported.** `memory-wipe-removed`, when the program has code for the rest of the function and none for that line, and at least one other wipe in the same program was found by the same method. It is `likely` when every wipe that must be there was found, and `review` otherwise. Severity is Low: someone needs a second problem, such as a crash dump, to read the leftover secret.
- **If the line only clears a buffer that holds no secret**, the compiler was right to remove it. Accept the finding in `seethru.toml` with a reason.
- **With `--build`**, seethru reads the linked programs the build makes (executables and dynamic libraries). A project that is only a library makes none, and the report says so. Wipes disappear when the program that uses the library is built, so pass that program with `--binary`.
- **`--binary`** takes a linked ELF or Mach-O file, up to 16 of them. An object file, a file with more than one architecture, or anything else is an error. The program must be built from the same checkout and must have line information. `--build` adds it for you. For your own cargo build, turn it on, for example with `debug = "line-tables-only"` in the release profile. On macOS the line information is in the `.dSYM` folder, which must stay next to the program. In an ELF program it is inside the file, so a stripped one cannot be checked. A program without line information is not checked, and the report says so.
- **How the tools are run.** seethru runs the tool directly, without a shell, with an empty environment, and prints the command first. It never runs a program that sits inside the scanned project. A tool gets 600 seconds. Set `SEETHRU_TOOL_TIMEOUT_SECS` (1 to 86400) to change that. If a tool is missing, is not the LLVM version, runs out of time or prints something seethru does not understand, the program is not checked and the report says so. Nothing of what the tool prints goes into the report except file paths inside your project and line numbers.
- **What this does not tell you.** Line information in an optimized program is not exact, so read the code before you trust a finding. Wipes done when a value is dropped, wipes inside macros, wipes in other languages, plain loops such as `*b = 0` and `self.fill(0)` are not recognized. A wipe that is still there does not prove that every copy of the secret is cleared. The report lists these limits every time.
- This check has been run on seethru's own test program and on two real projects, on macOS, one of which builds programs. No real project has produced a finding yet, so how often it is wrong on real code is not known. It has not been tried with the tools of a Linux system.

## Checking a running app

seethru can also look at the app you deployed. This is the only case where seethru sends anything over the network, and it does so only to an app you proved is yours.

**1. Ask seethru for the proof line.** Nothing is sent.

```bash
seethru own https://staging.example.com .
```

seethru prints an address and one line:

```
https://staging.example.com/.well-known/seethru-ownership.txt
seethru-ownership=<64 hex characters>
```

**2. Make the app serve that line at that address.** A plain text file with that one line is enough. In most web projects this is a file named `seethru-ownership.txt` in a `.well-known` folder inside the folder for static files, such as `public`.

**3. Deploy the app.**

**4. Scan with `--probe`.**

```bash
seethru scan . --probe https://staging.example.com --staging --tool curl
```

What to know:

- **The line is safe to publish.** It is made from a secret that stays on your computer in `PATH/.seethru/ownership`. A person who reads the line on your site cannot use it to check your app. The line works for one address only, so staging and production each need their own `seethru own`. Run the scan on the same project folder where you ran `seethru own`, because the secret is kept there. `.seethru` is ignored by git, so the secret is not committed. Remove the file from the app when you no longer want checks.
- **Staging first.** Say which kind of app the address is. `--staging` is a test copy. `--production` is the app real users use, and it also needs `--confirm-production`. Without that, seethru stops and sends nothing.
- **What is sent.** A few plain `GET` requests through `curl`, to that address only: first the proof file, then the first page, then the first page again with a made-up `Origin` header. There are no logins, no cookies, no request bodies and nothing that changes data. Requests are at least half a second apart, and one run sends at most 40.
- **seethru stays on your address.** A redirect to another site is not followed and the check ends there. The network address that answered the first request is kept for the rest of the run.
- **Only `https://`.** `http://` is accepted only for an app on this computer (`localhost` or `127.0.0.1`), because anyone on the network can read or change a plain `http` request.
- **What is kept.** The status code and up to eight response headers that the checks need. Page content is thrown away as it arrives, and cookies are never kept.
- **The audit log.** Every request is written to `PATH/.seethru/audit.jsonl` before it is sent, with the time, the path, why it was sent and the status that came back. If the log cannot be written, the request is not sent.
- **Proof files.** Each finding points to a file in `PATH/.seethru/proof` that lists the requests that showed it. The summary and the HTML report name the file.
- **What is reported.** `security-header-missing`: no content security policy, no `X-Content-Type-Options: nosniff`, nothing that stops other sites from showing the page in a frame, and on `https` no `Strict-Transport-Security`. `cors-allows-any-origin-with-credentials`: the app tells browsers that any site may read its answers with the visitor's cookies.
- **What is not checked.** Only the first page is read. Other pages, API addresses, logging in, and whether one account can read another account's data are not checked. Whether a content security policy is a good one is not judged. The report says so under "Not checked".
- The fix is in the app or in the hosting settings. After you fix it, deploy and scan again, because only the running app shows the result.
- The report, the HTML file and the JSON do not contain the address of the app. The audit log does.
- `--sarif-out` leaves these findings out, because a SARIF result needs a file and a line. seethru says how many it left out. They are in the report.
- `curl` gets 30 seconds per request. `SEETHRU_TOOL_TIMEOUT_SECS` changes that too.
- So far this has been run against test servers on the same computer. It has not been run against a real `https` site from start to finish.

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
- `--sarif-out` writes seethru's own findings as SARIF, for example for GitHub code scanning. Accepted findings are marked as suppressed. Results that came from another scanner are not written again. Findings on a running app have no file and are left out. seethru prints how many.
- Joern's `joern-scan` prints text and has no SARIF option. Joern exports SARIF from a script that calls `cpg.finding.toSarifJson()`. The `tests/test-sarif.sc` file in the Joern repository shows how.

## Using seethru from a coding agent (MCP)

`seethru mcp` lets a coding agent such as Claude Code or Cursor call seethru through MCP (Model Context Protocol). The agent can scan a folder, read a finding in full and see what was not checked.

Register it with the full path of the `seethru` program and the folder the agent may scan. For Claude Code:

```bash
claude mcp add seethru -- /full/path/to/seethru mcp --root /full/path/to/project
```

For an agent that reads a JSON list of MCP servers:

```json
{
  "mcpServers": {
    "seethru": {
      "command": "/full/path/to/seethru",
      "args": ["mcp", "--root", "/full/path/to/project"]
    }
  }
}
```

**Only the flags you start the server with decide what may run.** The agent cannot change them from inside a conversation.

| Flag                 | What it allows                                                                    |
|----------------------|-----------------------------------------------------------------------------------|
| `--root DIR`         | A folder the agent may scan. Can be given more than once. Without it, only the folder the server was started in |
| `--allow-build`      | The agent may ask for a scan that builds the project, like `--build`              |
| `--tool NAME[=PATH]` | The agent may ask for a scan that runs this outside tool. `objdump` and `dwarfdump` only, and it needs `--allow-build` |

- Without `--allow-build` and `--tool`, the server only reads files.
- When the agent asks for something you did not allow, the server refuses and tells the agent to ask you. To allow it, change the registration yourself and restart the agent.
- Even when a build or a tool is allowed, the server tells the agent to ask you before each call that uses one.
- A folder outside the `--root` folders is refused, also through a symbolic link.
- The tools the agent gets:

| Tool               | What it does                                                                     |
|--------------------|----------------------------------------------------------------------------------|
| `scan`             | Scans a folder and returns the counts, up to 200 findings and what was not checked |
| `get_finding`      | Returns one finding of the last scan in full, with the fix prompt                |
| `list_limitations` | Returns what the last scan could not check                                       |
| `get_permissions`  | Returns what you allowed when you started the server                             |

- Checking a running app (`--probe`) is not available through MCP. Neither are `--binary`, `--llvm-ir`, `--build-output`, `--sarif`, `--compile-commands` and `--no-config`. A scan through MCP always reads the project's `seethru.toml`. Use the command line for those.
- The server speaks MCP over standard input and output, protocol versions `2025-11-25`, `2025-06-18`, `2025-03-26` and `2024-11-05`.

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
