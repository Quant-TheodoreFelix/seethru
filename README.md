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


| Check                     | What it finds                                                                                |
|---------------------------|----------------------------------------------------------------------------------------------|
| Supabase RLS              | Tables with RLS off and policies that open every row, from migration SQL                     |
| service_role key exposure | Browser code that reads the service_role key from a public env variable                      |
| Exposed secrets           | API keys and database URLs in code, build output and env files                               |
| Missing table schema      | Tables the code queries that no SQL file in the repo creates, so their RLS cannot be checked |

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

| Rule ID                            | Severity        | Finding                                                                                |
|------------------------------------|-----------------|----------------------------------------------------------------------------------------|
| `supabase-rls-disabled`            | Critical        | A table in the `public` schema has RLS off                                             |
| `supabase-policy-unrestricted`     | Low to Critical | A policy lets anyone, or any signed-in user, reach every row                           |
| `supabase-service-role-in-browser` | Critical        | Browser code reads the service_role key from a public env variable                     |
| `secret-in-browser-code`           | Critical        | A secret in code or files that reach the browser                                       |
| `secret-in-public-env-var`         | Critical        | A secret in an env variable with a public prefix such as `VITE_`                       |
| `secret-in-source-code`            | High            | A secret in a file that does not reach the browser, such as server code or an env file |
| `supabase-table-schema-missing`    | Info            | The code queries a table that no SQL file in the repo creates                          |

- A finding ID is the rule ID followed by the graph node, such as `supabase-rls-disabled:table:public.orders`.
- The ID of a secret finding names the file, the kind of secret and its order among secrets of that kind in the file, such as `secret-in-source-code:secret:src/pay.ts:stripeSecretKey:1`. It stays the same when other code in the file moves.
- Accepted findings stay in the report and the CLI summary under their own heading, with the reason. They do not count toward the totals or color the graph.
- If `seethru.toml` cannot be used, the scan stops and names the line instead of ignoring it. That covers unknown keys, a missing reason, an unknown rule ID and invalid patterns. The file must be a regular file of up to 64 KB, with at most 256 `exclude` patterns and 1,000 `[[accept]]` entries.
- `--no-config` ignores the file. Use it when you review a project someone else wrote, so its config cannot hide anything from you.

## Build output

seethru never runs your build. Build the project yourself, then pass the output folder.

```bash
$ seethru scan . --build-output dist
$ seethru scan . --build-output .next
```

- The folder must be inside the scanned project and must not be a symbolic link. It is read even when an `exclude` pattern matches it.
- **Vite**: turn on `build.manifest` and `build.sourcemap` in `vite.config` so seethru can see every file in the bundle. With source maps for every chunk, files that the bundle leaves out are no longer treated as browser code.
- **Next**: seethru reads `.next`. The `"use client"` files are confirmed from the build manifests. To confirm every file that reaches the browser, set `productionBrowserSourceMaps: true` in `next.config`. Routes from the build appear as entry points in the graph.
- Findings on files that the build output confirms are no longer marked as likely. A secret found in a bundle points back to its source line through the source map.
- If any source file is newer than the build output by more than 2 seconds, the build output is not used and the report says so under "Not checked". Build again and rerun.
- Even without the option, files under `.next/server` and `.next/standalone` are treated as server code, `.next/static` as browser code and `.next/cache` as build cache.

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, checks and how to add a new rule.

## Responsible use

Only use seethru on apps you own or are authorized to test. seethru does not run dynamic checks against any target that has not passed ownership verification.

## License

Licensed under the [Apache License 2.0](LICENSE).
