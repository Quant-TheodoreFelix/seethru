# seethru

<div align="center">

**"_See through_ your app before attackers do."**

English | [한국어](README_KR.md)

</div>

seethru is a **defensive security checker** that lets you see the security problems in your vibe-coded app and fix them yourself with the AI tools you already use. It belongs to the same category as DAST (Dynamic Application Security Testing) tools such as OWASP ZAP and Burp Suite. What sets it apart is **how it shows** the results and **how it fixes** them.

> [!WARNING]
> Early stage of development. Offline static analysis (Security Map) and fix prompts (Fix Prompt) work today. Dynamic checks (Proof Replay) have a first step: security headers and CORS on the first page of a running app you proved is yours. Reproducing access problems between test accounts is not implemented yet.

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

By default seethru only reads files. It runs or sends something only when you name it with an option, and it prints what it is about to run first.

All options, `seethru.toml`, finding IDs, exit codes, and the notes for each kind of project (Next and Vite, Supabase, C, C++ and firmware, Rust, SARIF results) are in [USAGE.md](USAGE.md).

## What it checks

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
| Checks that can stop a program | In compiled Rust code of a kernel, firmware or FFI library, a check that panics on a value from an exported entry point |
| Cargo dependencies        | Git and `*` dependencies that are not fixed to one version in a project with no `Cargo.lock`                         |
| Removed memory wipes      | In a built Rust program, a line that clears memory in the source and has no code in the program. Needs `--tool`      |
| Security headers          | On the first page of a running app you own, a missing content security policy, `nosniff`, frame protection or HSTS. Needs `--probe` |
| Open CORS                 | A running app you own that lets any site read its answers with the visitor's cookies. Needs `--probe`                |
| Missing table schema      | Tables the code queries that no SQL file in the repo creates, so their RLS cannot be checked                         |

## Beyond reading files

Each of these is off until you turn it on with an option.

- **Built programs.** `seethru scan . --build --tool objdump --tool dwarfdump` checks whether the memory wipes in your Rust source are still in the program the compiler made. `--tool` names the outside tools seethru may run. See [USAGE.md](USAGE.md#checking-that-memory-wipes-are-still-in-the-built-program).
- **A running app.** `seethru own URL` gives you one line to put on your app. After that, `seethru scan . --probe URL --staging --tool curl` checks the security headers and CORS of its first page with a few slow, read-only requests, and writes every request to an audit log first. See [USAGE.md](USAGE.md#checking-a-running-app).
- **Coding agents (MCP).** `seethru mcp --root DIR` lets an agent such as Claude Code or Cursor scan a folder and read the findings. Only the flags you start it with decide what may run. The agent cannot change them. See [USAGE.md](USAGE.md#using-seethru-from-a-coding-agent-mcp).

## Agent skill

This repository is also a Claude Code plugin marketplace. The `seethru` plugin adds a skill that lets a coding agent run a scan, read the report, fix the findings in order and rescan to prove the fix. The skill makes the agent ask you before every step that builds, runs an outside tool or checks a running app. Install it inside Claude Code with `/plugin install seethru --marketplace Quant-TheodoreFelix/seethru`. Other install, update and removal commands are in [USAGE.md](USAGE.md#agent-skill).

## Safety by design

**seethru is not an attack tool.** The principles below are not optional. They are required for *every feature*.

1. **No dynamic checks without proof of ownership**: Only domains whose ownership has been verified through a DNS TXT record or a file such as `/.well-known/` are checked, and verification is repeated periodically.
2. **Scope lock**: No request is sent outside the verified domain. If a redirect reaches an external domain, the check stops immediately.
3. **Non-destructive checks only**: No deleting or modifying data, no denial of service, no bulk requests. Only test accounts created by the user are used.
4. **Rate limiting**: Request rates are limited so the target server is never overloaded.
5. **No collection of real user data**: Real data exposed during a reproduction is masked and never stored.
6. **Audit log**: Every check request is logged and can be reviewed by the user.
7. **Staging first**: Checking production requires explicit confirmation.

The check of a running app follows all seven today. Ownership is proved with a file under `/.well-known/` (the DNS TXT method is not built yet), only `GET` requests are sent, and test accounts are not used yet. The details are in [USAGE.md](USAGE.md#checking-a-running-app).

## Tech stack

Designed for Zero-Trust and Air-Gapped environments, favoring a single binary and a small dependency tree. Dependencies are pinned to exact versions and `unsafe` code is forbidden.

| Area   | Choice                                                                     |
|--------|----------------------------------------------------------------------------|
| Engine | Rust 1.99.1 (2024 edition), single binary, oxc (JS/TS parser)              |
| Data   | serde, serde_json, schemars (JSON Schema), toml, lexopt (CLI arguments)    |
| Web UI | React 19, React Flow, ELK.js, Motion, Vite 8, TypeScript 7, built with pnpm |

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
