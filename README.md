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

The report is written to `<project path>/.seethru/report.html`, and that directory is ignored by git automatically. The report opens as a single file without any outside requests, and every secret it finds is masked so the raw value never appears. Add `--json` to print the result as JSON.

| Check                     | What it finds                                                            |
|---------------------------|--------------------------------------------------------------------------|
| Supabase RLS              | Tables with RLS off and policies that open every row, from migration SQL |
| service_role key exposure | Browser code that reads the service_role key from a public env variable  |
| Exposed secrets           | API keys and database URLs in code, build output and env files           |

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

## Responsible use

Only use seethru on apps you own or are authorized to test. seethru does not run dynamic checks against any target that has not passed ownership verification.

## License

Licensed under the [Apache License 2.0](LICENSE).
