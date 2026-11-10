use std::cell::Cell;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use seethru_core::{DivisionLine, MachineCode, ScanReport};
use seethru_mcp::{
    Host, LATEST_PROTOCOL_VERSION, MAX_LINE_BYTES, Permissions, PlainHost, ScanRequest, plain_scan,
    serve,
};

struct Temp {
    root: PathBuf,
}

impl Temp {
    fn new(name: &str) -> Self {
        let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("mcp-{name}"));
        let _ = fs::remove_dir_all(&root);
        assert!(fs::create_dir_all(&root).is_ok());
        let Ok(root) = fs::canonicalize(&root) else {
            unreachable!("temp folder")
        };
        Self { root }
    }

    fn with_fixture(name: &str) -> Self {
        let temp = Self::new(name);
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/supabase-vite");
        copy(&fixture, &temp.root.join("app"));
        temp
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn copy(from: &Path, to: &Path) {
    assert!(fs::create_dir_all(to).is_ok());
    let Ok(entries) = fs::read_dir(from) else {
        unreachable!("fixture folder")
    };
    for entry in entries.flatten() {
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy(&entry.path(), &target);
        } else {
            assert!(fs::copy(entry.path(), &target).is_ok());
        }
    }
}

struct Counting {
    roots: Vec<PathBuf>,
    permissions: Permissions,
    scans: Cell<u32>,
    last: Cell<Option<ScanRequest>>,
}

impl Counting {
    fn new(root: &Path, permissions: Permissions) -> Self {
        Self {
            roots: vec![root.to_path_buf()],
            permissions,
            scans: Cell::new(0),
            last: Cell::new(None),
        }
    }
}

impl Host for Counting {
    fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    fn permissions(&self) -> &Permissions {
        &self.permissions
    }

    fn scan(&self, request: &ScanRequest) -> Result<ScanReport, String> {
        self.scans.set(self.scans.get() + 1);
        self.last.set(Some(request.clone()));
        plain_scan(&request.root)
    }
}

struct Listed(Counting);

impl Host for Listed {
    fn roots(&self) -> &[PathBuf] {
        self.0.roots()
    }

    fn permissions(&self) -> &Permissions {
        self.0.permissions()
    }

    fn scan(&self, request: &ScanRequest) -> Result<ScanReport, String> {
        let mut report = self.0.scan(request)?;
        report.target.machine_code = Some(MachineCode {
            divisions: 201,
            division_lines: (1..=201)
                .map(|line| DivisionLine {
                    path: "src/lib.rs".to_owned(),
                    line,
                    secret: false,
                    assembly: false,
                })
                .collect(),
            ..MachineCode::default()
        });
        Ok(report)
    }
}

fn run_raw(host: &dyn Host, input: &[u8]) -> Vec<Value> {
    let mut output = Vec::new();
    assert!(serve(Cursor::new(input), &mut output, host).is_ok());
    let Ok(text) = String::from_utf8(output) else {
        unreachable!("output is UTF-8")
    };
    text.lines()
        .map(|line| {
            let Ok(value) = serde_json::from_str::<Value>(line) else {
                unreachable!("each line is JSON: {line}")
            };
            assert_eq!(value["jsonrpc"], "2.0");
            value
        })
        .collect()
}

fn run(host: &dyn Host, messages: &[Value]) -> Vec<Value> {
    let mut input = String::new();
    for message in messages {
        input.push_str(&message.to_string());
        input.push('\n');
    }
    run_raw(host, input.as_bytes())
}

fn initialize(version: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": { "name": "test", "version": "0" },
        },
    })
}

fn initialized() -> Value {
    json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
}

fn call(id: u32, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": name, "arguments": arguments },
    })
}

fn is_tool_error(reply: &Value) -> bool {
    reply["result"]["isError"] == true && reply["result"].get("structuredContent").is_none()
}

fn error_text(reply: &Value) -> &str {
    reply["result"]["content"][0]["text"].as_str().unwrap_or("")
}

#[test]
fn a_whole_session_scans_and_explains_a_finding() {
    let temp = Temp::with_fixture("session");
    let app = temp.root.join("app");
    let host = PlainHost::new(vec![temp.root.clone()]);
    let path = app.display().to_string();
    let first = run(
        &host,
        &[
            initialize(LATEST_PROTOCOL_VERSION),
            initialized(),
            json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }),
            call(2, "scan", json!({ "path": path })),
        ],
    );
    assert_eq!(first.len(), 3, "{first:?}");
    assert_eq!(
        first[0]["result"]["protocolVersion"],
        LATEST_PROTOCOL_VERSION
    );
    assert_eq!(first[0]["result"]["serverInfo"]["name"], "seethru");
    assert!(first[0]["result"]["capabilities"]["tools"].is_object());
    assert!(
        first[0]["result"]["instructions"]
            .as_str()
            .is_some_and(|text| text.contains("ask the user"))
    );
    let Some(tools) = first[1]["result"]["tools"].as_array() else {
        unreachable!("tools")
    };
    let names: Vec<&str> = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    assert_eq!(
        names,
        ["scan", "get_finding", "list_limitations", "get_permissions"]
    );
    for tool in tools {
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert!(
            tool["description"]
                .as_str()
                .is_some_and(|text| !text.is_empty())
        );
    }
    let scan = &first[2]["result"];
    assert!(scan.get("isError").is_none(), "{scan}");
    let structured = &scan["structuredContent"];
    let Some(text) = scan["content"][0]["text"].as_str() else {
        unreachable!("text content")
    };
    assert_eq!(
        serde_json::from_str::<Value>(text).ok().as_ref(),
        Some(structured)
    );
    let Some(findings) = structured["findings"].as_array() else {
        unreachable!("findings")
    };
    assert!(!findings.is_empty());
    assert_eq!(structured["findingsTotal"], findings.len());
    assert_eq!(structured["findingsCapped"], false);
    assert_eq!(structured["ran"], json!({ "build": false, "tools": [] }));
    assert!(structured.get("machineCode").is_none(), "{structured}");
    let root_text = temp.root.display().to_string();
    let listed = structured["findings"].to_string() + &structured["limitations"].to_string();
    assert!(!listed.contains(&root_text));
    let Some(id) = findings[0]["id"].as_str() else {
        unreachable!("id")
    };

    let second = run(
        &host,
        &[
            initialize(LATEST_PROTOCOL_VERSION),
            call(1, "scan", json!({ "path": "app", "lang": "ko" })),
            call(
                2,
                "get_finding",
                json!({ "path": path, "id": id, "lang": "ko" }),
            ),
            call(3, "list_limitations", json!({ "path": path })),
            call(4, "get_finding", json!({ "path": path, "id": "nope" })),
        ],
    );
    assert_eq!(second.len(), 5, "{second:?}");
    let again = &second[1]["result"]["structuredContent"];
    assert_eq!(again["findingsTotal"], structured["findingsTotal"]);
    assert_eq!(again["findings"][0]["id"], id);
    assert_ne!(again["findings"][0]["title"], findings[0]["title"]);
    let finding = &second[2]["result"]["structuredContent"];
    assert_eq!(finding["id"], id);
    assert!(
        finding["explanation"]
            .as_str()
            .is_some_and(|text| !text.is_empty())
    );
    assert!(finding["evidence"].is_array());
    assert_eq!(finding["origin"]["engine"], "seethru");
    assert!(finding["cwe"].is_array());
    assert!(
        finding["fixPrompt"]
            .as_str()
            .is_some_and(|text| !text.is_empty())
    );
    assert!(second[3]["result"]["structuredContent"]["limitations"].is_array());
    assert!(is_tool_error(&second[4]));
}

#[test]
fn a_long_machine_code_list_is_cut_and_the_cut_is_said() {
    let temp = Temp::with_fixture("machine-list");
    let host = Listed(Counting::new(&temp.root, Permissions::default()));
    let replies = run(
        &host,
        &[
            initialize(LATEST_PROTOCOL_VERSION),
            call(1, "scan", json!({ "path": "app" })),
        ],
    );
    let machine = &replies[1]["result"]["structuredContent"]["machineCode"];
    assert_eq!(machine["divisions"], 201, "{}", replies[1]);
    assert_eq!(machine["linesCapped"], true);
    assert_eq!(machine["divisionLines"].as_array().map(Vec::len), Some(200));
}

#[test]
fn follow_up_tools_need_a_scan_first() {
    let temp = Temp::with_fixture("unscanned");
    let host = PlainHost::new(vec![temp.root.clone()]);
    let replies = run(
        &host,
        &[
            initialize(LATEST_PROTOCOL_VERSION),
            call(1, "list_limitations", json!({ "path": "app" })),
        ],
    );
    assert!(is_tool_error(&replies[1]));
    assert!(error_text(&replies[1]).contains("scan first"));
}

#[test]
fn an_unknown_version_gets_the_latest_and_an_old_one_is_kept() {
    let temp = Temp::with_fixture("versions");
    let host = PlainHost::new(vec![temp.root.clone()]);
    let unknown = run(&host, &[initialize("1999-01-01")]);
    assert_eq!(
        unknown[0]["result"]["protocolVersion"],
        LATEST_PROTOCOL_VERSION
    );
    let old = run(
        &host,
        &[
            initialize("2024-11-05"),
            call(1, "scan", json!({ "path": "app" })),
        ],
    );
    assert_eq!(old[0]["result"]["protocolVersion"], "2024-11-05");
    assert!(old[1]["result"]["content"][0]["text"].is_string());
    assert!(old[1]["result"].get("structuredContent").is_none());
}

#[test]
fn a_folder_outside_the_allowed_roots_is_refused() {
    let temp = Temp::with_fixture("outside");
    let allowed = temp.root.join("app");
    let other = temp.root.join("other");
    assert!(fs::create_dir_all(&other).is_ok());
    let host = Counting::new(&allowed, Permissions::default());
    let mut messages = vec![initialize(LATEST_PROTOCOL_VERSION)];
    let tries = [
        other.display().to_string(),
        "..".to_owned(),
        "../other".to_owned(),
        allowed.join("..").join("other").display().to_string(),
        "/".to_owned(),
        allowed.join("missing").display().to_string(),
        allowed.join("vite.config.ts").display().to_string(),
    ];
    for (at, path) in tries.iter().enumerate() {
        messages.push(call(at as u32 + 1, "scan", json!({ "path": path })));
    }
    let replies = run(&host, &messages);
    assert_eq!(replies.len(), tries.len() + 1);
    for reply in &replies[1..] {
        assert!(is_tool_error(reply), "{reply}");
        assert!(error_text(reply).contains("--root"));
    }
    assert_eq!(host.scans.get(), 0);
}

#[cfg(unix)]
#[test]
fn a_link_that_leaves_the_allowed_root_is_refused() {
    let temp = Temp::with_fixture("link");
    let allowed = temp.root.join("app");
    let other = temp.root.join("other");
    assert!(fs::create_dir_all(&other).is_ok());
    assert!(std::os::unix::fs::symlink(&other, allowed.join("escape")).is_ok());
    let host = Counting::new(&allowed, Permissions::default());
    let replies = run(
        &host,
        &[
            initialize(LATEST_PROTOCOL_VERSION),
            call(1, "scan", json!({ "path": "escape" })),
            call(
                2,
                "scan",
                json!({ "path": allowed.join("escape").display().to_string() }),
            ),
            call(3, "scan", json!({ "path": "src" })),
        ],
    );
    assert!(is_tool_error(&replies[1]));
    assert!(is_tool_error(&replies[2]));
    assert!(replies[3]["result"].get("isError").is_none());
    assert_eq!(host.scans.get(), 1);
}

#[test]
fn arguments_cannot_allow_what_the_user_did_not() {
    let temp = Temp::with_fixture("refuse");
    let host = Counting::new(&temp.root, Permissions::default());
    let replies = run(
        &host,
        &[
            initialize(LATEST_PROTOCOL_VERSION),
            call(1, "scan", json!({ "path": "app", "build": true })),
            call(2, "scan", json!({ "path": "app", "tools": ["objdump"] })),
            call(
                3,
                "scan",
                json!({ "path": "app", "allow_build": true, "build": true }),
            ),
            call(4, "get_permissions", json!({})),
        ],
    );
    assert!(is_tool_error(&replies[1]));
    assert!(error_text(&replies[1]).contains("--allow-build"));
    assert!(is_tool_error(&replies[2]));
    assert!(error_text(&replies[2]).contains("--tool"));
    assert!(is_tool_error(&replies[3]));
    assert_eq!(host.scans.get(), 0);
    let allowed = &replies[4]["result"]["structuredContent"];
    assert_eq!(allowed["build"], false);
    assert_eq!(allowed["tools"], json!([]));
    assert!(
        allowed["askFirst"]
            .as_str()
            .is_some_and(|text| text.contains("Ask the user"))
    );
}

#[test]
fn what_the_user_allowed_reaches_the_host() {
    let temp = Temp::with_fixture("allowed");
    let permissions = Permissions {
        build: true,
        tools: vec!["objdump".to_owned()],
    };
    let host = Counting::new(&temp.root, permissions);
    let replies = run(
        &host,
        &[
            initialize(LATEST_PROTOCOL_VERSION),
            call(
                1,
                "scan",
                json!({ "path": "app", "build": true, "tools": ["objdump"] }),
            ),
            call(
                2,
                "scan",
                json!({ "path": "app", "tools": ["objdump", "ghidra"] }),
            ),
        ],
    );
    assert!(
        replies[1]["result"].get("isError").is_none(),
        "{}",
        replies[1]
    );
    assert!(is_tool_error(&replies[2]));
    assert_eq!(host.scans.get(), 1);
    let Some(request) = host.last.take() else {
        unreachable!("request")
    };
    assert!(request.build);
    assert_eq!(request.tools, ["objdump"]);
    assert_eq!(request.root, temp.root.join("app"));
}

#[test]
fn bad_input_gets_an_error_and_the_loop_goes_on() {
    let temp = Temp::with_fixture("bad");
    let host = Counting::new(&temp.root, Permissions::default());
    let mut input = Vec::new();
    let mut push = |line: &str| {
        input.extend_from_slice(line.as_bytes());
        input.push(b'\n');
    };
    push(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }).to_string());
    push(&json!({ "jsonrpc": "2.0", "id": 2, "method": "ping" }).to_string());
    push(&initialize(LATEST_PROTOCOL_VERSION).to_string());
    push("{ not json");
    push("");
    push("[1, 2]");
    push(r#"{"jsonrpc":"2.0","id":3}"#);
    push(r#"{"jsonrpc":"1.0","id":4,"method":"ping"}"#);
    push(r#"{"jsonrpc":"2.0","id":{},"method":"ping"}"#);
    push(r#"{"jsonrpc":"2.0","id":5,"method":"nope/nothing"}"#);
    push(r#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#);
    push(r#"{"jsonrpc":"2.0","id":6,"result":{}}"#);
    push(r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"nope"}}"#);
    push(r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{}}"#);
    push(r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"scan"}}"#);
    push(
        r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"scan","arguments":{"path":7}}}"#,
    );
    push(
        r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"scan","arguments":[]}}"#,
    );
    push(r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":[]}"#);
    push(
        r#"{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"scan","arguments":{"path":"app","lang":"fr"}}}"#,
    );
    let long = format!(
        r#"{{"jsonrpc":"2.0","id":14,"method":"ping","params":{{"pad":"{}"}}}}"#,
        "a".repeat(MAX_LINE_BYTES)
    );
    push(&long);
    input.extend_from_slice(b"\xff\xfe\n");
    input.extend_from_slice(br#"{"jsonrpc":"2.0","id":"last","method":"ping"}"#);

    let replies = run_raw(&host, &input);
    let codes: Vec<(Value, Value)> = replies
        .iter()
        .map(|reply| (reply["id"].clone(), reply["error"]["code"].clone()))
        .collect();
    let null = Value::Null;
    let expected = [
        (json!(1), json!(-32600)),
        (json!(2), null.clone()),
        (json!(0), null.clone()),
        (null.clone(), json!(-32700)),
        (null.clone(), json!(-32600)),
        (json!(3), json!(-32600)),
        (json!(4), json!(-32600)),
        (null.clone(), json!(-32600)),
        (json!(5), json!(-32601)),
        (json!(7), json!(-32602)),
        (json!(8), json!(-32602)),
        (json!(9), null.clone()),
        (json!(10), null.clone()),
        (json!(11), json!(-32602)),
        (json!(12), json!(-32602)),
        (json!(13), null.clone()),
        (null.clone(), json!(-32600)),
        (null.clone(), json!(-32700)),
        (json!("last"), null.clone()),
    ];
    assert_eq!(codes, expected, "{replies:#?}");
    for at in [11, 12, 15] {
        assert!(is_tool_error(&replies[at]), "{}", replies[at]);
    }
    for reply in &replies {
        assert!(reply.get("result").is_some() != reply.get("error").is_some());
    }
    assert_eq!(host.scans.get(), 0);
}
