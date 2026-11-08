use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

const FORBIDDEN_IN_SCRIPT: &[&str] = &["</script", "<!--"];
const FORBIDDEN_IN_STYLE: &[&str] = &["</style"];

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let dist = manifest_dir.join("../../web/dist");
    let js_path = dist.join("app.js");
    let css_path = dist.join("app.css");
    println!("cargo:rerun-if-changed={}", js_path.display());
    println!("cargo:rerun-if-changed={}", css_path.display());

    let (js, css) = match (fs::read_to_string(&js_path), fs::read_to_string(&css_path)) {
        (Ok(js), Ok(css)) => (js, css),
        _ => {
            println!(
                "cargo:warning=web UI bundle not found in web/dist, HTML reports are disabled until `pnpm build` runs"
            );
            (String::new(), String::new())
        }
    };
    check(&js, FORBIDDEN_IN_SCRIPT, "app.js")?;
    check(&css, FORBIDDEN_IN_STYLE, "app.css")?;

    fs::write(out_dir.join("app.js"), &js)?;
    fs::write(out_dir.join("app.css"), &css)?;
    let bundled = !js.is_empty() && !css.is_empty();
    let generated = format!(
        "pub(crate) const BUNDLED: bool = {bundled};\n\
         pub(crate) const APP_JS: &str = include_str!(concat!(env!(\"OUT_DIR\"), \"/app.js\"));\n\
         pub(crate) const APP_CSS: &str = include_str!(concat!(env!(\"OUT_DIR\"), \"/app.css\"));\n\
         pub(crate) const APP_JS_SHA256: &str = \"{}\";\n\
         pub(crate) const APP_CSS_SHA256: &str = \"{}\";\n",
        digest(&js),
        digest(&css),
    );
    write_if_changed(&out_dir.join("assets.rs"), &generated)?;
    Ok(())
}

fn check(content: &str, forbidden: &[&str], name: &str) -> Result<(), Box<dyn Error>> {
    let lower = content.to_ascii_lowercase();
    match forbidden.iter().find(|needle| lower.contains(*needle)) {
        Some(needle) => {
            Err(format!("{name} contains `{needle}` and cannot be inlined safely").into())
        }
        None => Ok(()),
    }
}

fn digest(content: &str) -> String {
    STANDARD.encode(Sha256::digest(content.as_bytes()))
}

fn write_if_changed(path: &Path, content: &str) -> Result<(), Box<dyn Error>> {
    if fs::read_to_string(path).is_ok_and(|current| current == content) {
        return Ok(());
    }
    fs::write(path, content)?;
    Ok(())
}
