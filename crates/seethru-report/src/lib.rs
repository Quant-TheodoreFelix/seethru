mod assets {
    include!(concat!(env!("OUT_DIR"), "/assets.rs"));
}

use std::fmt;

use seethru_core::{Lang, ScanReport};

pub const DATA_ELEMENT_ID: &str = "seethru-report";

#[derive(Debug)]
pub enum ReportError {
    WebUiMissing,
    Serialize(serde_json::Error),
}

impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WebUiMissing => f.write_str(
                "this build of seethru has no web UI bundle, run `pnpm build` and rebuild to enable HTML reports",
            ),
            Self::Serialize(error) => write!(f, "cannot serialize report: {error}"),
        }
    }
}

impl std::error::Error for ReportError {}

pub fn html_available() -> bool {
    assets::BUNDLED
}

pub fn render_html(report: &ScanReport, lang: Lang) -> Result<String, ReportError> {
    if !assets::BUNDLED {
        return Err(ReportError::WebUiMissing);
    }
    let data = serde_json::to_string(report).map_err(ReportError::Serialize)?;
    let data = escape_json_for_script(&data);
    let csp = content_security_policy();
    let title = escape_html(&report.target.name);
    let mut html =
        String::with_capacity(assets::APP_JS.len() + assets::APP_CSS.len() + data.len() + 1024);
    html.push_str(&format!(
        "<!doctype html>\n<html lang=\"{}\">\n<head>\n<meta charset=\"utf-8\">\n",
        lang.code()
    ));
    html.push_str(&format!(
        "<meta http-equiv=\"Content-Security-Policy\" content=\"{csp}\">\n"
    ));
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    html.push_str("<meta name=\"referrer\" content=\"no-referrer\">\n");
    html.push_str(&format!("<title>seethru - {title}</title>\n"));
    html.push_str("<style>");
    html.push_str(assets::APP_CSS);
    html.push_str("</style>\n</head>\n<body>\n<div id=\"root\"></div>\n");
    html.push_str(&format!(
        "<script type=\"application/json\" id=\"{DATA_ELEMENT_ID}\">"
    ));
    html.push_str(&data);
    html.push_str("</script>\n<script type=\"module\">");
    html.push_str(assets::APP_JS);
    html.push_str("</script>\n</body>\n</html>\n");
    Ok(html)
}

fn content_security_policy() -> String {
    [
        "default-src 'none'".to_owned(),
        format!("script-src 'sha256-{}'", assets::APP_JS_SHA256),
        format!("style-src 'sha256-{}'", assets::APP_CSS_SHA256),
        "img-src data:".to_owned(),
        "font-src 'none'".to_owned(),
        "connect-src 'none'".to_owned(),
        "worker-src 'none'".to_owned(),
        "frame-src 'none'".to_owned(),
        "object-src 'none'".to_owned(),
        "base-uri 'none'".to_owned(),
        "form-action 'none'".to_owned(),
    ]
    .join("; ")
}

fn escape_json_for_script(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        match c {
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out
}

fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{escape_html, escape_json_for_script};

    #[test]
    fn json_cannot_close_the_script_element() {
        let json = r#"{"label":"</script><script>alert(1)</script>&"}"#;
        let escaped = escape_json_for_script(json);
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        let parsed: serde_json::Value = serde_json::from_str(&escaped).unwrap_or_default();
        assert_eq!(parsed["label"], "</script><script>alert(1)</script>&");
    }

    #[test]
    fn title_is_html_escaped() {
        assert_eq!(
            escape_html("a<b>\"c\"&'d'\n"),
            "a&lt;b&gt;&quot;c&quot;&amp;&#39;d&#39;"
        );
    }
}
