use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;

const MAX_SOURCES: usize = 100_000;
const MAX_SECTIONS: usize = 10_000;
const MAX_VLQ_SHIFT: u32 = 60;
const MAPPING_URL_MARKER: &str = "sourceMappingURL=";
const INLINE_PREFIX: &str = "data:application/json;base64,";
const TAIL_BYTES: usize = 4096;

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawMap {
    sources: Vec<Option<String>>,
    #[serde(rename = "sourceRoot")]
    source_root: Option<String>,
    mappings: String,
    sections: Vec<RawSection>,
}

#[derive(Deserialize)]
struct RawSection {
    offset: RawOffset,
    map: RawMap,
}

#[derive(Deserialize)]
struct RawOffset {
    line: u32,
    column: u32,
}

struct Part {
    line: u32,
    column: u32,
    sources: Vec<Option<String>>,
    source_root: Option<String>,
    mappings: String,
}

pub(crate) struct SourceMap {
    parts: Vec<Part>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Mapped<'a> {
    pub source: &'a str,
    pub source_root: Option<&'a str>,
    pub line: u32,
    pub column: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MapRef {
    Path(String),
    Inline(Vec<u8>),
}

impl SourceMap {
    pub(crate) fn parse(bytes: &[u8]) -> Option<Self> {
        let raw: RawMap = serde_json::from_slice(bytes).ok()?;
        let mut parts = Vec::new();
        if raw.sections.is_empty() {
            parts.push(Part {
                line: 0,
                column: 0,
                sources: raw.sources,
                source_root: raw.source_root,
                mappings: raw.mappings,
            });
        } else {
            for section in raw.sections.into_iter().take(MAX_SECTIONS) {
                if !section.map.sections.is_empty() {
                    continue;
                }
                parts.push(Part {
                    line: section.offset.line,
                    column: section.offset.column,
                    sources: section.map.sources,
                    source_root: section.map.source_root,
                    mappings: section.map.mappings,
                });
            }
        }
        let mut budget = MAX_SOURCES;
        for part in &mut parts {
            part.sources.truncate(budget);
            budget = budget.saturating_sub(part.sources.len());
        }
        Some(Self { parts })
    }

    pub(crate) fn sources(&self) -> impl Iterator<Item = (Option<&str>, &str)> {
        self.parts.iter().flat_map(|part| {
            part.sources
                .iter()
                .flatten()
                .map(|source| (part.source_root.as_deref(), source.as_str()))
        })
    }

    pub(crate) fn lookup(&self, line: u32, column: u32) -> Option<Mapped<'_>> {
        let part = self
            .parts
            .iter()
            .rev()
            .find(|part| (part.line, part.column) <= (line, column))?;
        let local_line = line - part.line;
        let local_column = if local_line == 0 {
            column - part.column
        } else {
            column
        };
        let (index, line, column) = lookup_mappings(&part.mappings, local_line, local_column)?;
        let source = part.sources.get(index)?.as_deref()?;
        Some(Mapped {
            source,
            source_root: part.source_root.as_deref(),
            line,
            column,
        })
    }
}

pub(crate) fn map_ref(chunk: &[u8]) -> Option<MapRef> {
    let start = chunk.len().saturating_sub(TAIL_BYTES);
    let tail = &chunk[start..];
    let inline_tail = chunk
        .windows(MAPPING_URL_MARKER.len() + INLINE_PREFIX.len())
        .rposition(|window| {
            window.starts_with(MAPPING_URL_MARKER.as_bytes())
                && window.ends_with(INLINE_PREFIX.as_bytes())
        });
    if let Some(position) = inline_tail {
        let from = position + MAPPING_URL_MARKER.len() + INLINE_PREFIX.len();
        let encoded: Vec<u8> = chunk[from..]
            .iter()
            .copied()
            .take_while(|byte| !byte.is_ascii_whitespace() && *byte != b'*')
            .collect();
        return STANDARD.decode(encoded).ok().map(MapRef::Inline);
    }
    let text = std::str::from_utf8(tail).ok()?;
    let at = text.rfind(MAPPING_URL_MARKER)?;
    let value: String = text[at + MAPPING_URL_MARKER.len()..]
        .chars()
        .take_while(|c| !c.is_whitespace() && *c != '*')
        .collect();
    if value.is_empty() || value.contains(':') || value.starts_with('/') || value.contains('\\') {
        return None;
    }
    Some(MapRef::Path(value))
}

fn lookup_mappings(mappings: &str, line: u32, column: u32) -> Option<(usize, u32, u32)> {
    let mut source = 0i64;
    let mut original_line = 0i64;
    let mut original_column = 0i64;
    let mut name = 0i64;
    let mut best = None;
    for (index, line_text) in mappings.split(';').enumerate() {
        let current = u32::try_from(index).ok()?;
        if current > line {
            break;
        }
        let mut generated = 0i64;
        for segment in line_text.split(',').filter(|segment| !segment.is_empty()) {
            let values = decode_segment(segment)?;
            generated = generated.checked_add(*values.first()?)?;
            if values.len() >= 4 {
                source = source.checked_add(values[1])?;
                original_line = original_line.checked_add(values[2])?;
                original_column = original_column.checked_add(values[3])?;
            }
            if values.len() >= 5 {
                name = name.checked_add(values[4])?;
            }
            if current == line && values.len() >= 4 && generated <= i64::from(column) {
                best = Some((source, original_line, original_column));
            }
        }
    }
    let _ = name;
    let (source, line, column) = best?;
    Some((
        usize::try_from(source).ok()?,
        u32::try_from(line).ok()?,
        u32::try_from(column).ok()?,
    ))
}

fn decode_segment(segment: &str) -> Option<Vec<i64>> {
    let mut values = Vec::with_capacity(5);
    let mut value = 0i64;
    let mut shift = 0u32;
    for byte in segment.bytes() {
        let digit = i64::from(base64_digit(byte)?);
        value |= (digit & 31) << shift;
        if digit & 32 != 0 {
            shift += 5;
            if shift > MAX_VLQ_SHIFT {
                return None;
            }
            continue;
        }
        let magnitude = value >> 1;
        values.push(if value & 1 == 1 {
            -magnitude
        } else {
            magnitude
        });
        if values.len() > 5 {
            return None;
        }
        value = 0;
        shift = 0;
    }
    (shift == 0 && !values.is_empty()).then_some(values)
}

fn base64_digit(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{MapRef, Mapped, SourceMap, decode_segment, map_ref};

    const VITE_MAP: &str = r#"{"version":3,"file":"Settings-BXJJZpdy.js","names":["render"],"sources":["../../src/pages/Settings.ts"],"sourcesContent":["export function render() {\n  const token = \"settings-page-marker\";\n  console.log(token);\n}\n"],"mappings":"AAAA,SAAgBA,GAAS,CAEvB,QAAQ,IAAI,sBAAK,CACnB,C"}"#;

    #[test]
    fn decodes_vlq_segments() {
        assert_eq!(decode_segment("AAAA"), Some(vec![0, 0, 0, 0]));
        assert_eq!(decode_segment("SAAgBA"), Some(vec![9, 0, 0, 16, 0]));
        assert_eq!(decode_segment("D"), Some(vec![-1]));
        assert_eq!(decode_segment("g"), None);
        assert_eq!(decode_segment("!"), None);
        assert_eq!(decode_segment(&"g".repeat(20)), None);
    }

    #[test]
    fn finds_the_original_position_in_a_vite_map() {
        let Some(map) = SourceMap::parse(VITE_MAP.as_bytes()) else {
            unreachable!("map should parse")
        };
        assert_eq!(
            map.sources().collect::<Vec<_>>(),
            vec![(None, "../../src/pages/Settings.ts")]
        );
        assert_eq!(
            map.lookup(0, 9),
            Some(Mapped {
                source: "../../src/pages/Settings.ts",
                source_root: None,
                line: 0,
                column: 16
            })
        );
        assert_eq!(
            map.lookup(0, 40).map(|mapped| (mapped.line, mapped.column)),
            Some((2, 14))
        );
        assert_eq!(map.lookup(5, 0), None);
    }

    #[test]
    fn index_maps_shift_positions_by_their_section_offset() {
        let index = r#"{"version":3,"sources":[],"sections":[
            {"offset":{"line":0,"column":0},"map":{"version":3,"sources":["../a.js"],"mappings":"AAAA"}},
            {"offset":{"line":3,"column":4},"map":{"version":3,"sources":[null,"../b.js"],"mappings":"ACCA,EAAE"}},
            {"offset":{"line":9,"column":0},"map":{"version":3,"sections":[],"mappings":"AAAA","sources":["../c.js"]}}
        ]}"#;
        let Some(map) = SourceMap::parse(index.as_bytes()) else {
            unreachable!("index map should parse")
        };
        assert_eq!(
            map.sources().map(|(_, source)| source).collect::<Vec<_>>(),
            vec!["../a.js", "../b.js", "../c.js"]
        );
        assert_eq!(
            map.lookup(3, 7)
                .map(|mapped| (mapped.source, mapped.line, mapped.column)),
            Some(("../b.js", 1, 2))
        );
        assert_eq!(
            map.lookup(0, 5).map(|mapped| mapped.source),
            Some("../a.js")
        );
        assert_eq!(map.lookup(1, 0), None);
    }

    #[test]
    fn follows_only_safe_map_references() {
        assert_eq!(
            map_ref(b"var a=1;\n//# sourceMappingURL=index-DWa_saO0.js.map\n"),
            Some(MapRef::Path("index-DWa_saO0.js.map".to_owned()))
        );
        assert_eq!(
            map_ref(b"x\n/*# sourceMappingURL=a.css.map */"),
            Some(MapRef::Path("a.css.map".to_owned()))
        );
        for hostile in [
            "https://evil.example/a.map",
            "/etc/passwd",
            "C:\\\\a.map",
            "file:///a.map",
        ] {
            let chunk = format!("x\n//# sourceMappingURL={hostile}\n");
            assert_eq!(map_ref(chunk.as_bytes()), None, "{hostile}");
        }
        let inline = b"x\n//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ==\n";
        assert_eq!(
            map_ref(inline),
            Some(MapRef::Inline(br#"{"version":3}"#.to_vec()))
        );
        assert_eq!(map_ref(b"var a=1;"), None);
        assert!(SourceMap::parse(b"not json").is_none());
    }
}
