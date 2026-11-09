const MAX_PATTERN_CHARS: usize = 512;
const MAX_PARTS: usize = 32;
const MAX_DOUBLE_STARS: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Glob {
    parts: Vec<String>,
}

impl Glob {
    pub(crate) fn new(pattern: &str) -> Result<Self, String> {
        let trimmed = pattern.trim();
        let trimmed = trimmed.strip_prefix("./").unwrap_or(trimmed);
        if trimmed.is_empty()
            || trimmed.chars().count() > MAX_PATTERN_CHARS
            || trimmed.starts_with('/')
            || trimmed.contains('\\')
            || trimmed.chars().any(char::is_control)
        {
            return Err(format!("'{pattern}' is not a valid path pattern"));
        }
        let mut parts: Vec<String> = trimmed
            .split('/')
            .filter(|part| !part.is_empty())
            .map(str::to_owned)
            .collect();
        if parts.iter().any(|part| part == "." || part == "..") {
            return Err(format!("'{pattern}' must stay inside the project"));
        }
        if parts.iter().filter(|part| *part == "**").count() > MAX_DOUBLE_STARS
            || parts.len() > MAX_PARTS
        {
            return Err(format!("'{pattern}' is too complex"));
        }
        if parts.len() == 1 && parts[0] != "**" {
            parts.insert(0, "**".to_owned());
        }
        Ok(Self { parts })
    }

    pub(crate) fn matches(&self, rel_path: &str) -> bool {
        let segments: Vec<&str> = rel_path
            .split('/')
            .filter(|part| !part.is_empty())
            .collect();
        (1..=segments.len()).any(|end| match_parts(&self.parts, &segments[..end]))
    }
}

fn match_parts(parts: &[String], segments: &[&str]) -> bool {
    match parts.split_first() {
        None => segments.is_empty(),
        Some((part, rest)) if part == "**" => {
            (0..=segments.len()).any(|skip| match_parts(rest, &segments[skip..]))
        }
        Some((part, rest)) => match segments.split_first() {
            Some((segment, others)) => match_segment(part, segment) && match_parts(rest, others),
            None => false,
        },
    }
}

fn match_segment(pattern: &str, segment: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let segment: Vec<char> = segment.chars().collect();
    let mut row = vec![false; segment.len() + 1];
    row[0] = true;
    for symbol in &pattern {
        let mut next = vec![false; segment.len() + 1];
        if *symbol == '*' {
            next[0] = row[0];
        }
        for index in 1..=segment.len() {
            next[index] = match symbol {
                '*' => next[index - 1] || row[index],
                '?' => row[index - 1],
                c => row[index - 1] && *c == segment[index - 1],
            };
        }
        row = next;
    }
    row[segment.len()]
}

#[cfg(test)]
mod tests {
    use super::Glob;

    fn matches(pattern: &str, path: &str) -> bool {
        Glob::new(pattern).is_ok_and(|glob| glob.matches(path))
    }

    #[test]
    fn matches_files_folders_and_wildcards() {
        assert!(matches("legacy", "legacy/old/app.ts"));
        assert!(matches("legacy/**", "legacy/app.ts"));
        assert!(matches("./supabase/seed.sql", "supabase/seed.sql"));
        assert!(matches("*.test.ts", "src/lib/db.test.ts"));
        assert!(matches(
            "src/**/*.stories.tsx",
            "src/ui/button/Button.stories.tsx"
        ));
        assert!(matches("src/**/*.stories.tsx", "src/Button.stories.tsx"));
        assert!(matches(
            "supabase/migrations/2023*_init.sql",
            "supabase/migrations/20230530_init.sql"
        ));
        assert!(matches("file?.ts", "a/file1.ts"));
        assert!(!matches("legacy", "src/legacyish.ts"));
        assert!(!matches("src/*.ts", "src/lib/db.ts"));
        assert!(!matches("supabase/seed.sql", "other/supabase/seed.sql"));
    }

    #[test]
    fn rejects_patterns_that_leave_the_project_or_explode() {
        assert!(Glob::new("").is_err());
        assert!(Glob::new("/etc/passwd").is_err());
        assert!(Glob::new("../outside").is_err());
        assert!(Glob::new("a\\b").is_err());
        assert!(Glob::new("**/**/**/**/**/x").is_err());
        assert!(Glob::new(&"a/".repeat(40)).is_err());
    }
}
