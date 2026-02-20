use std::path::{Path, PathBuf};

use rustmap_types::{ScriptCategory, ScriptPhase};

use crate::error::ScriptError;

/// The language a script is written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptLanguage {
    Lua,
    Python,
    #[cfg(feature = "wasm")]
    Wasm,
}

/// Metadata parsed from a script file's header.
#[derive(Debug, Clone)]
pub struct ScriptMeta {
    /// Script identifier (filename without extension).
    pub id: String,
    /// Full path to the script file.
    pub path: PathBuf,
    /// Human-readable description of what the script does.
    pub description: String,
    /// Categories this script belongs to.
    pub categories: Vec<ScriptCategory>,
    /// Execution phases this script participates in.
    pub phases: Vec<ScriptPhase>,
    /// Scripts that must run before this one.
    pub dependencies: Vec<String>,
    /// Language this script is written in.
    pub language: ScriptLanguage,
}

/// Discovers Lua scripts from filesystem directories and resolves
/// user-specified script patterns into concrete script metadata.
pub struct ScriptDiscovery {
    script_dirs: Vec<PathBuf>,
    scripts: Vec<ScriptMeta>,
}

impl ScriptDiscovery {
    /// Create a new discovery instance with the given search directories.
    pub fn new(script_dirs: Vec<PathBuf>) -> Self {
        Self {
            script_dirs,
            scripts: Vec::new(),
        }
    }

    /// Scan all configured directories for script files and parse their metadata.
    pub fn discover(&mut self) -> Result<&[ScriptMeta], ScriptError> {
        self.scripts.clear();

        let dirs: Vec<PathBuf> = self.script_dirs.clone();
        for dir in &dirs {
            if !dir.is_dir() {
                continue;
            }
            self.discover_dir(dir)?;
        }

        // Sort by id for deterministic ordering
        self.scripts.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(&self.scripts)
    }

    /// Discover scripts in a single directory (non-recursive).
    fn discover_dir(&mut self, dir: &Path) -> Result<(), ScriptError> {
        let entries = std::fs::read_dir(dir).map_err(|e| {
            ScriptError::Discovery(format!("failed to read directory {}: {}", dir.display(), e))
        })?;

        for entry in entries {
            let entry =
                entry.map_err(|e| ScriptError::Discovery(format!("failed to read entry: {e}")))?;
            if entry.file_type().is_ok_and(|ft| ft.is_symlink()) {
                continue;
            }
            let path = entry.path();
            match path.extension().and_then(|e| e.to_str()) {
                Some("lua") => match self.parse_script_meta(&path) {
                    Ok(meta) => self.scripts.push(meta),
                    Err(e) => {
                        eprintln!("warning: skipping {}: {e}", path.display());
                    }
                },
                Some("py") => match self.parse_python_meta(&path) {
                    Ok(meta) => self.scripts.push(meta),
                    Err(e) => {
                        eprintln!("warning: skipping {}: {e}", path.display());
                    }
                },
                #[cfg(feature = "wasm")]
                Some("wasm") => match self.parse_wasm_meta(&path) {
                    Ok(meta) => self.scripts.push(meta),
                    Err(e) => {
                        eprintln!("warning: skipping {}: {e}", path.display());
                    }
                },
                _ => {}
            }
        }

        Ok(())
    }

    /// Parse script metadata from a Lua file's header comments.
    ///
    /// Expects a `description` table at the top of the file with fields:
    /// - `summary`: one-line description
    /// - `categories`: list of category strings
    /// - `phases`: list of phase strings
    /// - `dependencies`: optional list of script id strings
    fn parse_script_meta(&self, path: &Path) -> Result<ScriptMeta, ScriptError> {
        let content = std::fs::read_to_string(path)?;
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| {
                ScriptError::Discovery(format!("invalid script filename: {}", path.display()))
            })?
            .to_string();

        let description = parse_field(&content, "summary").unwrap_or_default();
        let categories = parse_list_field(&content, "categories")
            .iter()
            .filter_map(|s| ScriptCategory::from_str_loose(s))
            .collect();
        let phases = parse_list_field(&content, "phases")
            .iter()
            .filter_map(|s| parse_phase(s))
            .collect();
        let dependencies = parse_list_field(&content, "dependencies");

        Ok(ScriptMeta {
            id,
            path: path.to_path_buf(),
            description,
            categories,
            phases,
            dependencies,
            language: ScriptLanguage::Lua,
        })
    }

    /// Parse script metadata from a Python file's header comments.
    ///
    /// Expects comment lines at the top of the file like:
    /// ```python
    /// # summary = "Shows the title of a web page"
    /// # categories = ["default", "safe", "discovery"]
    /// # phases = ["portrule"]
    /// ```
    fn parse_python_meta(&self, path: &Path) -> Result<ScriptMeta, ScriptError> {
        let content = std::fs::read_to_string(path)?;
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| {
                ScriptError::Discovery(format!("invalid script filename: {}", path.display()))
            })?
            .to_string();

        // Extract metadata from Python comment lines (# key = value)
        let stripped = python_comment_content(&content);

        let description = parse_field(&stripped, "summary").unwrap_or_default();
        let categories = parse_python_list_field(&stripped, "categories")
            .iter()
            .filter_map(|s| ScriptCategory::from_str_loose(s))
            .collect();
        let phases = parse_python_list_field(&stripped, "phases")
            .iter()
            .filter_map(|s| parse_phase(s))
            .collect();
        let dependencies = parse_python_list_field(&stripped, "dependencies");

        Ok(ScriptMeta {
            id,
            path: path.to_path_buf(),
            description,
            categories,
            phases,
            dependencies,
            language: ScriptLanguage::Python,
        })
    }

    /// Parse script metadata from a WASM module's custom section.
    ///
    /// Expects a custom section named "rustmap" containing JSON:
    /// ```json
    /// {"summary": "...", "categories": ["default"], "phases": ["portrule"]}
    /// ```
    #[cfg(feature = "wasm")]
    fn parse_wasm_meta(&self, path: &Path) -> Result<ScriptMeta, ScriptError> {
        let bytes = std::fs::read(path)?;
        let meta_json = extract_wasm_custom_section(&bytes, "rustmap").ok_or_else(|| {
            ScriptError::Discovery(format!(
                "WASM module {} missing 'rustmap' custom section",
                path.display()
            ))
        })?;
        let meta: WasmMetadata = serde_json::from_slice(&meta_json).map_err(|e| {
            ScriptError::Discovery(format!("invalid metadata in {}: {e}", path.display()))
        })?;

        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| {
                ScriptError::Discovery(format!("invalid script filename: {}", path.display()))
            })?
            .to_string();

        Ok(ScriptMeta {
            id,
            path: path.to_path_buf(),
            description: meta.summary,
            categories: meta
                .categories
                .iter()
                .filter_map(|s| ScriptCategory::from_str_loose(s))
                .collect(),
            phases: meta.phases.iter().filter_map(|s| parse_phase(s)).collect(),
            dependencies: meta.dependencies,
            language: ScriptLanguage::Wasm,
        })
    }

    /// Resolve user-specified patterns into matching scripts.
    ///
    /// Patterns can be:
    /// - Exact script name: `http-title`
    /// - Category name: `default`, `safe`
    /// - Glob pattern: `http-*`
    pub fn resolve_scripts(&self, patterns: &[String]) -> Vec<ScriptMeta> {
        if patterns.is_empty() {
            return Vec::new();
        }

        let mut results = Vec::new();
        let mut seen_ids = std::collections::HashSet::new();

        for pattern in patterns {
            // Check if it's a category name
            if let Some(category) = ScriptCategory::from_str_loose(pattern) {
                for script in &self.scripts {
                    if script.categories.contains(&category) && seen_ids.insert(script.id.clone()) {
                        results.push(script.clone());
                    }
                }
                continue;
            }

            // Check if it's a glob pattern
            if pattern.contains('*') || pattern.contains('?') {
                for script in &self.scripts {
                    if glob_match(pattern, &script.id) && seen_ids.insert(script.id.clone()) {
                        results.push(script.clone());
                    }
                }
                continue;
            }

            // Exact name match
            for script in &self.scripts {
                if script.id == *pattern && seen_ids.insert(script.id.clone()) {
                    results.push(script.clone());
                }
            }
        }

        // Sort by dependency order, then alphabetically
        sort_by_dependencies(&mut results);
        results
    }

    /// Get all discovered scripts.
    pub fn scripts(&self) -> &[ScriptMeta] {
        &self.scripts
    }
}

/// Simple glob matching supporting `*` (any chars) and `?` (single char).
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let mut dp = vec![vec![false; text.len() + 1]; pattern.len() + 1];
    dp[0][0] = true;

    // Handle leading *s
    for (i, &pc) in pattern.iter().enumerate() {
        if pc == '*' {
            dp[i + 1][0] = dp[i][0];
        }
    }

    for (i, &pc) in pattern.iter().enumerate() {
        for (j, &tc) in text.iter().enumerate() {
            if pc == '*' {
                dp[i + 1][j + 1] = dp[i][j + 1] || dp[i + 1][j];
            } else if pc == '?' || pc == tc {
                dp[i + 1][j + 1] = dp[i][j];
            }
        }
    }

    dp[pattern.len()][text.len()]
}

/// Parse a simple string field from script content.
/// Looks for patterns like: `summary = "..."` or `summary = '...'`
fn parse_field(content: &str, field: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(field) {
            let rest = rest.trim();
            if let Some(rest) = rest.strip_prefix('=') {
                let rest = rest.trim();
                if let Some(val) = extract_quoted_string(rest) {
                    return Some(val);
                }
            }
        }
    }
    None
}

/// Parse a list field from script content.
/// Looks for patterns like: `categories = {"default", "safe"}`
fn parse_list_field(content: &str, field: &str) -> Vec<String> {
    let mut results = Vec::new();
    let mut in_field = false;
    let mut brace_depth = 0;

    for line in content.lines() {
        let trimmed = line.trim();

        if !in_field {
            if let Some(rest) = trimmed.strip_prefix(field) {
                let rest = rest.trim();
                if let Some(rest) = rest.strip_prefix('=') {
                    let rest = rest.trim();
                    if let Some(rest) = rest.strip_prefix('{') {
                        in_field = true;
                        brace_depth = 1;
                        // Parse items on this line
                        parse_list_items(rest, &mut results, &mut brace_depth);
                        if brace_depth == 0 {
                            break;
                        }
                    }
                }
            }
        } else {
            parse_list_items(trimmed, &mut results, &mut brace_depth);
            if brace_depth == 0 {
                break;
            }
        }
    }

    results
}

fn parse_list_items(text: &str, results: &mut Vec<String>, brace_depth: &mut usize) {
    let mut chars = text.chars().peekable();
    while let Some(&ch) = chars.peek() {
        match ch {
            '"' | '\'' => {
                let quote = ch;
                chars.next();
                let mut val = String::new();
                while let Some(&c) = chars.peek() {
                    if c == quote {
                        chars.next();
                        break;
                    }
                    val.push(c);
                    chars.next();
                }
                if !val.is_empty() {
                    results.push(val);
                }
            }
            '}' => {
                *brace_depth -= 1;
                if *brace_depth == 0 {
                    return;
                }
                chars.next();
            }
            '{' => {
                *brace_depth += 1;
                chars.next();
            }
            _ => {
                chars.next();
            }
        }
    }
}

fn extract_quoted_string(s: &str) -> Option<String> {
    let s = s.trim();
    if (s.starts_with('"') && s.contains('"')) || (s.starts_with('\'') && s.contains('\'')) {
        let quote = s.chars().next()?;
        let rest = &s[1..];
        if let Some(end) = rest.find(quote) {
            return Some(rest[..end].to_string());
        }
    }
    None
}

/// Extract content from Python comment-header lines.
/// Strips the leading `# ` from each line that starts with `#`.
fn python_comment_content(content: &str) -> String {
    let mut out = String::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix('#') {
            out.push_str(rest.trim_start());
            out.push('\n');
        } else if trimmed.is_empty() || trimmed.starts_with("#!/") {
            // Skip blank lines and shebangs
            continue;
        } else {
            // Stop at first non-comment, non-blank line
            break;
        }
    }
    out
}

/// Parse a JSON-style list from Python metadata comments.
/// Handles: `categories = ["default", "safe"]`
fn parse_python_list_field(content: &str, field: &str) -> Vec<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(field) {
            let rest = rest.trim();
            if let Some(rest) = rest.strip_prefix('=') {
                let rest = rest.trim();
                if let Some(rest) = rest.strip_prefix('[')
                    && let Some(list_content) = rest.strip_suffix(']')
                {
                    return list_content
                        .split(',')
                        .map(|s| s.trim().trim_matches('"').trim_matches('\'').to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
            }
        }
    }
    Vec::new()
}

fn parse_phase(s: &str) -> Option<ScriptPhase> {
    match s.to_ascii_lowercase().as_str() {
        "prerule" => Some(ScriptPhase::Prerule),
        "hostrule" => Some(ScriptPhase::Hostrule),
        "portrule" => Some(ScriptPhase::Portrule),
        "postrule" => Some(ScriptPhase::Postrule),
        _ => None,
    }
}

/// Metadata embedded in a WASM module's "rustmap" custom section.
#[cfg(feature = "wasm")]
#[derive(serde::Deserialize)]
struct WasmMetadata {
    summary: String,
    categories: Vec<String>,
    phases: Vec<String>,
    #[serde(default)]
    dependencies: Vec<String>,
}

/// Extract a named custom section from a WASM binary.
///
/// WASM custom sections (section ID = 0) contain a name followed by content bytes.
/// Returns the content bytes if a section with the given name is found.
#[cfg(feature = "wasm")]
fn extract_wasm_custom_section(bytes: &[u8], name: &str) -> Option<Vec<u8>> {
    // WASM binary: magic (4 bytes) + version (4 bytes) + sections
    if bytes.len() < 8 || &bytes[0..4] != b"\0asm" {
        return None;
    }
    let mut pos = 8;
    while pos < bytes.len() {
        let section_id = bytes[pos];
        pos += 1;
        let (section_len, consumed) = read_leb128_u32(&bytes[pos..])?;
        pos += consumed;
        let section_end = pos + section_len as usize;
        if section_end > bytes.len() {
            return None;
        }

        if section_id == 0 {
            // Custom section: name_len (LEB128) + name bytes + content bytes
            let (name_len, name_consumed) = read_leb128_u32(&bytes[pos..])?;
            let name_start = pos + name_consumed;
            let name_end = name_start + name_len as usize;
            if name_end > section_end {
                pos = section_end;
                continue;
            }
            if &bytes[name_start..name_end] == name.as_bytes() {
                return Some(bytes[name_end..section_end].to_vec());
            }
        }
        pos = section_end;
    }
    None
}

/// Decode a LEB128-encoded unsigned 32-bit integer.
///
/// Returns `(value, bytes_consumed)` or `None` if the encoding is invalid.
#[cfg(feature = "wasm")]
fn read_leb128_u32(bytes: &[u8]) -> Option<(u32, usize)> {
    let mut result: u32 = 0;
    let mut shift = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= ((byte & 0x7F) as u32) << shift;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
        if shift >= 35 {
            return None; // Overflow
        }
    }
    None // Truncated
}

/// Sort scripts by dependencies (topological sort, stable).
fn sort_by_dependencies(scripts: &mut Vec<ScriptMeta>) {
    // Simple insertion-sort-style dependency ordering:
    // If script A depends on B, ensure B comes before A.
    let ids: Vec<String> = scripts.iter().map(|s| s.id.clone()).collect();
    let mut sorted = Vec::with_capacity(scripts.len());
    let mut placed = std::collections::HashSet::new();

    // Multiple passes to handle transitive dependencies
    for _ in 0..scripts.len() {
        for script in scripts.iter() {
            if placed.contains(&script.id) {
                continue;
            }
            let deps_satisfied = script
                .dependencies
                .iter()
                .all(|dep| !ids.contains(dep) || placed.contains(dep));
            if deps_satisfied {
                placed.insert(script.id.clone());
                sorted.push(script.clone());
            }
        }
        if sorted.len() == scripts.len() {
            break;
        }
    }

    // Add any remaining (circular dependency fallback)
    for script in scripts.iter() {
        if !placed.contains(&script.id) {
            sorted.push(script.clone());
        }
    }

    *scripts = sorted;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn create_test_script(dir: &Path, name: &str, content: &str) {
        fs::write(dir.join(format!("{name}.lua")), content).unwrap();
    }

    fn sample_script_content(summary: &str, categories: &[&str], phases: &[&str]) -> String {
        let cats = categories
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let ph = phases
            .iter()
            .map(|p| format!("\"{p}\""))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            r#"description = {{}}
summary = "{summary}"
categories = {{{cats}}}
phases = {{{ph}}}

portrule = function(host, port)
    return port.number == 80
end

action = function(host, port)
    return "test output"
end
"#
        )
    }

    #[test]
    fn discover_finds_lua_files() {
        let tmp = std::env::temp_dir().join("rustmap_test_discover");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        create_test_script(
            &tmp,
            "test-script",
            &sample_script_content("A test", &["default", "safe"], &["portrule"]),
        );
        create_test_script(
            &tmp,
            "another-script",
            &sample_script_content("Another", &["discovery"], &["hostrule"]),
        );
        // Non-lua file should be ignored
        fs::write(tmp.join("readme.txt"), "not a script").unwrap();

        let mut discovery = ScriptDiscovery::new(vec![tmp.clone()]);
        let scripts = discovery.discover().unwrap();

        assert_eq!(scripts.len(), 2);
        let ids: Vec<&str> = scripts.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"test-script"));
        assert!(ids.contains(&"another-script"));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn discover_nonexistent_dir_ok() {
        let mut discovery = ScriptDiscovery::new(vec![PathBuf::from("/nonexistent/path/xyzzy")]);
        let scripts = discovery.discover().unwrap();
        assert!(scripts.is_empty());
    }

    #[test]
    fn resolve_by_exact_name() {
        let tmp = std::env::temp_dir().join("rustmap_test_resolve_exact");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        create_test_script(
            &tmp,
            "http-title",
            &sample_script_content("HTTP title", &["default"], &["portrule"]),
        );
        create_test_script(
            &tmp,
            "ssh-hostkey",
            &sample_script_content("SSH key", &["default"], &["portrule"]),
        );

        let mut discovery = ScriptDiscovery::new(vec![tmp.clone()]);
        discovery.discover().unwrap();

        let resolved = discovery.resolve_scripts(&["http-title".into()]);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].id, "http-title");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resolve_by_category() {
        let tmp = std::env::temp_dir().join("rustmap_test_resolve_cat");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        create_test_script(
            &tmp,
            "script-a",
            &sample_script_content("A", &["default", "safe"], &["portrule"]),
        );
        create_test_script(
            &tmp,
            "script-b",
            &sample_script_content("B", &["discovery"], &["portrule"]),
        );
        create_test_script(
            &tmp,
            "script-c",
            &sample_script_content("C", &["default"], &["hostrule"]),
        );

        let mut discovery = ScriptDiscovery::new(vec![tmp.clone()]);
        discovery.discover().unwrap();

        let resolved = discovery.resolve_scripts(&["default".into()]);
        assert_eq!(resolved.len(), 2);
        let ids: Vec<&str> = resolved.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"script-a"));
        assert!(ids.contains(&"script-c"));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resolve_by_glob() {
        let tmp = std::env::temp_dir().join("rustmap_test_resolve_glob");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        create_test_script(
            &tmp,
            "http-title",
            &sample_script_content("title", &["safe"], &["portrule"]),
        );
        create_test_script(
            &tmp,
            "http-headers",
            &sample_script_content("headers", &["safe"], &["portrule"]),
        );
        create_test_script(
            &tmp,
            "ssh-hostkey",
            &sample_script_content("key", &["safe"], &["portrule"]),
        );

        let mut discovery = ScriptDiscovery::new(vec![tmp.clone()]);
        discovery.discover().unwrap();

        let resolved = discovery.resolve_scripts(&["http-*".into()]);
        assert_eq!(resolved.len(), 2);
        let ids: Vec<&str> = resolved.iter().map(|s| s.id.as_str()).collect();
        assert!(ids.contains(&"http-title"));
        assert!(ids.contains(&"http-headers"));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn resolve_empty_patterns() {
        let discovery = ScriptDiscovery::new(vec![]);
        let resolved = discovery.resolve_scripts(&[]);
        assert!(resolved.is_empty());
    }

    #[test]
    fn resolve_deduplicates() {
        let tmp = std::env::temp_dir().join("rustmap_test_resolve_dedup");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        create_test_script(
            &tmp,
            "test-script",
            &sample_script_content("test", &["default", "safe"], &["portrule"]),
        );

        let mut discovery = ScriptDiscovery::new(vec![tmp.clone()]);
        discovery.discover().unwrap();

        // Both "default" and "safe" match, but should only appear once
        let resolved = discovery.resolve_scripts(&["default".into(), "safe".into()]);
        assert_eq!(resolved.len(), 1);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn glob_match_basic() {
        assert!(glob_match("http-*", "http-title"));
        assert!(glob_match("http-*", "http-headers"));
        assert!(!glob_match("http-*", "ssh-hostkey"));
        assert!(glob_match("*-title", "http-title"));
        assert!(glob_match("http-?itle", "http-title"));
        assert!(!glob_match("http-?itle", "http-ttitle"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "other"));
    }

    #[test]
    fn parse_field_extracts_value() {
        let content = r#"
description = {}
summary = "Shows the title of a web page"
categories = {"default", "safe"}
"#;
        assert_eq!(
            parse_field(content, "summary"),
            Some("Shows the title of a web page".into())
        );
    }

    #[test]
    fn parse_list_field_extracts_items() {
        let content = r#"
categories = {"default", "safe", "discovery"}
phases = {"portrule"}
"#;
        assert_eq!(
            parse_list_field(content, "categories"),
            vec!["default", "safe", "discovery"]
        );
        assert_eq!(parse_list_field(content, "phases"), vec!["portrule"]);
    }

    #[test]
    fn parse_list_field_multiline() {
        let content = r#"
categories = {
    "default",
    "safe",
}
"#;
        assert_eq!(
            parse_list_field(content, "categories"),
            vec!["default", "safe"]
        );
    }

    #[test]
    fn dependency_ordering() {
        let mut scripts = vec![
            ScriptMeta {
                id: "b".into(),
                path: PathBuf::from("b.lua"),
                description: String::new(),
                categories: vec![],
                phases: vec![],
                dependencies: vec!["a".into()],
                language: ScriptLanguage::Lua,
            },
            ScriptMeta {
                id: "a".into(),
                path: PathBuf::from("a.lua"),
                description: String::new(),
                categories: vec![],
                phases: vec![],
                dependencies: vec![],
                language: ScriptLanguage::Lua,
            },
        ];

        sort_by_dependencies(&mut scripts);
        assert_eq!(scripts[0].id, "a");
        assert_eq!(scripts[1].id, "b");
    }

    #[test]
    fn discover_finds_python_files() {
        let tmp = std::env::temp_dir().join("rustmap_test_discover_py");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        // Lua script
        create_test_script(
            &tmp,
            "test-lua",
            &sample_script_content("A Lua script", &["default"], &["portrule"]),
        );

        // Python script
        fs::write(
            tmp.join("py-test.py"),
            r#"# summary = "A Python script"
# categories = ["default", "safe"]
# phases = ["portrule"]

def portrule(host, port):
    return True

def action(host, port):
    return "hello from python"
"#,
        )
        .unwrap();

        let mut discovery = ScriptDiscovery::new(vec![tmp.clone()]);
        let scripts = discovery.discover().unwrap();

        assert_eq!(scripts.len(), 2);

        let lua_script = scripts.iter().find(|s| s.id == "test-lua").unwrap();
        assert_eq!(lua_script.language, ScriptLanguage::Lua);

        let py_script = scripts.iter().find(|s| s.id == "py-test").unwrap();
        assert_eq!(py_script.language, ScriptLanguage::Python);
        assert_eq!(py_script.description, "A Python script");
        assert!(py_script.categories.contains(&ScriptCategory::Default));
        assert!(py_script.categories.contains(&ScriptCategory::Safe));
        assert!(py_script.phases.contains(&ScriptPhase::Portrule));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn python_metadata_parsing() {
        let content = r#"#!/usr/bin/env python3
# summary = "Grabs SSH version"
# categories = ["default", "version"]
# phases = ["portrule"]

import socket
"#;
        let stripped = python_comment_content(content);
        assert_eq!(
            parse_field(&stripped, "summary"),
            Some("Grabs SSH version".into())
        );
        let cats = parse_python_list_field(&stripped, "categories");
        assert_eq!(cats, vec!["default", "version"]);
        let phases = parse_python_list_field(&stripped, "phases");
        assert_eq!(phases, vec!["portrule"]);
    }

    // -----------------------------------------------------------------------
    // Phase 19: Discovery integration tests against the real scripts directory
    // -----------------------------------------------------------------------

    /// Find the real scripts directory relative to the crate root.
    fn real_scripts_dir() -> PathBuf {
        let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
        PathBuf::from(manifest).join("scripts")
    }

    #[test]
    fn discover_all_scripts_at_least_53() {
        let dir = real_scripts_dir();
        if !dir.exists() {
            eprintln!("Skipping: scripts dir not found at {dir:?}");
            return;
        }
        let mut discovery = ScriptDiscovery::new(vec![dir]);
        let scripts = discovery.discover().unwrap();
        assert!(
            scripts.len() >= 53,
            "Expected >= 53 scripts, found {}",
            scripts.len()
        );
    }

    #[test]
    fn all_scripts_have_metadata() {
        let dir = real_scripts_dir();
        if !dir.exists() {
            return;
        }
        let mut discovery = ScriptDiscovery::new(vec![dir]);
        let scripts = discovery.discover().unwrap();
        for script in scripts {
            assert!(
                !script.description.is_empty(),
                "{} has no summary",
                script.id
            );
            assert!(
                !script.categories.is_empty(),
                "{} has no categories",
                script.id
            );
            assert!(!script.phases.is_empty(), "{} has no phases", script.id);
        }
    }

    #[test]
    fn all_new_scripts_have_safe_category() {
        let dir = real_scripts_dir();
        if !dir.exists() {
            return;
        }
        let mut discovery = ScriptDiscovery::new(vec![dir]);
        let scripts = discovery.discover().unwrap();

        let new_scripts = [
            "http-robots",
            "http-security-headers",
            "http-favicon-hash",
            "http-open-redirect",
            "http-cors",
            "py-http-headers-full",
            "smb-os-discovery",
            "smb-protocols",
            "smb-security-mode",
            "nbstat",
            "smb2-time",
            "mongodb-info",
            "memcached-info",
            "redis-info",
            "postgresql-info",
            "dns-recursion",
            "dns-zone-transfer",
            "dns-service-discovery",
            "snmp-info",
            "snmp-sysdescr",
            "snmp-interfaces",
            "ldap-rootdse",
            "ldap-search",
            "py-ldap-info",
            "rdp-ntlm-info",
            "rdp-enum-encryption",
            "vnc-info",
            "ntp-info",
            "ntp-monlist",
            "mqtt-subscribe",
            "mqtt-version",
            "sip-methods",
            "sip-enum-users",
            "imap-capabilities",
            "pop3-capabilities",
            "imap-ntlm-info",
            "docker-version",
            "docker-containers",
            "pptp-version",
            "rtsp-methods",
        ];

        for script_id in &new_scripts {
            let script = scripts.iter().find(|s| s.id == *script_id);
            assert!(script.is_some(), "Script '{script_id}' not discovered");
            let script = script.unwrap();
            assert!(
                script.categories.contains(&ScriptCategory::Safe),
                "Script '{}' missing 'safe' category (has {:?})",
                script_id,
                script.categories
            );
        }
    }

    #[test]
    fn http_scripts_match_expected_ports() {
        let dir = real_scripts_dir();
        if !dir.exists() {
            return;
        }
        let mut discovery = ScriptDiscovery::new(vec![dir]);
        discovery.discover().unwrap();

        let resolved = discovery.resolve_scripts(&["http-*".into()]);
        // Should find at least the new HTTP scripts + existing ones
        assert!(
            resolved.len() >= 8,
            "Expected >= 8 http-* scripts, found {}",
            resolved.len()
        );
    }

    #[test]
    fn smb_scripts_discovered() {
        let dir = real_scripts_dir();
        if !dir.exists() {
            return;
        }
        let mut discovery = ScriptDiscovery::new(vec![dir]);
        discovery.discover().unwrap();

        let resolved = discovery.resolve_scripts(&["smb-*".into()]);
        assert!(
            resolved.len() >= 3,
            "Expected >= 3 smb-* scripts, found {}",
            resolved.len()
        );
    }

    #[test]
    fn database_scripts_discovered() {
        let dir = real_scripts_dir();
        if !dir.exists() {
            return;
        }
        let mut discovery = ScriptDiscovery::new(vec![dir]);
        let scripts = discovery.discover().unwrap();

        let db_scripts = [
            "mongodb-info",
            "memcached-info",
            "redis-info",
            "postgresql-info",
        ];
        for id in &db_scripts {
            assert!(
                scripts.iter().any(|s| s.id == *id),
                "Database script '{}' not found",
                id
            );
        }
    }

    #[test]
    fn udp_scripts_discovered() {
        let dir = real_scripts_dir();
        if !dir.exists() {
            return;
        }
        let mut discovery = ScriptDiscovery::new(vec![dir]);
        let scripts = discovery.discover().unwrap();

        let udp_scripts = [
            "snmp-info",
            "snmp-sysdescr",
            "snmp-interfaces",
            "ntp-info",
            "ntp-monlist",
            "nbstat",
        ];
        for id in &udp_scripts {
            assert!(
                scripts.iter().any(|s| s.id == *id),
                "UDP script '{}' not found",
                id
            );
        }
    }

    #[test]
    fn python_scripts_discovered() {
        let dir = real_scripts_dir();
        if !dir.exists() {
            return;
        }
        let mut discovery = ScriptDiscovery::new(vec![dir]);
        let scripts = discovery.discover().unwrap();

        let py_scripts: Vec<_> = scripts
            .iter()
            .filter(|s| s.language == ScriptLanguage::Python)
            .collect();
        assert!(
            py_scripts.len() >= 4,
            "Expected >= 4 Python scripts, found {}",
            py_scripts.len()
        );
    }

    #[test]
    fn discovery_scripts_sorted_by_id() {
        let dir = real_scripts_dir();
        if !dir.exists() {
            return;
        }
        let mut discovery = ScriptDiscovery::new(vec![dir]);
        let scripts = discovery.discover().unwrap();

        for w in scripts.windows(2) {
            assert!(
                w[0].id <= w[1].id,
                "Scripts not sorted: '{}' > '{}'",
                w[0].id,
                w[1].id
            );
        }
    }

    // -----------------------------------------------------------------------
    // WASM custom section parsing tests (no wasmtime dependency needed)
    // -----------------------------------------------------------------------

    #[cfg(feature = "wasm")]
    #[test]
    fn extract_wasm_custom_section_found() {
        let name = b"rustmap";
        let content = b"{\"summary\":\"test\"}";
        let name_len = name.len() as u8;
        let section_payload_len = 1 + name.len() + content.len();

        let mut wasm: Vec<u8> = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        wasm.push(0x00); // section id: custom
        wasm.push(section_payload_len as u8); // section length
        wasm.push(name_len);
        wasm.extend_from_slice(name);
        wasm.extend_from_slice(content);

        let result = super::extract_wasm_custom_section(&wasm, "rustmap");
        assert_eq!(result, Some(content.to_vec()));
    }

    #[cfg(feature = "wasm")]
    #[test]
    fn extract_wasm_custom_section_missing() {
        // Minimal valid WASM with no custom sections
        let wasm = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(super::extract_wasm_custom_section(&wasm, "rustmap"), None);
    }

    #[cfg(feature = "wasm")]
    #[test]
    fn extract_wasm_custom_section_wrong_name() {
        let name = b"other";
        let content = b"data";
        let name_len = name.len() as u8;
        let section_payload_len = 1 + name.len() + content.len();

        let mut wasm: Vec<u8> = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        wasm.push(0x00);
        wasm.push(section_payload_len as u8);
        wasm.push(name_len);
        wasm.extend_from_slice(name);
        wasm.extend_from_slice(content);

        assert_eq!(super::extract_wasm_custom_section(&wasm, "rustmap"), None);
    }

    #[cfg(feature = "wasm")]
    #[test]
    fn read_leb128_u32_basic() {
        assert_eq!(super::read_leb128_u32(&[0x00]), Some((0, 1)));
        assert_eq!(super::read_leb128_u32(&[0x7f]), Some((127, 1)));
        assert_eq!(super::read_leb128_u32(&[0x80, 0x01]), Some((128, 2)));
        assert_eq!(
            super::read_leb128_u32(&[0xe5, 0x8e, 0x26]),
            Some((624485, 3))
        );
    }

    #[cfg(feature = "wasm")]
    #[test]
    fn read_leb128_u32_invalid() {
        // Empty input
        assert_eq!(super::read_leb128_u32(&[]), None);
        // Truncated (high bit set but no continuation)
        assert_eq!(super::read_leb128_u32(&[0x80]), None);
    }
}
