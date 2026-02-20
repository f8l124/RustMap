use serde::{Deserialize, Serialize};
use std::fmt;

/// Result from running a single script against a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptResult {
    /// Script identifier (filename without .lua extension).
    pub id: String,
    /// Human-readable output text.
    pub output: String,
    /// Structured data returned by the script (Lua tables become maps/lists).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elements: Option<ScriptValue>,
}

/// Structured data returned by scripts (Lua tables converted to Rust).
///
/// **Note:** Uses `#[serde(untagged)]` for natural JSON representation. The `Map`
/// variant serializes as an array of `[key, value]` pairs. Due to serde's untagged
/// deserialization order, a serialized `Map` may deserialize as `List` when
/// round-tripping through JSON. Construct `Map` values programmatically (e.g., from
/// Lua table conversion), not by deserializing from JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ScriptValue {
    String(String),
    Number(f64),
    Bool(bool),
    List(Vec<ScriptValue>),
    /// Preserves insertion order from Lua tables.
    Map(Vec<(String, ScriptValue)>),
}

/// Script execution phase, matching nmap's NSE phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptPhase {
    Prerule,
    Hostrule,
    Portrule,
    Postrule,
}

impl fmt::Display for ScriptPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prerule => write!(f, "prerule"),
            Self::Hostrule => write!(f, "hostrule"),
            Self::Portrule => write!(f, "portrule"),
            Self::Postrule => write!(f, "postrule"),
        }
    }
}

/// Script category, matching nmap's 13 categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScriptCategory {
    Auth,
    Broadcast,
    Brute,
    Default,
    Discovery,
    Dos,
    Exploit,
    External,
    Fuzzer,
    Intrusive,
    Malware,
    Safe,
    Version,
}

impl fmt::Display for ScriptCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth => write!(f, "auth"),
            Self::Broadcast => write!(f, "broadcast"),
            Self::Brute => write!(f, "brute"),
            Self::Default => write!(f, "default"),
            Self::Discovery => write!(f, "discovery"),
            Self::Dos => write!(f, "dos"),
            Self::Exploit => write!(f, "exploit"),
            Self::External => write!(f, "external"),
            Self::Fuzzer => write!(f, "fuzzer"),
            Self::Intrusive => write!(f, "intrusive"),
            Self::Malware => write!(f, "malware"),
            Self::Safe => write!(f, "safe"),
            Self::Version => write!(f, "version"),
        }
    }
}

impl ScriptCategory {
    /// Parse a category name string (case-insensitive).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "auth" => Some(Self::Auth),
            "broadcast" => Some(Self::Broadcast),
            "brute" => Some(Self::Brute),
            "default" => Some(Self::Default),
            "discovery" => Some(Self::Discovery),
            "dos" => Some(Self::Dos),
            "exploit" => Some(Self::Exploit),
            "external" => Some(Self::External),
            "fuzzer" => Some(Self::Fuzzer),
            "intrusive" => Some(Self::Intrusive),
            "malware" => Some(Self::Malware),
            "safe" => Some(Self::Safe),
            "version" => Some(Self::Version),
            _ => None,
        }
    }
}

/// CLI configuration for the scripting engine.
#[derive(Debug, Clone, Default)]
pub struct ScriptConfig {
    /// Whether scripting is enabled.
    pub enabled: bool,
    /// Script names, patterns, or categories to run.
    pub scripts: Vec<String>,
    /// Key-value arguments passed to scripts.
    pub script_args: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_result_round_trip() {
        let result = ScriptResult {
            id: "http-title".into(),
            output: "Title: Example".into(),
            elements: None,
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ScriptResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "http-title");
        assert_eq!(parsed.output, "Title: Example");
        assert!(parsed.elements.is_none());
    }

    #[test]
    fn script_result_with_elements() {
        let result = ScriptResult {
            id: "test".into(),
            output: "output".into(),
            elements: Some(ScriptValue::Map(vec![
                ("key".into(), ScriptValue::String("value".into())),
                ("num".into(), ScriptValue::Number(42.0)),
            ])),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ScriptResult = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "test");
        assert!(parsed.elements.is_some());
    }

    #[test]
    fn script_value_variants_serialize() {
        let string_val = ScriptValue::String("hello".into());
        let json = serde_json::to_string(&string_val).unwrap();
        assert_eq!(json, "\"hello\"");

        let num_val = ScriptValue::Number(3.15);
        let json = serde_json::to_string(&num_val).unwrap();
        assert!(json.contains("3.15"));

        let bool_val = ScriptValue::Bool(true);
        let json = serde_json::to_string(&bool_val).unwrap();
        assert_eq!(json, "true");

        let list_val = ScriptValue::List(vec![
            ScriptValue::Number(1.0),
            ScriptValue::Number(2.0),
        ]);
        let json = serde_json::to_string(&list_val).unwrap();
        assert!(json.contains("["));
    }

    #[test]
    fn script_phase_display() {
        assert_eq!(ScriptPhase::Prerule.to_string(), "prerule");
        assert_eq!(ScriptPhase::Hostrule.to_string(), "hostrule");
        assert_eq!(ScriptPhase::Portrule.to_string(), "portrule");
        assert_eq!(ScriptPhase::Postrule.to_string(), "postrule");
    }

    #[test]
    fn script_category_display() {
        assert_eq!(ScriptCategory::Auth.to_string(), "auth");
        assert_eq!(ScriptCategory::Default.to_string(), "default");
        assert_eq!(ScriptCategory::Safe.to_string(), "safe");
        assert_eq!(ScriptCategory::Version.to_string(), "version");
    }

    #[test]
    fn script_category_from_str_loose() {
        assert_eq!(ScriptCategory::from_str_loose("default"), Some(ScriptCategory::Default));
        assert_eq!(ScriptCategory::from_str_loose("DEFAULT"), Some(ScriptCategory::Default));
        assert_eq!(ScriptCategory::from_str_loose("Safe"), Some(ScriptCategory::Safe));
        assert_eq!(ScriptCategory::from_str_loose("unknown"), None);
    }

    #[test]
    fn script_config_default() {
        let config = ScriptConfig::default();
        assert!(!config.enabled);
        assert!(config.scripts.is_empty());
        assert!(config.script_args.is_empty());
    }

    #[test]
    fn script_phase_serialize_round_trip() {
        let phase = ScriptPhase::Portrule;
        let json = serde_json::to_string(&phase).unwrap();
        let parsed: ScriptPhase = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ScriptPhase::Portrule);
    }

    #[test]
    fn script_category_serialize_round_trip() {
        let cat = ScriptCategory::Discovery;
        let json = serde_json::to_string(&cat).unwrap();
        let parsed: ScriptCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ScriptCategory::Discovery);
    }
}
