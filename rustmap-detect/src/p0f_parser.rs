use std::path::Path;

use rustmap_types::{TcpFingerprint, TcpOptionKind};

/// A parsed label from a p0f signature entry.
#[derive(Debug, Clone)]
pub struct P0fLabel {
    /// OS class (e.g., "unix", "win").
    pub class: String,
    /// OS name (e.g., "Linux", "Windows").
    pub name: String,
    /// OS flavor/version (e.g., "3.11 and newer", "7 or 8").
    pub flavor: String,
}

/// How the MSS field should be matched.
#[derive(Debug, Clone)]
pub enum P0fMssSpec {
    /// Any MSS value matches.
    Wildcard,
    /// Exact MSS value.
    Exact(u16),
}

/// How the window size field should be matched.
#[derive(Debug, Clone)]
pub enum P0fWindowSpec {
    /// Any window size matches.
    Wildcard,
    /// Exact window size.
    Exact(u16),
    /// Window = MSS * multiplier.
    MssMul(u16),
    /// Window = MTU * multiplier (MTU = MSS + 40).
    MtuMul(u16),
    /// Window = value % modulo == 0.
    Modulo(u16),
}

/// A single parsed p0f signature.
#[derive(Debug, Clone)]
pub struct P0fSignature {
    pub label: P0fLabel,
    pub initial_ttl: u8,
    pub ip_opt_len: u8,
    pub mss: P0fMssSpec,
    pub window_spec: P0fWindowSpec,
    pub window_scale: Option<u8>,
    pub tcp_options: Vec<TcpOptionKind>,
    pub df_bit: bool,
}

/// A match result from the p0f database.
#[derive(Debug, Clone)]
pub struct P0fMatch {
    pub label: P0fLabel,
    pub score: u8,
}

/// Database of parsed p0f signatures.
#[derive(Debug, Clone, Default)]
pub struct P0fDatabase {
    /// SYN signatures from [tcp:request] section.
    pub syn_signatures: Vec<P0fSignature>,
    /// SYN+ACK signatures from [tcp:response] section.
    pub synack_signatures: Vec<P0fSignature>,
}

/// Error type for p0f parsing.
#[derive(Debug, thiserror::Error)]
pub enum P0fParseError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse error on line {line}: {message}")]
    Parse { line: usize, message: String },
}

impl P0fDatabase {
    /// Parse a p0f fingerprint file from the given path.
    pub fn parse_file(path: &Path) -> Result<Self, P0fParseError> {
        let content = std::fs::read_to_string(path)?;
        Self::parse_str(&content)
    }

    /// Parse p0f fingerprint data from a string.
    pub fn parse_str(content: &str) -> Result<Self, P0fParseError> {
        let mut db = P0fDatabase::default();
        let mut current_section = Section::None;
        let mut current_label: Option<P0fLabel> = None;

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with(';') {
                continue;
            }

            // Section header
            if line.starts_with('[') && line.ends_with(']') {
                current_section = match &line[1..line.len() - 1] {
                    "tcp:request" => Section::TcpRequest,
                    "tcp:response" => Section::TcpResponse,
                    _ => Section::Other,
                };
                current_label = None;
                continue;
            }

            // Only parse tcp sections
            if matches!(current_section, Section::None | Section::Other) {
                continue;
            }

            // Label line: "label = class:name:flavor"
            if let Some(rest) = line.strip_prefix("label") {
                let rest = rest.trim().strip_prefix('=').unwrap_or(rest).trim();
                current_label = parse_label(rest, line_num)?;
                continue;
            }

            // Signature line: "sig = ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass"
            if let Some(rest) = line.strip_prefix("sig") {
                let rest = rest.trim().strip_prefix('=').unwrap_or(rest).trim();
                if let Some(ref label) = current_label
                    && let Some(sig) = parse_signature(rest, label.clone(), line_num)?
                {
                    match current_section {
                        Section::TcpRequest => db.syn_signatures.push(sig),
                        Section::TcpResponse => db.synack_signatures.push(sig),
                        _ => {}
                    }
                }
                continue;
            }
        }

        Ok(db)
    }

    /// Match a TcpFingerprint against synack signatures (for SYN/ACK responses).
    pub fn match_synack(&self, fingerprint: &TcpFingerprint) -> Option<P0fMatch> {
        self.match_against(&self.synack_signatures, fingerprint)
    }

    /// Match a TcpFingerprint against syn signatures (for SYN requests).
    pub fn match_syn(&self, fingerprint: &TcpFingerprint) -> Option<P0fMatch> {
        self.match_against(&self.syn_signatures, fingerprint)
    }

    fn match_against(
        &self,
        signatures: &[P0fSignature],
        fingerprint: &TcpFingerprint,
    ) -> Option<P0fMatch> {
        let mut best_match: Option<P0fMatch> = None;

        for sig in signatures {
            let score = score_p0f_match(sig, fingerprint);
            if score >= 50
                && best_match.as_ref().is_none_or(|m| score > m.score)
            {
                best_match = Some(P0fMatch {
                    label: sig.label.clone(),
                    score,
                });
            }
        }

        best_match
    }
}

/// Score how well a fingerprint matches a p0f signature (0-100).
fn score_p0f_match(sig: &P0fSignature, fp: &TcpFingerprint) -> u8 {
    let mut score: u16 = 0;

    // TTL match (25 points)
    if fp.initial_ttl == sig.initial_ttl {
        score += 25;
    }

    // TCP options order match (40 points)
    let fp_kinds: Vec<TcpOptionKind> = fp.tcp_options.iter().map(|o| o.kind()).collect();
    if fp_kinds == sig.tcp_options {
        score += 40;
    } else {
        // Partial match via LCS
        let lcs = lcs_length(&fp_kinds, &sig.tcp_options);
        let max_len = fp_kinds.len().max(sig.tcp_options.len());
        if max_len > 0 {
            score += (40 * lcs / max_len) as u16;
        }
    }

    // Window size match (20 points)
    match &sig.window_spec {
        P0fWindowSpec::Wildcard => score += 20,
        P0fWindowSpec::Exact(w) => {
            if fp.window_size == *w {
                score += 20;
            }
        }
        P0fWindowSpec::MssMul(mul) => {
            if let Some(mss) = fp.mss
                && fp.window_size == mss.saturating_mul(*mul)
            {
                score += 20;
            }
        }
        P0fWindowSpec::MtuMul(mul) => {
            if let Some(mss) = fp.mss {
                let mtu = mss as u32 + 40;
                if fp.window_size as u32 == mtu * (*mul as u32) {
                    score += 20;
                }
            }
        }
        P0fWindowSpec::Modulo(m) => {
            if *m > 0 && fp.window_size.is_multiple_of(*m) {
                score += 20;
            }
        }
    }

    // DF bit match (10 points)
    if fp.df_bit == sig.df_bit {
        score += 10;
    }

    // MSS match (5 points)
    match &sig.mss {
        P0fMssSpec::Wildcard => score += 5,
        P0fMssSpec::Exact(m) => {
            if fp.mss == Some(*m) {
                score += 5;
            }
        }
    }

    score.min(100) as u8
}

/// Longest Common Subsequence length for TCP option ordering comparison.
fn lcs_length(a: &[TcpOptionKind], b: &[TcpOptionKind]) -> usize {
    let m = a.len();
    let n = b.len();
    if m == 0 || n == 0 {
        return 0;
    }

    let mut prev = vec![0usize; n + 1];
    let mut curr = vec![0usize; n + 1];

    for i in 1..=m {
        for j in 1..=n {
            if a[i - 1] == b[j - 1] {
                curr[j] = prev[j - 1] + 1;
            } else {
                curr[j] = prev[j].max(curr[j - 1]);
            }
        }
        std::mem::swap(&mut prev, &mut curr);
        curr.fill(0);
    }

    prev[n]
}

#[derive(Debug, Clone, Copy)]
enum Section {
    None,
    TcpRequest,
    TcpResponse,
    Other,
}

/// Parse a p0f label line: "class:name:flavor" or "s:class:name:flavor"
fn parse_label(s: &str, line_num: usize) -> Result<Option<P0fLabel>, P0fParseError> {
    let parts: Vec<&str> = s.split(':').collect();

    // Format: "s:class:name:flavor" or "class:name:flavor"
    let (class, name, flavor) = match parts.len() {
        4 => (parts[1], parts[2], parts[3]),
        3 => (parts[0], parts[1], parts[2]),
        _ => {
            return Err(P0fParseError::Parse {
                line: line_num + 1,
                message: format!("invalid label format: {s}"),
            })
        }
    };

    Ok(Some(P0fLabel {
        class: class.to_string(),
        name: name.to_string(),
        flavor: flavor.to_string(),
    }))
}

/// Parse a p0f signature line: "ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass"
fn parse_signature(
    s: &str,
    label: P0fLabel,
    line_num: usize,
) -> Result<Option<P0fSignature>, P0fParseError> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() < 8 {
        return Err(P0fParseError::Parse {
            line: line_num + 1,
            message: format!("expected 8 fields, got {}", parts.len()),
        });
    }

    // ver (field 0): skip IPv6-only entries
    let ver = parts[0].trim();
    if ver == "6" {
        return Ok(None);
    }

    // ittl (field 1): initial TTL
    let ittl_str = parts[1].trim();
    let initial_ttl = parse_ttl(ittl_str).ok_or_else(|| P0fParseError::Parse {
        line: line_num + 1,
        message: format!("invalid TTL: {ittl_str}"),
    })?;

    // olen (field 2): IP options length
    let ip_opt_len = parts[2]
        .trim()
        .parse::<u8>()
        .unwrap_or(0);

    // mss (field 3)
    let mss = parse_mss_spec(parts[3].trim());

    // wsize,scale (field 4)
    let (window_spec, window_scale) = parse_window_spec(parts[4].trim());

    // olayout (field 5): TCP options layout
    let tcp_options = parse_options_layout(parts[5].trim());

    // quirks (field 6): behavioral quirks
    let quirks = parts[6].trim();
    let df_bit = quirks.split(',').any(|q| q.trim() == "df");

    // pclass (field 7): payload class — we don't filter on this

    Ok(Some(P0fSignature {
        label,
        initial_ttl,
        ip_opt_len,
        mss,
        window_spec,
        window_scale,
        tcp_options,
        df_bit,
    }))
}

fn parse_ttl(s: &str) -> Option<u8> {
    // Handle "64+1" format (TTL+distance) — just take the base TTL
    let base = s.split('+').next()?;
    // Handle wildcard
    if base == "*" {
        return Some(64); // Default assumption
    }
    base.parse::<u8>().ok()
}

fn parse_mss_spec(s: &str) -> P0fMssSpec {
    if s == "*" {
        P0fMssSpec::Wildcard
    } else {
        s.parse::<u16>()
            .map(P0fMssSpec::Exact)
            .unwrap_or(P0fMssSpec::Wildcard)
    }
}

fn parse_window_spec(s: &str) -> (P0fWindowSpec, Option<u8>) {
    let parts: Vec<&str> = s.split(',').collect();
    let wsize_str = parts[0].trim();
    let scale = parts
        .get(1)
        .and_then(|s| {
            let s = s.trim();
            if s == "*" {
                None
            } else {
                s.parse::<u8>().ok()
            }
        });

    let window_spec = if wsize_str == "*" {
        P0fWindowSpec::Wildcard
    } else if let Some(rest) = wsize_str.strip_prefix("mss*") {
        rest.parse::<u16>()
            .map(P0fWindowSpec::MssMul)
            .unwrap_or(P0fWindowSpec::Wildcard)
    } else if let Some(rest) = wsize_str.strip_prefix("mtu*") {
        rest.parse::<u16>()
            .map(P0fWindowSpec::MtuMul)
            .unwrap_or(P0fWindowSpec::Wildcard)
    } else if let Some(rest) = wsize_str.strip_prefix('%') {
        rest.parse::<u16>()
            .map(P0fWindowSpec::Modulo)
            .unwrap_or(P0fWindowSpec::Wildcard)
    } else {
        wsize_str
            .parse::<u16>()
            .map(P0fWindowSpec::Exact)
            .unwrap_or(P0fWindowSpec::Wildcard)
    };

    (window_spec, scale)
}

fn parse_options_layout(s: &str) -> Vec<TcpOptionKind> {
    if s.is_empty() || s == "." {
        return Vec::new();
    }

    s.split(',')
        .filter_map(|opt| {
            let opt = opt.trim();
            match opt {
                "mss" => Some(TcpOptionKind::Mss),
                "nop" => Some(TcpOptionKind::Nop),
                "ws" => Some(TcpOptionKind::WindowScale),
                "sok" => Some(TcpOptionKind::SackPermitted),
                "ts" => Some(TcpOptionKind::Timestamp),
                "eol" => Some(TcpOptionKind::Eol),
                _ if opt.starts_with("eol+") => Some(TcpOptionKind::Eol),
                _ if opt.starts_with("?") => None, // Unknown option, skip
                _ => None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustmap_types::TcpOption;

    const SAMPLE_P0F: &str = r#"
; p0f - passive OS fingerprinting
; Sample data for testing

[tcp:request]

label = s:unix:Linux:3.11 and newer
sig   = *:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+:0

label = s:unix:Linux:2.6.x
sig   = *:64:0:*:mss*4,7:mss,sok,ts,nop,ws:df,id+:0

label = s:win:Windows:7 or 8
sig   = *:128:0:*:8192,8:mss,nop,ws,nop,nop,sok:df,id+:0

[tcp:response]

label = s:unix:Linux:3.x
sig   = *:64:0:*:mss*10,7:mss,sok,ts,nop,ws:df:0

label = s:win:Windows:7 or 8
sig   = *:128:0:*:8192,8:mss,nop,ws,nop,nop,sok:df:0

label = s:unix:FreeBSD:9.x
sig   = *:64:0:*:65535,6:mss,nop,ws,nop,nop,ts,sok:df:0
"#;

    #[test]
    fn parse_sample_p0f_file() {
        let db = P0fDatabase::parse_str(SAMPLE_P0F).unwrap();
        assert_eq!(db.syn_signatures.len(), 3);
        assert_eq!(db.synack_signatures.len(), 3);
    }

    #[test]
    fn parse_label_correctly() {
        let db = P0fDatabase::parse_str(SAMPLE_P0F).unwrap();
        let linux = &db.syn_signatures[0];
        assert_eq!(linux.label.class, "unix");
        assert_eq!(linux.label.name, "Linux");
        assert_eq!(linux.label.flavor, "3.11 and newer");
    }

    #[test]
    fn parse_ttl_correctly() {
        let db = P0fDatabase::parse_str(SAMPLE_P0F).unwrap();
        assert_eq!(db.syn_signatures[0].initial_ttl, 64); // Linux
        assert_eq!(db.syn_signatures[2].initial_ttl, 128); // Windows
    }

    #[test]
    fn parse_options_layout_correctly() {
        let db = P0fDatabase::parse_str(SAMPLE_P0F).unwrap();

        // Linux: mss,sok,ts,nop,ws
        let linux = &db.syn_signatures[0];
        assert_eq!(
            linux.tcp_options,
            vec![
                TcpOptionKind::Mss,
                TcpOptionKind::SackPermitted,
                TcpOptionKind::Timestamp,
                TcpOptionKind::Nop,
                TcpOptionKind::WindowScale,
            ]
        );

        // Windows: mss,nop,ws,nop,nop,sok
        let windows = &db.syn_signatures[2];
        assert_eq!(
            windows.tcp_options,
            vec![
                TcpOptionKind::Mss,
                TcpOptionKind::Nop,
                TcpOptionKind::WindowScale,
                TcpOptionKind::Nop,
                TcpOptionKind::Nop,
                TcpOptionKind::SackPermitted,
            ]
        );
    }

    #[test]
    fn parse_df_bit_from_quirks() {
        let db = P0fDatabase::parse_str(SAMPLE_P0F).unwrap();
        assert!(db.syn_signatures[0].df_bit); // Linux has df
        assert!(db.syn_signatures[2].df_bit); // Windows has df
    }

    #[test]
    fn parse_window_spec_mss_multiplier() {
        let db = P0fDatabase::parse_str(SAMPLE_P0F).unwrap();
        match &db.syn_signatures[0].window_spec {
            P0fWindowSpec::MssMul(20) => {} // mss*20
            other => panic!("expected MssMul(20), got {:?}", other),
        }
    }

    #[test]
    fn match_linux_synack() {
        let db = P0fDatabase::parse_str(SAMPLE_P0F).unwrap();

        let linux_fp = TcpFingerprint {
            initial_ttl: 64,
            window_size: 14600,
            tcp_options: vec![
                TcpOption::Mss(1460),
                TcpOption::SackPermitted,
                TcpOption::Timestamp(0, 0),
                TcpOption::Nop,
                TcpOption::WindowScale(7),
            ],
            df_bit: true,
            mss: Some(1460),
        };

        let result = db.match_synack(&linux_fp);
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.label.name, "Linux");
        assert!(m.score >= 50);
    }

    #[test]
    fn match_windows_synack() {
        let db = P0fDatabase::parse_str(SAMPLE_P0F).unwrap();

        let win_fp = TcpFingerprint {
            initial_ttl: 128,
            window_size: 8192,
            tcp_options: vec![
                TcpOption::Mss(1460),
                TcpOption::Nop,
                TcpOption::WindowScale(8),
                TcpOption::Nop,
                TcpOption::Nop,
                TcpOption::SackPermitted,
            ],
            df_bit: true,
            mss: Some(1460),
        };

        let result = db.match_synack(&win_fp);
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.label.name, "Windows");
    }

    #[test]
    fn no_match_for_unknown_fingerprint() {
        let db = P0fDatabase::parse_str(SAMPLE_P0F).unwrap();

        let weird_fp = TcpFingerprint {
            initial_ttl: 255,
            window_size: 1234,
            tcp_options: vec![TcpOption::Eol],
            df_bit: false,
            mss: None,
        };

        assert!(db.match_synack(&weird_fp).is_none());
    }

    #[test]
    fn lcs_exact_match() {
        let a = vec![TcpOptionKind::Mss, TcpOptionKind::Nop, TcpOptionKind::WindowScale];
        assert_eq!(lcs_length(&a, &a), 3);
    }

    #[test]
    fn lcs_partial_match() {
        let a = vec![TcpOptionKind::Mss, TcpOptionKind::Nop, TcpOptionKind::WindowScale];
        let b = vec![TcpOptionKind::Mss, TcpOptionKind::WindowScale];
        assert_eq!(lcs_length(&a, &b), 2);
    }

    #[test]
    fn lcs_no_match() {
        let a = vec![TcpOptionKind::Mss];
        let b = vec![TcpOptionKind::Nop];
        assert_eq!(lcs_length(&a, &b), 0);
    }

    #[test]
    fn lcs_empty() {
        let empty: Vec<TcpOptionKind> = vec![];
        assert_eq!(lcs_length(&empty, &empty), 0);
    }

    #[test]
    fn parse_empty_content() {
        let db = P0fDatabase::parse_str("").unwrap();
        assert!(db.syn_signatures.is_empty());
        assert!(db.synack_signatures.is_empty());
    }

    #[test]
    fn parse_comments_only() {
        let db = P0fDatabase::parse_str("; just a comment\n; another").unwrap();
        assert!(db.syn_signatures.is_empty());
    }
}
