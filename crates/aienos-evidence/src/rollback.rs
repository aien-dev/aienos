//! Machine 1 native-boot rollback verdict (docs/NATIVE_BOOT_ONE_TIME.md).
//!
//! Compares the pre-boot and post-return captures written by
//! `scripts/verify_native_rollback.sh --capture-pre/--capture-post` and prints
//! the report and verdict. Exit status: 0 PASS, 1 FAIL, 3 BLOCKED, and 2 when a
//! capture cannot be read or does not have the capture shape.
//!
//! This replaces the former embedded Python verifier. The report lines keep
//! that verifier's wording, including its rendering of missing values as
//! `None`, booleans as `True`/`False` and lists as `['a', 'b']`, so earlier
//! reports stay comparable.

use serde_json::{Map, Value};

#[derive(Debug, Eq, PartialEq)]
pub enum Verdict {
    Pass,
    Fail,
    Blocked,
}

impl Verdict {
    pub fn exit_code(&self) -> i32 {
        match self {
            Verdict::Pass => 0,
            Verdict::Fail => 1,
            Verdict::Blocked => 3,
        }
    }
}

/// Exit status when a capture file is unreadable or malformed.
pub const EXIT_UNPARSEABLE: i32 = 2;

/// Top-level fields that must be strings when present (the verifier lowercases,
/// splits or trims them).
const STRING_FIELDS: [&str; 4] = ["secure_boot", "boot_order", "boot_current", "boot_next"];

/// Reads and parses one capture, checking the shape the verifier relies on.
/// The error text follows `ERROR: Cannot parse <path>: `.
pub fn load(path: &str) -> Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let v: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    check_shape(&v)?;
    Ok(v)
}

/// A capture must be a JSON object; the fields the verifier transforms must be
/// strings when present, and `root`/`esp` must be objects when present.
pub fn check_shape(v: &Value) -> Result<(), String> {
    let obj = v
        .as_object()
        .ok_or("capture is not a JSON object".to_string())?;
    for key in STRING_FIELDS {
        if let Some(f) = obj.get(key) {
            if !f.is_string() {
                return Err(format!("field `{key}` is not a string"));
            }
        }
    }
    for key in ["root", "esp"] {
        if let Some(f) = obj.get(key) {
            if !f.is_object() {
                return Err(format!("field `{key}` is not an object"));
            }
        }
    }
    if let Some(opts) = obj.get("root").and_then(|r| r.get("options")) {
        if !opts.is_string() {
            return Err("field `root.options` is not a string".into());
        }
    }
    Ok(())
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn section<'a>(v: &'a Value, key: &str) -> Option<&'a Map<String, Value>> {
    v.get(key).and_then(Value::as_object)
}

/// `section.get(key)` with a missing section or key read as JSON null.
fn field<'a>(sec: Option<&'a Map<String, Value>>, key: &str) -> &'a Value {
    sec.and_then(|s| s.get(key)).unwrap_or(&Value::Null)
}

/// Python truthiness of a JSON value.
fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// Python `str()` of a JSON value, as the former report printed it.
fn show(v: &Value) -> String {
    match v {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn py_bool(b: bool) -> &'static str {
    if b {
        "True"
    } else {
        "False"
    }
}

/// Python `repr()` of a list of strings: `['0001', '0003']`.
fn py_list<S: AsRef<str>>(items: &[S]) -> String {
    let quoted: Vec<String> = items
        .iter()
        .map(|s| {
            let s = s.as_ref();
            let q = if s.contains('\'') && !s.contains('"') {
                '"'
            } else {
                '\''
            };
            let mut out = String::from(q);
            for c in s.chars() {
                match c {
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c if c == q => {
                        out.push('\\');
                        out.push(c);
                    }
                    c => out.push(c),
                }
            }
            out.push(q);
            out
        })
        .collect();
    format!("[{}]", quoted.join(", "))
}

fn boot_order(v: &Value) -> Vec<String> {
    text(v, "boot_order")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Returns the full report text and the verdict.
pub fn verify(pre: &Value, post: &Value) -> (String, Verdict) {
    let mut errors: Vec<String> = Vec::new();
    let mut blocked: Vec<String> = Vec::new();

    // 1. Secure Boot must be on before and after, and unchanged.
    let sb_pre = text(pre, "secure_boot").to_lowercase();
    let sb_post = text(post, "secure_boot").to_lowercase();
    if sb_pre != "enabled" {
        blocked.push(format!("Pre-boot Secure Boot is not enabled: {sb_pre}"));
    }
    if sb_post != "enabled" {
        blocked.push(format!("Post-boot Secure Boot is not enabled: {sb_post}"));
    }
    if sb_pre != sb_post {
        errors.push(format!(
            "Secure Boot state changed from '{sb_pre}' to '{sb_post}'"
        ));
    }

    // 2. BootOrder: default entry and relative order of every original entry kept.
    let bo_pre = boot_order(pre);
    let bo_post = boot_order(post);
    if bo_pre.is_empty() {
        errors.push("Pre-boot BootOrder is empty".into());
    }
    if bo_post.is_empty() {
        errors.push("Post-boot BootOrder is empty".into());
    }
    if let (Some(first_pre), Some(first_post)) = (bo_pre.first(), bo_post.first()) {
        if first_pre != first_post {
            errors.push(format!(
                "Permanent default boot entry altered: pre was {first_pre}, post is {first_post}"
            ));
        }
        let common_post: Vec<&String> = bo_post.iter().filter(|x| bo_pre.contains(x)).collect();
        if !common_post.iter().copied().eq(bo_pre.iter()) {
            errors.push(format!(
                "BootOrder sequence changed: pre={}, filtered_post={}",
                py_list(&bo_pre),
                py_list(&common_post)
            ));
        }
    }

    // 3. Returned to the default entry.
    let cur_post = text(post, "boot_current").trim();
    if let Some(first_pre) = bo_pre.first() {
        if cur_post != first_pre {
            errors.push(format!(
                "Post-boot did not return to default entry: expected {first_pre}, got {cur_post}"
            ));
        }
    }

    // 4. BootNext consumed by firmware.
    let next_post = text(post, "boot_next").trim();
    if !next_post.is_empty() {
        errors.push(format!(
            "BootNext was not consumed by firmware: still set to {next_post}"
        ));
    }

    // 5. Root filesystem unchanged and writable.
    let (root_pre, root_post) = (section(pre, "root"), section(post, "root"));
    let (root_uuid_pre, root_uuid_post) = (field(root_pre, "uuid"), field(root_post, "uuid"));
    if truthy(root_uuid_pre) && root_uuid_pre != root_uuid_post {
        errors.push(format!(
            "Root UUID changed: pre={}, post={}",
            show(root_uuid_pre),
            show(root_uuid_post)
        ));
    }
    let root_opts = field(root_post, "options");
    if !root_opts
        .as_str()
        .unwrap_or("")
        .split(',')
        .any(|o| o == "rw")
    {
        errors.push(format!(
            "Root filesystem not mounted rw after return: {}",
            show(root_opts)
        ));
    }

    // 6. ESP unchanged.
    let (esp_pre, esp_post) = (section(pre, "esp"), section(post, "esp"));
    let (esp_uuid_pre, esp_uuid_post) = (field(esp_pre, "uuid"), field(esp_post, "uuid"));
    if truthy(esp_uuid_pre) && esp_uuid_pre != esp_uuid_post {
        errors.push(format!(
            "ESP UUID changed: pre={}, post={}",
            show(esp_uuid_pre),
            show(esp_uuid_post)
        ));
    }

    let top = |v: &Value, key: &str| show(v.get(key).unwrap_or(&Value::Null));
    let mut r = String::new();
    r.push_str("=== NATIVE BOOT ROLLBACK VERIFICATION REPORT ===\n");
    r.push_str(&format!(
        "Pre-capture:  {} on {}\n",
        top(pre, "captured_utc"),
        top(pre, "host")
    ));
    r.push_str(&format!(
        "Post-capture: {} on {}\n",
        top(post, "captured_utc"),
        top(post, "host")
    ));
    r.push_str(&format!("Secure Boot:  before={sb_pre}, after={sb_post}\n"));
    r.push_str(&format!(
        "BootOrder:    before={}, after={}\n",
        py_list(&bo_pre),
        py_list(&bo_post)
    ));
    r.push_str(&format!(
        "BootCurrent:  after={cur_post} (expected={})\n",
        bo_pre.first().map_or("unknown", String::as_str)
    ));
    r.push_str(&format!(
        "BootNext:     after={}\n",
        if next_post.is_empty() {
            "<empty>"
        } else {
            next_post
        }
    ));
    r.push_str(&format!(
        "Root UUID:    {} (matched={})\n",
        show(root_uuid_post),
        py_bool(root_uuid_pre == root_uuid_post)
    ));
    r.push_str(&format!(
        "ESP UUID:     {} (matched={})\n",
        show(esp_uuid_post),
        py_bool(esp_uuid_pre == esp_uuid_post)
    ));

    if !blocked.is_empty() {
        r.push_str("\n--- BLOCKED REASONS ---\n");
        for b in &blocked {
            r.push_str(&format!("* {b}\n"));
        }
        r.push_str("\nVERDICT: BLOCKED\n");
        return (r, Verdict::Blocked);
    }
    if !errors.is_empty() {
        r.push_str("\n--- VIOLATIONS ---\n");
        for e in &errors {
            r.push_str(&format!("* FAIL: {e}\n"));
        }
        r.push_str("\nVERDICT: FAIL\n");
        return (r, Verdict::Fail);
    }
    r.push_str("\nAll rollback assertions verified.\nVERDICT: PASS\n");
    (r, Verdict::Pass)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn capture() -> Value {
        json!({
            "captured_utc": "2026-09-25T00:00:00Z", "host": "spark",
            "secure_boot": "enabled", "boot_order": "0001,0003,0004",
            "boot_current": "0001", "boot_next": "",
            "root": {"uuid": "r-1", "options": "rw,relatime"},
            "esp": {"uuid": "e-1"}
        })
    }

    #[test]
    fn identical_return_passes() {
        let (report, v) = verify(&capture(), &capture());
        assert_eq!(v, Verdict::Pass, "{report}");
        assert_eq!(v.exit_code(), 0);
        assert!(report.ends_with("\nAll rollback assertions verified.\nVERDICT: PASS\n"));
    }

    #[test]
    fn report_lines_match_former_python_rendering() {
        let (report, _) = verify(&capture(), &capture());
        let expected = "=== NATIVE BOOT ROLLBACK VERIFICATION REPORT ===\n\
Pre-capture:  2026-09-25T00:00:00Z on spark\n\
Post-capture: 2026-09-25T00:00:00Z on spark\n\
Secure Boot:  before=enabled, after=enabled\n\
BootOrder:    before=['0001', '0003', '0004'], after=['0001', '0003', '0004']\n\
BootCurrent:  after=0001 (expected=0001)\n\
BootNext:     after=<empty>\n\
Root UUID:    r-1 (matched=True)\n\
ESP UUID:     e-1 (matched=True)\n";
        assert!(report.starts_with(expected), "{report}");
    }

    #[test]
    fn missing_values_render_as_none() {
        let mut post = capture();
        post.as_object_mut().unwrap().remove("host");
        post["root"].as_object_mut().unwrap().remove("uuid");
        post["root"].as_object_mut().unwrap().remove("options");
        let (report, v) = verify(&capture(), &post);
        assert_eq!(v, Verdict::Fail);
        assert!(report.contains("Post-capture: 2026-09-25T00:00:00Z on None\n"));
        assert!(report.contains("Root UUID:    None (matched=False)\n"));
        assert!(report.contains("* FAIL: Root UUID changed: pre=r-1, post=None\n"));
        assert!(report.contains("* FAIL: Root filesystem not mounted rw after return: None\n"));
    }

    #[test]
    fn added_candidate_entry_outside_order_is_allowed() {
        let mut post = capture();
        post["boot_order"] = json!("0001,0000,0003,0004");
        assert_eq!(verify(&capture(), &post).1, Verdict::Pass);
    }

    #[test]
    fn unconsumed_boot_next_fails() {
        let mut post = capture();
        post["boot_next"] = json!("0000");
        let (report, v) = verify(&capture(), &post);
        assert_eq!(v, Verdict::Fail);
        assert_eq!(v.exit_code(), 1);
        assert!(
            report.contains("* FAIL: BootNext was not consumed by firmware: still set to 0000\n")
        );
    }

    #[test]
    fn reordered_or_changed_default_fails() {
        let mut post = capture();
        post["boot_order"] = json!("0003,0001,0004");
        post["boot_current"] = json!("0003");
        let (report, v) = verify(&capture(), &post);
        assert_eq!(v, Verdict::Fail);
        assert!(report.contains("Permanent default boot entry altered: pre was 0001, post is 0003"));
        assert!(report.contains(
            "BootOrder sequence changed: pre=['0001', '0003', '0004'], filtered_post=['0003', '0001', '0004']"
        ));
        assert!(report.contains("expected 0001, got 0003"));
    }

    #[test]
    fn duplicated_entry_changes_sequence() {
        let mut post = capture();
        post["boot_order"] = json!("0001,0003,0003,0004");
        assert_eq!(verify(&capture(), &post).1, Verdict::Fail);
    }

    #[test]
    fn read_only_root_or_changed_esp_fails() {
        let mut post = capture();
        post["root"]["options"] = json!("ro");
        assert_eq!(verify(&capture(), &post).1, Verdict::Fail);
        let mut post = capture();
        post["esp"]["uuid"] = json!("e-2");
        let (report, v) = verify(&capture(), &post);
        assert_eq!(v, Verdict::Fail);
        assert!(report.contains("* FAIL: ESP UUID changed: pre=e-1, post=e-2\n"));
        assert!(report.contains("ESP UUID:     e-2 (matched=False)\n"));
    }

    #[test]
    fn empty_pre_uuid_is_not_compared() {
        let mut pre = capture();
        pre["root"]["uuid"] = json!("");
        pre["esp"]["uuid"] = json!("");
        assert_eq!(verify(&pre, &capture()).1, Verdict::Pass);
    }

    #[test]
    fn secure_boot_is_case_insensitive() {
        let mut pre = capture();
        pre["secure_boot"] = json!("Enabled");
        assert_eq!(verify(&pre, &capture()).1, Verdict::Pass);
    }

    #[test]
    fn secure_boot_off_blocks_even_with_other_failures() {
        let mut pre = capture();
        pre["secure_boot"] = json!("disabled");
        let mut post = capture();
        post["boot_next"] = json!("0000");
        let (report, v) = verify(&pre, &post);
        assert_eq!(v, Verdict::Blocked);
        assert_eq!(v.exit_code(), 3);
        assert!(report.contains("* Pre-boot Secure Boot is not enabled: disabled\n"));
        assert!(!report.contains("VIOLATIONS"));
    }

    #[test]
    fn empty_boot_orders_fail() {
        let mut post = capture();
        post["boot_order"] = json!(" , ");
        let (report, v) = verify(&capture(), &post);
        assert_eq!(v, Verdict::Fail);
        assert!(report.contains("* FAIL: Post-boot BootOrder is empty\n"));
        assert!(report.contains("after=[]"));
    }

    #[test]
    fn python_list_repr() {
        assert_eq!(py_list::<&str>(&[]), "[]");
        assert_eq!(py_list(&["a'b"]), "[\"a'b\"]");
        assert_eq!(py_list(&["a'b\""]), "['a\\'b\"']");
    }

    #[test]
    fn shape_rejects_values_the_verifier_cannot_use() {
        assert!(check_shape(&capture()).is_ok());
        assert!(check_shape(&json!({})).is_ok());
        assert!(check_shape(&json!([])).is_err());
        let mut c = capture();
        c["boot_next"] = Value::Null;
        assert!(check_shape(&c).is_err());
        let mut c = capture();
        c["root"] = json!("x");
        assert!(check_shape(&c).is_err());
        let mut c = capture();
        c["root"]["options"] = json!(1);
        assert!(check_shape(&c).is_err());
    }
}
