//! OKF compatibility tests through the Governor Interface.

use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use agent_work_governor::{CheckRequest, Governor};
use serde_json::{Value, json};
use tempfile::TempDir;

// LLM-CONTRACT
// id: agent-work-governor.rust-okf-tests
// state: FIXTURE -> GOVERNOR_CHECK -> COMPATIBLE_VERDICT | TEST_FAILURE
// preconditions: every fixture is isolated in a temporary bundle
// invariant: tests exercise OKF behavior only through the Governor Interface
// failure: assertions identify the incompatible status or reason code
// source: https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/3fcbb9f828c2f23d109c855ee403c3a4c81f3a96/okf/SPEC.md
// knowledge: bundle:knowledge/references/okf-v0.2.md
// enforced_by: check
// test: bundle:rust/tests/okf.rs

type TestResult = Result<(), Box<dyn Error>>;

fn profile_metadata(concept_type: &str) -> Value {
    json!({
        "type": concept_type,
        "status": "draft",
        "generated": {
            "by": "process:rust-okf-test",
            "at": "2026-07-28T00:00:00+09:00"
        },
        "stale_after": "2026-10-28",
        "sources": [{"resource": "https://example.invalid/primary"}]
    })
}

fn frontmatter(metadata: &Value, body: &str) -> Result<String, serde_json::Error> {
    serde_json::to_string(metadata).map(|metadata| format!("---\n{metadata}\n---\n{body}"))
}

fn write(path: &Path, text: &str) -> Result<(), io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, text)
}

fn root_index(bundle: &Path) -> Result<(), io::Error> {
    write(
        &bundle.join("index.md"),
        "---\n{\"okf_version\":\"0.2\"}\n---\n# Index\n",
    )
}

fn check(bundle: PathBuf) -> Result<Value, Box<dyn Error>> {
    let report = Governor.check(CheckRequest::Okf { bundle })?;
    Ok(serde_json::to_value(report)?)
}

fn plugin_root() -> Result<PathBuf, io::Error> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| io::Error::other("Rust crate has no plugin parent"))
}

fn python_check(bundle: &Path) -> Result<Value, Box<dyn Error>> {
    let output = Command::new("python3")
        .arg(plugin_root()?.join("scripts/validate_okf.py"))
        .arg(bundle)
        .arg("--json")
        .output()?;
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn codes(report: &Value, pointer: &str) -> Vec<String> {
    let Some(findings) = report.pointer(pointer).and_then(Value::as_array) else {
        return Vec::new();
    };
    findings
        .iter()
        .filter_map(|finding| {
            finding
                .get("code")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect()
}

fn status<'a>(report: &'a Value, pointer: &str) -> Option<&'a str> {
    report.pointer(pointer).and_then(Value::as_str)
}

fn assert_document_read_error_matches_python(bundle: &Path) -> TestResult {
    let rust_report = check(bundle.to_path_buf())?;
    let python_report = python_check(bundle)?;
    let rust_codes = codes(&rust_report, "/okf_core/errors");

    assert_eq!(status(&rust_report, "/okf_core/status"), Some("invalid"));
    assert_eq!(
        status(&rust_report, "/okf_core/status"),
        status(&python_report, "/okf_core/status")
    );
    assert_eq!(
        rust_codes,
        codes(&python_report, "/okf_core/errors"),
        "Rust and Python must enumerate the same unreadable Markdown document"
    );
    assert_eq!(rust_codes, vec!["DOCUMENT_READ_ERROR".to_owned()]);
    Ok(())
}

#[test]
fn bundled_knowledge_passes_core_and_profile() -> TestResult {
    let report = check(plugin_root()?.join("knowledge"))?;
    assert_eq!(status(&report, "/okf_core/status"), Some("valid"));
    assert_eq!(status(&report, "/governor_profile/status"), Some("valid"));
    Ok(())
}

#[test]
fn iso_datetime_forms_match_python_profile() -> TestResult {
    let cases = [
        ("20260728", true),
        ("2026-W31", true),
        ("2026W31", true),
        ("2026-W31-2", true),
        ("2026W312", true),
        ("2026-07-28T12:34:56+0900", true),
        ("20260728T123456+0900", true),
        ("2026-W31-2T12:34:56+09:00", true),
        ("2026W312T123456+0900", true),
        ("2026-W31_12:34:56+09:00", true),
        ("2026-07-28z12:34:56", true),
        ("2026-07-28T12:34:56Z", true),
        ("2026-07-28Z", true),
        ("20260728Z", true),
        ("2026-W31Z", true),
        ("2026-W31🦀12:34:56+09:00", true),
        ("2026W31/123456+0900", true),
        ("2026-07-28T12:34:56+09:00:30", true),
        ("2026-07-28T12:34:56+090030", true),
        ("2026-07-28T12:34:56+09:00:30.5", true),
        ("2026-07-28T12:34:56+090030,5", true),
        ("2026-07-28T12:34:56+09:99:99", true),
        ("9999-W52-5", true),
        ("0000-01-01", false),
        ("2026-W54", false),
        ("2026W00", false),
        ("2026-W54-1", false),
        ("2026-W31-8", false),
        ("20261301", false),
        ("20260728T256000+0900", false),
        ("20260728T123456+2460", false),
        ("2026-07-28XX12:34:56+09:00", false),
        ("2026-07-28Z12:34:56", false),
        ("2026-W31_", false),
        ("9999-W52-6", false),
        ("9999-W52-7", false),
        ("2026-07-28T12:34:56+24:00:00", false),
        ("2026-07-28T12:34:56+240000", false),
        ("2026-07-28T12:34:56+09:00:30.", false),
        ("2026-07-28T12:34:56+090030.", false),
    ];

    for (generated_at, expected_valid) in cases {
        let temporary = TempDir::new()?;
        root_index(temporary.path())?;
        let mut metadata = profile_metadata("Reference");
        metadata["generated"]["at"] = json!(generated_at);
        write(
            &temporary.path().join("concept.md"),
            &frontmatter(&metadata, "# Body\n")?,
        )?;

        let rust_report = check(temporary.path().to_path_buf())?;
        let python_report = python_check(temporary.path())?;
        let rust_status = status(&rust_report, "/governor_profile/status");
        let python_status = status(&python_report, "/governor_profile/status");
        assert_eq!(
            rust_status, python_status,
            "status mismatch for {generated_at}"
        );
        assert_eq!(
            codes(&rust_report, "/governor_profile/errors"),
            codes(&python_report, "/governor_profile/errors"),
            "reason-code mismatch for {generated_at}"
        );
        assert_eq!(
            rust_status == Some("valid"),
            expected_valid,
            "unexpected validity for {generated_at}"
        );
    }
    Ok(())
}

#[test]
fn markdown_directory_is_document_read_error_like_python() -> TestResult {
    let temporary = TempDir::new()?;
    root_index(temporary.path())?;
    fs::create_dir(temporary.path().join("directory.md"))?;

    assert_document_read_error_matches_python(temporary.path())
}

#[cfg(unix)]
#[test]
fn unreadable_markdown_directory_is_document_read_error_like_python() -> TestResult {
    let temporary = TempDir::new()?;
    root_index(temporary.path())?;
    let locked = temporary.path().join("locked.md");
    fs::create_dir(&locked)?;
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000))?;

    let result = assert_document_read_error_matches_python(temporary.path());
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700))?;
    result
}

#[test]
fn root_index_directory_is_not_a_profile_index() -> TestResult {
    let temporary = TempDir::new()?;
    fs::create_dir(temporary.path().join("index.md"))?;

    let report = check(temporary.path().to_path_buf())?;
    assert_eq!(status(&report, "/okf_core/status"), Some("invalid"));
    assert_eq!(
        codes(&report, "/governor_profile/errors"),
        vec!["PROFILE_INDEX_REQUIRED".to_owned()]
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn broken_markdown_symlink_is_document_read_error_like_python() -> TestResult {
    let temporary = TempDir::new()?;
    root_index(temporary.path())?;
    std::os::unix::fs::symlink("missing-target.md", temporary.path().join("broken.md"))?;

    assert_document_read_error_matches_python(temporary.path())
}

#[cfg(unix)]
#[test]
fn markdown_fifo_fails_closed_without_blocking() -> TestResult {
    let temporary = TempDir::new()?;
    root_index(temporary.path())?;
    let fifo = temporary.path().join("blocking.md");
    let mkfifo_status = Command::new("mkfifo").arg(&fifo).status()?;
    if !mkfifo_status.success() {
        return Err("mkfifo could not create the regression fixture".into());
    }

    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-work-governor"))
        .arg("okf")
        .arg(temporary.path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let child_status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err("OKF validation blocked while opening a Markdown FIFO".into());
        }
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(child_status.code(), Some(1));

    let report = check(temporary.path().to_path_buf())?;
    assert_eq!(status(&report, "/okf_core/status"), Some("invalid"));
    assert_eq!(
        codes(&report, "/okf_core/errors"),
        vec!["DOCUMENT_READ_ERROR".to_owned()]
    );
    Ok(())
}

#[cfg(unix)]
#[test]
fn wide_bundle_stays_within_a_small_descriptor_budget() -> TestResult {
    let temporary = TempDir::new()?;
    root_index(temporary.path())?;
    for index in 0..96 {
        fs::create_dir(temporary.path().join(format!("sibling-{index:03}")))?;
    }

    let output = Command::new("sh")
        .args(["-c", "ulimit -n 64; exec \"$1\" okf \"$2\"", "sh"])
        .arg(env!("CARGO_BIN_EXE_agent-work-governor"))
        .arg(temporary.path())
        .output()?;
    assert!(
        output.status.success(),
        "wide bundle failed under descriptor limit: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn missing_index_and_invalid_source_actor_are_profile_only() -> TestResult {
    let temporary = TempDir::new()?;
    let metadata = {
        let mut metadata = profile_metadata("Reference");
        metadata["sources"] = json!([{
            "resource": "https://example.invalid/source",
            "author": "team:not-an-okf-actor",
            "last_modified": "2026-07-24"
        }]);
        metadata
    };
    write(
        &temporary.path().join("concept.md"),
        &frontmatter(&metadata, "# Body\n")?,
    )?;

    let report = check(temporary.path().to_path_buf())?;
    assert_eq!(status(&report, "/okf_core/status"), Some("valid"));
    assert_eq!(status(&report, "/governor_profile/status"), Some("invalid"));
    let profile_codes = codes(&report, "/governor_profile/errors");
    assert!(profile_codes.contains(&"PROFILE_INDEX_REQUIRED".to_owned()));
    assert!(profile_codes.contains(&"PROFILE_SOURCE_AUTHOR_INVALID".to_owned()));
    Ok(())
}

#[test]
fn general_yaml_is_inconclusive_instead_of_invalid() -> TestResult {
    let temporary = TempDir::new()?;
    write(
        &temporary.path().join("concept.md"),
        "---\ntype: Reference\n---\n# Body\n",
    )?;

    let report = check(temporary.path().to_path_buf())?;
    assert_eq!(status(&report, "/okf_core/status"), Some("inconclusive"));
    assert_eq!(
        status(&report, "/governor_profile/status"),
        Some("inconclusive")
    );
    assert_eq!(
        codes(&report, "/okf_core/inconclusive"),
        vec!["YAML_PARSE_INCONCLUSIVE".to_owned()]
    );
    Ok(())
}

#[test]
fn unknown_type_and_broken_link_remain_non_blocking() -> TestResult {
    let temporary = TempDir::new()?;
    root_index(temporary.path())?;
    let mut metadata = profile_metadata("Future Concept");
    metadata["unknown_extension"] = json!({"safe": true});
    write(
        &temporary.path().join("concept.md"),
        &frontmatter(&metadata, "[Missing](not-yet-written.md)\n")?,
    )?;

    let report = check(temporary.path().to_path_buf())?;
    assert_eq!(status(&report, "/okf_core/status"), Some("valid"));
    assert_eq!(status(&report, "/governor_profile/status"), Some("valid"));
    assert_eq!(
        codes(&report, "/warnings"),
        vec!["BROKEN_LINK_ALLOWED_BY_OKF".to_owned()]
    );
    Ok(())
}

#[test]
fn missing_type_and_reserved_frontmatter_are_core_failures() -> TestResult {
    let temporary = TempDir::new()?;
    root_index(temporary.path())?;
    let mut metadata = profile_metadata("Reference");
    if let Some(object) = metadata.as_object_mut() {
        object.remove("type");
    }
    write(
        &temporary.path().join("concept.md"),
        &frontmatter(&metadata, "# Body\n")?,
    )?;
    write(
        &temporary.path().join("nested/index.md"),
        "---\n{}\n---\n# Nested\n",
    )?;

    let report = check(temporary.path().to_path_buf())?;
    assert_eq!(status(&report, "/okf_core/status"), Some("invalid"));
    let core_codes = codes(&report, "/okf_core/errors");
    assert!(core_codes.contains(&"TYPE_REQUIRED".to_owned()));
    assert!(core_codes.contains(&"RESERVED_FRONTMATTER".to_owned()));
    Ok(())
}

#[test]
fn valid_attested_computation_passes() -> TestResult {
    let temporary = TempDir::new()?;
    root_index(temporary.path())?;
    write(
        &temporary.path().join("scripts/compute.py"),
        "print('ok')\n",
    )?;
    write(&temporary.path().join("scripts/attest.py"), "print('ok')\n")?;
    write(&temporary.path().join("runbooks/execute.txt"), "execute\n")?;
    let mut metadata = profile_metadata("Attested Computation");
    metadata["runtime"] = json!("python");
    metadata["parameters"] = json!([{"name": "input", "type": "path", "required": true}]);
    metadata["computation"] = json!("../scripts/compute.py");
    metadata["executor"] = json!({
        "resource": "../runbooks/execute.txt",
        "receipt": ["input_digest", "output_digest"]
    });
    metadata["attester"] = json!({"resource": "../scripts/attest.py"});
    write(
        &temporary.path().join("computations/check.md"),
        &frontmatter(&metadata, "# Contract\n")?,
    )?;

    let report = check(temporary.path().to_path_buf())?;
    assert_eq!(status(&report, "/okf_core/status"), Some("valid"));
    assert_eq!(status(&report, "/governor_profile/status"), Some("valid"));
    Ok(())
}

#[test]
fn malformed_attested_computation_reports_each_contract_failure() -> TestResult {
    let temporary = TempDir::new()?;
    root_index(temporary.path())?;
    let metadata = profile_metadata("Attested Computation");
    write(
        &temporary.path().join("computations/check.md"),
        &frontmatter(&metadata, "# Contract\n")?,
    )?;

    let report = check(temporary.path().to_path_buf())?;
    assert_eq!(status(&report, "/governor_profile/status"), Some("invalid"));
    let profile_codes = codes(&report, "/governor_profile/errors");
    for expected in [
        "COMPUTATION_RUNTIME_REQUIRED",
        "COMPUTATION_SOURCE_AMBIGUOUS",
        "COMPUTATION_EXECUTOR_INVALID",
        "COMPUTATION_ATTESTER_INVALID",
    ] {
        assert!(profile_codes.contains(&expected.to_owned()));
    }
    Ok(())
}
