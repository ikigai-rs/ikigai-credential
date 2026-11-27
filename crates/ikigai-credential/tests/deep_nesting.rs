//! A deeply nested request is refused before any parser recurses. Run in a child process, so a
//! stack overflow would fail this test rather than abort the test harness.

use std::process::Command;

const CHILD: &str = "IKIGAI_CREDENTIAL_DEEP_CHILD";

#[test]
fn deep_nesting_is_refused_before_parsing() {
    if std::env::var_os(CHILD).is_some() {
        let depth = 200_000;
        let body = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
        let err = ikigai_credential::verify(body.as_bytes(), "2026-11-27T00:00:00Z", |_, _| {
            Err("unreachable".into())
        })
        .unwrap_err();
        assert!(matches!(err, ikigai_credential::Error::Input(_)), "{err:?}");
        let err = ikigai_credential::parse_bounded(body.as_bytes()).unwrap_err();
        println!("refused: {err}");
        return;
    }
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "deep_nesting_is_refused_before_parsing",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "child failed: {out:?}");
    assert!(stdout.contains("refused: "), "{stdout}");
}
