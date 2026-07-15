use assert_cmd::Command;
use predicates::prelude::*;

fn s2() -> Command {
    Command::cargo_bin("s2").unwrap()
}

#[test]
fn test_health_encrypted_ok() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.env");
    let p = path.to_str().unwrap();

    s2().args(["init", p]).assert().success();
    s2().args(["set", "API_KEY", "-f", p])
        .write_stdin("sk-test-123")
        .assert()
        .success();

    // Decrypts with the stored passphrase → success, no output needed.
    s2().args(["health", "-f", p]).assert().success();
}

#[test]
fn test_health_plaintext_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plain.env");
    let p = path.to_str().unwrap();

    // A plaintext file is not age-encrypted → health check rejects it.
    s2().args(["init", "--no-encrypt", p]).assert().success();

    s2().args(["health", "-f", p])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not age-encrypted"));
}

#[test]
fn test_health_wildcard_makes_no_ssm_call() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("secrets.env");
    let p = path.to_str().unwrap();

    s2().args(["init", p]).assert().success();
    // The atlas wildcard mapping: key `*` → an SSM prefix URI.
    s2().args(["set", "*", "-f", p])
        .write_stdin("ssm:///bogus/prefix/that/does/not/exist")
        .assert()
        .success();

    // health only decrypts — it must NOT resolve the `*` URI. A command that
    // resolved providers would issue GetParametersByPath here and fail without
    // AWS creds/network; health succeeds, proving the passphrase signal is clean.
    s2().args(["health", "-f", p]).assert().success();
}
