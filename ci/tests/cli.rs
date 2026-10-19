//! The binary as the workflows run it: exit codes, output that never carries a value, the curl config
//! file's mode.

use std::process::{Command, Output};

const ID: &str = "0123456789abcdef0123456789abcdef.access";
const SECRET: &str = "cfast_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKL";

fn run(args: &[&str], upstream_auth: Option<&str>) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nft-gate-ci"));
    c.args(args).env_remove("UPSTREAM_AUTH_HEADERS");
    if let Some(v) = upstream_auth {
        c.env("UPSTREAM_AUTH_HEADERS", v);
    }
    c.output().unwrap()
}

fn good() -> String {
    format!(
        r#"[{{"name":"CF-Access-Client-Id","value":"{ID}"}},{{"name":"CF-Access-Client-Secret","value":"{SECRET}"}}]"#
    )
}

fn text(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn a_good_secret_passes_and_no_value_is_printed() {
    let o = run(&["check-upstream-auth"], Some(&good()));
    assert!(o.status.success(), "{}", text(&o));
    let out = text(&o);
    assert!(out.contains("2 header(s)") && out.contains("shape ok"));
    assert!(!out.contains(ID) && !out.contains(SECRET));
}

#[test]
fn bad_values_fail_the_deploy_without_echoing_them() {
    for bad in [
        "",
        "not json with a secret-looking-value",
        r#"[{"name":"CF-Access-Client-Id","value":"hunter2"}]"#,
    ] {
        let o = run(&["check-upstream-auth"], Some(bad));
        assert_eq!(o.status.code(), Some(1), "{bad}");
        assert!(!text(&o).contains("hunter2") && !text(&o).contains("secret-looking-value"));
    }
    assert_eq!(run(&["check-upstream-auth"], None).status.code(), Some(1));
}

#[cfg(unix)]
#[test]
fn the_curl_config_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("nft-gate-ci-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("curl.conf");
    let o = run(
        &["check-upstream-auth", "--curl-config", path.to_str().unwrap()],
        Some(&good()),
    );
    assert!(o.status.success(), "{}", text(&o));
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(body.contains(&format!("header = \"CF-Access-Client-Id: {ID}\"")));
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn origin_probes_are_classified_and_reported() {
    let dir = std::env::temp_dir().join(format!("nft-gate-ci-h-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let hdrs = dir.join("h.txt");
    std::fs::write(&hdrs, "HTTP/2 403\r\nserver: cloudflare\r\ncf-access-domain: o.example\r\n\r\n").unwrap();
    let h = hdrs.to_str().unwrap();
    let o = run(&["classify-origin", "--status", "403", "--headers", h], None);
    assert!(o.status.success());
    assert!(text(&o).starts_with("locked "), "{}", text(&o));
    let o = run(&["classify-origin", "--status", "200"], None);
    assert!(text(&o).starts_with("open "));
    // The positive probe: a 403 from Access fails the deploy, a 200 passes.
    let o = run(&["report-origin-check", "--url", "https://o.example/v1/tip-config", "--status", "403", "--headers", h], None);
    assert_eq!(o.status.code(), Some(1));
    assert!(text(&o).contains("::error::The origin rejected UPSTREAM_AUTH_HEADERS"));
    let o = run(&["report-origin-check", "--url", "https://o.example/v1/tip-config", "--status", "200"], None);
    assert!(o.status.success());
    assert!(run(&["bogus"], None).status.code() == Some(1));
    std::fs::remove_dir_all(&dir).unwrap();
}
