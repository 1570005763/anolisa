//! Native local assessment validates inputs without invoking the retired Python CLI.

mod common;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use asc_cli::{Cli, InputError, Plan};

fn installation() -> common::Directory {
    let binary = Path::new(env!("CARGO_BIN_EXE_agent-sec-cli"));
    let directory = common::Directory(
        binary
            .parent()
            .unwrap()
            .join(format!("score-install-{}", uuid::Uuid::new_v4())),
    );
    std::fs::create_dir_all(directory.0.join("bin")).unwrap();
    // A parallel child must not inherit a writable copy descriptor for another test's executable.
    std::fs::hard_link(binary, directory.0.join("bin/agent-sec-cli")).unwrap();
    directory
}

fn command(prefix: &Path) -> Command {
    let mut command = Command::new(prefix.join("bin/agent-sec-cli"));
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("AGENT_SEC_DAEMON_SOCKET", "relative-invalid-socket")
        .env(
            "AGENT_SEC_MODEL_CONFIG",
            prefix.join("no-model-config.json"),
        )
        .args(["skillsec", "score"]);
    command
}

#[test]
fn score_is_explicitly_local_and_never_constructs_a_daemon_request() {
    let cli = Cli::parse_from(["cli", "skillsec", "score", "plan", "skill"]).unwrap();
    assert!(matches!(cli.plan(), Plan::SkillScore(_)));
    assert!(cli.socket().is_none());
    assert!(!cli.is_skill_sec());
    assert!(matches!(cli.request(), Err(InputError::LocalCommand)));
}

#[test]
fn old_and_new_skill_names_keep_the_same_daemon_contract() {
    let parse =
        |name| Cli::parse_from(["cli", "--socket", "/run/fixture.sock", name, "status"]).unwrap();
    let old = parse("skill-ledger");
    let new = parse("skillsec");
    assert!(matches!(new.plan(), Plan::Daemon { .. }));
    assert!(new.is_skill_sec());
    assert_eq!(
        serde_json::to_value(old.request().unwrap()).unwrap(),
        serde_json::to_value(new.request().unwrap()).unwrap()
    );
    assert_eq!(old.timeout(), new.timeout());
}

#[test]
fn score_rejects_daemon_and_context_options_instead_of_ignoring_them() {
    for (option, value) in [
        ("--socket", "/run/fixture.sock"),
        ("--timeout-ms", "9000"),
        ("--otel-context", "{}"),
        ("--trace-context", "{}"),
    ] {
        let error =
            Cli::parse_from(["cli", option, value, "skillsec", "score", "run", "-"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
        assert!(error.to_string().contains(option), "{error}");
    }
    let error = Cli::parse_from([
        "cli",
        "skillsec",
        "score",
        "plan",
        "skill",
        "--timeout-ms=9000",
    ])
    .unwrap_err();
    assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn public_help_and_usage_errors_do_not_need_a_payload() {
    let prefix = installation();
    for arguments in [
        vec!["--help"],
        vec!["plan", "--help"],
        vec!["run", "--help"],
    ] {
        let output = command(&prefix.0).args(arguments).output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("skillsec score"));
    }
    let output = Command::new(prefix.0.join("bin/agent-sec-cli"))
        .arg("--help")
        .output()
        .unwrap();
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("skillsec"), "{help}");
    assert!(help.contains("skill-ledger"), "{help}");
    for arguments in [
        vec![],
        vec!["plan"],
        vec!["run"],
        vec!["unknown"],
        vec!["run", "-", "--unknown"],
        vec!["plan", "skill", "--evidence-dir", "evidence"],
    ] {
        let output = command(&prefix.0).args(arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(!String::from_utf8_lossy(&output.stderr).contains("scoring payload"));
    }
}

#[test]
fn malformed_task_rejects_inline_file_and_stdin_before_runtime_or_model() {
    let prefix = installation();
    let input = r#"{"schema_version":"agent-sec-skill-score/task-v1","skill_path":"ignored","content_hash":"invalid","audit":{}}"#;
    let path = prefix.0.join("input.json");
    std::fs::write(&path, input).unwrap();
    for argument in [input, "-", path.to_str().unwrap()] {
        let mut child = command(&prefix.0)
            .args(["run", argument])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if argument == "-" {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
        }
        let result = child.wait_with_output().unwrap();
        assert_eq!(result.status.code(), Some(2), "{result:?}");
        assert!(result.stdout.is_empty());
        assert!(String::from_utf8_lossy(&result.stderr).contains("content_hash"));
    }
}

#[test]
fn native_plan_does_not_invoke_retired_payload_and_rejects_output_in_skill() {
    use std::os::unix::fs::PermissionsExt as _;
    let prefix = installation();
    let skill = prefix.0.join("skill with spaces");
    std::fs::create_dir(&skill).unwrap();
    std::fs::write(skill.join("SKILL.md"), "# Example").unwrap();
    let retired = prefix
        .0
        .join("lib/anolisa/sec-core/skill-score/cli/bin/agent-sec-cli");
    std::fs::create_dir_all(retired.parent().unwrap()).unwrap();
    std::fs::write(
        &retired,
        "#!/bin/sh
exit 77
",
    )
    .unwrap();
    std::fs::set_permissions(retired, std::fs::Permissions::from_mode(0o755)).unwrap();
    let result = command(&prefix.0)
        .arg("plan")
        .arg(&skill)
        .arg("--output-file")
        .arg(skill.join("task.json"))
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("outside"));
    let result = command(&prefix.0).arg("plan").arg(&skill).output().unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("model"));
}

#[test]
fn cancellation_interrupts_open_stdin_without_waiting_for_eof() {
    let prefix = installation();
    let mut child = command(&prefix.0)
        .args(["run", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(200));
    let pid = rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap();
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            break;
        }
        if start.elapsed() > Duration::from_secs(3) {
            let _ = child.kill();
            panic!("native stdin did not respond to cancellation");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
