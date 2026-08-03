"""Unit tests for cosh-extension/hooks/pii_checker_hook.py."""

import io
import json
import subprocess
from pathlib import Path

import pytest
from standalone_hook_test_loader import load_standalone_hook

_COSH_HOOK = str(
    Path(__file__).resolve().parents[2]
    / ".."
    / "cosh-extension"
    / "hooks"
    / "pii_checker_hook.py"
)

pii_checker_hook = load_standalone_hook(
    "cosh_pii_checker_hook",
    Path(_COSH_HOOK),
)
_format_cosh = pii_checker_hook._format_cosh


class TestFormatCosh:
    def test_pass_returns_allow(self):
        result = json.loads(_format_cosh({"verdict": "pass", "findings": []}))
        assert result == {"decision": "allow"}

    def test_warn_returns_allow_with_reason(self):
        result = json.loads(
            _format_cosh(
                {
                    "verdict": "warn",
                    "findings": [
                        {
                            "type": "email",
                            "severity": "warn",
                            "evidence_redacted": "a***@example.com",
                            "raw_evidence": "alice@example.com",
                        }
                    ],
                }
            )
        )

        assert result["decision"] == "allow"
        assert "[pii-checker]" in result["reason"]
        assert "email" in result["reason"]
        assert "a***@example.com" in result["reason"]
        assert "alice@example.com" not in result["reason"]
        assert "raw_evidence" not in result["reason"]

    def test_deny_returns_allow_with_high_risk_reason(self):
        result = json.loads(
            _format_cosh(
                {
                    "verdict": "deny",
                    "findings": [
                        {
                            "type": "credential",
                            "severity": "deny",
                            "evidence_redacted": "password=[REDACTED]",
                        }
                    ],
                }
            )
        )

        assert result["decision"] == "allow"
        assert "高风险" in result["reason"]
        assert "credential" in result["reason"]

    def test_warn_without_findings_allows(self):
        result = json.loads(_format_cosh({"verdict": "warn", "findings": []}))
        assert result == {"decision": "allow"}

    @pytest.mark.parametrize("verdict", ["error", "unknown", ""])
    def test_error_and_unknown_verdicts_allow(self, verdict):
        result = json.loads(_format_cosh({"verdict": verdict, "findings": [{}]}))
        assert result == {"decision": "allow"}

    @pytest.mark.parametrize(
        ("policy", "warns"),
        [
            ("observe", False),
            ("warn", True),
            ("ask", True),
            ("block", True),
        ],
    )
    def test_unified_policy_matrix_falls_back_to_non_blocking_warning(
        self, policy, warns
    ):
        result = json.loads(
            _format_cosh(
                {
                    "verdict": "deny",
                    "findings": [
                        {
                            "type": "credential",
                            "severity": "deny",
                            "evidence_redacted": "token=[REDACTED]",
                        }
                    ],
                },
                policy,
            )
        )

        assert result["decision"] == "allow"
        if warns:
            assert "token=[REDACTED]" in result["reason"]
            assert "本轮请求将继续处理" in result["reason"]
        else:
            assert result == {"decision": "allow"}


class TestCoshHookMain:
    def _run_main(self, monkeypatch, capsys, input_data):
        monkeypatch.setenv("PII_CHECKER_HOOK_POLICY", "warn")
        monkeypatch.setattr(pii_checker_hook.sys, "stdin", io.StringIO(input_data))
        pii_checker_hook.main()
        return json.loads(capsys.readouterr().out)

    def test_empty_prompt_allows_without_cli(self, monkeypatch, capsys):
        def fail_run(*args, **kwargs):
            raise AssertionError("CLI should not be called")

        monkeypatch.setattr(pii_checker_hook.subprocess, "run", fail_run)

        output = self._run_main(monkeypatch, capsys, '{"prompt": ""}')
        assert output == {"decision": "allow"}

    def test_invalid_json_allows_without_cli(self, monkeypatch, capsys):
        def fail_run(*args, **kwargs):
            raise AssertionError("CLI should not be called")

        monkeypatch.setattr(pii_checker_hook.subprocess, "run", fail_run)

        output = self._run_main(monkeypatch, capsys, "not-json")
        assert output == {"decision": "allow"}

    def test_missing_prompt_allows_without_cli(self, monkeypatch, capsys):
        def fail_run(*args, **kwargs):
            raise AssertionError("CLI should not be called")

        monkeypatch.setattr(pii_checker_hook.subprocess, "run", fail_run)

        output = self._run_main(monkeypatch, capsys, '{"session_id": "abc"}')
        assert output == {"decision": "allow"}

    def test_calls_scan_pii_with_user_input_source(self, monkeypatch, capsys):
        captured = {}

        def fake_run(args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout=json.dumps(
                    {
                        "verdict": "warn",
                        "findings": [
                            {
                                "type": "phone_cn",
                                "severity": "warn",
                                "evidence_redacted": "138****8000",
                            }
                        ],
                    }
                ),
                stderr="",
            )

        monkeypatch.setattr(pii_checker_hook.subprocess, "run", fake_run)

        output = self._run_main(
            monkeypatch,
            capsys,
            json.dumps({"prompt": "Phone: 13800138000"}),
        )

        expected_context = json.dumps(
            {"agent_name": "cosh"},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        assert captured["args"] == [
            "agent-sec-cli",
            "--trace-context",
            expected_context,
            "scan-pii",
            "--stdin",
            "--format",
            "json",
            "--redact-output",
            "--source",
            "user_input",
        ]
        assert captured["kwargs"]["input"] == "Phone: 13800138000"
        assert captured["kwargs"]["timeout"] == 10
        assert output["decision"] == "allow"
        assert "phone_cn" in output["reason"]

    def test_injects_trace_context_into_scan_pii_command(self, monkeypatch, capsys):
        captured = {}

        def fake_run(args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout=json.dumps({"verdict": "pass", "findings": []}),
                stderr="",
            )

        monkeypatch.setattr(pii_checker_hook.subprocess, "run", fake_run)

        output = self._run_main(
            monkeypatch,
            capsys,
            json.dumps(
                {
                    "prompt": "Phone: 13800138000",
                    "trace_id": "trace-1",
                    "session_id": "session-1",
                    "sessionId": "wrong-session",
                    "run_id": "run-1",
                    "tool_use_id": "tool-1",
                }
            ),
        )

        expected_context = json.dumps(
            {
                "agent_name": "cosh",
                "trace_id": "trace-1",
                "session_id": "session-1",
                "run_id": "run-1",
                "tool_call_id": "tool-1",
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        assert output == {"decision": "allow"}
        assert captured["args"] == [
            "agent-sec-cli",
            "--trace-context",
            expected_context,
            "scan-pii",
            "--stdin",
            "--format",
            "json",
            "--redact-output",
            "--source",
            "user_input",
        ]
        assert captured["kwargs"]["check"] is False

    @pytest.mark.parametrize(
        ("payload", "expected_stdin", "expected_source"),
        [
            (
                {"hook_event_name": "PreToolUse", "tool_input": {"command": "echo ok"}},
                '{"command":"echo ok"}',
                "tool_input",
            ),
            (
                {
                    "hook_event_name": "PostToolUse",
                    "tool_response": {"stdout": "alice@example.com"},
                },
                '{"stdout":"alice@example.com"}',
                "tool_output",
            ),
            (
                {
                    "hook_event_name": "PostToolUseFailure",
                    "error": "token=secret123456",
                },
                "token=secret123456",
                "tool_output",
            ),
            (
                {
                    "hook_event_name": "AfterModel",
                    "llm_response": {"text": "Contact alice@example.com"},
                },
                "Contact alice@example.com",
                "model_output",
            ),
        ],
    )
    def test_scans_additional_hook_events(
        self,
        monkeypatch,
        capsys,
        payload,
        expected_stdin,
        expected_source,
    ):
        captured = {}

        def fake_run(args, **kwargs):
            captured["args"] = args
            captured["kwargs"] = kwargs
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout=json.dumps(
                    {
                        "verdict": "warn",
                        "findings": [
                            {
                                "type": "email",
                                "severity": "warn",
                                "evidence_redacted": "a***@example.com",
                            }
                        ],
                    }
                ),
                stderr="",
            )

        monkeypatch.setattr(pii_checker_hook.subprocess, "run", fake_run)

        output = self._run_main(monkeypatch, capsys, json.dumps(payload))

        expected_context = json.dumps(
            {"agent_name": "cosh"},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        assert captured["args"] == [
            "agent-sec-cli",
            "--trace-context",
            expected_context,
            "scan-pii",
            "--stdin",
            "--format",
            "json",
            "--redact-output",
            "--source",
            expected_source,
        ]
        assert captured["kwargs"]["input"] == expected_stdin
        assert output["decision"] == "allow"
        assert "a***@example.com" in output["reason"]

    def test_cli_nonzero_allows(self, monkeypatch, capsys):
        def fake_run(args, **kwargs):
            return subprocess.CompletedProcess(
                args=args,
                returncode=1,
                stdout="",
                stderr="boom",
            )

        monkeypatch.setattr(pii_checker_hook.subprocess, "run", fake_run)

        output = self._run_main(monkeypatch, capsys, '{"prompt": "hello"}')
        assert output == {"decision": "allow"}

    def test_cli_bad_json_allows(self, monkeypatch, capsys):
        def fake_run(args, **kwargs):
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout="not-json",
                stderr="",
            )

        monkeypatch.setattr(pii_checker_hook.subprocess, "run", fake_run)

        output = self._run_main(monkeypatch, capsys, '{"prompt": "hello"}')
        assert output == {"decision": "allow"}


def test_environment_disabled_short_circuits_before_input_and_cli(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("PII_CHECKER_HOOK_ENABLED", "false")
    disabled_hook = load_standalone_hook(
        "cosh_pii_checker_disabled_hook",
        Path(_COSH_HOOK),
    )
    monkeypatch.setattr(
        disabled_hook.sys,
        "stdin",
        type(
            "UnreadableInput",
            (),
            {"read": lambda *_args, **_kwargs: pytest.fail("input should not be read")},
        )(),
    )
    monkeypatch.setattr(
        disabled_hook.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("CLI should not be called"),
    )

    disabled_hook.main()

    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"decision": "allow"}
    assert captured.err == ""


def test_new_policy_overrides_conflicting_legacy_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PII_CHECKER_HOOK_POLICY", "observe")
    monkeypatch.setenv("PII_CHECKER_MODE", "deny")

    assert pii_checker_hook._read_policy() == "observe"


def test_manifest_registers_only_user_prompt_submit_for_pii():
    manifest_path = (
        Path(__file__).resolve().parents[2]
        / ".."
        / "cosh-extension"
        / "cosh-extension.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    pii_locations = []
    for hook_name, groups in manifest["hooks"].items():
        for group in groups:
            for hook in group.get("hooks", []):
                if hook.get("name") == "pii-checker":
                    pii_locations.append(hook_name)

    assert pii_locations == [
        "PreToolUse",
        "UserPromptSubmit",
        "AfterModel",
        "PostToolUse",
        "PostToolUseFailure",
    ]


def test_invalid_legacy_mode_reports_observe_fallback(monkeypatch, capsys):
    monkeypatch.delenv("PII_CHECKER_HOOK_POLICY", raising=False)
    monkeypatch.setenv("PII_CHECKER_MODE", "banana")

    assert pii_checker_hook._read_policy() == "observe"
    assert "invalid legacy mode; using observe" in capsys.readouterr().err
