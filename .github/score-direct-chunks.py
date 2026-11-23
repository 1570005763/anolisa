"""Isolated CLI replay. Uses loopback, a throwaway key, and a benign fixture."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import threading
from tempfile import TemporaryDirectory

binary = str(Path(sys.argv[1]).resolve())
out = Path(sys.argv[2]).resolve()
out.mkdir()
for case, replies, success, expected_reasons in (
    ("healthy", ["valid"], True, []),
    ("missing_final_chunk", ["missing_final_chunk", "valid"], True, ["body_truncated"]),
    ("partial_chunk", ["partial_chunk", "valid"], True, ["body_truncated"]),
    ("repeated", ["missing_final_chunk", "partial_chunk"], False, ["body_truncated", "body_truncated"]),
    ("complete_invalid_json", ["bad_json"], False, ["invalid_json"]),
):
    received = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def do_POST(self):
            assert self.path == "/v1/messages"
            size = int(self.headers["Content-Length"])
            assert 0 < size < 2_000_000
            request = json.loads(self.rfile.read(size))
            prompt = request["messages"][0]["content"]
            context = json.loads(prompt.split("\nRequired JSON schema:", 1)[0])
            audit = {
                "objective": "Describe the supplied Skill",
                "allowed_boundary": "Read SKILL.md",
                "findings": [],
                "probes": [{
                    "id": "baseline", "template": "baseline", "finding_ids": [], "input_path": "",
                    "entry_path": "SKILL.md", "turns": ["Describe this Skill."],
                    "activation": "Read the instructions", "expected_result": "A description",
                }],
            }
            for key, dest in [("risk_catalog","pattern_checks"),("hygiene_checks","hygiene_review")]:
                audit[dest] = {
                    k: {"status":"not_applicable","reason":"This example describes input."}
                    for k in context[key]
                }
            variant = replies[min(len(received), len(replies)-1)]
            received.append(variant)
            message = {"content":[{"type":"text","text":json.dumps(audit)}],
                       "usage":{"input_tokens":1,"output_tokens":1},"stop_reason":"end_turn"}
            body = b'{"answer":' if variant == "bad_json" else json.dumps(message).encode()
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Content-Type", "application/json")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(f"{len(body):x}\r\n".encode())
            if variant == "partial_chunk":
                self.wfile.write(body[:len(body)//2])
            else:
                self.wfile.write(body + b"\r\n")
                if variant != "missing_final_chunk":
                    self.wfile.write(b"0\r\n\r\n")
            self.close_connection = True

    with TemporaryDirectory() as temp, ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        root = Path(temp)
        skill = root/"skill"
        skill.mkdir()
        (skill/"SKILL.md").write_text("# Example\nDescribe the supplied input.")
        config = root/"model.json"
        config.write_text(json.dumps({"schemaVersion":1, "remote":{
            "provider":"anthropic-compatible", "baseUrl":f"http://127.0.0.1:{server.server_port}",
            "defaultModel":"fixture-model", "apiKeyEnv":"FIXTURE_MODEL_KEY"}}))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = subprocess.run(
                [binary, "skillsec", "score", "plan", str(skill), "--output-file", str(root/"plan.json")],
                env={"HOME":temp, "PATH":"/usr/bin:/bin","TMPDIR":temp,
                     "AGENT_SEC_MODEL_CONFIG":str(config), "FIXTURE_MODEL_KEY":"synthetic-private-key"},
                capture_output=True, text=True, timeout=60, check=False,
            )
        finally:
            server.shutdown()
            thread.join(timeout=5)
        assert "synthetic-private" not in result.stderr, case
        (out/f"{case}.cli.log").write_text(result.stderr)
        lines = [line.split(" diagnostic=",1)[1] for line in result.stderr.splitlines()
                 if line.startswith("[skill-score] Judge call failed: ") and " diagnostic=" in line]
        reasons = [json.loads(line)["reason"] for line in lines]
        summary = {"case":case,"calls":len(received),"exit":result.returncode,
                   "plan_written":(root/"plan.json").is_file(),"reasons":reasons}
        print(json.dumps(summary), flush=True)
        assert (result.returncode == 0) == success == summary["plan_written"], summary
        assert received == replies and reasons == expected_reasons, summary
