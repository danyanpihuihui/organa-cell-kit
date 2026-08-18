import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import organa_cell_kit.cli as cli


def run_cli(args, cwd: Path):
    return subprocess.run(
        [sys.executable, "-m", "organa_cell_kit.cli", *args],
        cwd=cwd,
        env={**os.environ, "PYTHONPATH": "src"},
        text=True,
        capture_output=True,
    )


def make_package(root: Path):
    root.mkdir()
    resource = root / "proof-index.json"
    resource.write_text("{}\n", encoding="utf-8")
    manifest = {
        "schema_version": "organa-cell-resolution-v0.1", "coordinate": "720202.bitmap", "cell_type": "organa-cell", "version": "0.3.0",
        "created_at_utc": "2026-08-16T00:00:00+00:00", "lifecycle_status": "live",
        "controller": {}, "public_base_url": "https://example.invalid", "agents": [{"id": "a"}], "services": [{"id": "s"}],
        "resources": [{"path": "proof-index.json", "sha256": "sha256:" + hashlib.sha256(resource.read_bytes()).hexdigest()}],
    }
    (root / "organa-cell.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")


def test_pilot_cli_sequence_uses_separate_workspaces(tmp_path: Path):
    repo = Path(__file__).parents[1]
    fixture = tmp_path / "fixture"
    make_package(fixture)
    pilot = tmp_path / "pilot"
    initialized = run_cli(["pilot-init", str(pilot), "--fixture-source", str(fixture)], repo)
    assert initialized.returncode == 0, initialized.stdout + initialized.stderr

    config_path = pilot / "pilot-config.json"
    config = json.loads(config_path.read_text())
    config["requester"].update(cell_coordinate="820001.bitmap", endpoint="https://dq.invalid", signing_public_key="identity-key:dq-test-public")
    config["worker"].update(cell_coordinate="820002.bitmap", endpoint="https://n6.invalid", signing_public_key="identity-key:n6-test-public")
    config["verifier"].update(cell_coordinate="820003.bitmap", endpoint="local://verifier", signing_public_key="identity-key:verifier-test-public")
    config_path.write_text(json.dumps(config) + "\n")

    published = run_cli(["pilot-requester-publish", str(pilot)], repo)
    assert published.returncode == 2
    failure = json.loads(published.stdout)
    assert failure["ok"] is False
    assert "artifact authorization" in failure["error"]


def test_pilot_verify_handoff_cli_routes_to_complete_verifier(tmp_path: Path, monkeypatch, capsys):
    handoff = tmp_path / "pilot-handoff-receipt.json"
    handoff.write_text("{}\n", encoding="utf-8")
    called = {}

    def fake_verify(path, *, project_root):
        called.update(path=path, project_root=project_root)
        return {"ok": True, "execution_mode": "local-rehearsal"}

    monkeypatch.setattr(cli, "verify_pilot_handoff", fake_verify)
    assert cli.main(["pilot-verify-handoff", str(tmp_path), "--handoff", str(handoff)]) == 0
    assert called == {"path": handoff, "project_root": tmp_path}
    assert json.loads(capsys.readouterr().out)["ok"] is True
