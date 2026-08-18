import json
import os
import subprocess
import sys
from pathlib import Path


def test_run_demo_cli_writes_verified_receipt_and_disclosures(tmp_path: Path):
    env = {**os.environ, "PYTHONPATH": "src"}
    result = subprocess.run(
        [sys.executable, "-m", "organa_cell_kit.cli", "run-demo", str(tmp_path)],
        cwd=Path(__file__).parents[1],
        env=env,
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["simulation_scope"] == "same-controller-simulation-not-external-adoption"
    assert payload["payment_scope"] == "local-test-credits-only-no-real-payment"
    receipt = Path(payload["receipt_path"])
    assert receipt.exists()
    assert receipt.parent.parent == tmp_path / "runs"
    assert json.loads((tmp_path / "current.json").read_text(encoding="utf-8"))["receipt_path"] == str(receipt.relative_to(tmp_path))


def test_run_demo_cli_accepts_an_organa_package_directory(tmp_path: Path):
    package = tmp_path / "package"
    package.mkdir()
    resource = package / "proof-index.json"
    resource.write_text('{"entries": []}\n', encoding="utf-8")
    import hashlib
    manifest = {
        "schema_version": "organa-cell-resolution-v0.1",
        "coordinate": "999003.bitmap",
        "cell_type": "organa-cell",
        "version": "0.1.0",
        "created_at_utc": "2026-08-16T00:00:00+00:00",
        "lifecycle_status": "simulation",
        "controller": {"address": "bc1qtestcontroller", "claim_type": "bitmap-controller-wallet-claim", "signature_status": "pending-user-signature", "signature_request_url": "https://example.invalid/signature-request.json"},
        "public_base_url": "https://example.invalid/organa-cell",
        "agents": [{"id": "test-agent"}],
        "services": [{"id": "test-service"}],
        "resources": [{"path": "proof-index.json", "sha256": "sha256:" + hashlib.sha256(resource.read_bytes()).hexdigest()}],
    }
    (package / "organa-cell.json").write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    run = tmp_path / "run"
    env = {**os.environ, "PYTHONPATH": "src"}

    result = subprocess.run(
        [sys.executable, "-m", "organa_cell_kit.cli", "run-demo", str(run), "--target-package", str(package)],
        cwd=Path(__file__).parents[1], env=env, text=True, capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["ok"] is True


def test_worker_run_cli_discovers_board_task_and_persists_artifacts(tmp_path: Path):
    env = {**os.environ, "PYTHONPATH": "src"}
    prepare = subprocess.run(
        [sys.executable, "-m", "organa_cell_kit.cli", "run-demo", str(tmp_path), "--prepare-only"],
        cwd=Path(__file__).parents[1], env=env, text=True, capture_output=True,
    )
    assert prepare.returncode == 0, prepare.stderr
    source_package = json.loads(prepare.stdout)["source_package"]

    result = subprocess.run(
        [sys.executable, "-m", "organa_cell_kit.cli", "worker-run", str(tmp_path),
         "--board", str(tmp_path / "board.json"), "--worker-id", "local-worker-alpha",
         "--verifier-id", "local-verifier-alpha", "--verifier-coordinate", "100003.bitmap",
         "--source-package", source_package],
        cwd=Path(__file__).parents[1], env=env, text=True, capture_output=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert Path(payload["acceptance_path"]).exists()
    assert Path(payload["worker_result_path"]).exists()


def test_verify_receipt_cli_inspects_run(tmp_path: Path):
    env = {**os.environ, "PYTHONPATH": "src"}
    generated = subprocess.run(
        [sys.executable, "-m", "organa_cell_kit.cli", "run-demo", str(tmp_path)],
        cwd=Path(__file__).parents[1], env=env, text=True, capture_output=True,
    )
    assert generated.returncode == 0, generated.stderr
    receipt = json.loads(generated.stdout)["receipt_path"]
    checked = subprocess.run(
        [sys.executable, "-m", "organa_cell_kit.cli", "verify-receipt", str(tmp_path), "--receipt", receipt],
        cwd=Path(__file__).parents[1], env=env, text=True, capture_output=True,
    )
    assert checked.returncode == 0, checked.stderr
    assert json.loads(checked.stdout) == {"ok": True, "errors": [], "authoritative_board_checked": True}


def test_verify_receipt_cli_rejects_mutated_authoritative_board(tmp_path: Path):
    env = {**os.environ, "PYTHONPATH": "src"}
    generated = subprocess.run([sys.executable, "-m", "organa_cell_kit.cli", "run-demo", str(tmp_path)], cwd=Path(__file__).parents[1], env=env, text=True, capture_output=True)
    receipt = Path(json.loads(generated.stdout)["receipt_path"]); snapshot = (receipt.parent / "board.json").read_bytes()
    board_path = tmp_path / "board.json"; board = json.loads(board_path.read_text(encoding="utf-8")); board["tasks"][0]["status"] = "closed"; board_path.write_text(json.dumps(board) + "\n", encoding="utf-8")
    checked = subprocess.run([sys.executable, "-m", "organa_cell_kit.cli", "verify-receipt", str(tmp_path), "--receipt", str(receipt)], cwd=Path(__file__).parents[1], env=env, text=True, capture_output=True)
    payload = json.loads(checked.stdout)
    assert checked.returncode != 0
    assert payload["ok"] is False and payload["authoritative_board_checked"] is True
    assert (receipt.parent / "board.json").read_bytes() == snapshot


def test_verify_receipt_cli_rejects_wrong_project_root(tmp_path: Path):
    env = {**os.environ, "PYTHONPATH": "src"}; project = tmp_path / "project"
    generated = subprocess.run([sys.executable, "-m", "organa_cell_kit.cli", "run-demo", str(project)], cwd=Path(__file__).parents[1], env=env, text=True, capture_output=True)
    wrong = tmp_path / "wrong"; wrong.mkdir(); (wrong / "board.json").write_bytes((project / "board.json").read_bytes())
    checked = subprocess.run([sys.executable, "-m", "organa_cell_kit.cli", "verify-receipt", str(wrong), "--receipt", json.loads(generated.stdout)["receipt_path"]], cwd=Path(__file__).parents[1], env=env, text=True, capture_output=True)
    payload = json.loads(checked.stdout)
    assert checked.returncode != 0
    assert payload["ok"] is False and payload["authoritative_board_checked"] is True
    assert any("project receipt" in error for error in payload["errors"])
