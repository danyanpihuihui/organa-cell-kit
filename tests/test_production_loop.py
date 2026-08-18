import hashlib
import json
import multiprocessing
import os
from pathlib import Path

import pytest
import organa_cell_kit.production_loop as production_loop_module

from organa_cell_kit.production_loop import (
    ProductionLoopError,
    TRUSTED_VERIFIER,
    canonical_sha256,
    publish_frozen_task,
    run_demo,
    run_production_loop,
    verify_receipt,
    worker_execute_from_board,
)


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_canonical_json_rejects_non_finite_numbers_and_duplicate_keys(tmp_path: Path):
    with pytest.raises(ValueError):
        canonical_sha256({"not_finite": float("nan")})

    with pytest.raises(ValueError):
        production_loop_module._write_json(tmp_path / "artifact.json", {"not_finite": float("inf")})

    with pytest.raises(ValueError):
        production_loop_module.append_reputation_event(tmp_path / "reputation.jsonl", {"not_finite": float("-inf")})

    board_path = tmp_path / "board.json"
    board_path.write_text('{"schema_version":"organa-local-json-board-v0.2","schema_version":"organa-local-json-board-v0.2","tasks":[],"workers":[]}\n', encoding="utf-8")
    with pytest.raises(ProductionLoopError, match="invalid JSON artifact"):
        worker_execute_from_board(
            root=tmp_path,
            board_path=board_path,
            worker_id="worker",
            verifier_id="verifier",
            verifier_coordinate="100003.bitmap",
            source_package=tmp_path,
        )


def test_manifest_parser_rejects_json_nan_constant(tmp_path: Path):
    source = make_organa_package(tmp_path / "source")
    manifest_path = source / "organa-cell.json"
    raw = manifest_path.read_text(encoding="utf-8").replace('"version": "0.1.0"', '"version": NaN')
    manifest_path.write_text(raw, encoding="utf-8")

    with pytest.raises(ProductionLoopError, match="invalid JSON artifact"):
        run_demo(tmp_path / "run", target_package=source)


def receipt_path(root: Path) -> Path:
    pointer = load(root / "current.json")
    return root / pointer["receipt_path"]


def run_dir(root: Path) -> Path:
    return receipt_path(root).parent


def make_organa_package(root: Path, *, coordinate="999001.bitmap") -> Path:
    root.mkdir(parents=True)
    resource = root / "agent-registry.json"
    resource.write_text('{"entries": []}\n', encoding="utf-8")
    manifest = {
        "schema_version": "organa-cell-resolution-v0.1",
        "coordinate": coordinate,
        "cell_type": "organa-cell",
        "version": "0.1.0",
        "created_at_utc": "2026-08-16T00:00:00+00:00",
        "lifecycle_status": "simulation",
        "controller": {"address": "bc1qtestcontroller", "claim_type": "bitmap-controller-wallet-claim", "signature_status": "pending-user-signature", "signature_request_url": "https://example.invalid/signature-request.json"},
        "public_base_url": "https://example.invalid/organa-cell",
        "agents": [{"id": "test-agent"}],
        "services": [{"id": "test-service"}],
        "resources": [{"path": "agent-registry.json", "sha256": "sha256:" + hashlib.sha256(resource.read_bytes()).hexdigest()}],
    }
    (root / "organa-cell.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return root


def test_public_board_publishes_frozen_rewarded_task_and_worker_discovers_it(tmp_path: Path):
    prepared = run_demo(tmp_path, prepare_only=True)
    board = load(tmp_path / "board.json")

    assert len(board["tasks"]) == 1
    published = board["tasks"][0]
    assert published["status"] == "open"
    assert published["task_hash"] == canonical_sha256(published["frozen_task"])
    assert published["frozen_task"]["reward_test_credits"] == 3
    assert published["frozen_task"]["trusted_verifier"] == TRUSTED_VERIFIER

    exchange = worker_execute_from_board(
        root=tmp_path,
        board_path=tmp_path / "board.json",
        worker_id="local-worker-alpha",
        verifier_id="local-verifier-alpha",
        verifier_coordinate="100003.bitmap",
        source_package=Path(prepared["source_package"]),
    )
    acceptance = load(Path(exchange["acceptance_path"]))
    result = load(Path(exchange["worker_result_path"]))
    assert acceptance["task_hash"] == published["task_hash"]
    assert acceptance["discovered_from_board_hash"] == canonical_sha256(board)
    assert result["acceptance_hash"] == canonical_sha256(acceptance)
    assert result["report"]["integrity_valid"] is True


def test_coordinator_consumes_persisted_acceptance_instead_of_synthesizing_it(tmp_path: Path):
    prepared = run_demo(tmp_path, prepare_only=True)
    acceptance_path = Path(prepared["acceptance_path"])
    acceptance = load(acceptance_path)
    acceptance["worker_id"] = "forged-worker"
    acceptance_path.write_text(json.dumps(acceptance) + "\n", encoding="utf-8")

    with pytest.raises(ProductionLoopError, match="acceptance"):
        run_production_loop(
            root=tmp_path,
            board_path=tmp_path / "board.json",
            acceptance_path=acceptance_path,
            worker_result_path=Path(prepared["worker_result_path"]),
            budget=10,
        )


def test_run_demo_completes_in_immutable_run_and_receipt_binds_trusted_verifier(tmp_path: Path):
    result = run_demo(tmp_path)
    receipt = load(Path(result["receipt_path"]))
    directory = Path(result["receipt_path"]).parent

    assert directory.parent.name == "runs"
    assert result["simulation_scope"] == "same-controller-simulation-not-external-adoption"
    assert result["payment_scope"] == "local-test-credits-only-no-real-payment"
    assert receipt["separate_process_verifier_rerun"] is True
    assert receipt["trusted_verifier"] == TRUSTED_VERIFIER
    assert receipt["project_binding"] == {
        "absolute_root": str(tmp_path.resolve()),
        "board_relative_path": "board.json",
    }
    assert receipt["settlement"] == load(directory / "settlement.json")
    assert verify_receipt(Path(result["receipt_path"])) == {"ok": True, "errors": [], "authoritative_board_checked": False}
    assert load(tmp_path / "current.json")["receipt_path"] == str(Path(result["receipt_path"]).relative_to(tmp_path))


def test_worker_package_verify_py_cannot_bypass_trusted_verifier(tmp_path: Path):
    prepared = run_demo(tmp_path, prepare_only=True)
    package = Path(prepared["source_package"])
    (package / "output.json").write_text('{"answer": 999}\n', encoding="utf-8")
    (package / "verify.py").write_text('print("{\\"ok\\": true}")\n', encoding="utf-8")
    exchange = worker_execute_from_board(
        root=tmp_path,
        board_path=tmp_path / "board.json",
        worker_id="local-worker-alpha",
        verifier_id="local-verifier-alpha",
        verifier_coordinate="100003.bitmap",
        source_package=package,
    )

    with pytest.raises(ProductionLoopError, match="separate process verifier rerun failed"):
        run_production_loop(
            root=tmp_path,
            board_path=tmp_path / "board.json",
            acceptance_path=Path(exchange["acceptance_path"]),
            worker_result_path=Path(exchange["worker_result_path"]),
            budget=10,
        )
    assert not (tmp_path / "current.json").exists()


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("requester_id", "", "agent id"),
        ("requester_coordinate", "not-bitmap", "coordinate"),
        ("requester_coordinate", "100002.bitmap", "distinct"),
    ],
)
def test_all_agent_ids_and_bitmap_coordinates_must_be_present_valid_and_distinct(tmp_path: Path, field, value, error):
    prepared = run_demo(tmp_path, prepare_only=True)
    board_path = tmp_path / "board.json"
    board = load(board_path)
    board["tasks"][0]["frozen_task"][field] = value
    board["tasks"][0]["task_hash"] = canonical_sha256(board["tasks"][0]["frozen_task"])
    board_path.write_text(json.dumps(board, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(ProductionLoopError, match=error):
        worker_execute_from_board(
            root=tmp_path,
            board_path=board_path,
            worker_id="local-worker-alpha",
            verifier_id="local-verifier-alpha",
            verifier_coordinate="100003.bitmap",
            source_package=Path(prepared["source_package"]),
        )


def test_reputation_chain_tamper_and_truncation_are_detected(tmp_path: Path):
    result = run_demo(tmp_path)
    receipt = Path(result["receipt_path"])
    events_path = receipt.parent / "reputation-events.jsonl"
    original = events_path.read_text(encoding="utf-8").splitlines()

    tampered = [json.loads(line) for line in original]
    tampered[1]["agent_id"] = "tampered"
    events_path.write_text("\n".join(json.dumps(x, sort_keys=True) for x in tampered) + "\n", encoding="utf-8")
    checked = verify_receipt(receipt)
    assert checked["ok"] is False
    assert any("reputation" in error for error in checked["errors"])

    events_path.write_text("\n".join(original[:-1]) + "\n", encoding="utf-8")
    checked = verify_receipt(receipt)
    assert checked["ok"] is False
    assert "reputation event count mismatch" in checked["errors"]


def test_append_refuses_corrupted_reputation_history(tmp_path: Path):
    result = run_demo(tmp_path)
    path = Path(result["receipt_path"]).parent / "reputation-events.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0]); first["event"] = "corrupt"
    path.write_text(json.dumps(first) + "\n" + "\n".join(lines[1:]) + "\n", encoding="utf-8")

    from organa_cell_kit.production_loop import append_reputation_event
    with pytest.raises(ProductionLoopError, match="corrupted reputation history"):
        append_reputation_event(path, {"event": "new"})


def test_exact_rerun_is_idempotent_and_conflicting_rerun_cannot_double_settle(tmp_path: Path):
    first = run_demo(tmp_path)
    events = Path(first["receipt_path"]).parent / "reputation-events.jsonl"
    before = events.read_bytes()
    second = run_production_loop(
        root=tmp_path,
        board_path=tmp_path / "board.json",
        acceptance_path=Path(run_demo(tmp_path, prepare_only=True)["acceptance_path"]),
        worker_result_path=Path(run_demo(tmp_path, prepare_only=True)["worker_result_path"]),
        budget=10,
    )
    assert second["receipt_path"] == first["receipt_path"]
    assert events.read_bytes() == before

    prepared = run_demo(tmp_path, prepare_only=True)
    with pytest.raises(ProductionLoopError, match="already settled"):
        run_production_loop(
            root=tmp_path,
            board_path=tmp_path / "board.json",
            acceptance_path=Path(prepared["acceptance_path"]),
            worker_result_path=Path(prepared["worker_result_path"]),
            budget=2,
        )
    assert verify_receipt(Path(first["receipt_path"]))["ok"] is True
    assert not any(p.name.startswith(".staging-") for p in (tmp_path / "runs").glob("*"))


def test_pointer_publication_failure_is_reported_and_exact_retry_repairs_crash_state(tmp_path: Path, monkeypatch):
    prepared = run_demo(tmp_path, prepare_only=True)
    real_atomic_write = production_loop_module._atomic_write_json
    failed = False

    def fail_current_once(path, value):
        nonlocal failed
        if Path(path) == tmp_path / "current.json" and not failed:
            failed = True
            raise OSError("injected current pointer failure")
        return real_atomic_write(path, value)

    monkeypatch.setattr(production_loop_module, "_atomic_write_json", fail_current_once)
    with pytest.raises(OSError, match="injected current pointer failure"):
        run_production_loop(
            root=tmp_path,
            board_path=tmp_path / "board.json",
            acceptance_path=Path(prepared["acceptance_path"]),
            worker_result_path=Path(prepared["worker_result_path"]),
            budget=10,
        )

    receipts = list((tmp_path / "runs").glob("*/receipt.json"))
    assert len(receipts) == 1
    assert not (tmp_path / "current.json").exists()
    assert verify_receipt(receipts[0], project_root=tmp_path)["ok"] is False

    recovered = run_production_loop(
        root=tmp_path,
        board_path=tmp_path / "board.json",
        acceptance_path=Path(prepared["acceptance_path"]),
        worker_result_path=Path(prepared["worker_result_path"]),
        budget=10,
    )

    assert recovered["receipt_path"] == str(receipts[0])
    assert load(tmp_path / "current.json") == {
        "task_hash": load(receipts[0])["hash_closure"]["task_hash"],
        "receipt_path": str(receipts[0].relative_to(tmp_path)),
    }
    assert verify_receipt(receipts[0], project_root=tmp_path) == {
        "ok": True,
        "errors": [],
        "authoritative_board_checked": True,
    }


def test_exact_retry_repairs_invalid_current_pointer_before_success(tmp_path: Path):
    first = run_demo(tmp_path)
    prepared = run_demo(tmp_path, prepare_only=True)
    _write(tmp_path / "current.json", {"unexpected": True})

    recovered = run_production_loop(
        root=tmp_path,
        board_path=tmp_path / "board.json",
        acceptance_path=Path(prepared["acceptance_path"]),
        worker_result_path=Path(prepared["worker_result_path"]),
        budget=10,
    )

    receipt = Path(first["receipt_path"])
    assert recovered["receipt_path"] == str(receipt)
    assert verify_receipt(receipt, project_root=tmp_path)["ok"] is True


def test_pointer_publication_is_authoritatively_verified_before_success(tmp_path: Path, monkeypatch):
    prepared = run_demo(tmp_path, prepare_only=True)
    real_atomic_write = production_loop_module._atomic_write_json

    def publish_corrupt_pointer(path, value):
        if Path(path) == tmp_path / "current.json":
            return real_atomic_write(path, {"unexpected": True})
        return real_atomic_write(path, value)

    monkeypatch.setattr(production_loop_module, "_atomic_write_json", publish_corrupt_pointer)
    with pytest.raises(ProductionLoopError, match="not authoritative"):
        run_production_loop(
            root=tmp_path,
            board_path=tmp_path / "board.json",
            acceptance_path=Path(prepared["acceptance_path"]),
            worker_result_path=Path(prepared["worker_result_path"]),
            budget=10,
        )

    receipt = next((tmp_path / "runs").glob("*/receipt.json"))
    assert verify_receipt(receipt, project_root=tmp_path)["ok"] is False

    monkeypatch.setattr(production_loop_module, "_atomic_write_json", real_atomic_write)
    recovered = run_production_loop(
        root=tmp_path,
        board_path=tmp_path / "board.json",
        acceptance_path=Path(prepared["acceptance_path"]),
        worker_result_path=Path(prepared["worker_result_path"]),
        budget=10,
    )
    assert recovered["receipt_path"] == str(receipt)
    assert verify_receipt(receipt, project_root=tmp_path)["ok"] is True


def test_concurrent_conflicting_attempts_cannot_both_settle_same_task(tmp_path: Path):
    prepared = run_demo(tmp_path, prepare_only=True)
    context = multiprocessing.get_context("fork")
    barrier = context.Barrier(2)
    queue = context.Queue()

    def settle(budget):
        try:
            barrier.wait(timeout=20)
            value = run_production_loop(
                root=tmp_path,
                board_path=tmp_path / "board.json",
                acceptance_path=Path(prepared["acceptance_path"]),
                worker_result_path=Path(prepared["worker_result_path"]),
                budget=budget,
            )
            queue.put(("ok", value["receipt_path"]))
        except Exception as exc:
            queue.put(("error", str(exc)))

    processes = [context.Process(target=settle, args=(budget,)) for budget in (10, 9)]
    for process in processes:
        process.start()
    for process in processes:
        process.join(30)
        assert process.exitcode == 0

    outcomes = [queue.get(timeout=5) for _ in processes]
    assert sum(status == "ok" for status, _ in outcomes) == 1
    assert any(status == "error" and "already settled" in message for status, message in outcomes)
    receipts = list((tmp_path / "runs").glob("*/receipt.json"))
    assert len(receipts) == 1
    assert verify_receipt(receipts[0])["ok"] is True


def test_task_is_revalidated_at_each_transition(tmp_path: Path):
    prepared = run_demo(tmp_path, prepare_only=True)
    board = load(tmp_path / "board.json")
    board["tasks"][0]["frozen_task"]["reward_test_credits"] = 4
    (tmp_path / "board.json").write_text(json.dumps(board) + "\n", encoding="utf-8")

    with pytest.raises(ProductionLoopError, match="frozen task hash mismatch"):
        run_production_loop(
            root=tmp_path,
            board_path=tmp_path / "board.json",
            acceptance_path=Path(prepared["acceptance_path"]),
            worker_result_path=Path(prepared["worker_result_path"]),
            budget=10,
        )


def test_initial_ledger_and_task_unique_settlement_are_bound(tmp_path: Path):
    result = run_demo(tmp_path)
    directory = Path(result["receipt_path"]).parent
    initial = load(directory / "credit-ledger-initial.json")
    final = load(directory / "credit-ledger.json")
    settlement = load(directory / "settlement.json")
    receipt = load(Path(result["receipt_path"]))

    assert initial["balances"] == {"local-requester-alpha": 10, "local-worker-alpha": 0}
    assert final["balances"] == {"local-requester-alpha": 7, "local-worker-alpha": 3}
    assert settlement["task_hash"] not in initial["settled_task_hashes"]
    assert settlement["task_hash"] in final["settled_task_hashes"]
    assert receipt["settlement"] == settlement
    assert receipt["hash_closure"]["initial_credit_ledger_hash"] == canonical_sha256(initial)


def test_source_package_symlinks_are_rejected_before_copy(tmp_path: Path):
    prepared = run_demo(tmp_path, prepare_only=True)
    source = Path(prepared["source_package"])
    outside = tmp_path / "outside.txt"; outside.write_text("secret", encoding="utf-8")
    (source / "escape").symlink_to(outside)

    with pytest.raises(ProductionLoopError, match="source package cannot contain symlinks"):
        worker_execute_from_board(
            root=tmp_path,
            board_path=tmp_path / "board.json",
            worker_id="local-worker-alpha",
            verifier_id="local-verifier-alpha",
            verifier_coordinate="100003.bitmap",
            source_package=source,
        )


def test_receipt_rejects_symlinked_linked_artifact(tmp_path: Path):
    result = run_demo(tmp_path)
    receipt = Path(result["receipt_path"])
    board = receipt.parent / "board.json"
    target = tmp_path / "outside-board.json"; target.write_bytes(board.read_bytes())
    board.unlink(); board.symlink_to(target)

    checked = verify_receipt(receipt)
    assert checked["ok"] is False
    assert "unsafe linked artifact: board.json" in checked["errors"]


@pytest.mark.parametrize(
    "mutate,error",
    [
        (lambda m: m.update(schema_version="wrong"), "schema version"),
        (lambda m: m.update(coordinate="bad"), "coordinate"),
        (lambda m: m.update(resources=[]), "non-empty"),
        (lambda m: m["resources"][0].update(path="a/../agent-registry.json"), "normalized"),
        (lambda m: m["resources"][0].update(sha256="sha256:" + "A" * 64), "lowercase"),
    ],
)
def test_organa_manifest_schema_is_strictly_validated(tmp_path: Path, mutate, error):
    source = make_organa_package(tmp_path / "source")
    manifest_path = source / "organa-cell.json"
    manifest = load(manifest_path); mutate(manifest)
    manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")

    with pytest.raises(ProductionLoopError, match=error):
        run_demo(tmp_path / "run", target_package=source)


def test_failed_rerun_leaves_no_authoritative_partial_artifacts(tmp_path: Path):
    prepared = run_demo(tmp_path, prepare_only=True)
    package = Path(prepared["source_package"])
    (package / "output.json").write_text('{"answer": 0}\n', encoding="utf-8")
    exchange = worker_execute_from_board(
        root=tmp_path, board_path=tmp_path / "board.json", worker_id="local-worker-alpha",
        verifier_id="local-verifier-alpha", verifier_coordinate="100003.bitmap", source_package=package,
    )
    with pytest.raises(ProductionLoopError):
        run_production_loop(root=tmp_path, board_path=tmp_path / "board.json", acceptance_path=Path(exchange["acceptance_path"]), worker_result_path=Path(exchange["worker_result_path"]), budget=10)

    assert not (tmp_path / "current.json").exists()
    assert not list((tmp_path / "runs").glob("*/receipt.json")) if (tmp_path / "runs").exists() else True


def rewrite_acceptance_and_result(prepared: dict, mutate_acceptance=None, mutate_result=None):
    acceptance_path = Path(prepared["acceptance_path"])
    result_path = Path(prepared["worker_result_path"])
    acceptance = load(acceptance_path)
    result = load(result_path)
    if mutate_acceptance:
        mutate_acceptance(acceptance)
        acceptance_path.write_text(json.dumps(acceptance) + "\n", encoding="utf-8")
        result["acceptance_hash"] = canonical_sha256(acceptance)
    if mutate_result:
        mutate_result(result)
    result_path.write_text(json.dumps(result) + "\n", encoding="utf-8")
    return acceptance_path, result_path


@pytest.mark.parametrize(
    "mutate,error",
    [
        (lambda a: a.update(status="rejected"), "acceptance status"),
        (lambda a: a.update(schema_version="forged"), "acceptance schema"),
        (lambda a: a.update(requester_id="forged-requester"), "requester provenance"),
        (lambda a: a.update(requester_coordinate="900001.bitmap"), "requester provenance"),
        (lambda a: a.update(worker_id="forged-worker"), "worker provenance"),
        (lambda a: a.update(worker_coordinate="900002.bitmap"), "worker provenance"),
    ],
)
def test_acceptance_requires_schema_status_and_board_role_provenance(tmp_path: Path, mutate, error):
    prepared = run_demo(tmp_path, prepare_only=True)
    acceptance_path, result_path = rewrite_acceptance_and_result(prepared, mutate_acceptance=mutate)
    with pytest.raises(ProductionLoopError, match=error):
        run_production_loop(root=tmp_path, board_path=tmp_path / "board.json", acceptance_path=acceptance_path, worker_result_path=result_path, budget=10)


@pytest.mark.parametrize(
    "mutate,error",
    [
        (lambda r: r.update(schema_version="forged"), "worker result schema"),
        (lambda r: r.update(claimed_status="failed"), "worker result status"),
        (lambda r: r.update(worker_coordinate="900002.bitmap"), "worker result identity"),
        (lambda r: r.update(verifier_coordinate="900003.bitmap"), "worker result identity"),
    ],
)
def test_worker_result_requires_completion_and_exact_role_bindings(tmp_path: Path, mutate, error):
    prepared = run_demo(tmp_path, prepare_only=True)
    acceptance_path, result_path = rewrite_acceptance_and_result(prepared, mutate_result=mutate)
    with pytest.raises(ProductionLoopError, match=error):
        run_production_loop(root=tmp_path, board_path=tmp_path / "board.json", acceptance_path=acceptance_path, worker_result_path=result_path, budget=10)


def test_runtime_verifier_must_be_expected_installed_file_and_match_frozen_descriptor(tmp_path: Path, monkeypatch):
    prepared = run_demo(tmp_path, prepare_only=True)
    replacement = tmp_path / "trusted_verifier.py"
    replacement.write_text(
        'import json,sys\nVERIFIER_ID="organa-cell-kit.trusted-package-verifier"\nVERIFIER_VERSION="1.0.0"\nprint(json.dumps({"ok": True, "check": "bypass"}))\n',
        encoding="utf-8",
    )
    from organa_cell_kit import trusted_verifier
    monkeypatch.setattr(trusted_verifier, "__file__", str(replacement))
    with pytest.raises(ProductionLoopError, match="trusted verifier"):
        run_production_loop(root=tmp_path, board_path=tmp_path / "board.json", acceptance_path=Path(prepared["acceptance_path"]), worker_result_path=Path(prepared["worker_result_path"]), budget=10)


def test_board_is_reread_immediately_after_verifier_before_settlement(tmp_path: Path, monkeypatch):
    prepared = run_demo(tmp_path, prepare_only=True)
    import organa_cell_kit.production_loop as loop
    real_run = loop.subprocess.run

    def mutate_board(*args, **kwargs):
        completed = real_run(*args, **kwargs)
        board_path = tmp_path / "board.json"
        board = load(board_path)
        board["tasks"][0]["frozen_task"]["reward_test_credits"] = 4
        board["tasks"][0]["task_hash"] = canonical_sha256(board["tasks"][0]["frozen_task"])
        board_path.write_text(json.dumps(board) + "\n", encoding="utf-8")
        return completed

    monkeypatch.setattr(loop.subprocess, "run", mutate_board)
    with pytest.raises(ProductionLoopError, match="authoritative board task changed"):
        run_production_loop(root=tmp_path, board_path=tmp_path / "board.json", acceptance_path=Path(prepared["acceptance_path"]), worker_result_path=Path(prepared["worker_result_path"]), budget=10)
    assert not (tmp_path / "current.json").exists()
    assert not list((tmp_path / "runs").glob("*/receipt.json"))


def test_deleting_current_pointer_cannot_allow_second_settlement(tmp_path: Path):
    first = run_demo(tmp_path)
    (tmp_path / "current.json").unlink()
    prepared = run_demo(tmp_path, prepare_only=True)
    with pytest.raises(ProductionLoopError, match="already settled"):
        run_production_loop(root=tmp_path, board_path=tmp_path / "board.json", acceptance_path=Path(prepared["acceptance_path"]), worker_result_path=Path(prepared["worker_result_path"]), budget=9)
    assert len(list((tmp_path / "runs").glob("*/receipt.json"))) == 1
    assert verify_receipt(Path(first["receipt_path"]))["ok"] is True


@pytest.mark.parametrize("package_path", ["../../external", "/tmp/external", ".", "worker-package/../worker-package"])
def test_worker_package_path_must_be_normalized_relative_and_contained(tmp_path: Path, package_path):
    prepared = run_demo(tmp_path, prepare_only=True)
    acceptance_path, result_path = rewrite_acceptance_and_result(prepared, mutate_result=lambda r: r.update(package_path=package_path))
    with pytest.raises(ProductionLoopError, match="package path"):
        run_production_loop(root=tmp_path, board_path=tmp_path / "board.json", acceptance_path=acceptance_path, worker_result_path=result_path, budget=10)


def rehash_receipt_artifacts(directory: Path):
    receipt_file = directory / "receipt.json"
    receipt = load(receipt_file)
    mappings = {
        "board_hash": "board.json", "acceptance_hash": "acceptance.json", "worker_result_hash": "worker-result.json",
        "verifier_result_hash": "verification.json", "settlement_hash": "settlement.json", "credit_ledger_hash": "credit-ledger.json",
        "initial_credit_ledger_hash": "credit-ledger-initial.json",
    }
    for key, filename in mappings.items():
        receipt["hash_closure"][key] = canonical_sha256(load(directory / filename))
    receipt["settlement"] = load(directory / "settlement.json")
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    receipt["receipt_sha256"] = canonical_sha256(body)
    receipt_file.write_text(json.dumps(receipt) + "\n", encoding="utf-8")


def test_verify_receipt_rejects_rehashed_false_receipt_rerun_claim(tmp_path: Path):
    result = run_demo(tmp_path)
    directory = Path(result["receipt_path"]).parent
    receipt = load(directory / "receipt.json")
    receipt["separate_process_verifier_rerun"] = False
    _write(directory / "receipt.json", receipt)
    rehash_receipt_artifacts(directory)
    checked = verify_receipt(directory / "receipt.json")
    assert checked["ok"] is False
    assert any("verifier rerun" in error for error in checked["errors"])


@pytest.mark.parametrize(
    "agent_id,coordinate,error",
    [
        ("local-requester-alpha", "100003.bitmap", "agent ids must be distinct"),
        ("local-verifier-alpha", "100001.bitmap", "coordinates must be distinct"),
    ],
)
def test_verify_receipt_rejects_rehashed_duplicate_roles(tmp_path: Path, agent_id: str, coordinate: str, error: str):
    result = run_demo(tmp_path)
    directory = Path(result["receipt_path"]).parent
    acceptance = load(directory / "acceptance.json")
    acceptance.update(verifier_id=agent_id, verifier_coordinate=coordinate)
    _write(directory / "acceptance.json", acceptance)
    worker = load(directory / "worker-result.json")
    worker.update(verifier_id=agent_id, verifier_coordinate=coordinate, acceptance_hash=canonical_sha256(acceptance))
    _write(directory / "worker-result.json", worker)
    verification = load(directory / "verification.json"); verification["verifier_id"] = agent_id; _write(directory / "verification.json", verification)
    receipt = load(directory / "receipt.json"); receipt["roles"]["verifier"] = {"agent_id": agent_id, "cell_coordinate": coordinate}; _write(directory / "receipt.json", receipt)
    events = []
    for line in (directory / "reputation-events.jsonl").read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        if event["event"] == "verifier-verified": event.update(agent_id=agent_id, cell_coordinate=coordinate)
        events.append(json.dumps(event, sort_keys=True))
    (directory / "reputation-events.jsonl").write_text("\n".join(events) + "\n", encoding="utf-8")
    _rehash_reputation(directory); rehash_receipt_artifacts(directory)
    checked = verify_receipt(directory / "receipt.json")
    assert checked["ok"] is False
    assert any(error in item for item in checked["errors"])


def test_authoritative_board_must_equal_immutable_receipt_snapshot(tmp_path: Path):
    result = run_demo(tmp_path)
    receipt = Path(result["receipt_path"])
    snapshot = (receipt.parent / "board.json").read_bytes()
    board = load(tmp_path / "board.json"); board["tasks"][0]["status"] = "closed"; _write(tmp_path / "board.json", board)
    checked = verify_receipt(receipt, project_root=tmp_path)
    assert checked["ok"] is False
    assert checked["authoritative_board_checked"] is True
    assert any("authoritative board" in error for error in checked["errors"])
    assert (receipt.parent / "board.json").read_bytes() == snapshot


def test_authoritative_board_rejects_wrong_project_root(tmp_path: Path):
    project = tmp_path / "project"; result = run_demo(project)
    wrong = tmp_path / "wrong"; wrong.mkdir()
    (wrong / "board.json").write_bytes((project / "board.json").read_bytes())
    checked = verify_receipt(Path(result["receipt_path"]), project_root=wrong)
    assert checked["ok"] is False
    assert checked["authoritative_board_checked"] is True
    assert any("project receipt" in error for error in checked["errors"])


def test_authoritative_wrong_root_rehashed_binding_still_rejects_receipt_owned_by_good_root(tmp_path: Path):
    good = tmp_path / "good"; result = run_demo(good); receipt_file = Path(result["receipt_path"])
    wrong = tmp_path / "wrong"; wrong.mkdir(); (wrong / "board.json").write_bytes((good / "board.json").read_bytes())
    receipt = load(receipt_file)
    receipt["project_binding"]["absolute_root"] = str(wrong.resolve())
    _write(receipt_file, receipt); rehash_receipt_artifacts(receipt_file.parent)

    checked = verify_receipt(receipt_file, project_root=wrong)

    assert checked["ok"] is False
    assert checked["authoritative_board_checked"] is True
    assert any("project receipt" in error for error in checked["errors"])


def test_authoritative_copied_receipt_without_current_pointer_is_rejected(tmp_path: Path):
    good = tmp_path / "good"; result = run_demo(good)
    wrong = tmp_path / "wrong"; copied_run = wrong / "runs" / "copied-run"; copied_run.mkdir(parents=True)
    copied = copied_run / "receipt.json"; copied.write_bytes(Path(result["receipt_path"]).read_bytes())

    checked = verify_receipt(copied, project_root=wrong)

    assert checked["ok"] is False
    assert any("current.json" in error for error in checked["errors"])


@pytest.mark.parametrize(
    "pointer",
    [
        None,
        {"task_hash": "sha256:" + "0" * 64, "receipt_path": "runs/copied-run/receipt.json"},
        {"task_hash": "sha256:" + "1" * 64, "receipt_path": "runs/other-run/receipt.json"},
        {"task_hash": "sha256:" + "1" * 64, "receipt_path": "runs/../runs/copied-run/receipt.json"},
        {"task_hash": "sha256:" + "1" * 64, "receipt_path": "/tmp/receipt.json"},
        {"unexpected": True},
    ],
)
def test_authoritative_copied_full_run_requires_exact_current_pointer(tmp_path: Path, pointer):
    good = tmp_path / "good"; result = run_demo(good); source_run = Path(result["receipt_path"]).parent
    wrong = tmp_path / "wrong"; wrong.mkdir(); (wrong / "board.json").write_bytes((good / "board.json").read_bytes())
    copied_run = wrong / "runs" / "copied-run"
    import shutil
    shutil.copytree(source_run, copied_run)
    receipt_file = copied_run / "receipt.json"
    receipt = load(receipt_file); receipt["project_binding"]["absolute_root"] = str(wrong.resolve()); _write(receipt_file, receipt); rehash_receipt_artifacts(copied_run)
    if pointer is not None:
        _write(wrong / "current.json", pointer)

    checked = verify_receipt(receipt_file, project_root=wrong)

    assert checked["ok"] is False
    assert any("current.json" in error or "current receipt" in error for error in checked["errors"])


@pytest.mark.parametrize("placement", ["direct", "hidden", "wrong-name", "symlink-receipt", "symlink-run"])
def test_authoritative_receipt_path_must_be_safe_owned_run_receipt(tmp_path: Path, placement: str):
    project = tmp_path / "project"; result = run_demo(project); original = Path(result["receipt_path"])
    if placement == "direct":
        candidate = project / "receipt.json"; candidate.write_bytes(original.read_bytes())
    elif placement == "hidden":
        candidate = project / "runs" / ".staging-copy" / "receipt.json"; candidate.parent.mkdir(); candidate.write_bytes(original.read_bytes())
    elif placement == "wrong-name":
        candidate = original.with_name("other.json"); candidate.write_bytes(original.read_bytes())
    elif placement == "symlink-receipt":
        link_run = project / "runs" / "linked-receipt-run"; link_run.mkdir(); candidate = link_run / "receipt.json"; candidate.symlink_to(original)
    else:
        alias_run = project / "runs" / "linked-run"; alias_run.symlink_to(original.parent, target_is_directory=True); candidate = alias_run / "receipt.json"

    checked = verify_receipt(candidate, project_root=project)

    assert checked["ok"] is False
    assert any("project receipt" in error for error in checked["errors"])


def test_authoritative_project_root_relative_and_symlink_aliases_resolve_consistently(tmp_path: Path, monkeypatch):
    project = tmp_path / "project"; result = run_demo(project)
    receipt = Path(result["receipt_path"])
    alias = tmp_path / "project-alias"; alias.symlink_to(project, target_is_directory=True)
    monkeypatch.chdir(tmp_path)

    assert verify_receipt(receipt, project_root=Path("project"))["ok"] is True
    assert verify_receipt(receipt, project_root=alias)["ok"] is True
    assert verify_receipt(alias / receipt.relative_to(project), project_root=alias)["ok"] is True
    assert verify_receipt(receipt, authoritative_board_path=alias / "board.json")["ok"] is True


def test_snapshot_only_verification_rejects_rehashed_invalid_project_binding(tmp_path: Path):
    result = run_demo(tmp_path); directory = Path(result["receipt_path"]).parent
    receipt = load(directory / "receipt.json")
    receipt["project_binding"]["board_relative_path"] = "nested/board.json"
    _write(directory / "receipt.json", receipt); rehash_receipt_artifacts(directory)

    checked = verify_receipt(directory / "receipt.json")
    assert checked["ok"] is False
    assert checked["authoritative_board_checked"] is False
    assert any("project binding" in error for error in checked["errors"])


@pytest.mark.parametrize("status", [1, "closed", "unknown"])
def test_verify_receipt_rejects_consistently_rehashed_invalid_task_status(tmp_path: Path, status):
    result = run_demo(tmp_path); directory = Path(result["receipt_path"]).parent
    task = load(directory / "task.json"); task["status"] = status; _write(directory / "task.json", task)
    board = load(directory / "board.json"); board["tasks"][0] = task; _write(directory / "board.json", board)
    rehash_receipt_artifacts(directory)

    snapshot = verify_receipt(directory / "receipt.json")
    authoritative = verify_receipt(directory / "receipt.json", project_root=tmp_path)
    assert snapshot["ok"] is False
    assert authoritative["ok"] is False
    assert any("task status" in error for error in snapshot["errors"])


def test_task_status_is_required_by_worker_and_coordinator(tmp_path: Path):
    prepared = run_demo(tmp_path, prepare_only=True)
    board_path = tmp_path / "board.json"; board = load(board_path); board["tasks"][0].pop("status"); _write(board_path, board)
    with pytest.raises(ProductionLoopError, match="task schema"):
        worker_execute_from_board(
            root=tmp_path, board_path=board_path, worker_id="local-worker-alpha",
            verifier_id="local-verifier-alpha", verifier_coordinate="100003.bitmap",
            source_package=Path(prepared["source_package"]),
        )
    with pytest.raises(ProductionLoopError, match="task schema"):
        run_production_loop(
            root=tmp_path, board_path=board_path, acceptance_path=Path(prepared["acceptance_path"]),
            worker_result_path=Path(prepared["worker_result_path"]), budget=10,
        )


@pytest.mark.parametrize("case", ["settlement", "ledger", "verification", "package_binding", "reputation"])
def test_verify_receipt_rejects_rehashed_semantic_forgery(tmp_path: Path, case):
    result = run_demo(tmp_path)
    directory = Path(result["receipt_path"]).parent
    if case == "settlement":
        settlement = load(directory / "settlement.json"); settlement["amount"] = 999
        (directory / "settlement.json").write_text(json.dumps(settlement) + "\n", encoding="utf-8")
    elif case == "ledger":
        ledger = load(directory / "credit-ledger.json"); ledger["balances"]["local-worker-alpha"] = 999
        (directory / "credit-ledger.json").write_text(json.dumps(ledger) + "\n", encoding="utf-8")
        settlement = load(directory / "settlement.json"); settlement["poststate_hash"] = canonical_sha256(ledger)
        (directory / "settlement.json").write_text(json.dumps(settlement) + "\n", encoding="utf-8")
    elif case == "verification":
        verification = load(directory / "verification.json"); verification["result"]["ok"] = False
        (directory / "verification.json").write_text(json.dumps(verification) + "\n", encoding="utf-8")
    elif case == "package_binding":
        worker = load(directory / "worker-result.json"); worker["task_hash"] = "sha256:" + "0" * 64
        (directory / "worker-result.json").write_text(json.dumps(worker) + "\n", encoding="utf-8")
    else:
        lines = (directory / "reputation-events.jsonl").read_text(encoding="utf-8").splitlines()
        events, previous = [], None
        for line in lines:
            event = json.loads(line); event["event"] = "wrong-event"
            event["previous_event_hash"] = previous
            event["event_hash"] = canonical_sha256({k: v for k, v in event.items() if k != "event_hash"})
            previous = event["event_hash"]; events.append(json.dumps(event, sort_keys=True))
        (directory / "reputation-events.jsonl").write_text("\n".join(events) + "\n", encoding="utf-8")
        receipt = load(directory / "receipt.json"); receipt["reputation"]["chain_head"] = previous; receipt["hash_closure"]["reputation_event_hash"] = previous
        body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}; receipt["receipt_sha256"] = canonical_sha256(body)
        (directory / "receipt.json").write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    if case != "reputation":
        rehash_receipt_artifacts(directory)
    checked = verify_receipt(directory / "receipt.json")
    assert checked["ok"] is False
    assert checked["errors"]


def test_manifest_rejects_unknown_top_level_and_resource_fields(tmp_path: Path):
    for location in ("top", "resource"):
        source = make_organa_package(tmp_path / location / "source")
        manifest_path = source / "organa-cell.json"
        manifest = load(manifest_path)
        if location == "top": manifest["unexpected_top"] = True
        else: manifest["resources"][0]["unexpected"] = True
        manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
        with pytest.raises(ProductionLoopError, match="unknown manifest"):
            run_demo(tmp_path / location / "run", target_package=source)


def test_real_720202_manifest_shape_is_supported(tmp_path: Path):
    source = Path("/Users/danyanpihuihui/Desktop/projects/bitmap/bitmap-memory-portal/output/organa-cell-720202-github-pages/versions/0.3.0")
    assert source.is_dir()
    result = run_demo(tmp_path, target_package=source)
    assert result["ok"] is True
    assert verify_receipt(Path(result["receipt_path"])) == {"ok": True, "errors": [], "authoritative_board_checked": False}


def _write(path: Path, value: dict):
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _rehash_reputation(directory: Path):
    path = directory / "reputation-events.jsonl"
    previous = None
    rewritten = []
    for line in path.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        event["previous_event_hash"] = previous
        event["event_hash"] = canonical_sha256({key: value for key, value in event.items() if key != "event_hash"})
        previous = event["event_hash"]
        rewritten.append(json.dumps(event, sort_keys=True))
    path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
    receipt = load(directory / "receipt.json")
    receipt["reputation"] = {"event_count": len(rewritten), "chain_head": previous}
    receipt["hash_closure"]["reputation_event_hash"] = previous
    _write(directory / "receipt.json", receipt)


def test_verify_receipt_rejects_consistently_rehashed_unlisted_worker(tmp_path: Path):
    result = run_demo(tmp_path)
    directory = Path(result["receipt_path"]).parent
    acceptance = load(directory / "acceptance.json")
    acceptance.update(worker_id="unlisted-worker", worker_coordinate="900002.bitmap")
    _write(directory / "acceptance.json", acceptance)
    worker = load(directory / "worker-result.json")
    worker.update(worker_id="unlisted-worker", worker_coordinate="900002.bitmap", acceptance_hash=canonical_sha256(acceptance))
    _write(directory / "worker-result.json", worker)
    initial = load(directory / "credit-ledger-initial.json"); initial["balances"] = {"local-requester-alpha": 10, "unlisted-worker": 0}
    final = load(directory / "credit-ledger.json"); final["balances"] = {"local-requester-alpha": 7, "unlisted-worker": 3}
    _write(directory / "credit-ledger-initial.json", initial); _write(directory / "credit-ledger.json", final)
    settlement = load(directory / "settlement.json")
    settlement.update(payee="unlisted-worker", prestate_hash=canonical_sha256(initial), poststate_hash=canonical_sha256(final))
    _write(directory / "settlement.json", settlement)
    receipt = load(directory / "receipt.json")
    receipt["roles"]["worker"] = {"agent_id": "unlisted-worker", "cell_coordinate": "900002.bitmap"}; receipt["settlement"] = settlement
    _write(directory / "receipt.json", receipt)
    lines = []
    for line in (directory / "reputation-events.jsonl").read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        if event["event"].startswith("worker-"): event.update(agent_id="unlisted-worker", cell_coordinate="900002.bitmap")
        lines.append(json.dumps(event, sort_keys=True))
    (directory / "reputation-events.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    _rehash_reputation(directory); rehash_receipt_artifacts(directory)
    checked = verify_receipt(directory / "receipt.json")
    assert checked["ok"] is False
    assert any("worker provenance" in error for error in checked["errors"])


@pytest.mark.parametrize("artifact", ["board", "task", "worker_advertisement", "acceptance", "worker_result", "verification", "initial_ledger", "final_ledger", "settlement", "receipt", "project_binding", "roles", "reputation_envelope", "reputation_event", "trusted_verifier"])
@pytest.mark.parametrize("mutation", ["unknown", "missing"])
def test_hash_closed_artifacts_use_closed_schemas(tmp_path: Path, artifact: str, mutation: str):
    result = run_demo(tmp_path); directory = Path(result["receipt_path"]).parent; receipt_file = directory / "receipt.json"
    filename = {"board": "board.json", "task": "task.json", "acceptance": "acceptance.json", "worker_result": "worker-result.json", "verification": "verification.json", "initial_ledger": "credit-ledger-initial.json", "final_ledger": "credit-ledger.json", "settlement": "settlement.json"}.get(artifact)
    target_path = directory / filename if filename else receipt_file; target = load(target_path)
    if artifact == "worker_advertisement": target = load(directory / "board.json"); target_path = directory / "board.json"; obj = target["workers"][0]
    elif artifact == "project_binding": obj = target["project_binding"]
    elif artifact == "roles": obj = target["roles"]
    elif artifact == "reputation_envelope": obj = target["reputation"]
    elif artifact == "trusted_verifier": obj = target["trusted_verifier"]
    elif artifact == "reputation_event":
        events_path = directory / "reputation-events.jsonl"; events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]; obj = events[0]
        if mutation == "unknown": obj["unexpected"] = True
        else: obj.pop("agent_id")
        events_path.write_text("\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n", encoding="utf-8"); _rehash_reputation(directory); rehash_receipt_artifacts(directory)
        assert verify_receipt(receipt_file)["ok"] is False; return
    else: obj = target
    if mutation == "unknown": obj["unexpected"] = True
    else:
        required = {"board": "workers", "task": "status", "worker_advertisement": "status", "acceptance": "status", "worker_result": "claimed_status", "verification": "result", "initial_ledger": "balances", "final_ledger": "balances", "settlement": "status", "receipt": "claims_scope", "project_binding": "absolute_root", "roles": "worker", "reputation_envelope": "chain_head", "trusted_verifier": "module_path"}[artifact]
        obj.pop(required, None)
    _write(target_path, target); rehash_receipt_artifacts(directory)
    assert verify_receipt(receipt_file)["ok"] is False


@pytest.mark.parametrize("artifact", ["board", "acceptance", "worker_result"])
@pytest.mark.parametrize("mutation", ["unknown", "missing"])
def test_coordinator_rejects_open_or_incomplete_input_schemas(tmp_path: Path, artifact: str, mutation: str):
    prepared = run_demo(tmp_path, prepare_only=True)
    path = {"board": tmp_path / "board.json", "acceptance": Path(prepared["acceptance_path"]), "worker_result": Path(prepared["worker_result_path"])}[artifact]
    value = load(path)
    if mutation == "unknown": value["unexpected"] = True
    else: value.pop({"board": "workers", "acceptance": "status", "worker_result": "claimed_status"}[artifact])
    _write(path, value)
    if artifact == "acceptance":
        result_value = load(Path(prepared["worker_result_path"])); result_value["acceptance_hash"] = canonical_sha256(value); _write(Path(prepared["worker_result_path"]), result_value)
    with pytest.raises(ProductionLoopError, match="schema"):
        run_production_loop(root=tmp_path, board_path=tmp_path / "board.json", acceptance_path=Path(prepared["acceptance_path"]), worker_result_path=Path(prepared["worker_result_path"]), budget=10)


def test_trusted_verifier_descriptor_is_install_root_independent(tmp_path: Path):
    result = run_demo(tmp_path)
    receipt = load(Path(result["receipt_path"]))
    expected = "organa_cell_kit/trusted_verifier.py"
    assert receipt["trusted_verifier"]["module_path"] == expected
    assert load(Path(result["receipt_path"]).parent / "task.json")["frozen_task"]["trusted_verifier"]["module_path"] == expected
    assert "expected_path" not in receipt["trusted_verifier"]


def test_receipt_rejects_changed_verifier_module_path_even_when_rehashed(tmp_path: Path):
    result = run_demo(tmp_path); directory = Path(result["receipt_path"]).parent
    task = load(directory / "task.json"); task["frozen_task"]["trusted_verifier"]["module_path"] = "replacement/trusted_verifier.py"; task["task_hash"] = canonical_sha256(task["frozen_task"]); _write(directory / "task.json", task)
    receipt = load(directory / "receipt.json"); receipt["trusted_verifier"]["module_path"] = "replacement/trusted_verifier.py"; _write(directory / "receipt.json", receipt); rehash_receipt_artifacts(directory)
    assert verify_receipt(directory / "receipt.json")["ok"] is False


def test_receipt_has_structured_truthful_scope_contract(tmp_path: Path):
    result = run_demo(tmp_path); receipt = load(Path(result["receipt_path"]))
    assert receipt["settlement_mode"] == "local-test-credit"; assert receipt["settlement"]["real_payment"] is False
    assert receipt["claims_scope"] == {"fiat_payment": False, "cryptocurrency_payment": False, "onchain_transfer": False, "escrow": False, "financial_claim": False, "external_adoption": False, "independent_controller": False}
