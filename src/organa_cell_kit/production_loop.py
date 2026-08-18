from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any


SIMULATION_SCOPE = "same-controller-simulation-not-external-adoption"
PAYMENT_SCOPE = "local-test-credits-only-no-real-payment"
BOARD_SCHEMA = "organa-local-json-board-v0.2"
TASK_SCHEMA = "organa-frozen-task-v0.2"
MANIFEST_SCHEMA = "organa-cell-resolution-v0.1"
ACCEPTANCE_SCHEMA = "organa-local-task-acceptance-v0.2"
WORKER_RESULT_SCHEMA = "organa-local-worker-result-v0.2"
VERIFICATION_SCHEMA = "organa-local-verification-v0.2"
LEDGER_SCHEMA = "organa-local-credit-ledger-v0.2"
RECEIPT_SCHEMA = "organa-local-production-receipt-v0.3"
CLAIMS_SCOPE = {
    "fiat_payment": False,
    "cryptocurrency_payment": False,
    "onchain_transfer": False,
    "escrow": False,
    "financial_claim": False,
    "external_adoption": False,
    "independent_controller": False,
}
BOARD_KEYS = {"schema_version", "tasks", "workers"}
TASK_KEYS = {"schema_version", "frozen_task", "task_hash", "status"}
FROZEN_TASK_KEYS = {"input", "operation", "requester_id", "requester_coordinate", "required_capability", "reward_test_credits", "task_id", "trusted_verifier", "fixture_package_sha256"}
WORKER_ADVERTISEMENT_KEYS = {"capabilities", "controller_scope", "cell_coordinate", "price_test_credits", "status", "worker_id"}
ACCEPTANCE_KEYS = {"schema_version", "task_hash", "frozen_task", "discovered_from_board_hash", "requester_id", "requester_coordinate", "worker_id", "worker_coordinate", "verifier_id", "verifier_coordinate", "status"}
WORKER_RESULT_KEYS = {"schema_version", "task_hash", "frozen_task", "acceptance_hash", "worker_id", "worker_coordinate", "verifier_id", "verifier_coordinate", "package_path", "package_sha256", "claimed_status", "report"}
VERIFICATION_KEYS = {"schema_version", "task_hash", "package_hash", "verifier_id", "trusted_verifier", "separate_process_verifier_rerun", "result"}
LEDGER_KEYS = {"schema_version", "unit", "real_payment", "balances", "settled_task_hashes"}
SETTLEMENT_KEYS = {"task_hash", "amount", "budget_before", "budget_after", "status", "unit", "real_payment", "payer", "payee", "prestate_hash", "poststate_hash"}
TRUSTED_VERIFIER_KEYS = {"id", "version", "sha256", "module_path"}
ROLE_KEYS = {"agent_id", "cell_coordinate"}
ROLES_KEYS = {"requester", "worker", "verifier"}
REPUTATION_ENVELOPE_KEYS = {"event_count", "chain_head"}
REPUTATION_EVENT_KEYS = {"event", "agent_id", "cell_coordinate", "package_hash", "task_hash", "previous_event_hash", "event_hash"}
HASH_CLOSURE_KEYS = {"task_hash", "board_hash", "acceptance_hash", "worker_result_hash", "package_hash", "verifier_result_hash", "initial_credit_ledger_hash", "credit_ledger_hash", "settlement_hash", "reputation_event_hash"}
PROJECT_BINDING_KEYS = {"absolute_root", "board_relative_path"}
CURRENT_POINTER_KEYS = {"task_hash", "receipt_path"}
RECEIPT_KEYS = {"schema_version", "simulation_scope", "payment_scope", "settlement_mode", "claims_scope", "separate_process_verifier_rerun", "trusted_verifier", "roles", "settlement", "reputation", "hash_closure", "project_binding", "receipt_sha256"}
MANIFEST_REQUIRED_KEYS = {
    "schema_version", "coordinate", "cell_type", "version", "created_at_utc", "lifecycle_status",
    "controller", "public_base_url", "resources", "agents", "services",
}
MANIFEST_ALLOWED_KEYS = MANIFEST_REQUIRED_KEYS | {
    "cell_type", "title", "version", "created_at_utc", "lifecycle_status", "activation_status",
    "state_semantics", "status_note", "previous_manifest", "controller", "public_base_url", "agents",
    "services", "disclosure_policy_url", "proof_index_url", "machine_instructions",
}
RESOURCE_REQUIRED_KEYS = {"path", "sha256"}
RESOURCE_ALLOWED_KEYS = RESOURCE_REQUIRED_KEYS | {"url"}
BITMAP_RE = re.compile(r"^[1-9][0-9]*\.bitmap$")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
AGENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")


class ProductionLoopError(ValueError):
    pass


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _strict_json_loads(value: str) -> Any:
    return json.loads(value, parse_constant=_reject_json_constant, object_pairs_hook=_reject_duplicate_keys)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_json(path: Path) -> dict:
    try:
        value = _strict_json_loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProductionLoopError(f"invalid JSON artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ProductionLoopError(f"JSON object required: {path}")
    return value


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _validate_agent(agent_id: Any, coordinate: Any, role: str) -> tuple[str, str]:
    if not isinstance(agent_id, str) or not AGENT_RE.fullmatch(agent_id):
        raise ProductionLoopError(f"{role} agent id is missing or invalid")
    if not isinstance(coordinate, str) or not BITMAP_RE.fullmatch(coordinate):
        raise ProductionLoopError(f"{role} coordinate must be a valid *.bitmap coordinate")
    return agent_id, coordinate


def _validate_distinct_roles(roles: list[tuple[str, str]]) -> None:
    if len({item[0] for item in roles}) != len(roles):
        raise ProductionLoopError("requester, worker, and verifier agent ids must be distinct")
    if len({item[1] for item in roles}) != len(roles):
        raise ProductionLoopError("requester, worker, and verifier coordinates must be distinct")


def _validate_exact_keys(value: Any, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict):
        raise ProductionLoopError(f"invalid {label} schema: object required")
    missing = keys - set(value)
    unknown = set(value) - keys
    if missing or unknown:
        details = []
        if missing: details.append("missing " + ", ".join(sorted(missing)))
        if unknown: details.append("unknown " + ", ".join(sorted(unknown)))
        raise ProductionLoopError(f"invalid {label} schema: " + "; ".join(details))
    return value


def _validate_trusted_verifier(value: Any) -> dict:
    descriptor = _validate_exact_keys(value, TRUSTED_VERIFIER_KEYS, "trusted verifier")
    if descriptor != TRUSTED_VERIFIER:
        raise ProductionLoopError("trusted verifier descriptor mismatch")
    return descriptor


def _validate_frozen_input(frozen: dict) -> None:
    operation = frozen.get("operation")
    value = frozen.get("input")
    if operation == "add":
        value = _validate_exact_keys(value, {"left", "right"}, "addition task input")
        if not all(isinstance(value[name], int) for name in value):
            raise ProductionLoopError("invalid addition task input schema: integers required")
    elif operation == "verify-organa-manifest-resources":
        value = _validate_exact_keys(value, {"target"}, "manifest task input")
        if value.get("target") != "organa-cell.json":
            raise ProductionLoopError("invalid manifest task input schema: target")
    else:
        raise ProductionLoopError("unsupported frozen task operation")
    fixture_hash = frozen.get("fixture_package_sha256")
    if frozen.get("operation") == "verify-organa-manifest-resources" and (not isinstance(fixture_hash, str) or not SHA256_RE.fullmatch(fixture_hash)):
        raise ProductionLoopError("frozen task fixture package hash is required")


def _validate_frozen_task(record: dict) -> dict:
    _validate_exact_keys(record, TASK_KEYS, "task")
    frozen = _validate_exact_keys(record.get("frozen_task"), FROZEN_TASK_KEYS, "frozen task")
    if record.get("schema_version") != TASK_SCHEMA:
        raise ProductionLoopError("invalid frozen task record")
    if record.get("task_hash") != canonical_sha256(frozen):
        raise ProductionLoopError("frozen task hash mismatch")
    status = record.get("status")
    if not isinstance(status, str) or status not in {"open"}:
        raise ProductionLoopError("task status must be the string 'open'")
    _validate_agent(frozen.get("requester_id"), frozen.get("requester_coordinate"), "requester")
    _validate_frozen_input(frozen)
    reward = frozen.get("reward_test_credits")
    if not isinstance(reward, int) or reward < 0:
        raise ProductionLoopError("invalid frozen task reward")
    if not isinstance(frozen.get("required_capability"), str) or not frozen["required_capability"]:
        raise ProductionLoopError("frozen task capability is required")
    _validate_string(frozen.get("task_id"), "frozen task")
    verifier = frozen.get("trusted_verifier")
    _validate_trusted_verifier(verifier)
    return frozen


def _validate_worker_advertisement(worker: Any) -> dict:
    worker = _validate_exact_keys(worker, WORKER_ADVERTISEMENT_KEYS, "worker advertisement")
    _validate_agent(worker.get("worker_id"), worker.get("cell_coordinate"), "worker")
    if not isinstance(worker.get("capabilities"), list) or not all(isinstance(item, str) and item for item in worker["capabilities"]):
        raise ProductionLoopError("invalid worker advertisement schema: capabilities")
    if not isinstance(worker.get("controller_scope"), str) or not isinstance(worker.get("price_test_credits"), int) or worker["price_test_credits"] < 0 or worker.get("status") not in {"available", "unavailable"}:
        raise ProductionLoopError("invalid worker advertisement schema: values")
    return worker


def _validate_board(board: dict) -> None:
    _validate_exact_keys(board, BOARD_KEYS, "board")
    if board.get("schema_version") != BOARD_SCHEMA:
        raise ProductionLoopError("unsupported JSON board schema")
    if not isinstance(board.get("tasks"), list) or not isinstance(board.get("workers"), list):
        raise ProductionLoopError("invalid board schema: tasks and workers arrays are required")
    for task in board["tasks"]:
        _validate_frozen_task(task)
    for worker in board["workers"]:
        _validate_worker_advertisement(worker)


def _authoritative_task(board_path: Path, accepted_task: dict) -> dict:
    board = _read_json(Path(board_path).resolve())
    _validate_board(board)
    matches = [task for task in board["tasks"] if task.get("task_hash") == accepted_task.get("task_hash")]
    if len(matches) != 1 or matches[0] != accepted_task:
        raise ProductionLoopError("authoritative board task changed")
    return board


def _matching_board_worker(board: dict, frozen: dict, worker_id: Any, coordinate: Any) -> dict:
    workers = board.get("workers") if isinstance(board, dict) else None
    if not isinstance(workers, list):
        raise ProductionLoopError("worker provenance does not match an available compatible board worker")
    matches = [
        worker for worker in workers
        if isinstance(worker, dict)
        and worker.get("worker_id") == worker_id
        and worker.get("cell_coordinate") == coordinate
        and worker.get("status") == "available"
        and frozen.get("required_capability") in worker.get("capabilities", [])
        and worker.get("price_test_credits") == frozen.get("reward_test_credits")
    ]
    if len(matches) != 1:
        raise ProductionLoopError("worker provenance does not match an available compatible board worker")
    return matches[0]


def publish_frozen_task(*, board_path: Path, frozen_task: dict, workers: list[dict]) -> dict:
    task = {"schema_version": TASK_SCHEMA, "frozen_task": frozen_task, "task_hash": canonical_sha256(frozen_task), "status": "open"}
    board = {"schema_version": BOARD_SCHEMA, "tasks": [task], "workers": workers}
    _validate_board(board)
    _write_json(board_path, board)
    return task


def _discover_task_and_worker(board: dict, worker_id: str) -> tuple[dict, dict]:
    _validate_board(board)
    workers = [w for w in board["workers"] if isinstance(w, dict) and w.get("worker_id") == worker_id and w.get("status") == "available"]
    if not workers:
        raise ProductionLoopError("requested worker is not available on JSON board")
    worker = workers[0]
    _validate_agent(worker.get("worker_id"), worker.get("cell_coordinate"), "worker")
    compatible = [t for t in board["tasks"] if t.get("status") == "open" and t["frozen_task"]["required_capability"] in worker.get("capabilities", [])]
    if not compatible:
        raise ProductionLoopError("no open compatible task discovered on JSON board")
    compatible.sort(key=lambda item: item["task_hash"])
    return compatible[0], worker


def _reject_source_symlinks(source: Path) -> None:
    if source.is_symlink() or not source.is_dir():
        raise ProductionLoopError("source package directory is missing or unsafe")
    for path in source.rglob("*"):
        if path.is_symlink():
            raise ProductionLoopError("source package cannot contain symlinks")


def _package_manifest(package_dir: Path) -> dict:
    package_dir = Path(package_dir).resolve()
    if not package_dir.is_dir():
        raise ProductionLoopError("worker package directory is missing")
    files = {}
    for path in sorted(package_dir.rglob("*")):
        if path.is_symlink():
            raise ProductionLoopError("worker package cannot contain symlinks")
        if path.is_file():
            try:
                relative = path.resolve().relative_to(package_dir).as_posix()
            except ValueError as exc:
                raise ProductionLoopError("worker package file escapes package") from exc
            files[relative] = _file_sha256(path)
    if not files:
        raise ProductionLoopError("worker package is empty")
    return {"files": files}


def _normalized_resource_path(value: str) -> bool:
    pure = PurePosixPath(value)
    return bool(value) and value != "." and not pure.is_absolute() and value == pure.as_posix() and all(part not in ("", ".", "..") for part in pure.parts)


def _verify_organa_manifest_resources(package_dir: Path) -> dict:
    package_dir = Path(package_dir).resolve()
    manifest = _read_json(package_dir / "organa-cell.json")
    missing = MANIFEST_REQUIRED_KEYS - set(manifest)
    unknown = set(manifest) - MANIFEST_ALLOWED_KEYS
    if missing:
        raise ProductionLoopError("resource integrity failed: missing manifest fields: " + ", ".join(sorted(missing)))
    if unknown:
        raise ProductionLoopError("resource integrity failed: unknown manifest fields: " + ", ".join(sorted(unknown)))
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        raise ProductionLoopError("resource integrity failed: unsupported manifest schema version")
    if manifest.get("cell_type") != "organa-cell":
        raise ProductionLoopError("resource integrity failed: invalid manifest cell type")
    if not isinstance(manifest.get("version"), str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", manifest["version"]):
        raise ProductionLoopError("resource integrity failed: invalid manifest version")
    if not isinstance(manifest.get("created_at_utc"), str) or not manifest["created_at_utc"]:
        raise ProductionLoopError("resource integrity failed: invalid manifest creation time")
    if manifest.get("lifecycle_status") not in {"live", "simulation", "pending", "deprecated"}:
        raise ProductionLoopError("resource integrity failed: invalid manifest lifecycle status")
    if not isinstance(manifest.get("controller"), dict) or not isinstance(manifest.get("public_base_url"), str):
        raise ProductionLoopError("resource integrity failed: invalid manifest controller or public URL")
    if not isinstance(manifest.get("agents"), list) or not manifest["agents"] or not isinstance(manifest.get("services"), list) or not manifest["services"]:
        raise ProductionLoopError("resource integrity failed: non-empty agents and services arrays required")
    if not isinstance(manifest.get("coordinate"), str) or not BITMAP_RE.fullmatch(manifest["coordinate"]):
        raise ProductionLoopError("resource integrity failed: invalid manifest coordinate")
    resources = manifest.get("resources")
    if not isinstance(resources, list) or not resources:
        raise ProductionLoopError("resource integrity failed: non-empty manifest resources array required")
    errors, seen = [], set()
    for item in resources:
        if not isinstance(item, dict):
            errors.append("malformed resource entry")
            continue
        missing_resource = RESOURCE_REQUIRED_KEYS - set(item)
        unknown_resource = set(item) - RESOURCE_ALLOWED_KEYS
        if missing_resource:
            errors.append("missing resource fields: " + ", ".join(sorted(missing_resource)))
            continue
        if unknown_resource:
            errors.append("unknown manifest resource fields: " + ", ".join(sorted(unknown_resource)))
            continue
        if not isinstance(item.get("path"), str) or not isinstance(item.get("sha256"), str):
            errors.append("malformed resource entry")
            continue
        relative, digest = item["path"], item["sha256"]
        if not _normalized_resource_path(relative):
            errors.append("resource path must be normalized: " + relative)
            continue
        if not SHA256_RE.fullmatch(digest):
            errors.append("resource sha256 must use lowercase sha256:<64 hex>: " + relative)
            continue
        if relative in seen:
            errors.append("duplicate resource: " + relative)
            continue
        seen.add(relative)
        path = package_dir / relative
        if path.is_symlink():
            errors.append("unsafe symlink resource: " + relative)
            continue
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(package_dir)
        except (OSError, ValueError):
            errors.append("missing or unsafe resource: " + relative)
            continue
        if not resolved.is_file():
            errors.append("missing resource: " + relative)
        elif "sha256:" + _file_sha256(resolved) != digest:
            errors.append("resource hash mismatch: " + relative)
    if errors:
        raise ProductionLoopError("resource integrity failed: " + "; ".join(errors))
    return {"integrity_valid": True, "manifest_coordinate": manifest["coordinate"], "resources_checked": len(resources)}


def _execute_task(package_dir: Path, frozen_task: dict) -> dict:
    if frozen_task.get("operation") == "add":
        output = _read_json(package_dir / "output.json")
        expected = frozen_task["input"]["left"] + frozen_task["input"]["right"]
        return {"integrity_valid": output.get("answer") == expected, "answer": output.get("answer"), "expected": expected}
    if frozen_task.get("operation") == "verify-organa-manifest-resources":
        return _verify_organa_manifest_resources(package_dir)
    raise ProductionLoopError("unsupported frozen task operation")


def worker_execute_from_board(*, root: Path, board_path: Path, worker_id: str, verifier_id: str, verifier_coordinate: str, source_package: Path) -> dict:
    root = Path(root).resolve()
    board_path = Path(board_path).resolve()
    board = _read_json(board_path)
    task, worker = _discover_task_and_worker(board, worker_id)
    frozen = _validate_frozen_task(task)
    requester = _validate_agent(frozen.get("requester_id"), frozen.get("requester_coordinate"), "requester")
    worker_role = _validate_agent(worker.get("worker_id"), worker.get("cell_coordinate"), "worker")
    verifier = _validate_agent(verifier_id, verifier_coordinate, "verifier")
    _validate_distinct_roles([requester, worker_role, verifier])
    if worker.get("price_test_credits") != frozen.get("reward_test_credits"):
        raise ProductionLoopError("worker price does not match frozen task reward")

    exchange = root / "exchanges" / task["task_hash"].removeprefix("sha256:")[:16]
    package_dir = exchange / "worker-package"
    _reject_source_symlinks(Path(source_package))
    if package_dir.exists():
        shutil.rmtree(package_dir)
    exchange.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source_package, package_dir)
    report = _execute_task(package_dir, frozen)
    acceptance = {
        "schema_version": "organa-local-task-acceptance-v0.2",
        "task_hash": task["task_hash"],
        "frozen_task": frozen,
        "discovered_from_board_hash": canonical_sha256(board),
        "requester_id": requester[0], "requester_coordinate": requester[1],
        "worker_id": worker_role[0], "worker_coordinate": worker_role[1],
        "verifier_id": verifier[0], "verifier_coordinate": verifier[1],
        "status": "accepted",
    }
    _write_json(exchange / "acceptance.json", acceptance)
    result = {
        "schema_version": "organa-local-worker-result-v0.2",
        "task_hash": task["task_hash"], "frozen_task": frozen,
        "acceptance_hash": canonical_sha256(acceptance),
        "worker_id": worker_role[0], "worker_coordinate": worker_role[1],
        "verifier_id": verifier[0], "verifier_coordinate": verifier[1],
        "package_path": "worker-package", "package_sha256": canonical_sha256(_package_manifest(package_dir)),
        "claimed_status": "completed", "report": report,
    }
    _write_json(exchange / "worker-result.json", result)
    return {"ok": True, "acceptance_path": str(exchange / "acceptance.json"), "worker_result_path": str(exchange / "worker-result.json"), "package_dir": str(package_dir)}


def _trusted_verifier_descriptor() -> dict:
    from . import trusted_verifier
    expected = Path(__file__).with_name("trusted_verifier.py").absolute()
    declared = Path(trusted_verifier.__file__).absolute()
    if declared != expected or expected.is_symlink():
        raise ProductionLoopError("trusted verifier path mismatch or unsafe replacement")
    try:
        path = expected.resolve(strict=True)
    except OSError as exc:
        raise ProductionLoopError("trusted verifier installed file is missing") from exc
    if path != expected.resolve() or not path.is_file() or path.is_symlink():
        raise ProductionLoopError("trusted verifier installed file is not a safe regular file")
    return {"id": trusted_verifier.VERIFIER_ID, "version": trusted_verifier.VERIFIER_VERSION, "sha256": "sha256:" + _file_sha256(path), "module_path": "organa_cell_kit/trusted_verifier.py"}


_TRUSTED_VERIFIER_PATH = Path(__file__).with_name("trusted_verifier.py").absolute()
TRUSTED_VERIFIER = {"id": "organa-cell-kit.trusted-package-verifier", "version": "1.0.0", "sha256": "sha256:" + _file_sha256(_TRUSTED_VERIFIER_PATH), "module_path": "organa_cell_kit/trusted_verifier.py"}


def _run_trusted_verifier(package_dir: Path, task: dict) -> tuple[dict, dict]:
    descriptor_before = _trusted_verifier_descriptor()
    if descriptor_before != task.get("trusted_verifier") or descriptor_before != TRUSTED_VERIFIER:
        raise ProductionLoopError("trusted verifier runtime descriptor does not match frozen task")
    verifier_path = Path(__file__).with_name("trusted_verifier.py").resolve(strict=True)
    env = dict(os.environ)
    package_root = str(Path(__file__).resolve().parents[1])
    env["PYTHONPATH"] = package_root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    proc = subprocess.run([sys.executable, str(verifier_path), str(package_dir), json.dumps(task, sort_keys=True, allow_nan=False)], text=True, capture_output=True, timeout=20, env=env)
    descriptor_after = _trusted_verifier_descriptor()
    if descriptor_after != descriptor_before or descriptor_after != task.get("trusted_verifier"):
        raise ProductionLoopError("trusted verifier changed during execution")
    try:
        result = _strict_json_loads(proc.stdout or "{}")
    except (json.JSONDecodeError, ValueError) as exc:
        raise ProductionLoopError("separate process verifier returned malformed JSON") from exc
    if proc.returncode != 0 or not isinstance(result, dict) or result.get("ok") is not True:
        detail = result.get("error") if isinstance(result, dict) else proc.stderr
        raise ProductionLoopError("separate process verifier rerun failed: " + str(detail or proc.stderr or "verification failed"))
    return result, descriptor_after


def validate_reputation_chain(path: Path) -> dict:
    try:
        raw_lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ProductionLoopError("missing reputation history") from exc
    events, previous = [], None
    for index, line in enumerate(raw_lines):
        if not line.strip():
            continue
        try:
            event = _strict_json_loads(line)
        except (json.JSONDecodeError, ValueError) as exc:
            raise ProductionLoopError(f"corrupted reputation history at event {index + 1}") from exc
        if not isinstance(event, dict):
            raise ProductionLoopError(f"corrupted reputation history at event {index + 1}")
        try:
            _validate_exact_keys(event, REPUTATION_EVENT_KEYS, "reputation event")
        except ProductionLoopError as exc:
            raise ProductionLoopError(f"corrupted reputation history at event {index + 1}: {exc}") from exc
        claimed = event.get("event_hash")
        body = {key: value for key, value in event.items() if key != "event_hash"}
        if event.get("previous_event_hash") != previous or claimed != canonical_sha256(body):
            raise ProductionLoopError(f"corrupted reputation history at event {index + 1}")
        previous, events = claimed, events + [event]
    return {"event_count": len(events), "chain_head": previous, "events": events}


def append_reputation_event(path: Path, event: dict) -> dict:
    if Path(path).exists():
        chain = validate_reputation_chain(path)
        previous = chain["chain_head"]
    else:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        previous = None
    payload = {**event, "previous_event_hash": previous}
    payload["event_hash"] = canonical_sha256(payload)
    with Path(path).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n")
    return payload


def _validate_string(value: Any, label: str) -> None:
    if not isinstance(value, str) or not value:
        raise ProductionLoopError(f"invalid {label} schema: string required")


def _validate_hash(value: Any, label: str) -> None:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ProductionLoopError(f"invalid {label} schema: sha256 required")


def _validate_execution_report(value: Any, frozen: dict, label: str, *, verifier: bool) -> dict:
    operation = frozen.get("operation")
    if operation == "add":
        keys = {"ok", "check", "answer"} if verifier else {"integrity_valid", "answer", "expected"}
    elif operation == "verify-organa-manifest-resources":
        keys = {"ok", "check", "integrity_valid", "manifest_coordinate", "resources_checked"} if verifier else {"integrity_valid", "manifest_coordinate", "resources_checked"}
    else:
        raise ProductionLoopError(f"invalid {label} schema: unsupported operation")
    value = _validate_exact_keys(value, keys, label)
    for key, item in value.items():
        if key in {"ok", "integrity_valid"} and not isinstance(item, bool): raise ProductionLoopError(f"invalid {label} schema: boolean required")
        if key in {"answer", "expected", "resources_checked"} and not isinstance(item, int): raise ProductionLoopError(f"invalid {label} schema: integer required")
        if key in {"check", "manifest_coordinate"} and not isinstance(item, str): raise ProductionLoopError(f"invalid {label} schema: string required")
    return value


def _validate_acceptance(value: Any) -> dict:
    value = _validate_exact_keys(value, ACCEPTANCE_KEYS, "acceptance")
    if value.get("schema_version") != ACCEPTANCE_SCHEMA:
        raise ProductionLoopError("invalid acceptance schema")
    for name in ("task_hash", "discovered_from_board_hash"): _validate_hash(value.get(name), "acceptance")
    if not isinstance(value.get("frozen_task"), dict): raise ProductionLoopError("invalid acceptance schema: frozen task")
    for prefix in ("requester", "worker", "verifier"): _validate_agent(value.get(prefix + "_id"), value.get(prefix + "_coordinate"), prefix)
    _validate_string(value.get("status"), "acceptance")
    return value


def _validate_worker_result(value: Any) -> dict:
    value = _validate_exact_keys(value, WORKER_RESULT_KEYS, "worker result")
    if value.get("schema_version") != WORKER_RESULT_SCHEMA: raise ProductionLoopError("invalid worker result schema")
    for name in ("task_hash", "acceptance_hash", "package_sha256"): _validate_hash(value.get(name), "worker result")
    frozen = value.get("frozen_task")
    if not isinstance(frozen, dict): raise ProductionLoopError("invalid worker result schema: object field")
    _validate_execution_report(value.get("report"), frozen, "worker report", verifier=False)
    for prefix in ("worker", "verifier"): _validate_agent(value.get(prefix + "_id"), value.get(prefix + "_coordinate"), prefix)
    _validate_string(value.get("package_path"), "worker result"); _validate_string(value.get("claimed_status"), "worker result")
    return value


def _validate_verification(value: Any) -> dict:
    value = _validate_exact_keys(value, VERIFICATION_KEYS, "verification")
    if value.get("schema_version") != VERIFICATION_SCHEMA: raise ProductionLoopError("invalid verification schema")
    _validate_hash(value.get("task_hash"), "verification"); _validate_hash(value.get("package_hash"), "verification")
    _validate_string(value.get("verifier_id"), "verification"); _validate_trusted_verifier(value.get("trusted_verifier"))
    if not isinstance(value.get("separate_process_verifier_rerun"), bool): raise ProductionLoopError("invalid verification schema: values")
    return value


def _validate_ledger(value: Any, label: str) -> dict:
    value = _validate_exact_keys(value, LEDGER_KEYS, label)
    if value.get("schema_version") != LEDGER_SCHEMA or not isinstance(value.get("unit"), str) or not isinstance(value.get("real_payment"), bool) or not isinstance(value.get("balances"), dict) or not all(isinstance(key, str) and isinstance(amount, int) for key, amount in value["balances"].items()) or not isinstance(value.get("settled_task_hashes"), list) or not all(isinstance(item, str) and SHA256_RE.fullmatch(item) for item in value["settled_task_hashes"]):
        raise ProductionLoopError(f"invalid {label} schema: values")
    return value


def _validate_settlement(value: Any) -> dict:
    value = _validate_exact_keys(value, SETTLEMENT_KEYS, "settlement")
    for name in ("task_hash", "prestate_hash", "poststate_hash"): _validate_hash(value.get(name), "settlement")
    for name in ("amount", "budget_before", "budget_after"):
        if not isinstance(value.get(name), int): raise ProductionLoopError("invalid settlement schema: integer required")
    for name in ("status", "unit", "payer", "payee"): _validate_string(value.get(name), "settlement")
    if not isinstance(value.get("real_payment"), bool): raise ProductionLoopError("invalid settlement schema: boolean required")
    return value


def _validate_roles(value: Any) -> dict:
    value = _validate_exact_keys(value, ROLES_KEYS, "roles")
    for label in ROLES_KEYS:
        role = _validate_exact_keys(value[label], ROLE_KEYS, f"{label} role")
        _validate_agent(role.get("agent_id"), role.get("cell_coordinate"), label)
    return value


def _validate_project_binding(value: Any) -> dict:
    value = _validate_exact_keys(value, PROJECT_BINDING_KEYS, "project binding")
    absolute_root = value.get("absolute_root")
    if not isinstance(absolute_root, str) or not absolute_root or not Path(absolute_root).is_absolute():
        raise ProductionLoopError("invalid project binding schema: absolute root required")
    if os.path.normpath(absolute_root) != absolute_root:
        raise ProductionLoopError("invalid project binding schema: normalized absolute root required")
    if value.get("board_relative_path") != "board.json":
        raise ProductionLoopError("invalid project binding schema: board_relative_path must be board.json")
    return value


def _authoritative_project_receipt(receipt_path: Path, project_root: Path) -> Path:
    supplied = Path(receipt_path)
    if supplied.name != "receipt.json" or supplied.is_symlink() or not supplied.is_file():
        raise ProductionLoopError("authoritative project receipt must be a safe regular PROJECT/runs/<run>/receipt.json")
    runs = project_root / "runs"
    run_path = supplied.parent
    if run_path.name.startswith(".") or run_path.parent.resolve(strict=True) != runs.resolve(strict=True) or run_path.is_symlink():
        raise ProductionLoopError("authoritative project receipt must be a safe regular PROJECT/runs/<non-hidden-run>/receipt.json")
    resolved = supplied.resolve(strict=True)
    if resolved.parent != run_path.resolve(strict=True):
        raise ProductionLoopError("authoritative project receipt path cannot use a symlinked receipt")
    try:
        resolved.relative_to(runs.resolve(strict=True))
    except ValueError as exc:
        raise ProductionLoopError("authoritative project receipt must remain under PROJECT/runs") from exc
    return resolved


def _validate_current_pointer(project_root: Path, receipt_path: Path, task_hash: Any) -> None:
    current_path = project_root / "current.json"
    if current_path.is_symlink() or not current_path.is_file():
        raise ProductionLoopError("authoritative current.json must be a safe regular file")
    resolved_current = current_path.resolve(strict=True)
    if resolved_current != current_path or resolved_current.parent != project_root:
        raise ProductionLoopError("authoritative current.json must resolve exactly to PROJECT/current.json")
    current = _validate_exact_keys(_read_json(current_path), CURRENT_POINTER_KEYS, "current.json pointer")
    pointer_task_hash = current.get("task_hash")
    _validate_hash(pointer_task_hash, "current pointer task")
    relative = current.get("receipt_path")
    if not isinstance(relative, str) or not _normalized_resource_path(relative):
        raise ProductionLoopError("current.json receipt_path must be normalized and relative")
    pure = PurePosixPath(relative)
    if len(pure.parts) != 3 or pure.parts[0] != "runs" or pure.parts[1].startswith(".") or pure.parts[2] != "receipt.json":
        raise ProductionLoopError("current.json receipt_path must be runs/<non-hidden-run>/receipt.json")
    pointer_path = project_root.joinpath(*pure.parts)
    if pointer_path.is_symlink() or pointer_path.parent.is_symlink():
        raise ProductionLoopError("current.json receipt_path cannot use symlinks")
    try:
        resolved_pointer = pointer_path.resolve(strict=True)
        resolved_pointer.relative_to((project_root / "runs").resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise ProductionLoopError("current.json receipt_path must remain under PROJECT/runs") from exc
    if resolved_pointer != receipt_path:
        raise ProductionLoopError("supplied receipt is not the current project receipt")
    if pointer_task_hash != task_hash:
        raise ProductionLoopError("current.json task_hash does not match receipt closure task_hash")


def _validate_receipt_schema(value: Any) -> dict:
    value = _validate_exact_keys(value, RECEIPT_KEYS, "receipt")
    if value.get("schema_version") != RECEIPT_SCHEMA: raise ProductionLoopError("invalid receipt schema")
    for name in ("simulation_scope", "payment_scope", "settlement_mode"): _validate_string(value.get(name), "receipt")
    if value.get("separate_process_verifier_rerun") is not True: raise ProductionLoopError("invalid receipt schema: verifier rerun must be true")
    _validate_trusted_verifier(value.get("trusted_verifier")); _validate_roles(value.get("roles")); _validate_settlement(value.get("settlement")); _validate_project_binding(value.get("project_binding"))
    reputation = _validate_exact_keys(value.get("reputation"), REPUTATION_ENVELOPE_KEYS, "reputation envelope")
    if not isinstance(reputation.get("event_count"), int) or not isinstance(reputation.get("chain_head"), str): raise ProductionLoopError("invalid reputation envelope schema: values")
    closure = _validate_exact_keys(value.get("hash_closure"), HASH_CLOSURE_KEYS, "hash closure")
    for item in closure.values(): _validate_hash(item, "hash closure")
    claims = _validate_exact_keys(value.get("claims_scope"), set(CLAIMS_SCOPE), "claims scope")
    if not all(isinstance(item, bool) for item in claims.values()): raise ProductionLoopError("invalid claims scope schema: booleans required")
    _validate_hash(value.get("receipt_sha256"), "receipt")
    return value


def _safe_linked(root: Path, name: str) -> Path | None:
    path = root / name
    if path.is_symlink() or not path.is_file():
        return None
    try:
        path.resolve(strict=True).relative_to(root.resolve())
    except (OSError, ValueError):
        return None
    return path


def _semantic_receipt_errors(root: Path, receipt: dict, artifacts: dict[str, dict], package_hash: str | None, chain: dict | None) -> list[str]:
    errors: list[str] = []
    board = artifacts.get("board.json", {})
    task = artifacts.get("task.json", {})
    acceptance = artifacts.get("acceptance.json", {})
    worker = artifacts.get("worker-result.json", {})
    verification = artifacts.get("verification.json", {})
    initial = artifacts.get("credit-ledger-initial.json", {})
    final = artifacts.get("credit-ledger.json", {})
    settlement = artifacts.get("settlement.json", {})
    closure = receipt.get("hash_closure", {})
    roles = receipt.get("roles", {})

    if receipt.get("schema_version") != RECEIPT_SCHEMA:
        errors.append("invalid receipt schema")
    for label, value, validator in [
        ("board", board, _validate_board), ("acceptance", acceptance, _validate_acceptance),
        ("worker result", worker, _validate_worker_result), ("verification", verification, _validate_verification),
        ("initial ledger", initial, lambda item: _validate_ledger(item, "initial ledger")),
        ("final ledger", final, lambda item: _validate_ledger(item, "final ledger")),
        ("settlement", settlement, _validate_settlement),
    ]:
        try:
            validator(value)
        except ProductionLoopError as exc:
            errors.append(str(exc))
    try:
        frozen = _validate_frozen_task(task)
        _validate_execution_report(verification.get("result"), frozen, "verifier result", verifier=True)
    except ProductionLoopError:
        frozen = {}
        errors.append("invalid linked task")
    if board.get("schema_version") != BOARD_SCHEMA or task not in board.get("tasks", []):
        errors.append("board task binding mismatch")
    if acceptance.get("schema_version") != ACCEPTANCE_SCHEMA or acceptance.get("status") != "accepted":
        errors.append("invalid acceptance state")
    if worker.get("schema_version") != WORKER_RESULT_SCHEMA or worker.get("claimed_status") != "completed":
        errors.append("invalid worker result state")
    if verification.get("schema_version") != VERIFICATION_SCHEMA or verification.get("result", {}).get("ok") is not True or verification.get("separate_process_verifier_rerun") is not True:
        errors.append("verification did not succeed")
    if initial.get("schema_version") != LEDGER_SCHEMA or final.get("schema_version") != LEDGER_SCHEMA:
        errors.append("invalid ledger schema")

    task_hash = task.get("task_hash")
    expected_roles = {
        "requester": {"agent_id": acceptance.get("requester_id"), "cell_coordinate": acceptance.get("requester_coordinate")},
        "worker": {"agent_id": acceptance.get("worker_id"), "cell_coordinate": acceptance.get("worker_coordinate")},
        "verifier": {"agent_id": acceptance.get("verifier_id"), "cell_coordinate": acceptance.get("verifier_coordinate")},
    }
    if roles != expected_roles:
        errors.append("receipt role binding mismatch")
    for role_source in (expected_roles, roles):
        try:
            _validate_distinct_roles([
                _validate_agent(role_source.get(label, {}).get("agent_id"), role_source.get(label, {}).get("cell_coordinate"), label)
                for label in ("requester", "worker", "verifier")
            ])
        except ProductionLoopError as exc:
            errors.append(str(exc))
    if (acceptance.get("requester_id"), acceptance.get("requester_coordinate")) != (frozen.get("requester_id"), frozen.get("requester_coordinate")):
        errors.append("requester task binding mismatch")
    if acceptance.get("task_hash") != task_hash or acceptance.get("frozen_task") != frozen:
        errors.append("acceptance task binding mismatch")
    if acceptance.get("discovered_from_board_hash") != canonical_sha256(board):
        errors.append("acceptance board binding mismatch")
    try:
        _matching_board_worker(board, frozen, acceptance.get("worker_id"), acceptance.get("worker_coordinate"))
    except ProductionLoopError as exc:
        errors.append(str(exc))
    if worker.get("task_hash") != task_hash or worker.get("frozen_task") != frozen or worker.get("acceptance_hash") != canonical_sha256(acceptance):
        errors.append("worker task binding mismatch")
    if (worker.get("worker_id"), worker.get("worker_coordinate"), worker.get("verifier_id"), worker.get("verifier_coordinate")) != (
        acceptance.get("worker_id"), acceptance.get("worker_coordinate"), acceptance.get("verifier_id"), acceptance.get("verifier_coordinate")
    ):
        errors.append("worker role binding mismatch")
    if worker.get("package_path") != "worker-package" or worker.get("package_sha256") != package_hash or closure.get("package_hash") != package_hash:
        errors.append("worker package binding mismatch")

    trusted = frozen.get("trusted_verifier")
    if trusted != TRUSTED_VERIFIER or verification.get("trusted_verifier") != trusted or receipt.get("trusted_verifier") != trusted:
        errors.append("trusted verifier semantic binding mismatch")
    if verification.get("task_hash") != task_hash or verification.get("package_hash") != package_hash or verification.get("verifier_id") != acceptance.get("verifier_id"):
        errors.append("verification artifact binding mismatch")
    if receipt.get("separate_process_verifier_rerun") is not True or verification.get("separate_process_verifier_rerun") is not True or receipt.get("separate_process_verifier_rerun") != verification.get("separate_process_verifier_rerun"):
        errors.append("verifier rerun truthfulness mismatch")

    reward = frozen.get("reward_test_credits")
    requester_id = acceptance.get("requester_id")
    worker_id = acceptance.get("worker_id")
    budget_before = settlement.get("budget_before")
    expected_budget_after = budget_before - reward if isinstance(budget_before, int) and isinstance(reward, int) else None
    required_settlement = {
        "task_hash": task_hash, "amount": reward, "budget_before": budget_before,
        "budget_after": expected_budget_after,
        "status": "settled-locally", "unit": "ORGANA_TEST_CREDIT", "real_payment": False,
        "payer": requester_id, "payee": worker_id, "prestate_hash": canonical_sha256(initial), "poststate_hash": canonical_sha256(final),
    }
    if settlement != required_settlement or receipt.get("settlement") != settlement:
        errors.append("settlement semantics mismatch")
    if initial.get("unit") != "ORGANA_TEST_CREDIT" or final.get("unit") != "ORGANA_TEST_CREDIT" or initial.get("real_payment") is not False or final.get("real_payment") is not False:
        errors.append("ledger unit or payment semantics mismatch")
    initial_balances, final_balances = initial.get("balances"), final.get("balances")
    if not isinstance(initial_balances, dict) or not isinstance(final_balances, dict) or set(initial_balances) != set(final_balances):
        errors.append("ledger account set mismatch")
    elif isinstance(reward, int):
        expected_balances = dict(initial_balances)
        if not isinstance(expected_balances.get(requester_id), int) or not isinstance(expected_balances.get(worker_id), int):
            errors.append("ledger role balances missing")
        else:
            expected_balances[requester_id] -= reward
            expected_balances[worker_id] += reward
            if final_balances != expected_balances or sum(initial_balances.values()) != sum(final_balances.values()):
                errors.append("ledger balance delta or conservation mismatch")
    initial_settled, final_settled = initial.get("settled_task_hashes"), final.get("settled_task_hashes")
    if not isinstance(initial_settled, list) or not isinstance(final_settled, list) or task_hash in initial_settled or final_settled != initial_settled + [task_hash] or final_settled.count(task_hash) != 1:
        errors.append("settled task movement mismatch")

    if chain is not None:
        expected_events = [
            ("worker-accepted", expected_roles["worker"]),
            ("worker-completed", expected_roles["worker"]),
            ("verifier-verified", expected_roles["verifier"]),
            ("requester-paid-local-test-credit", expected_roles["requester"]),
        ]
        actual = chain.get("events", [])
        if len(actual) != len(expected_events):
            errors.append("reputation event semantics mismatch")
        else:
            for event, (event_type, role) in zip(actual, expected_events):
                if event.get("event") != event_type or event.get("agent_id") != role["agent_id"] or event.get("cell_coordinate") != role["cell_coordinate"] or event.get("task_hash") != task_hash or event.get("package_hash") != package_hash:
                    errors.append("reputation event semantics mismatch")
                    break
    return errors


def verify_receipt(receipt_path: Path, *, project_root: Path | None = None, authoritative_board_path: Path | None = None, allow_relocated_project_root: bool = False) -> dict:
    if project_root is not None and authoritative_board_path is not None:
        raise ProductionLoopError("provide project_root or authoritative_board_path, not both")
    errors: list[str] = []
    resolved_project_root = None
    if project_root is not None:
        try:
            resolved_project_root = Path(project_root).resolve(strict=True)
            if not resolved_project_root.is_dir():
                raise ProductionLoopError("authoritative project root must be a directory")
            receipt_path = _authoritative_project_receipt(Path(receipt_path), resolved_project_root)
        except (OSError, ProductionLoopError) as exc:
            errors.append(str(exc) if isinstance(exc, ProductionLoopError) else "authoritative project receipt is missing or invalid")
            receipt_path = Path(receipt_path).resolve()
    else:
        receipt_path = Path(receipt_path).resolve()
    receipt = _read_json(receipt_path)
    root, artifacts = receipt_path.parent, {}
    try:
        _validate_receipt_schema(receipt)
    except ProductionLoopError as exc:
        errors.append(str(exc))
    claimed = receipt.get("receipt_sha256")
    body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if claimed != canonical_sha256(body): errors.append("receipt hash mismatch")
    closure = receipt.get("hash_closure", {})
    checks = {
        "board_hash": "board.json", "acceptance_hash": "acceptance.json", "worker_result_hash": "worker-result.json",
        "verifier_result_hash": "verification.json", "settlement_hash": "settlement.json", "credit_ledger_hash": "credit-ledger.json",
        "initial_credit_ledger_hash": "credit-ledger-initial.json",
    }
    for key, name in checks.items():
        path = _safe_linked(root, name)
        if path is None:
            errors.append("unsafe linked artifact: " + name)
        else:
            artifacts[name] = _read_json(path)
            if closure.get(key) != canonical_sha256(artifacts[name]):
                errors.append(key.removesuffix("_hash").replace("_", " ") + " hash mismatch")
    task_path = _safe_linked(root, "task.json")
    if task_path is None:
        errors.append("unsafe linked artifact: task.json")
    else:
        try:
            task = _read_json(task_path); artifacts["task.json"] = task; _validate_frozen_task(task)
            if closure.get("task_hash") != task.get("task_hash"): errors.append("task hash mismatch")
        except ProductionLoopError:
            errors.append("task hash mismatch")
    package_hash = None
    result = artifacts.get("worker-result.json")
    if result:
        package = root / str(result.get("package_path", ""))
        try:
            if package.is_symlink(): raise ProductionLoopError("unsafe")
            package.resolve(strict=True).relative_to(root.resolve())
            package_hash = canonical_sha256(_package_manifest(package))
        except (OSError, ValueError, ProductionLoopError): package_hash = None
        if closure.get("package_hash") != package_hash: errors.append("package hash mismatch")
    reputation = _safe_linked(root, "reputation-events.jsonl")
    chain = None
    if reputation is None:
        errors.append("unsafe linked artifact: reputation-events.jsonl")
    else:
        try:
            chain = validate_reputation_chain(reputation)
            if receipt.get("reputation", {}).get("event_count") != chain["event_count"]: errors.append("reputation event count mismatch")
            if receipt.get("reputation", {}).get("chain_head") != chain["chain_head"]: errors.append("reputation chain head mismatch")
            if closure.get("reputation_event_hash") != chain["chain_head"]: errors.append("reputation event hash mismatch")
        except ProductionLoopError as exc:
            errors.append(str(exc))
    errors.extend(_semantic_receipt_errors(root, receipt, artifacts, package_hash, chain))
    if receipt.get("simulation_scope") != SIMULATION_SCOPE: errors.append("simulation scope disclosure missing")
    if receipt.get("payment_scope") != PAYMENT_SCOPE: errors.append("payment scope disclosure missing")
    if receipt.get("settlement_mode") != "local-test-credit": errors.append("local test-credit settlement mode missing")
    if receipt.get("claims_scope") != CLAIMS_SCOPE: errors.append("truthful claims scope exclusions missing")
    if receipt.get("settlement", {}).get("real_payment") is not False: errors.append("no-real-payment disclosure missing")
    authoritative_checked = project_root is not None or authoritative_board_path is not None
    if authoritative_checked:
        try:
            binding = _validate_project_binding(receipt.get("project_binding"))
            if project_root is not None:
                resolved_root = resolved_project_root
                if resolved_root is None:
                    raise ProductionLoopError("authoritative project root is missing or invalid")
                _validate_current_pointer(resolved_root, receipt_path, closure.get("task_hash"))
                board_candidate = resolved_root / "board.json"
            else:
                supplied_board = Path(authoritative_board_path or "")
                if supplied_board.name != "board.json":
                    raise ProductionLoopError("authoritative board path must be PROJECT/board.json")
                resolved_root = supplied_board.parent.resolve(strict=True)
                board_candidate = resolved_root / "board.json"
            if not resolved_root.is_dir() or (not allow_relocated_project_root and str(resolved_root) != binding["absolute_root"]):
                errors.append("authoritative project root does not match frozen receipt project root")
            if board_candidate.is_symlink():
                raise ProductionLoopError("authoritative board path is an unsafe symlink")
            board_path = board_candidate.resolve(strict=True)
            if board_path != board_candidate or board_path.parent != resolved_root:
                raise ProductionLoopError("authoritative board path must resolve exactly to PROJECT/board.json")
            authoritative = _read_json(board_path)
            try:
                _validate_board(authoritative)
            except ProductionLoopError as exc:
                raise ProductionLoopError("authoritative board is missing or invalid") from exc
            snapshot = artifacts.get("board.json")
            task = artifacts.get("task.json", {})
            matching = [item for item in authoritative.get("tasks", []) if item.get("task_hash") == task.get("task_hash")]
            if authoritative != snapshot or canonical_sha256(authoritative) != closure.get("board_hash") or matching != [task]:
                errors.append("authoritative board does not exactly match immutable receipt board snapshot and task")
        except ProductionLoopError as exc:
            errors.append(str(exc))
        except OSError:
            errors.append("authoritative board is missing or invalid")
    return {"ok": not errors, "errors": errors, "authoritative_board_checked": authoritative_checked}


def _copy_artifact(source: Path, destination: Path) -> None:
    source = source.resolve(strict=True)
    if source.is_symlink() or not source.is_file(): raise ProductionLoopError("unsafe persisted artifact")
    shutil.copy2(source, destination)


def _existing_settled_receipt(root: Path, task_hash: str, run_name: str) -> Path | None:
    runs = root / "runs"
    if not runs.is_dir():
        return None
    exact = runs / run_name / "receipt.json"
    valid_matches = []
    for receipt_path in sorted(runs.glob("*/receipt.json")):
        if receipt_path.parent.name.startswith(".") or receipt_path.is_symlink() or not receipt_path.is_file():
            continue
        try:
            receipt = _read_json(receipt_path)
        except ProductionLoopError:
            continue
        if receipt.get("hash_closure", {}).get("task_hash") != task_hash:
            continue
        checked = verify_receipt(receipt_path)
        if not checked["ok"]:
            raise ProductionLoopError("existing settled receipt for task is invalid")
        valid_matches.append(receipt_path)
    if not valid_matches:
        return None
    if len(valid_matches) == 1 and valid_matches[0] == exact:
        return exact
    raise ProductionLoopError("task already settled with a different attempt")


def _resolved_worker_package(worker_result_path: Path, value: Any) -> Path:
    if not isinstance(value, str) or not _normalized_resource_path(value):
        raise ProductionLoopError("worker package path must be normalized and relative")
    parent = Path(worker_result_path).resolve().parent
    try:
        package = (parent / value).resolve(strict=True)
        package.relative_to(parent)
    except (OSError, ValueError) as exc:
        raise ProductionLoopError("worker package path escapes exchange directory") from exc
    return package


def _current_pointer_value(root: Path, receipt_path: Path, task_hash: str) -> dict:
    return {"task_hash": task_hash, "receipt_path": str(receipt_path.relative_to(root))}


def _publish_current_pointer(root: Path, receipt_path: Path, task_hash: str) -> None:
    _atomic_write_json(root / "current.json", _current_pointer_value(root, receipt_path, task_hash))
    checked = verify_receipt(receipt_path, project_root=root)
    if not checked["ok"]:
        raise ProductionLoopError("published receipt is not authoritative after current pointer update: " + str(checked["errors"]))


def _settlement_lock(root: Path):
    lock_path = root / ".settlement.lock"
    if lock_path.is_symlink():
        raise ProductionLoopError("settlement lock must not be a symlink")
    lock_file = lock_path.open("a+b")
    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
    return lock_file


def run_production_loop(*, root: Path, board_path: Path, acceptance_path: Path, worker_result_path: Path, budget: int, prepare_commit=None) -> dict:
    root = Path(root).resolve(); root.mkdir(parents=True, exist_ok=True)
    board_path = Path(board_path).resolve()
    expected_board_path = root / "board.json"
    if expected_board_path.is_symlink() or board_path != expected_board_path:
        raise ProductionLoopError("authoritative board path must be PROJECT/board.json")
    board = _read_json(board_path); _validate_board(board)
    acceptance = _validate_acceptance(_read_json(acceptance_path))
    result = _validate_worker_result(_read_json(worker_result_path))
    if acceptance.get("status") != "accepted":
        raise ProductionLoopError("acceptance status must be accepted")
    if result.get("schema_version") != WORKER_RESULT_SCHEMA:
        raise ProductionLoopError("invalid worker result schema")
    if result.get("claimed_status") != "completed":
        raise ProductionLoopError("worker result status must be completed")
    candidates = [t for t in board["tasks"] if t.get("task_hash") == acceptance.get("task_hash")]
    if len(candidates) != 1: raise ProductionLoopError("acceptance task is not an open public board task")
    task = candidates[0]; frozen = _validate_frozen_task(task)
    if task.get("status") != "open" or acceptance.get("frozen_task") != frozen: raise ProductionLoopError("acceptance frozen task mismatch")
    if acceptance.get("discovered_from_board_hash") != canonical_sha256(board): raise ProductionLoopError("acceptance board binding mismatch")
    if result.get("frozen_task") != frozen or result.get("task_hash") != task["task_hash"]: raise ProductionLoopError("worker result frozen task mismatch")
    if result.get("acceptance_hash") != canonical_sha256(acceptance): raise ProductionLoopError("worker result acceptance binding mismatch")
    requester = _validate_agent(acceptance.get("requester_id"), acceptance.get("requester_coordinate"), "requester")
    worker_role = _validate_agent(acceptance.get("worker_id"), acceptance.get("worker_coordinate"), "worker")
    verifier_role = _validate_agent(acceptance.get("verifier_id"), acceptance.get("verifier_coordinate"), "verifier")
    roles = [requester, worker_role, verifier_role]
    _validate_distinct_roles(roles)
    if requester != (frozen.get("requester_id"), frozen.get("requester_coordinate")):
        raise ProductionLoopError("requester provenance does not match frozen task")
    _matching_board_worker(board, frozen, worker_role[0], worker_role[1])
    if (result.get("worker_id"), result.get("worker_coordinate"), result.get("verifier_id"), result.get("verifier_coordinate")) != (
        worker_role[0], worker_role[1], verifier_role[0], verifier_role[1]
    ):
        raise ProductionLoopError("forged worker result identity or coordinate")
    reward = frozen["reward_test_credits"]

    attempt = canonical_sha256({"board": canonical_sha256(board), "acceptance": canonical_sha256(acceptance), "result": canonical_sha256(result), "budget": budget})
    run_name = task["task_hash"].removeprefix("sha256:")[:16] + "-" + attempt.removeprefix("sha256:")[:16]
    runs = root / "runs"; final = runs / run_name

    source_package = _resolved_worker_package(Path(worker_result_path), result.get("package_path"))
    _authoritative_task(board_path, task)
    runs.mkdir(parents=True, exist_ok=True)
    lock_file = _settlement_lock(root)
    settled = _existing_settled_receipt(root, task["task_hash"], run_name)
    if settled is not None:
        try:
            checked = verify_receipt(settled, authoritative_board_path=board_path)
            if not checked["ok"]:
                raise ProductionLoopError("current settled receipt is not valid against authoritative board")
            _publish_current_pointer(root, settled, task["task_hash"])
            return {"ok": True, **_read_json(settled), "receipt_path": str(settled)}
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            lock_file.close()
    if budget < reward:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        lock_file.close()
        raise ProductionLoopError("insufficient local test-credit budget")
    staging = runs / (".staging-" + run_name)
    if staging.exists(): shutil.rmtree(staging)
    staging.mkdir()
    try:
        _write_json(staging / "board.json", board); _write_json(staging / "task.json", task)
        _write_json(staging / "acceptance.json", acceptance); _write_json(staging / "worker-result.json", result)
        _reject_source_symlinks(source_package)
        shutil.copytree(source_package, staging / "worker-package")
        copied_result = dict(result); copied_result["package_path"] = "worker-package"
        _write_json(staging / "worker-result.json", copied_result)
        actual_package_hash = canonical_sha256(_package_manifest(staging / "worker-package"))
        if result.get("package_sha256") != actual_package_hash: raise ProductionLoopError("package hash mismatch")
        _authoritative_task(board_path, task)
        verifier_result, descriptor = _run_trusted_verifier(staging / "worker-package", frozen)
        _authoritative_task(board_path, task)
        verification = {"schema_version": VERIFICATION_SCHEMA, "task_hash": task["task_hash"], "package_hash": actual_package_hash, "verifier_id": roles[2][0], "trusted_verifier": descriptor, "separate_process_verifier_rerun": True, "result": verifier_result}
        _write_json(staging / "verification.json", verification)
        _authoritative_task(board_path, task)
        initial = {"schema_version": LEDGER_SCHEMA, "unit": "ORGANA_TEST_CREDIT", "real_payment": False, "balances": {roles[0][0]: budget, roles[1][0]: 0}, "settled_task_hashes": []}
        final_ledger = {**initial, "balances": {roles[0][0]: budget - reward, roles[1][0]: reward}, "settled_task_hashes": [task["task_hash"]]}
        settlement = {"task_hash": task["task_hash"], "amount": reward, "budget_before": budget, "budget_after": budget - reward, "status": "settled-locally", "unit": "ORGANA_TEST_CREDIT", "real_payment": False, "payer": roles[0][0], "payee": roles[1][0], "prestate_hash": canonical_sha256(initial), "poststate_hash": canonical_sha256(final_ledger)}
        _write_json(staging / "credit-ledger-initial.json", initial); _write_json(staging / "credit-ledger.json", final_ledger); _write_json(staging / "settlement.json", settlement)
        reputation_path = staging / "reputation-events.jsonl"
        for event_type, role in [("worker-accepted", roles[1]), ("worker-completed", roles[1]), ("verifier-verified", roles[2]), ("requester-paid-local-test-credit", roles[0])]:
            append_reputation_event(reputation_path, {"event": event_type, "agent_id": role[0], "cell_coordinate": role[1], "package_hash": actual_package_hash, "task_hash": task["task_hash"]})
        chain = validate_reputation_chain(reputation_path)
        closure = {"task_hash": task["task_hash"], "board_hash": canonical_sha256(board), "acceptance_hash": canonical_sha256(acceptance), "worker_result_hash": canonical_sha256(copied_result), "package_hash": actual_package_hash, "verifier_result_hash": canonical_sha256(verification), "initial_credit_ledger_hash": canonical_sha256(initial), "credit_ledger_hash": canonical_sha256(final_ledger), "settlement_hash": canonical_sha256(settlement), "reputation_event_hash": chain["chain_head"]}
        body = {"schema_version": RECEIPT_SCHEMA, "simulation_scope": SIMULATION_SCOPE, "payment_scope": PAYMENT_SCOPE, "settlement_mode": "local-test-credit", "claims_scope": CLAIMS_SCOPE, "separate_process_verifier_rerun": True, "trusted_verifier": descriptor, "project_binding": {"absolute_root": str(root), "board_relative_path": "board.json"}, "roles": {"requester": {"agent_id": roles[0][0], "cell_coordinate": roles[0][1]}, "worker": {"agent_id": roles[1][0], "cell_coordinate": roles[1][1]}, "verifier": {"agent_id": roles[2][0], "cell_coordinate": roles[2][1]}}, "settlement": settlement, "reputation": {"event_count": chain["event_count"], "chain_head": chain["chain_head"]}, "hash_closure": closure}
        receipt = {**body, "receipt_sha256": canonical_sha256(body)}; _write_json(staging / "receipt.json", receipt)
        _authoritative_task(board_path, task)
        checked = verify_receipt(staging / "receipt.json", authoritative_board_path=board_path)
        if not checked["ok"]: raise ProductionLoopError("receipt failed closure or semantics: " + str(checked["errors"]))
        _authoritative_task(board_path, task)
        if prepare_commit is not None:
            prepare_commit(staging, final, receipt)
        os.replace(staging, final)
        _fsync_directory(runs)
        _publish_current_pointer(root, final / "receipt.json", task["task_hash"])
        return {"ok": True, **receipt, "receipt_path": str(final / "receipt.json")}
    except Exception:
        if staging.exists(): shutil.rmtree(staging)
        raise
    finally:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        lock_file.close()


def run_demo(root: Path, *, prepare_only: bool = False, target_package: Path | None = None) -> dict:
    root = Path(root).resolve(); root.mkdir(parents=True, exist_ok=True)
    source = root / "source-package"
    if source.exists(): shutil.rmtree(source)
    if target_package is not None:
        _reject_source_symlinks(Path(target_package)); shutil.copytree(target_package, source)
        _verify_organa_manifest_resources(source); operation, capability = "verify-organa-manifest-resources", "organa-package-verification"
    else:
        source.mkdir(); _write_json(source / "output.json", {"answer": 42}); operation, capability = "add", "deterministic-addition"
    fixture_hash = canonical_sha256(_package_manifest(source))
    frozen = {"input": ({"target": "organa-cell.json"} if target_package is not None else {"left": 20, "right": 22}), "operation": operation, "requester_id": "local-requester-alpha", "requester_coordinate": "100001.bitmap", "required_capability": capability, "reward_test_credits": 3, "task_id": "organa-local-demo-001", "trusted_verifier": TRUSTED_VERIFIER, "fixture_package_sha256": fixture_hash}
    workers = [{"capabilities": [capability], "controller_scope": "same-controller-local-simulation", "cell_coordinate": "100002.bitmap", "price_test_credits": 3, "status": "available", "worker_id": "local-worker-alpha"}]
    task = publish_frozen_task(board_path=root / "board.json", frozen_task=frozen, workers=workers)
    _write_json(root / "task.json", task)
    exchange = worker_execute_from_board(root=root, board_path=root / "board.json", worker_id="local-worker-alpha", verifier_id="local-verifier-alpha", verifier_coordinate="100003.bitmap", source_package=source)
    prepared = {"ok": True, "source_package": str(source), **exchange, "simulation_scope": SIMULATION_SCOPE, "payment_scope": PAYMENT_SCOPE}
    if prepare_only: return prepared
    return run_production_loop(root=root, board_path=root / "board.json", acceptance_path=Path(exchange["acceptance_path"]), worker_result_path=Path(exchange["worker_result_path"]), budget=10)
