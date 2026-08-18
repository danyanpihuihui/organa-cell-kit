from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path, PurePosixPath
from typing import Any

from .pilot_identity import (
    IdentityPilotError,
    sign_json_artifact,
    verify_artifact_authorization,
    verify_signed_json_artifact,
)
from .production_loop import (
    PAYMENT_SCOPE,
    ProductionLoopError,
    TRUSTED_VERIFIER,
    canonical_sha256,
    publish_frozen_task,
    run_production_loop,
    verify_receipt,
    worker_execute_from_board,
)


PILOT_CONFIG_SCHEMA = "organa-cross-controller-pilot-config-v0.1"
PUBLICATION_SCHEMA = "organa-pilot-requester-publication-v0.1"
SUBMISSION_SCHEMA = "organa-pilot-worker-submission-v0.1"
PILOT_RECEIPT_SCHEMA = "organa-pilot-handoff-receipt-v0.2"
PILOT_ID = "dq-n6-two-role-production-001"
VERIFIER_AGENT_ID = "organa-verifier-922937"
PLACEHOLDER = "REQUIRED_REPLACE_ME"
ROLE_KEYS = {"agent_id", "cell_coordinate", "endpoint", "signing_public_key"}
VERIFIER_KEYS = ROLE_KEYS | {"controller_scope"}
EXECUTION_MODES = {"local-rehearsal", "cross-controller-pilot"}
CONFIG_KEYS = {"schema_version", "pilot_id", "execution_mode", "requester", "worker", "verifier", "fixture", "task", "settlement"}
FIXTURE_KEYS = {"coordinate", "version", "source_package"}
TASK_CONFIG_KEYS = {"task_id", "operation", "required_capability", "reward_test_credits"}
SETTLEMENT_CONFIG_KEYS = {"unit", "real_payment", "budget_test_credits"}
PUBLICATION_KEYS = {"schema_version", "pilot_id", "execution_mode", "board_hash", "task_hash", "config_hash", "fixture_package_sha256"}
SUBMISSION_KEYS = {"schema_version", "pilot_id", "execution_mode", "public_board_sha256", "board_hash", "task_hash", "acceptance_hash", "worker_result_hash", "package_sha256"}
HANDOFF_KEYS = {"schema_version", "pilot_id", "execution_mode", "task_hash", "production_receipt_relative_path", "production_receipt_sha256", "requester_signed_artifact_sha256", "worker_signed_artifact_sha256", "settlement_mode", "unit", "real_payment", "external_execution_claimed", "verifier_independence_claimed", "verifier_controller_scope", "payment_scope", "status"}


class PilotError(ValueError):
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


def _read_json(path: Path) -> dict:
    try:
        path = Path(path).absolute()
        for candidate in (path, *path.parents):
            if candidate.exists() and candidate.is_symlink():
                raise PilotError(f"pilot JSON artifact cannot use symlink path components: {path}")
        if not path.is_file():
            raise PilotError(f"pilot JSON artifact must be a safe regular file: {path}")
        value = json.loads(
            path.read_text(encoding="utf-8-sig"),
            parse_constant=_reject_json_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except PilotError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise PilotError(f"invalid pilot JSON artifact {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise PilotError(f"pilot JSON object required: {path}")
    return value


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def _exact(value: Any, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise PilotError(f"invalid {label} schema")
    return value


def _safe_directory(path: Path, label: str) -> Path:
    path = Path(path).absolute()
    for candidate in (path, *path.parents):
        if candidate.exists() and candidate.is_symlink():
            raise PilotError(f"{label} cannot use symlink path components")
    if path.is_symlink() or not path.is_dir():
        raise PilotError(f"{label} must be a safe directory")
    root = path.resolve(strict=True)
    for item in path.rglob("*"):
        if item.is_symlink():
            raise PilotError(f"{label} cannot contain symlinks")
        try:
            item.resolve(strict=True).relative_to(root)
        except (OSError, ValueError) as exc:
            raise PilotError(f"{label} contains an unsafe path") from exc
    return root


def _safe_root(path: Path, label: str, *, create: bool = False) -> Path:
    path = Path(path).absolute()
    for candidate in (path, *path.parents):
        if candidate.exists() and candidate.is_symlink():
            raise PilotError(f"{label} cannot use symlink path components")
    if create:
        path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise PilotError(f"{label} must be a safe directory")
    return path.resolve(strict=True)


def directory_sha256(path: Path) -> str:
    root = _safe_directory(path, "package")
    files = {}
    for item in sorted(root.rglob("*")):
        if item.is_file():
            files[item.relative_to(root).as_posix()] = hashlib.sha256(item.read_bytes()).hexdigest()
    if not files:
        raise PilotError("package is empty")
    return canonical_sha256({"files": files})


def identity_bound_hash(value: dict, *, exclude_identity: bool = False) -> str:
    body = dict(value)
    if exclude_identity:
        body.pop("identity_binding", None)
    return canonical_sha256(body)


def _role(agent_id: str, *, verifier: bool = False) -> dict:
    role = {
        "agent_id": agent_id,
        "cell_coordinate": PLACEHOLDER + "_BITMAP_COORDINATE",
        "endpoint": PLACEHOLDER + "_PUBLIC_OR_EXCHANGE_ENDPOINT",
        "signing_public_key": PLACEHOLDER + "_SIGNING_PUBLIC_KEY",
    }
    if verifier:
        role["controller_scope"] = "local-user-organa-controlled-not-independent-third-party"
    return role


def _validate_role(value: Any, expected_id: str, label: str, *, verifier: bool = False) -> dict:
    value = _exact(value, VERIFIER_KEYS if verifier else ROLE_KEYS, label)
    if value.get("agent_id") != expected_id:
        raise PilotError(f"{label} role provenance must be {expected_id}")
    for key in ("cell_coordinate", "endpoint", "signing_public_key"):
        field = value.get(key)
        if not isinstance(field, str) or not field or PLACEHOLDER in field:
            raise PilotError(f"required placeholder remains for {label}.{key}")
    coordinate = value["cell_coordinate"]
    if not coordinate.endswith(".bitmap") or not coordinate[:-7].isdigit() or coordinate.startswith("0"):
        raise PilotError(f"invalid {label} Bitmap coordinate")
    if verifier and value.get("controller_scope") != "local-user-organa-controlled-not-independent-third-party":
        raise PilotError("verifier controller scope must disclose local non-independent control")
    return value


def _validate_config(config: dict, *, require_ready: bool = True) -> dict:
    _exact(config, CONFIG_KEYS, "pilot config")
    if config.get("schema_version") != PILOT_CONFIG_SCHEMA or not isinstance(config.get("pilot_id"), str):
        raise PilotError("invalid pilot config schema or pilot id")
    if config.get("execution_mode") not in EXECUTION_MODES:
        raise PilotError("invalid closed-schema execution mode")
    if require_ready:
        requester = _validate_role(config.get("requester"), "dq", "requester")
        worker = _validate_role(config.get("worker"), "n6", "worker")
        verifier = _validate_role(config.get("verifier"), VERIFIER_AGENT_ID, "verifier", verifier=True)
        ids = {requester["agent_id"], worker["agent_id"], verifier["agent_id"]}
        coordinates = {requester["cell_coordinate"], worker["cell_coordinate"], verifier["cell_coordinate"]}
        if len(ids) != 3 or len(coordinates) != 3:
            raise PilotError("pilot role identities and Bitmap coordinates must be distinct")
        if len({requester["signing_public_key"], worker["signing_public_key"], verifier["signing_public_key"]}) != 3:
            raise PilotError("pilot operational signing public keys must be distinct")
    else:
        _exact(config.get("requester"), ROLE_KEYS, "requester")
        _exact(config.get("worker"), ROLE_KEYS, "worker")
        _exact(config.get("verifier"), VERIFIER_KEYS, "verifier")
    fixture = _exact(config.get("fixture"), FIXTURE_KEYS, "fixture")
    if fixture.get("coordinate") != "720202.bitmap" or fixture.get("version") != "0.3.0" or not isinstance(fixture.get("source_package"), str):
        raise PilotError("pilot fixture must be 720202.bitmap v0.3.0")
    task = _exact(config.get("task"), TASK_CONFIG_KEYS, "task config")
    if task != {"task_id": "dq-n6-verify-720202-v0.3.0", "operation": "verify-organa-manifest-resources", "required_capability": "organa-package-verification", "reward_test_credits": 3}:
        raise PilotError("pilot frozen task template changed")
    settlement = _exact(config.get("settlement"), SETTLEMENT_CONFIG_KEYS, "settlement config")
    if settlement.get("unit") != "ORGANA_TEST_CREDIT" or settlement.get("real_payment") is not False or settlement.get("budget_test_credits") != 10:
        raise PilotError("pilot settlement must be local ORGANA_TEST_CREDIT only")
    return config


def _identity_dir(root: Path, role: str) -> Path:
    return Path(root) / "identity" / role


def _copy_public_identity(source_root: Path, role: str, destination: Path) -> None:
    source = _identity_dir(source_root, role)
    destination.mkdir(parents=True, exist_ok=True)
    for name in ("identity-claim.json", "artifact-key.json", "artifact-authorization-request.json", "artifact-authorization.json"):
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise PilotError(f"valid {role} artifact authorization required")
        shutil.copy2(path, destination / name)


def _validate_signed_artifact(envelope: Any, identity_dir: Path, role: dict, label: str) -> dict:
    authorization_path = Path(identity_dir) / "artifact-authorization.json"
    try:
        authorization = _read_json(authorization_path)
        if not verify_artifact_authorization(authorization_path):
            raise PilotError(f"valid human {label} artifact authorization required")
        if not verify_signed_json_artifact(envelope, authorization, authorization_path=authorization_path):
            raise PilotError(f"invalid authorized Ed25519 signed {label} artifact")
    except IdentityPilotError as exc:
        raise PilotError(f"invalid {label} artifact authorization: {exc}") from exc
    expected = (role["agent_id"], role["cell_coordinate"], role["signing_public_key"])
    actual = (envelope.get("agent_id"), envelope.get("cell_coordinate"), envelope.get("public_key"))
    if actual != expected:
        raise PilotError(f"{label} signed identity provenance mismatch")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise PilotError(f"invalid {label} signed payload")
    return payload


def init_pilot(root: Path, *, fixture_source: Path) -> dict:
    root = Path(root).absolute()
    for candidate in (root, *root.parents):
        if candidate.exists() and candidate.is_symlink():
            raise PilotError("pilot root cannot use symlink path components")
    if root.exists() and any(root.iterdir()):
        raise PilotError("pilot directory must be new or empty")
    root.mkdir(parents=True, exist_ok=True)
    fixture = _safe_directory(fixture_source, "fixture source")
    config = {
        "schema_version": PILOT_CONFIG_SCHEMA,
        "pilot_id": PILOT_ID,
        "execution_mode": "cross-controller-pilot",
        "requester": _role("dq"),
        "worker": _role("n6"),
        "verifier": _role(VERIFIER_AGENT_ID, verifier=True),
        "fixture": {"coordinate": "720202.bitmap", "version": "0.3.0", "source_package": "fixtures/720202.bitmap/0.3.0"},
        "task": {"task_id": "dq-n6-verify-720202-v0.3.0", "operation": "verify-organa-manifest-resources", "required_capability": "organa-package-verification", "reward_test_credits": 3},
        "settlement": {"unit": "ORGANA_TEST_CREDIT", "real_payment": False, "budget_test_credits": 10},
    }
    _validate_config(config, require_ready=False)
    _write_json(root / "pilot-config.template.json", config)
    _write_json(root / "pilot-config.json", config)
    frozen_template = {
        "schema_version": "organa-pilot-frozen-task-template-v0.1",
        "requester_id": "dq",
        "worker_id": "n6",
        "verifier_id": VERIFIER_AGENT_ID,
        "fixture": {"coordinate": "720202.bitmap", "version": "0.3.0"},
        "fixture_package_sha256": "sha256:<requester-publication-fixture-hash>",
        "operation": "verify-organa-manifest-resources",
        "settlement_mode": "local-test-credit",
        "real_payment": False,
        "status": "template-awaiting-real-role-values",
    }
    _write_json(root / "frozen-task.template.json", frozen_template)
    _write_json(root / "public-board-package.template.json", {
        "schema_version": "organa-pilot-public-board-package-template-v0.1",
        "pilot_id": config["pilot_id"],
        "expected_files": ["board.json", "task.json", "pilot-config.snapshot.json", "requester-publication.json", "target-package/"],
        "requester_id": "dq",
        "worker_id": "n6",
        "status": "awaiting-requester-publication",
    })
    _write_json(root / "receipt.template.json", {
        "schema_version": PILOT_RECEIPT_SCHEMA,
        "pilot_id": config["pilot_id"],
        "requester_id": "dq",
        "worker_id": "n6",
        "verifier_id": VERIFIER_AGENT_ID,
        "settlement_mode": "local-test-credit",
        "unit": "ORGANA_TEST_CREDIT",
        "real_payment": False,
        "external_execution_claimed": False,
        "verifier_independence_claimed": False,
        "status": "awaiting-external-role-artifacts",
    })
    destination = root / config["fixture"]["source_package"]
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(fixture, destination)
    for path in (root / "exchange" / "requester-to-worker", root / "exchange" / "worker-to-verifier", root / "workspaces" / "dq-requester", root / "workspaces" / "n6-worker", root / "workspaces" / "local-verifier", root / "messages", root / "commands"):
        path.mkdir(parents=True, exist_ok=True)
    readme = """# dq 请求方 / n6 工作方 Organa 跨控制器 Pilot\n\n状态：**等待 dq 与 n6 外部控制器执行，尚未执行生产 Pilot。**\n\n本目录把请求方、工作方、验证方拆分为可交换文件的独立工作区。首个任务仅验证公开的 `720202.bitmap` v0.3.0 Organa Cell 包，低风险且机器可验证。\n\n## 重要边界\n\n- `dq` 固定为 Requester，`n6` 固定为 Worker。\n- 三方 Bitmap 坐标、公开端点、签名公钥都必须由真实控制器填写；预检会拒绝占位符。\n- 初始 Verifier 是 `organa-verifier-922937`，由用户/Organa 本地控制，**不是独立第三方验证者**。\n- 没有真实付款、链上转账、托管、PSBT 或矿工费；只使用 `ORGANA_TEST_CREDIT` 本地测试记账。\n- 当前提交至少绑定到声明的身份、公钥和 artifact hash；在接入真实签名适配器之前，不宣称密码学签名。\n\n## 顺序\n\n1. 填写 `pilot-config.json` 的全部 REQUIRED 占位符。\n2. dq 运行 `commands/1-requester-publish.sh`，把生成的 public-board 目录交给 n6。\n3. n6 运行 `commands/2-worker-run.sh`，把 submission 目录交给本地 Verifier。\n4. 用户/Organa 运行 `commands/3-verifier-settle.sh`。只有验证成功才结算本地测试积分并生成 Receipt。\n\n生产目录应保持未执行，直到 dq/n6 返回真实外部 artifact。`rehearsal/` 或另一个目录可使用测试身份演练。\n"""
    (root / "README.zh-CN.md").write_text(readme, encoding="utf-8-sig")
    (root / "messages" / "send-to-dq.md").write_text("# 发给 dq 的原文\n\n你是本 Pilot 的 Requester（requester_id=`dq`）。请填写你真实的 Bitmap 坐标、可交换 artifact 的公开/联系端点、签名公钥；不要提供私钥或助记词。然后运行 `commands/1-requester-publish.sh`。请把命令输出中的 `public_board_dir` 完整目录原样发送给 n6，不要修改已发布文件。\n", encoding="utf-8")
    (root / "messages" / "send-to-n6.md").write_text("# 发给 n6 的原文\n\n你是本 Pilot 的 Worker（worker_id=`n6`）。请从 dq 收到完整 `public_board_dir` 后运行 `commands/2-worker-run.sh PUBLIC_BOARD_DIR`。任务只验证公开的 720202.bitmap v0.3.0 包。请把输出中的 `submission_dir` 完整目录原样返回；不要修改 board、task、fixture 或验证规则，不要提供私钥。\n", encoding="utf-8")
    commands = {
        "1-requester-publish.sh": '#!/bin/sh\nset -eu\norgana-cell-kit pilot-requester-publish "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"\n',
        "2-worker-run.sh": '#!/bin/sh\nset -eu\n[ "$#" -eq 1 ] || { echo "usage: $0 PUBLIC_BOARD_DIR" >&2; exit 2; }\nROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)\norgana-cell-kit pilot-worker-run "$ROOT/workspaces/n6-worker" --public-board "$1"\n',
        "3-verifier-settle.sh": '#!/bin/sh\nset -eu\n[ "$#" -eq 2 ] || { echo "usage: $0 PUBLIC_BOARD_DIR WORKER_SUBMISSION_DIR" >&2; exit 2; }\nROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)\norgana-cell-kit pilot-verifier-settle "$ROOT/workspaces/local-verifier" --public-board "$1" --worker-submission "$2"\n',
    }
    for name, content in commands.items():
        path = root / "commands" / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o755)
    return {"ok": True, "pilot_root": str(root), "config_path": str(root / "pilot-config.json"), "status": "awaiting-required-role-values"}


def requester_publish(root: Path) -> dict:
    root = _safe_root(root, "pilot root")
    config = _validate_config(_read_json(root / "pilot-config.json"))
    fixture = _safe_directory(root / config["fixture"]["source_package"], "fixture package")
    manifest = _read_json(fixture / "organa-cell.json")
    if manifest.get("coordinate") != "720202.bitmap" or manifest.get("version") != "0.3.0":
        raise PilotError("fixture package identity mismatch")
    frozen = {
        "input": {"target": "organa-cell.json"},
        "operation": config["task"]["operation"],
        "requester_id": "dq",
        "requester_coordinate": config["requester"]["cell_coordinate"],
        "required_capability": config["task"]["required_capability"],
        "reward_test_credits": config["task"]["reward_test_credits"],
        "task_id": config["task"]["task_id"],
        "trusted_verifier": TRUSTED_VERIFIER,
        "fixture_package_sha256": directory_sha256(fixture),
    }
    worker = {
        "capabilities": [config["task"]["required_capability"]],
        "controller_scope": "separate-controller-pilot-worker",
        "cell_coordinate": config["worker"]["cell_coordinate"],
        "price_test_credits": config["task"]["reward_test_credits"],
        "status": "available",
        "worker_id": "n6",
    }
    staging = root / "workspaces" / "dq-requester" / "publication-staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True)
    task = publish_frozen_task(board_path=staging / "board.json", frozen_task=frozen, workers=[worker])
    _write_json(staging / "task.json", task)
    _write_json(staging / "pilot-config.snapshot.json", config)
    shutil.copytree(fixture, staging / "target-package")
    publication = {
        "schema_version": PUBLICATION_SCHEMA,
        "pilot_id": config["pilot_id"],
        "execution_mode": config["execution_mode"],
        "board_hash": canonical_sha256(_read_json(staging / "board.json")),
        "task_hash": task["task_hash"],
        "config_hash": canonical_sha256(config),
        "fixture_package_sha256": directory_sha256(staging / "target-package"),
    }
    try:
        signed_publication = sign_json_artifact(root, role="requester", payload=publication)
    except IdentityPilotError as exc:
        raise PilotError("valid human requester artifact authorization and Ed25519 signing key required: " + str(exc)) from exc
    _write_json(staging / "requester-publication.json", signed_publication)
    _copy_public_identity(root, "requester", staging / "requester-identity")
    public_hash = directory_sha256(staging).removeprefix("sha256:")[:16]
    public_dir = root / "exchange" / "requester-to-worker" / ("public-board-" + public_hash)
    public_dir.parent.mkdir(parents=True, exist_ok=True)
    if public_dir.exists():
        shutil.rmtree(staging)
    else:
        os.replace(staging, public_dir)
    return {"ok": True, "public_board_dir": str(public_dir), "public_board_sha256": directory_sha256(public_dir), "task_hash": task["task_hash"], "status": "published-awaiting-n6"}


def _validate_publication(public_dir: Path) -> tuple[dict, dict, dict]:
    public_dir = _safe_directory(public_dir, "public board package")
    config = _validate_config(_read_json(public_dir / "pilot-config.snapshot.json"))
    board = _read_json(public_dir / "board.json")
    task = _read_json(public_dir / "task.json")
    publication_envelope = _read_json(public_dir / "requester-publication.json")
    publication = _validate_signed_artifact(publication_envelope, public_dir / "requester-identity", config["requester"], "requester publication")
    _exact(publication, PUBLICATION_KEYS, "requester publication")
    if publication.get("schema_version") != PUBLICATION_SCHEMA or publication.get("pilot_id") != config["pilot_id"]:
        raise PilotError("requester publication schema or pilot mismatch")
    if publication.get("execution_mode") != config["execution_mode"]:
        raise PilotError("requester publication execution mode mismatch")
    if publication.get("board_hash") != canonical_sha256(board) or publication.get("task_hash") != task.get("task_hash") or publication.get("config_hash") != canonical_sha256(config):
        raise PilotError("requester publication hash or provenance mismatch")
    if board.get("tasks") != [task] or task.get("frozen_task", {}).get("requester_id") != "dq" or board.get("workers", [{}])[0].get("worker_id") != "n6":
        raise PilotError("requester publication role provenance mismatch")
    if task.get("frozen_task", {}).get("fixture_package_sha256") != publication.get("fixture_package_sha256"):
        raise PilotError("requester frozen fixture binding mismatch")
    if publication.get("fixture_package_sha256") != directory_sha256(public_dir / "target-package"):
        raise PilotError("requester fixture package hash mismatch")
    return config, board, task


def worker_run(*, public_board_dir: Path, worker_workspace: Path) -> dict:
    public_dir = _safe_directory(public_board_dir, "public board package")
    config, board, task = _validate_publication(public_dir)
    workspace = _safe_root(worker_workspace, "worker workspace", create=True)
    exchange = worker_execute_from_board(
        root=workspace,
        board_path=public_dir / "board.json",
        worker_id="n6",
        verifier_id=VERIFIER_AGENT_ID,
        verifier_coordinate=config["verifier"]["cell_coordinate"],
        source_package=public_dir / "target-package",
    )
    acceptance_path = Path(exchange["acceptance_path"])
    result_path = Path(exchange["worker_result_path"])
    acceptance = _read_json(acceptance_path)
    result = _read_json(result_path)
    if acceptance.get("requester_id") != "dq" or acceptance.get("worker_id") != "n6" or acceptance.get("verifier_id") != VERIFIER_AGENT_ID:
        raise PilotError("worker acceptance role provenance mismatch")
    submission_staging = workspace / "submission-staging"
    if submission_staging.exists():
        shutil.rmtree(submission_staging)
    submission_staging.mkdir()
    shutil.copy2(acceptance_path, submission_staging / "acceptance.json")
    shutil.copy2(result_path, submission_staging / "worker-result.json")
    shutil.copytree(Path(exchange["package_dir"]), submission_staging / "worker-package")
    submission = {
        "schema_version": SUBMISSION_SCHEMA,
        "pilot_id": config["pilot_id"],
        "execution_mode": config["execution_mode"],
        "public_board_sha256": directory_sha256(public_dir),
        "board_hash": canonical_sha256(board),
        "task_hash": task["task_hash"],
        "acceptance_hash": canonical_sha256(acceptance),
        "worker_result_hash": canonical_sha256(result),
        "package_sha256": directory_sha256(submission_staging / "worker-package"),
    }
    try:
        signed_submission = sign_json_artifact(workspace, role="worker", payload=submission)
    except IdentityPilotError as exc:
        raise PilotError("valid human worker artifact authorization and Ed25519 signing key required: " + str(exc)) from exc
    _write_json(submission_staging / "worker-submission.json", signed_submission)
    _copy_public_identity(workspace, "worker", submission_staging / "worker-identity")
    submission_hash = directory_sha256(submission_staging).removeprefix("sha256:")[:16]
    destination = workspace / "exports" / ("submission-" + submission_hash)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        shutil.rmtree(submission_staging)
    else:
        os.replace(submission_staging, destination)
    return {"ok": True, "submission_dir": str(destination), "task_hash": task["task_hash"], "status": "completed-awaiting-local-verifier"}


def verifier_settle(*, public_board_dir: Path, worker_submission_dir: Path, verifier_workspace: Path) -> dict:
    public_dir = _safe_directory(public_board_dir, "public board package")
    submission_dir = _safe_directory(worker_submission_dir, "worker submission")
    config, board, task = _validate_publication(public_dir)
    submission_envelope = _read_json(submission_dir / "worker-submission.json")
    submission = _validate_signed_artifact(submission_envelope, submission_dir / "worker-identity", config["worker"], "worker submission")
    _exact(submission, SUBMISSION_KEYS, "worker submission")
    if submission.get("schema_version") != SUBMISSION_SCHEMA or submission.get("pilot_id") != config["pilot_id"]:
        raise PilotError("worker submission schema or pilot mismatch")
    if submission.get("execution_mode") != config["execution_mode"]:
        raise PilotError("worker submission execution mode mismatch")
    if submission.get("public_board_sha256") != directory_sha256(public_dir):
        raise PilotError("requester public board directory hash mismatch")
    acceptance = _read_json(submission_dir / "acceptance.json")
    result = _read_json(submission_dir / "worker-result.json")
    checks = {
        "board_hash": canonical_sha256(board),
        "task_hash": task["task_hash"],
        "acceptance_hash": canonical_sha256(acceptance),
        "worker_result_hash": canonical_sha256(result),
        "package_sha256": directory_sha256(submission_dir / "worker-package"),
    }
    if any(submission.get(key) != value for key, value in checks.items()):
        raise PilotError("worker submission package or artifact hash mismatch")
    publication_envelope = _read_json(public_dir / "requester-publication.json")
    publication = publication_envelope.get("payload", {})
    expected_fixture_hash = publication.get("fixture_package_sha256")
    if submission.get("package_sha256") != expected_fixture_hash:
        raise PilotError("worker package hash does not match requester fixture package")

    if acceptance.get("requester_id") != "dq" or acceptance.get("worker_id") != "n6" or acceptance.get("verifier_id") != VERIFIER_AGENT_ID:
        raise PilotError("worker submission role provenance mismatch")
    expected_roles = {
        "requester": (config["requester"]["agent_id"], config["requester"]["cell_coordinate"]),
        "worker": (config["worker"]["agent_id"], config["worker"]["cell_coordinate"]),
        "verifier": (config["verifier"]["agent_id"], config["verifier"]["cell_coordinate"]),
    }
    for prefix in ("requester", "worker", "verifier"):
        if (acceptance.get(prefix + "_id"), acceptance.get(prefix + "_coordinate")) != expected_roles[prefix]:
            raise PilotError("cross-artifact role provenance mismatch")
    if (result.get("worker_id"), result.get("worker_coordinate"), result.get("verifier_id"), result.get("verifier_coordinate")) != (*expected_roles["worker"], *expected_roles["verifier"]):
        raise PilotError("worker result role provenance mismatch")
    workspace = _safe_root(verifier_workspace, "verifier workspace", create=True)
    board_path = workspace / "board.json"
    shutil.copy2(public_dir / "board.json", board_path)
    incoming = workspace / "incoming" / submission_dir.name
    if incoming.exists():
        shutil.rmtree(incoming)
    shutil.copytree(submission_dir, incoming)
    handoff_status = "local-rehearsal-complete" if config["execution_mode"] == "local-rehearsal" else "pilot-settled-from-imported-artifacts"

    def prepare_handoff(staging: Path, final: Path, receipt: dict) -> None:
        staged_receipt = staging / "receipt.json"
        final_receipt = final / "receipt.json"
        handoff = {
            "schema_version": PILOT_RECEIPT_SCHEMA,
            "pilot_id": config["pilot_id"],
            "execution_mode": config["execution_mode"],
            "task_hash": task["task_hash"],
            "production_receipt_relative_path": final_receipt.relative_to(workspace).as_posix(),
            "production_receipt_sha256": "sha256:" + hashlib.sha256(staged_receipt.read_bytes()).hexdigest(),
            "requester_signed_artifact_sha256": canonical_sha256(_read_json(public_dir / "requester-publication.json")),
            "worker_signed_artifact_sha256": canonical_sha256(submission_envelope),
            "settlement_mode": "local-test-credit",
            "unit": "ORGANA_TEST_CREDIT",
            "real_payment": False,
            "external_execution_claimed": False,
            "verifier_independence_claimed": False,
            "verifier_controller_scope": config["verifier"]["controller_scope"],
            "payment_scope": PAYMENT_SCOPE,
            "status": handoff_status,
        }
        try:
            signed_handoff = sign_json_artifact(workspace, role="verifier", payload=handoff)
        except IdentityPilotError as exc:
            raise PilotError("valid human verifier artifact authorization and Ed25519 signing key required: " + str(exc)) from exc
        _write_json(staging / "pilot-handoff-receipt.json", signed_handoff)
        _copy_public_identity(workspace, "verifier", staging / "verifier-identity")
        shutil.copy2(public_dir / "requester-publication.json", staging / "requester-signed-artifact.json")
        shutil.copytree(public_dir / "requester-identity", staging / "requester-identity")
        shutil.copy2(submission_dir / "worker-submission.json", staging / "worker-signed-artifact.json")
        shutil.copytree(submission_dir / "worker-identity", staging / "worker-identity")

    try:
        settled = run_production_loop(
            root=workspace,
            board_path=board_path,
            acceptance_path=incoming / "acceptance.json",
            worker_result_path=incoming / "worker-result.json",
            budget=config["settlement"]["budget_test_credits"],
            prepare_commit=prepare_handoff,
        )
    except ProductionLoopError as exc:
        raise PilotError("trusted verifier rejected pilot submission: " + str(exc)) from exc
    except PilotError:
        raise
    receipt_path = Path(settled["receipt_path"])
    pilot_receipt = receipt_path.parent / "pilot-handoff-receipt.json"
    return {"ok": True, "receipt_path": str(receipt_path), "pilot_receipt_path": str(pilot_receipt), "status": handoff_status}


def verify_pilot_handoff(handoff_path: Path, *, project_root: Path) -> dict:
    handoff_path = Path(handoff_path).absolute()
    project_root = Path(project_root).absolute()
    if project_root.is_symlink() or not project_root.is_dir():
        raise PilotError("project root must be a safe authoritative directory")
    try:
        resolved_project_root = project_root.resolve(strict=True)
    except OSError as exc:
        raise PilotError("project root must be a safe authoritative directory") from exc
    if resolved_project_root != project_root:
        raise PilotError("project root must be a safe authoritative directory without symlink ancestors")
    try:
        relative_handoff = handoff_path.relative_to(project_root)
    except ValueError as exc:
        raise PilotError("handoff must be a safe authoritative PROJECT/runs/<run>/pilot-handoff-receipt.json") from exc
    cursor = project_root
    for part in relative_handoff.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise PilotError("handoff must be a safe authoritative PROJECT/runs/<run>/pilot-handoff-receipt.json without symlinks")
    try:
        handoff_path = handoff_path.resolve(strict=True)
    except OSError as exc:
        raise PilotError("handoff must be a safe authoritative PROJECT/runs/<run>/pilot-handoff-receipt.json") from exc
    project_root = resolved_project_root
    run_root = handoff_path.parent
    if handoff_path.name != "pilot-handoff-receipt.json" or handoff_path.is_symlink() or run_root.parent != project_root / "runs":
        raise PilotError("handoff must be a safe authoritative PROJECT/runs/<run>/pilot-handoff-receipt.json")
    run_root = _safe_directory(run_root, "production receipt authoritative run")

    role_paths = {
        "requester": (run_root / "requester-signed-artifact.json", run_root / "requester-identity"),
        "worker": (run_root / "worker-signed-artifact.json", run_root / "worker-identity"),
        "verifier": (handoff_path, run_root / "verifier-identity"),
    }
    envelopes = {}
    authorizations = {}
    for role, (artifact_path, identity_dir) in role_paths.items():
        envelope = _read_json(artifact_path)
        authorization_path = identity_dir / "artifact-authorization.json"
        authorization = _read_json(authorization_path)
        try:
            if not verify_artifact_authorization(authorization_path):
                raise PilotError(f"invalid {role} artifact authorization or identity evidence")
            if not verify_signed_json_artifact(envelope, authorization, authorization_path=authorization_path):
                raise PilotError(f"invalid authorized signed {role} artifact")
        except IdentityPilotError as exc:
            raise PilotError(f"invalid {role} artifact authorization or identity evidence") from exc
        envelopes[role] = envelope
        authorizations[role] = authorization

    payload = envelopes["verifier"].get("payload")
    _exact(payload, HANDOFF_KEYS, "pilot handoff receipt")
    if payload["schema_version"] != PILOT_RECEIPT_SCHEMA or payload["execution_mode"] not in EXECUTION_MODES:
        raise PilotError("invalid handoff schema or execution mode")
    expected_status = "local-rehearsal-complete" if payload["execution_mode"] == "local-rehearsal" else "pilot-settled-from-imported-artifacts"
    if payload["status"] != expected_status:
        raise PilotError("handoff status does not match execution mode")
    if len({item.get("pilot_id") for item in (*envelopes.values(), *authorizations.values())} | {payload["pilot_id"]}) != 1:
        raise PilotError("cross-artifact pilot binding mismatch")
    for role in role_paths:
        if envelopes[role].get("role") != role or authorizations[role].get("role") != role:
            raise PilotError("cross-artifact role binding mismatch")

    for field, label in (("agent_id", "agent IDs"), ("cell_coordinate", "Bitmap coordinates"), ("artifact_signing_public_key", "operational public keys"), ("controller_address", "controller addresses")):
        if len({authorizations[role][field] for role in role_paths}) != 3:
            raise PilotError(f"requester, worker, and verifier {label} must be distinct")

    requester_payload = envelopes["requester"].get("payload", {})
    worker_payload = envelopes["worker"].get("payload", {})
    if any(item.get("pilot_id") != payload["pilot_id"] for item in (requester_payload, worker_payload)):
        raise PilotError("signed artifact pilot binding mismatch")
    if any(item.get("execution_mode") != payload["execution_mode"] for item in (requester_payload, worker_payload)):
        raise PilotError("signed artifact execution mode mismatch")
    if any(item.get("task_hash") != payload["task_hash"] for item in (requester_payload, worker_payload)):
        raise PilotError("signed artifact task binding mismatch")
    if payload["requester_signed_artifact_sha256"] != canonical_sha256(envelopes["requester"]):
        raise PilotError("requester signed artifact hash mismatch")
    if payload["worker_signed_artifact_sha256"] != canonical_sha256(envelopes["worker"]):
        raise PilotError("worker signed artifact hash mismatch")

    receipt_reference = payload["production_receipt_relative_path"]
    if not isinstance(receipt_reference, str):
        raise PilotError("production receipt relative path must be a normalized string")
    pure_reference = PurePosixPath(receipt_reference)
    if (
        not receipt_reference
        or pure_reference.is_absolute()
        or receipt_reference != pure_reference.as_posix()
        or any(part in ("", ".", "..") for part in pure_reference.parts)
    ):
        raise PilotError("production receipt relative path must be normalized and cannot escape project root")
    receipt_path = project_root.joinpath(*pure_reference.parts)
    if receipt_path != run_root / "receipt.json":
        raise PilotError("production receipt relative path must bind to the handoff run receipt")
    cursor = project_root
    for part in pure_reference.parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise PilotError("production receipt path cannot contain symlinks")
    try:
        resolved_receipt = receipt_path.resolve(strict=True)
        resolved_receipt.relative_to(project_root)
    except (OSError, ValueError) as exc:
        raise PilotError("production receipt relative path is missing or unsafe") from exc
    if resolved_receipt != receipt_path or not receipt_path.is_file():
        raise PilotError("production receipt relative path is not a safe regular file")
    if payload["production_receipt_sha256"] != "sha256:" + hashlib.sha256(receipt_path.read_bytes()).hexdigest():
        raise PilotError("production receipt byte hash mismatch")
    receipt_result = verify_receipt(receipt_path, project_root=project_root, allow_relocated_project_root=True)
    if not receipt_result.get("ok") or receipt_result.get("authoritative_board_checked") is not True:
        raise PilotError("production receipt is not valid against authoritative current project state: " + "; ".join(receipt_result.get("errors", [])))
    receipt = _read_json(receipt_path)
    if receipt.get("hash_closure", {}).get("task_hash") != payload["task_hash"]:
        raise PilotError("production receipt task binding mismatch")
    expected_receipt_roles = {role: {"agent_id": authorizations[role]["agent_id"], "cell_coordinate": authorizations[role]["cell_coordinate"]} for role in role_paths}
    if receipt.get("roles") != expected_receipt_roles:
        raise PilotError("production receipt role binding mismatch")
    return {"ok": True, "execution_mode": payload["execution_mode"], "authoritative_receipt_checked": True, "roles_verified": ["requester", "worker", "verifier"]}
