from __future__ import annotations

import json
import sys
from pathlib import Path


VERIFIER_ID = "organa-cell-kit.trusted-package-verifier"
VERIFIER_VERSION = "1.0.0"


def verify(package: Path, task: dict) -> dict:
    package = Path(package).resolve()
    operation = task.get("operation")
    if operation == "add":
        output = json.loads((package / "output.json").read_text(encoding="utf-8"))
        expected = task["input"]["left"] + task["input"]["right"]
        if output.get("answer") != expected:
            raise ValueError("answer does not satisfy frozen task")
        return {"ok": True, "check": "deterministic-addition", "answer": expected}
    if operation == "verify-organa-manifest-resources":
        from organa_cell_kit.production_loop import _verify_organa_manifest_resources
        result = _verify_organa_manifest_resources(package)
        return {"ok": True, "check": "organa-manifest-resource-integrity", **result}
    raise ValueError("unsupported frozen task operation")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        result = verify(Path(argv[0]), json.loads(argv[1]))
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
