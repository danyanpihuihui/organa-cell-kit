# Organa Agent Production Loop — Acceptance Contract

## Objective

Demonstrate a reproducible end-to-end task lifecycle in which logically separate requester, worker, and verifier agents coordinate through persisted machine-readable artifacts rather than a single in-memory function call.

## Required flow

```text
Requester publishes hash-frozen task + local test-credit reward
→ Worker discovers it from a persisted public board
→ Worker accepts it under a distinct Agent/Cell identity
→ Worker executes deterministic Organa package verification
→ Trusted Organa Cell Kit verifier re-runs the frozen acceptance criteria in a separate process
→ Accepted result triggers local test-credit settlement
→ Append-only reputation events are recorded
→ Final receipt binds every material artifact hash
```

## Truthful scope labels

This milestone must always state:

- `settlement_mode: local-test-credit` and `real_payment: false`
- structured `claims_scope` exclusions all set to false: fiat payment, cryptocurrency payment, on-chain transfer, escrow, financial claim, external adoption, and independent controller
- requester, worker, and verifier are logically distinct identities and Cell coordinates
- current run is `same-controller-simulation-not-external-adoption`
- `separate_process_verifier_rerun` means trusted installed kit code runs in another local process; it is not an independently controlled external verifier

## Fail-closed requirements

- The canonical task specification is frozen by SHA-256 before acceptance.
- Acceptance, execution, verification, settlement, and receipt generation reject a changed task specification.
- The fixed installed verifier reads and checks the target package without executing worker-provided verifier code or trusting a worker-declared success flag.
- Settlement is impossible unless verification is accepted and requester balance is sufficient.
- A failed/rejected/inconclusive task cannot produce a paid receipt.
- Reputation is represented as append-only events; every append validates every prior event hash and link.
- Immutable task/attempt run directories are staged and atomically promoted. Exact reruns are idempotent and a task cannot settle twice.
- The receipt binds the task specification, board, acceptance, submission, verifier identity/version/hash, initial and final ledgers, exact settlement, reputation event count, full chain head, and linked artifact hashes.
- Acceptance identities are provenance-bound: requester ID/coordinate exactly match the frozen task, and worker ID/coordinate must match one available compatible board advertisement. Worker results bind both IDs and coordinates and must declare the supported schema plus `claimed_status: completed`.
- The installed trusted verifier descriptor (ID, version, expected safe regular absolute path, and SHA-256) must exactly equal the frozen task immediately before and after subprocess execution. The absolute path is intentionally local-install-specific and reduces portability; this is acceptable only within the declared local simulation scope.
- Every hash-closed artifact uses a closed schema with exact required/allowed key sets and value types. Missing or unknown fields fail closed; extensibility requires a schema-version change. The current task-record status contract is the explicit string enum `{ "open" }`; creation, worker discovery, coordinator execution, snapshot receipt verification, and authoritative receipt verification reject missing, integer, or unknown status values.
- The receipt includes a closed and self-hashed `project_binding` containing the resolved creation-time absolute root and fixed `board_relative_path: "board.json"`; this self-hash is integrity closure, not cryptographic authorship. Authoritative `project_root` verification first binds the inspected artifact to the project: the receipt must be a safe regular non-symlink `PROJECT/runs/<non-hidden-run>/receipt.json`, and safe closed-schema `PROJECT/current.json` must name that exact receipt through a normalized relative path under `PROJECT/runs` and repeat the receipt closure task hash. `current.json` remains outside the receipt hash closure as an externally validated mutable pointer, avoiding circularity. The frozen root and exact `PROJECT/board.json` equality checks remain additional local disclosures and consistency gates. Relative paths and directory-symlink aliases resolving to the same project/receipt pass; receipt, run, current, and board symlinks fail closed.
- Immutable valid run receipts, not `current.json`, are authoritative for task settlement uniqueness. Exact attempts are idempotent; any different settled attempt is rejected.
- The receipt validator checks artifact schemas and cross-artifact semantics, including roles, package/task bindings, successful verifier output, settlement arithmetic, exact ledger deltas/conservation, one-time settled-task movement, and ordered reputation event roles/types.
- Receipt verification requires both the receipt-level and linked verification-artifact `separate_process_verifier_rerun` claims to be exactly `true`, and revalidates distinct requester/worker/verifier Agent IDs and Cell coordinates from accepted artifacts and receipt roles.
- Source packages and receipt-linked artifacts reject symlinks and root escape. Worker `package_path` must be normalized relative and contained by its exchange directory.
- Organa Manifest v0.1 uses a closed supported top-level field set and closed resource entries (`path`, `sha256`, optional `url`). Required production fields mirror the live 720202 manifest shape; unknown fields are rejected.

## Acceptance tests

1. Valid package completes the whole lifecycle and transfers local test credits.
2. Mutating the frozen task specification causes the next transition to fail.
3. A forged worker success report or worker-supplied `verify.py` is rejected when the trusted verifier finds damaged package bytes.
4. Insufficient requester balance prevents settlement and receipt finalization.
5. Reputation tamper and truncation are detected across the complete JSONL chain, and corrupted history refuses append.
6. The existing Organa Cell Kit lifecycle tests remain green.
7. A real demo runs against an actual generated/live-package directory and emits inspectable artifacts.
8. Rehashed false rerun claims and independently rehashed duplicate role IDs or coordinates are rejected.
9. Mutating or replacing the authoritative project board after publication makes CLI verification return nonzero with `ok: false`, without modifying the immutable receipt-local board.
10. Copying the exact board to a different project root, then editing `project_binding.absolute_root` and recomputing the unsigned receipt hash while the receipt remains under the original root, is rejected because the inspected receipt is not owned/current under the supplied project. The correct root and safe project/receipt aliases resolving to it pass.
11. Copying a receipt alone, or copying the full board/run without a valid exact `current.json` pointer, is rejected. Missing, unsafe, forged, open-schema, wrong-task, or wrong-receipt pointers fail closed.
12. Missing, integer, or unknown task status values are rejected by worker/coordinator validation and by consistently rehashed snapshot and authoritative receipt verification.

## Current-receipt lifecycle rule

For the current local contract, authoritative project identity, receipt ownership, active-pointer equality, and board equality are exact. A receipt remains current only when it is the safe project-owned run receipt selected by `PROJECT/current.json`, at its frozen resolved absolute root, and while `PROJECT/board.json` is canonically identical to the immutable board snapshot in its closure. A legitimate later lifecycle transition, including `open` to `closed`, therefore retires that receipt from current authoritative status; the old receipt remains self-contained immutable history and a new lifecycle snapshot must be issued. Python snapshot-only verification validates the frozen binding's closed shape but does not consult the mutable project pointer and is explicitly labeled `authoritative_board_checked: false`; active project operations and the CLI must use authoritative verification. Absolute-root binding deliberately reduces portability: moving a project requires a newly issued receipt rather than rebasing an old one.

## What this milestone proves

- Machine-readable task discovery and lifecycle transitions can operate across distinct logical Cell identities.
- Work output can be recomputed in a separate process against frozen acceptance criteria by trusted kit code.
- Settlement and reputation can be derived from verified task state.
- A final Receipt can expose a reproducible integrity closure.

## What it does not prove

- Independent human or wallet controllers.
- External adoption or market demand.
- Trustless economic settlement.
- Fiat, stablecoin, Bitcoin, or Ethereum payment.
- Dispute arbitration under subjective acceptance criteria.
- Resistance to collusion among separately controlled parties.
- Cryptographic authorship or resistance to an attacker who can replace the entire project tree and recompute every unsigned artifact; future Agent/controller signatures are required for that authenticity property.
