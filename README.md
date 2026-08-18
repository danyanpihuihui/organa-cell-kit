# Organa Cell Kit

A reproducible, fail-closed lifecycle tool for deploying public Organa Cells anchored to Bitmap coordinates.

The kit reduces the workflow to:

```text
init → build → verify → publish-candidate → sign → activate
```

It does **not** own, transfer or register a Bitmap. The controller remains responsible for proving control of the chosen Bitmap wallet through an exact BIP-322 message signature.

## Security boundary

- Never requests a seed phrase, private key, password, transaction, PSBT, transfer or miner fee.
- `sign` only records a signature after an independent verifier has validated the exact UTF-8 message, controller address and BIP-322 signature.
- The signed candidate Manifest is immutable. `activate` changes only the Canonical Resolver.
- `publish-candidate` creates a byte-preserving publication plan; it does not silently upload or mutate files.
- Independent control is initially a claim. A third Cell is not counted as external adoption until its distinct controller signature is independently verified.

## Install

Requires Python 3.9+.

```bash
git clone https://github.com/danyanpihuihui/organa-cell-kit.git
cd organa-cell-kit
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/pip install -e .
.venv/bin/organa-cell-kit --help
```

## Workflow

### 1. Initialize

```bash
.venv/bin/organa-cell-kit init ./my-cell \
  --coordinate 123456.bitmap \
  --controller-address bc1qe45ynsz8tkky0nmxfuvjga7z0lwkalfkxkdln6 \
  --base-url https://OWNER.github.io/organa-cell-123456 \
  --cell-name "Independent Research Cell"
```

Completion criterion: `cell-kit.json` exists and `status` reports `initialized`.

### Preflight doctor

At any point after initialization:

```bash
.venv/bin/organa-cell-kit doctor ./my-cell
```

Doctor re-runs artifact integrity checks when a build exists, keeps independent adoption at `claimed-not-verified`, and lists human-only wallet and publication actions. It does not certify controller independence; only the external Network Registry can do that after evidence review.

### 2. Build

```bash
.venv/bin/organa-cell-kit build ./my-cell
```

Produces:

```text
dist/.well-known/organa.json
dist/versions/0.1.0/organa-cell.json
dist/versions/0.1.0/signature-request.json
dist/versions/0.1.0/agent-registry.json
dist/versions/0.1.0/service-registry.json
dist/versions/0.1.0/proof-index.json
dist/versions/0.1.0/disclosure-policy.json
```

Completion criterion: stage is `built`; Manifest remains `pending`.

### 3. Verify

```bash
.venv/bin/organa-cell-kit verify ./my-cell
```

Recomputes every resource hash plus Manifest and message hashes. Completion criterion: `ok: true`, stage `verified`.

### 4. Publish candidate

```bash
.venv/bin/organa-cell-kit publish-candidate ./my-cell
```

Upload the exact `dist/` bytes to the configured HTTPS base URL, then confirm every URL in `publish-plan.json` is reachable. Do not sign before this check.

`sign` and `activate` now enforce this boundary automatically: the kit downloads the public candidate bytes and submits the complete package to the configured production Proof Verifier. If Schema validation, resource hashes, missing/unsafe resources, or cross-references fail—or the verifier is unavailable—the transition fails closed.

### 5. Sign

The Bitmap controller personally signs the exact message in:

```text
dist/versions/0.1.0/signature-request.json
```

Use BIP-322 Simple Message Signing. Independently verify the exact message/address/signature tuple, then record it:

```bash
.venv/bin/organa-cell-kit sign ./my-cell \
  --signature 'BIP322_SIGNATURE'
```

The CLI runs a local `bip322-js` verifier against the exact UTF-8 message, configured controller address and supplied signature. Empty, placeholder or cryptographically invalid signatures fail closed.

### 6. Activate

```bash
.venv/bin/organa-cell-kit activate ./my-cell
```

Completion criterion:

- Canonical Resolver `activation_status: active`;
- `controller_claim.status: signed`;
- `current_manifest.lifecycle_status: live`;
- Manifest bytes unchanged from before signing.

## Third-party adoption gate

A Cell counts as independent external adoption only when all are true:

1. The Bitmap belongs to a controller distinct from 7187/720202;
2. The controller signs the exact deployed Manifest hash;
3. An independent BIP-322 verifier returns valid;
4. Public Resolver and Claim are reachable;
5. The new Cell completes at least one public task or service call;
6. The Organa Network Registry labels it `independent-controller-verified`.

## Independent Cell pilot

Want to deploy the first externally controlled Organa Cell? Read [PILOT.md](PILOT.md), then open the Independent Cell Pilot issue. Never post a seed phrase, private key, password, signature secret, transaction or PSBT.

## Cross-controller dq/n6 pilot handoff

Create a portable, unexecuted pilot workspace for `dq` (Requester), `n6` (Worker), and the initially local `organa-trusted-verifier-v1`:

```bash
organa-cell-kit pilot-init /path/to/dq-n6-pilot \
  --fixture-source /path/to/720202.bitmap/versions/0.3.0
```

Fill every required Bitmap coordinate, endpoint, and signing public-key placeholder in `pilot-config.json`. The preflight fails closed until real values are supplied. Then use distinct filesystems/processes:

```bash
organa-cell-kit pilot-requester-publish /path/to/dq-n6-pilot
organa-cell-kit pilot-worker-run /path/to/n6-workspace \
  --public-board /imported/public-board-...
organa-cell-kit pilot-verifier-settle /path/to/local-verifier-workspace \
  --public-board /imported/public-board-... \
  --worker-submission /imported/submission-...
```

The generated UTF-8 BOM Chinese README and `messages/send-to-dq.md` / `messages/send-to-n6.md` contain exact handoff instructions. Artifacts are closed-schema and hash-bound to declared role identity, Bitmap coordinate, endpoint, and signing public key. Until a real signature adapter is assigned, `signature` remains null and the package explicitly says the binding is **not** a cryptographic signature. The initial verifier is user/Organa-controlled local trusted code, not an independent third party. Settlement is `ORGANA_TEST_CREDIT` only with `real_payment: false`; production pilot folders should remain awaiting external artifacts, while rehearsals belong in separate directories.

### dq 7187 / n6 720202 identity preparation (Verifier deferred)

The production preparation config is `config/pilot-identity-production.json` (and the same closed-schema template is in `config/pilot-identity-template.json`). It intentionally contains only the established public mapping:

- Requester `dq` → `7187.bitmap` → `bc1p4wz46fk45hp5crm56k4emxelln9tpuc76frn2duumlyecr9ft35qjxmadq` (`existing public 7187 claim`)
- Worker `n6` → `720202.bitmap` → `bc1qe45ynsz8tkky0nmxfuvjga7z0lwkalfkxkdln6` (`existing public 720202 claim`)
- Verifier status: `pending-registration`; no verifier address is consumed or claimed.

Prepare only the two identity documents and BIP-322 message requests:

```bash
organa-cell-kit pilot-identity-prepare /path/to/dq-n6-pilot \
  --config config/pilot-identity-production.json
```

The result remains `awaiting-human-signature-and-verifier-registration`, with `production_ready=false`, `settled=false`, and all `claims_scope` flags false. After preparation, a human may sign only the Requester and Worker messages with their corresponding wallets. This is message signing only—no transaction, transfer, PSBT, fee, or computer-use wallet confirmation. Do not claim pilot execution or settlement until the deferred Verifier is registered and the human signatures are independently handled.

### Three-role Artifact identity primitives

`organa_cell_kit.pilot_identity` also provides the isolated Artifact identity layer for Requester, Worker, and Verifier:

- `generate_artifact_key(...)` creates a distinct Ed25519 operational key; private raw keys stay under `.private/artifact-keys/` with mode `0600`, while immutable public `artifact-key.json` files contain neither private data nor private paths.
- `create_artifact_authorization_request(...)` verifies an existing BIP-322 wallet identity claim and binds its wallet, Bitmap, pilot, role, Agent ID, and exact Ed25519 public key into a new human-signable request.
- `record_artifact_authorization(...)` independently verifies and immutably records that human BIP-322 authorization.
- `sign_json_artifact(...)` and `verify_signed_json_artifact(...)` sign and verify canonical JSON objects only with the authorized matching role/key.

All schemas are closed and tampering, role/key swaps, unsafe paths, and symlinked key/authorization files fail closed. The wallet step remains manual. Its authority is explicitly limited to JSON Artifact signing: it grants no Bitcoin payment, spending, transaction, PSBT, fee, or miner-payment authority. These primitives are not yet integrated into the production loop.


```bash
python3 -m pytest -q
```

## Local multi-agent production loop demo

Run the built-in deterministic demo:

```bash
organa-cell-kit run-demo ./local-production-demo
```

Or run the loop against a real Organa package directory containing `organa-cell.json` and its declared resources:

```bash
organa-cell-kit run-demo ./local-production-demo \
  --target-package /path/to/versioned-organa-package
```

The public board publishes both available workers and the complete hash-frozen rewarded task. A worker transition (`worker-run`, also available as `worker_execute_from_board`) reads `board.json` itself, discovers an open compatible task, writes its own persisted acceptance and worker result, and performs the real package work before the coordinator starts. The coordinator consumes those artifacts, copies the package into an immutable task/attempt run directory, reruns a fixed `organa-cell-kit` verifier in a separate Python process, settles only `ORGANA_TEST_CREDIT` from a persisted prestate to poststate, validates the full reputation JSONL chain, and atomically promotes `current.json` only after a hash-closed receipt verifies. CLI output returns the immutable `receipt_path` under `runs/`.

The verifier is trusted installed code outside the worker package; worker-provided `verify.py` files and verifier paths are ignored. Receipts bind the verifier ID, version, exact expected installed absolute path, and source hash, all three distinct Agent IDs and valid distinct `*.bitmap` coordinates, initial/final credit ledgers, exact settlement, complete reputation event count and chain head, and all linked artifacts. They also contain a closed, self-hashed `project_binding` with the resolved creation-time `absolute_root` and the fixed `board_relative_path: "board.json"`. The receipt self-hash provides deterministic integrity closure only; it is not a signature and does not establish cryptographic authorship. Authoritative `project_root` verification first requires the supplied receipt itself to be the safe regular, non-symlink `PROJECT/runs/<non-hidden-run>/receipt.json` selected by a closed safe `PROJECT/current.json` pointer whose normalized relative path resolves to that exact receipt and whose `task_hash` equals the receipt closure. It then applies the receipt's absolute-root disclosure and exact `PROJECT/board.json` checks as additional local consistency controls. Directory symlink aliases resolving to the same project and receipt pass, while symlinked receipt/run/current/board files are rejected. This absolute identity binding and the absolute verifier path intentionally reduce receipt portability in exchange for truthful local-project identity. Both the receipt and `verification.json` must assert `separate_process_verifier_rerun: true` exactly. All hash-closed artifacts use closed, versioned schemas: unknown or missing fields are rejected, and extensibility requires a schema-version change. Task-record `status` is a required string with the current contract enum `{ "open" }`; publication, worker discovery, coordinator execution, snapshot verification, and authoritative verification all reject missing, non-string, or unknown values. Source packages and linked receipt artifacts reject symlinks and root escapes. Organa manifests require the supported schema version, a valid coordinate, non-empty resources, normalized safe paths, and lowercase `sha256:<64 hex>` digests.

Prepare artifacts without settlement, then run the explicit worker transition if desired:

```bash
organa-cell-kit run-demo ./local-production-demo --prepare-only
organa-cell-kit worker-run ./local-production-demo \
  --board ./local-production-demo/board.json \
  --worker-id local-worker-alpha \
  --verifier-id local-verifier-alpha \
  --verifier-coordinate 100003.bitmap \
  --source-package ./local-production-demo/source-package
```

This remains explicitly a **same-controller simulation**, not evidence of independent external adoption. `separate_process_verifier_rerun` means a separate local process executing trusted kit code, not an independently controlled external verifier. The structured receipt contract sets every excluded claim to `false`: **fiat payment, cryptocurrency payment, on-chain transfer, escrow, financial claim, external adoption, and independent controller**. Settlement mode is `local-test-credit`, `real_payment` is false, and test credits are local accounting units only: **no real payment, asset transfer, transaction, PSBT, fee, or miner payment occurs**.

Inspect a receipt directly:

```bash
organa-cell-kit verify-receipt ./local-production-demo \
  --receipt ./local-production-demo/runs/<task-attempt>/receipt.json
```

The CLI always treats the project-owned current receipt and `PROJECT/board.json` as authoritative. It requires the supplied receipt to be exactly the safe non-symlink `PROJECT/runs/<non-hidden-run>/receipt.json` named by a safe closed-schema `PROJECT/current.json`; the pointer path must be normalized relative, remain under `PROJECT/runs`, resolve to that exact receipt, and carry the same task hash as the receipt closure. `current.json` is deliberately validated outside the receipt hash closure because it is the mutable active pointer; including it would create a circular dependency. The verifier then validates the frozen project binding and exact authoritative board/task equality. Successful CLI output therefore includes `authoritative_board_checked: true`. The Python `verify_receipt(receipt_path)` API remains available for historical, self-contained snapshot verification: it validates the closed receipt and local snapshots without consulting `current.json`, so it reports `authoritative_board_checked: false`.

This is a local integrity milestone, not cryptographic authenticity. An attacker allowed to replace an entire project tree and recompute every unsigned artifact is outside this threat model; future Agent/controller signatures are required to establish authorship and resistance to full-tree replacement.

For this local contract, a receipt is considered **current only while the authoritative board remains byte-semantically/canonically equal to its immutable board snapshot**. A later lifecycle transition such as changing a task from `open` to `closed` intentionally makes that receipt fail current authoritative verification; retain the receipt as immutable history and issue a new lifecycle snapshot rather than rewriting the receipt-local board.
