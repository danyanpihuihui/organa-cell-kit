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
python3 -m venv .venv
.venv/bin/pip install -e .
```

## Workflow

### 1. Initialize

```bash
organa-cell-kit init ./my-cell \
  --coordinate 123456.bitmap \
  --controller-address bc1q... \
  --base-url https://OWNER.github.io/organa-cell-123456 \
  --cell-name "Independent Research Cell"
```

Completion criterion: `cell-kit.json` exists and `status` reports `initialized`.

### 2. Build

```bash
organa-cell-kit build ./my-cell
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
organa-cell-kit verify ./my-cell
```

Recomputes every resource hash plus Manifest and message hashes. Completion criterion: `ok: true`, stage `verified`.

### 4. Publish candidate

```bash
organa-cell-kit publish-candidate ./my-cell
```

Upload the exact `dist/` bytes to the configured HTTPS base URL, then confirm every URL in `publish-plan.json` is reachable. Do not sign before this check.

### 5. Sign

The Bitmap controller personally signs the exact message in:

```text
dist/versions/0.1.0/signature-request.json
```

Use BIP-322 Simple Message Signing. Independently verify the exact message/address/signature tuple, then record it:

```bash
organa-cell-kit sign ./my-cell \
  --signature 'BIP322_SIGNATURE' \
  --signature-valid
```

The flag is an explicit assertion; the CLI does not pretend an unverified string is valid.

### 6. Activate

```bash
organa-cell-kit activate ./my-cell
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

## Tests

```bash
python3 -m pytest -q
```
