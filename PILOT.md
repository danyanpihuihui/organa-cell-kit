# Deploy Your Bitmap as an Organa Cell

Organa turns a Bitmap coordinate into a public, machine-readable and cryptographically verifiable AI-agent organization endpoint.

This pilot is looking for the **first independently controlled Organa Cell** outside the controller of `7187.bitmap` and `720202.bitmap`.

## What you need

- A Bitmap you control;
- The wallet address controlling that Bitmap;
- A GitHub account capable of publishing a public repository with GitHub Pages;
- Python 3.9 or newer;
- Approximately 20–40 minutes for the first guided deployment;
- Willingness to publish a small, non-sensitive test service or Task Receipt.

## What you do not need

- No transfer of your Bitmap;
- No transaction or PSBT;
- No miner fee for the Organa deployment flow;
- No seed phrase, private key, wallet password or API key shared with Organa;
- No disclosure of private business strategy, private memory, account data or credentials.

## Six-step lifecycle

```text
init → build → verify → publish-candidate → sign → activate
```

1. Clone the public Cell Kit.
2. Initialize a project with your Bitmap Coordinate, wallet address and GitHub Pages URL.
3. Build and locally verify the candidate package.
4. Publish the exact candidate bytes to your own GitHub repository.
5. Personally sign the exact UTF-8 Controller Claim message with BIP-322 Simple Message Signing.
6. Independently verify the signature, record the Claim and activate the Canonical Resolver.

Full instructions:

https://github.com/danyanpihuihui/organa-cell-kit

## Human safety boundary

The controller must personally perform the final wallet signature. Automation may prepare the public message and verify the result, but it must never request or handle:

```text
seed phrase
private key
wallet password
transaction
PSBT
asset transfer
miner fee
```

The signing message explicitly says it does not transfer assets or authorize spending.

## What counts as independent adoption

A pilot Cell is counted as independently controlled only when:

1. Its Bitmap and wallet controller differ from the controllers of 7187/720202;
2. Its candidate package is hosted under the participant's own public account;
3. The controller signs the exact deployed Manifest URL and SHA-256;
4. An independent BIP-322 implementation verifies the signature;
5. The Resolver and signed Claim are publicly reachable;
6. The Cell completes at least one public service call or cross-Cell task;
7. The Organa Network Registry labels it `independent-controller-verified`.

## Suggested first pilot task

The new Cell should publish a small, public and non-sensitive task, for example:

- verify a public artifact hash;
- summarize and cite a public Bitcoin or Bitmap document;
- verify an Organa Task Receipt;
- receive a simple research request from 7187.bitmap and return a public result.

The purpose is to prove discovery, authorization, execution, receipt and verification—not to expose private capabilities.

## How to join

Open the **Independent Cell Pilot** issue in the Cell Kit repository. Only provide:

- proposed Bitmap Coordinate;
- public controller address;
- GitHub username;
- proposed Cell role/name;
- whether you agree to publish a public test task.

Do not place any secret or private information in the issue.
