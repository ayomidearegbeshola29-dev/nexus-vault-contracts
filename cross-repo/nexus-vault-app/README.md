# nexus-vault-app side of issue #53 (cross-repo vector parity)

This directory contains the artifacts that must be added to
[`nexus-vault/nexus-vault-app`](https://github.com/nexus-vault/nexus-vault-app) so the
`verify_receipt` Merkle vectors stay in sync with `nexus-vault-contracts`. It is
the mirror of the `vector-parity` job that lives in
`nexus-vault-contracts/.github/workflows/ci.yml`.

## What to do (open a PR in nexus-vault-app)

1. **Vendor the canonical vectors.** Copy
   `contracts/receipt-anchor/merkle-vectors.json` from `nexus-vault-contracts` into
   `packages/sdk/merkle-vectors.json` **byte-for-byte** (it is the single source
   of truth owned by `nexus-vault-contracts`). Commit the file's content hash:

   ```sh
   sha256sum packages/sdk/merkle-vectors.json > packages/sdk/merkle-vectors.json.sha256
   ```

   The SDK should import this JSON directly instead of maintaining its own copy
   or generating `vectors.ts` from a divergent source.

2. **Add the CI job.** Drop
   `.github/workflows/vector-parity.yml` (this folder) into
   `nexus-vault-app/.github/workflows/vector-parity.yml`.

3. **Pin the source ref.** In the nexus-vault-app repo settings, add a repository
   variable `ACCELSA_CONTRACTS_REF` set to the `nexus-vault-contracts` commit SHA or
   tag you want to track (do not leave it tracking `main` long-term).

4. **Open the PR** and link it back to
   [nexus-vault-contracts issue #53](https://github.com/nexus-vault/nexus-vault-contracts/issues/53).

## How the two halves fit together

| Repo            | Owns                                  | Checks against                          |
| --------------- | ------------------------------------- | --------------------------------------- |
| nexus-vault-contracts | `merkle-vectors.json` (canonical)  | nexus-vault-app's `packages/sdk/merkle-vectors.json` |
| nexus-vault-app     | vendored `packages/sdk/merkle-vectors.json` | nexus-vault-contracts' canonical `merkle-vectors.json` |

Each repo fails its build when its copy's hash differs from the other's. A push
to `nexus-vault-contracts/main` also fires a `repository_dispatch` that re-runs the
nexus-vault-app job, and a daily cron catches silent staleness on either side. See
`docs/CONFORMANCE.md` in `nexus-vault-contracts` for the full mechanism and its
limits.
