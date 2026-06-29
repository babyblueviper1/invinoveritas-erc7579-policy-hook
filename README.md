# invinoveritas ERC-7579 policy hook (reference)

**An ERC-7579 hook module that turns an independent, recomputable [`/review`](https://api.babyblueviper.com) verdict into an on-chain, fail-closed pre-execution gate for a modular smart account.**

This is the settlement-side member of the same family as [`invinoveritas-governance-gate-core`](../governance-gate-core) (the framework-agnostic verdict primitive) and [`invinoveritas-metamask-snap`](../metamask-snap) (verdict before you sign). Where those advise *off-chain*, this one is **on-chain enforcement**: an ERC-4337 / ERC-7579 modular account literally cannot execute a covered call unless an independent approve-verdict that binds to that exact call has been recorded and signature-verified.

## Why a smart account wants this

An account abstraction stack already lets you express *who* may act (validators) and *what* a session key may touch (policies). The piece it can't express is the one thing an account cannot self-serve: **an independent second opinion on whether a specific transaction is sound before it fires.** You can't self-issue a verdict a third party trusts. This module makes "an independent party judged *this* action and approved it" a precondition of execution — and makes that judgment recomputable, not asserted.

The AAR / action-receipt crowd is entirely absent from the settlement layer; a pre-sign guard that consumes an independent recomputable verdict is the native fit here.

## The three properties that make it evidence, not an attestation

1. **Recompute, don't trust.** `preCheck` derives the action digest from the *actual* execution the account is about to run — `sha256(abi.encode(chainId, account, mode, executionCalldata))` — never from a value handed in by the caller. The recorded approval must bind to that recomputed digest, or the execution reverts. Change the target, value, calldata, chain, or account and the digest moves; a verdict for one action can't admit another.
2. **Independence.** A verdict only counts if its signing key is in the account's independent-verifier allowlist **and** the signature verifies. A self-signed receipt cannot unlock execution — that is the entire point of an independent gate.
3. **Fail-closed.** No matching, unexpired, unconsumed approve-verdict ⇒ `preCheck` reverts ⇒ the account does not execute. This is the on-chain mirror of `governance-gate-core`'s `failMode: "closed"` for irreversible actions. Verdicts are **single-use** (consumed on admission) so an approval can't be silently replayed.

## Flow

```
1. Build the execution (mode, executionCalldata) you intend to run.
2. digest = hook.computeActionDigest(account, mode, executionCalldata)        // recompute it
3. Get an independent verdict bound to `digest` from /review, expressed as a
   BIP-340 signature over hook.verdictCommitment(account, digest, code, key, expiry).
4. anyone calls hook.recordVerdict(account, digest, code, key, expiry, sig)   // sig is the authority
5. The account executes. The installed hook's preCheck recomputes the digest
   from the real call and admits it exactly once — or reverts, fail-closed.
```

## Signature verification (the honest layering)

The **canonical** invinoveritas proof is the full BIP-340-signed [NIP-01 Nostr event](https://api.babyblueviper.com/ledger), Bitcoin-anchored (OpenTimestamps) and re-verifiable for free at [`/verify-proof`](https://api.babyblueviper.com/verify-proof) — trusting neither the presenter nor us. EVM cannot cheaply recompute a JSON Nostr event id, so **on-chain this module verifies a compact commitment to the same `(actionDigest, verdict, verifier_pubkey)` triple** via an injected [`IVerdictSigVerifier`](src/IVerdictSigVerifier.sol). The off-chain canonical proof remains the source of truth; the on-chain commitment is its enforceable projection, and the binding to the real action is preserved because the digest is **recomputed on-chain**, not trusted.

`IVerdictSigVerifier` abstracts the curve so you wire an audited on-chain **BIP-340 secp256k1** verifier (e.g. `verklegarden/crysol`, `chronicleprotocol/scribe`, or `witnet/elliptic-curve-solidity`) — the same schnorr scheme you verify off-chain. A [`MockVerdictSigVerifier`](test/MockVerdictSigVerifier.sol) is provided for tests.

> The exact preimage a verifier signs is `hook.verdictCommitment(...)`:
> `sha256(abi.encode(VERDICT_DOMAIN, chainId, hookAddress, account, actionDigest, verdictCode, verifierPubkey, expiry))`.
> Only `verdictCode ∈ {1 = approve, 2 = approve_with_concerns}` unlocks execution; `reject`/`review_unavailable` never do.

## Files

| File | What |
|---|---|
| [`src/InvinoveritasPolicyHook.sol`](src/InvinoveritasPolicyHook.sol) | the hook module (ERC-7579 module type 4) |
| [`src/IERC7579Module.sol`](src/IERC7579Module.sol) | minimal ERC-7579 `IModule` / `IHook` interfaces (no external dep) |
| [`src/IVerdictSigVerifier.sol`](src/IVerdictSigVerifier.sol) | pluggable signature-verifier interface (wire a BIP-340 verifier) |
| [`test/InvinoveritasPolicyHook.t.sol`](test/InvinoveritasPolicyHook.t.sol) | Foundry tests: bind/recompute, independence, fail-closed, expiry, replay, delegatecall refusal |
| [`test/MockVerdictSigVerifier.sol`](test/MockVerdictSigVerifier.sol) | test double for the verifier |

## Build & test

```bash
# contract is solc 0.8.26 compile-verified (0 errors / 0 warnings, optimizer on)
forge install foundry-rs/forge-std
forge build
forge test
```

## Scope

Reference / educational. Single-call ERC-7579 executions; batch is out of scope and delegatecall is refused by policy. Not audited — wire an audited BIP-340 verifier and review before any mainnet use. Composes with, and does not replace, your account's validators and session-key policies; it adds the independent-verdict precondition they can't express.

## Related

- [`invinoveritas-governance-gate-core`](../governance-gate-core) — the framework-agnostic verdict primitive
- [`invinoveritas-metamask-snap`](../metamask-snap) — verdict before you sign (EOA / Snaps)
- [preaction-governance-conformance](https://github.com/babyblueviper1/preaction-governance-conformance) — the conformance suite: independent verdict + external Bitcoin-anchored ordering, recomputable from public bytes
