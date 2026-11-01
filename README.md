# Tollgate — give an AI agent money, not the keys

Built at **NEAR HACKATHON** (Nov 2026) · track: **AI Security & Defense** (`security`) · also fits `agents`.

An AI agent that pays for APIs, compute or data needs to sign transactions. Handing it a
full-access key means one prompt injection drains the wallet. Tollgate is a NEAR contract
that holds the funds and gives each agent a **function-call access key that can only call
`spend` on the vault**. Every spend runs a policy check on-chain:

| verdict | when | what happens |
|---|---|---|
| **Allow** | known agent, receiver not blocklisted, within per-tx and rolling-24h caps, on allowlist (if required) | NEAR is transferred, `spent` event |
| **Warn** | over a cap, or receiver not on the agent's allowlist | parked in an approval queue for the human owner, `queued` event |
| **Block** | receiver on the shared blocklist (with evidence), agent frozen, unknown key, zero amount, vault itself | nothing moves, `blocked` event with reasons — the call does **not** revert, so the attempt stays on record |

An off-chain **SafeSigner** wrapper asks first (RPC counterparty signals + the vault's `check`
view) and refuses to sign on Block. The vault re-runs the same check, so a bypassed or
injected wrapper gains nothing.

## What NEAR does here

- **Function-call access keys** are the core: the agent's key is installed on the vault account
  by the contract itself (`add_agent` → `add_access_key` with method `spend` only and a 0.25 NEAR
  gas allowance). The protocol, not our code, stops that key from transferring NEAR, adding keys
  or calling any other method. The key's public key *is* the agent's identity
  (`env::signer_account_pk()`), so per-agent limits need no extra registry.
- **NEP-297 events** give an audit trail every explorer and indexer can read.
- Named accounts make the blocklist readable (`drainer.someone.testnet`, not a hex blob).

## Limits of the agent key (read this)

- It **can** call `spend(receiver, amount, memo)` on the vault — nothing else. Calling `check`
  as a view needs no key.
- It **cannot** transfer NEAR directly, add or delete keys, deploy code, or call other contracts
  (L3 of the demo shows the RPC refusing: `Access key requires full access`).
- Its gas allowance is finite (0.25 NEAR). When it runs out the key stops working — a second,
  protocol-level brake, but also a way an agent can lock itself out. Top it up by revoking and
  re-adding the agent.
- Within its caps it can still pay any non-blocklisted receiver. Turn on `allowlist_only` for
  agents that should only ever pay known vendors.
- The owner's full-access key is the real root of trust. Keep it off the agent's machine.

## Run it (testnet, ~3 minutes)

Requirements: Node 20+, `near` CLI ([near-cli-rs](https://github.com/near/near-cli-rs)), Rust +
`wasm32-unknown-unknown` + [cargo-near](https://github.com/near/cargo-near) only if you rebuild the contract.

1. **Use the deployed demo vault** — see `demo.config.json` (`tollgate-1101-2897.testnet`). To run
   the scripts against it you need the owner key; to reproduce from scratch, do steps 2–4.
2. **Create two testnet accounts** (vault + owner) and two receivers:
   `near account create-account sponsor-by-faucet-service <vault>.testnet autogenerate-new-keypair save-to-legacy-keychain network-config testnet create`
   (same for `<owner>.testnet`; receivers as sub-accounts of the owner with `fund-myself`). Put the names in `demo.config.json`.
3. **Build and deploy** — `cd contract && cargo near build non-reproducible-wasm --no-abi` → see `target/near/tollgate.wasm`, then
   `near contract deploy <vault>.testnet use-file target/near/tollgate.wasm with-init-call new json-args '{"owner":"<owner>.testnet"}' prepaid-gas '30 Tgas' attached-deposit '0 NEAR' network-config testnet sign-with-legacy-keychain send`.
4. **Set up the agent** — `cd agent && npm install && npm run setup` → see the agent's public key and `list_agents` output (key installed, limits 0.3 NEAR/tx, 0.5 NEAR/24h, drainer reported).
5. **Run the attack** — `npm run attack` → see four layers in the log (`demo-log/attack-demo-*.log`):
   L1 wrapper refuses · L2 raw `spend` → `blocked` event, no transfer · L3 plain transfer → `Access key requires full access` · L4 0.4 NEAR → `queued`; then the honest 0.1 NEAR purchase → `spent`.
6. **Be the human** — `npm run approve` lists the queue, `npm run approve -- approve 0` sends it, `npm run approve -- freeze` is the kill switch.
7. **Unit tests** — `cd contract && cargo test` → 12 tests (caps, window reset, blocklist with evidence, allowlist, freeze, unknown key, outside caller, approval, stale approval vs. later report, agent cannot change its own policy).

Windows notes: if `cargo test` fails building `aws-lc-sys`, set `AWS_LC_SYS_PREBUILT_NASM=1`. If `wasm-opt` cannot open the
wasm under a non-ASCII path, set `CARGO_TARGET_DIR` to an ASCII path. ABI generation is skipped (`--no-abi`) because the
host cdylib does not link on MSVC.

## Recorded run

`demo-log/` holds the log of the run used in the demo video. Transactions are on
[testnet nearblocks](https://testnet.nearblocks.io/address/tollgate-1101-2897.testnet).

## Layout

```
contract/src/lib.rs     the vault: policy check, spend, approval queue, blocklist, events
contract/src/tests.rs   12 unit tests
agent/safe-signer.mjs   wrapper: RPC counterparty signals + vault check, refuses on Block
agent/attack-demo.mjs   prompt-injected agent vs. four layers
agent/setup-demo.mjs    owner installs the agent key, reports the drainer
agent/approve.mjs       owner approves / rejects / freezes
```

## Built with AI (disclosure, per rule Q-005)

All code in this repository was written during the hackathon (from 2026-11-01) with an AI coding
agent (Claude Code, Anthropic) directing and writing the contract, tests, scripts and this README,
under the author's review. No pre-hackathon code is reused. Libraries: `near-sdk` 5.30 (Rust),
`near-api-js` 7.4 (JS); tools: `cargo-near` 0.22, `near-cli-rs` 0.30.

## License

MIT — see `LICENSE`.
