// SafeSigner — the agent-side wrapper. It asks before it signs:
//   1. off-chain counterparty signals from RPC (does the receiver exist? is it a contract?)
//   2. the vault's own on-chain `check` (blocklist, caps, allowlist, freeze)
// Block → refuse to sign. Warn → tell the human, then submit (the vault queues it).
// Allow → submit. The vault re-runs the same check on-chain, so a wrapper that is
// bypassed or prompt-injected cannot do more than the vault allows.
import { cfg, provider, agentAccount, agentKeyPair, outcomeSummary, say, txLink } from "./lib.mjs";

const EMPTY_CODE = "11111111111111111111111111111111";

export async function counterpartySignals(receiver) {
  const reasons = [];
  let verdict = "Allow";
  try {
    const acc = await provider.viewAccount({ accountId: receiver });
    if (acc.code_hash && acc.code_hash !== EMPTY_CODE) {
      reasons.push(`receiver is a contract (code_hash ${acc.code_hash.slice(0, 8)}…) — paying contracts needs a human`);
      verdict = "Warn";
    }
  } catch {
    reasons.push("receiver account does not exist on-chain");
    verdict = "Block";
  }
  return { verdict, reasons };
}

export async function vaultCheck(receiver, amountYocto) {
  try {
    return await provider.callFunction({
      contractId: cfg.vault,
      method: "check",
      args: { agent: agentKeyPair().getPublicKey().toString(), receiver, amount: amountYocto.toString() },
    });
  } catch (e) {
    // A malformed receiver (e.g. smuggled punctuation) fails JSON decoding in the contract.
    return { verdict: "Block", reasons: [`vault rejected the request: ${String(e.message || e).slice(0, 160)}`] };
  }
}

const rank = { Allow: 0, Warn: 1, Block: 2 };

export async function pay(receiver, amountYocto, memo = "") {
  const off = await counterpartySignals(receiver);
  const on = await vaultCheck(receiver, amountYocto);
  const verdict = rank[off.verdict] >= rank[on.verdict] ? off.verdict : on.verdict;
  const reasons = [...on.reasons, ...off.reasons];
  say(`  [wrapper] pre-check ${receiver} ${amountYocto} yocto → ${verdict}`, reasons.length ? reasons : "");
  if (verdict === "Block") {
    say("  [wrapper] REFUSED to sign. Nothing was sent.");
    return { signed: false, verdict, reasons };
  }
  if (verdict === "Warn") say("  [wrapper] needs a human — submitting so the vault parks it in the approval queue.");
  return { signed: true, verdict, reasons, ...(await rawSpend(receiver, amountYocto, memo)) };
}

/** The bare call, no wrapper. Used by the attack demo to show the vault holds on its own. */
export async function rawSpend(receiver, amountYocto, memo = "") {
  const tx = await agentAccount().callFunctionRaw({
    contractId: cfg.vault,
    methodName: "spend",
    args: { receiver, amount: amountYocto.toString(), memo },
  });
  const s = outcomeSummary(tx);
  for (const e of s.events) say(`  [vault] event ${e.event}`, e.data[0]);
  say(`  [vault] tx ${txLink(s.hash)}`);
  return s;
}
