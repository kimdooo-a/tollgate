// The human's side of the queue. Signed with the owner's key, never the agent's.
//   node approve.mjs            → list pending
//   node approve.mjs approve 0  → send it
//   node approve.mjs reject 0   → drop it
//   node approve.mjs freeze     → kill switch for the demo agent
import { cfg, provider, ownerAccount, agentKeyPair, outcomeSummary, say, txLink } from "./lib.mjs";

const [cmd, id] = process.argv.slice(2);
const owner = ownerAccount();
const call = async (methodName, args) => {
  const s = outcomeSummary(await owner.callFunctionRaw({ contractId: cfg.vault, methodName, args }));
  for (const e of s.events) say(`[vault] event ${e.event}`, e.data[0]);
  say(s.failure ? `FAILED ${s.failure}` : "ok", txLink(s.hash));
};
if (cmd === "approve" || cmd === "reject") await call(cmd, { id: Number(id) });
else if (cmd === "freeze" || cmd === "unfreeze") await call(cmd, { public_key: agentKeyPair().getPublicKey().toString() });
say("pending:", await provider.callFunction({ contractId: cfg.vault, method: "list_pending", args: {} }));
