// One-time setup, signed by the human owner:
//   - create the agent's key locally and install it on the vault as a function-call key
//     (via add_agent — the contract adds the key to its own account)
//   - allowlist the shop, file a blocklist report against the drainer
import { cfg, provider, ownerAccount, agentKeyPair, outcomeSummary, say, txLink, near } from "./lib.mjs";

const owner = ownerAccount();
const kp = agentKeyPair({ create: true });
const pk = kp.getPublicKey().toString();
say(`agent public key: ${pk}`);

const agents = await provider.callFunction({ contractId: cfg.vault, method: "list_agents", args: {} });
if (!agents.some((a) => a.public_key === pk)) {
  const tx = await owner.callFunctionRaw({
    contractId: cfg.vault,
    methodName: "add_agent",
    args: {
      public_key: pk,
      policy: { per_tx_max: near(0.3).toString(), daily_max: near(0.5).toString(), allowlist_only: false, label: "research-agent" },
    },
    gas: 50_000_000_000_000n,
  });
  const s = outcomeSummary(tx);
  say("add_agent", s.failure || "ok", txLink(s.hash));
}

const report = await provider.callFunction({ contractId: cfg.vault, method: "get_report", args: { receiver: cfg.drainer } });
if (!report) {
  const tx = await owner.callFunctionRaw({
    contractId: cfg.vault,
    methodName: "report",
    args: { receiver: cfg.drainer, evidence: "Known drainer: asked agents to 'verify wallet' by sending funds (demo report)." },
  });
  say("report drainer", outcomeSummary(tx).failure || "ok");
}

say("agents:", await provider.callFunction({ contractId: cfg.vault, method: "list_agents", args: {} }));
