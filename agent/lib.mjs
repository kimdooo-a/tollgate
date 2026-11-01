// Shared helpers: config, keys, RPC, event parsing, logging.
import { readFileSync, existsSync, writeFileSync, mkdirSync, appendFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Account, JsonRpcProvider, KeyPair } from "near-api-js";

const here = dirname(fileURLToPath(import.meta.url));
export const ROOT = join(here, "..");
export const cfg = JSON.parse(readFileSync(join(ROOT, "demo.config.json"), "utf8"));
export const provider = new JsonRpcProvider({ url: process.env.RPC_URL || cfg.rpcUrl });

const AGENT_KEY_FILE = join(here, ".agent-key.json");

/** Full-access key of an account, from the near-cli legacy keychain (~/.near-credentials). */
export function legacyKey(accountId) {
  const p = join(process.env.NEAR_CREDENTIALS_DIR || join(homedir(), ".near-credentials"), cfg.network, `${accountId}.json`);
  if (!existsSync(p)) throw new Error(`no key for ${accountId} at ${p}`);
  return JSON.parse(readFileSync(p, "utf8")).private_key;
}

/** The agent's key. It is created locally and only ever installed as a function-call key. */
export function agentKeyPair({ create = false } = {}) {
  if (existsSync(AGENT_KEY_FILE)) return KeyPair.fromString(JSON.parse(readFileSync(AGENT_KEY_FILE, "utf8")).secret);
  if (!create) throw new Error("no agent key yet — run `npm run setup` first");
  const kp = KeyPair.fromRandom("ed25519");
  writeFileSync(AGENT_KEY_FILE, JSON.stringify({ public: kp.getPublicKey().toString(), secret: kp.toString() }, null, 2));
  return kp;
}

export const ownerAccount = () => new Account(cfg.owner, provider, legacyKey(cfg.owner));
/** The agent signs as the vault account, but with its scoped key only. */
export const agentAccount = () => new Account(cfg.vault, provider, agentKeyPair().toString());

export const NEAR = 10n ** 24n;
export const near = (x) => (BigInt(Math.round(Number(x) * 1e6)) * NEAR) / 1_000_000n;

/** Pull NEP-297 events and failures out of a transaction outcome. */
export function outcomeSummary(tx) {
  const events = [];
  for (const r of tx.receipts_outcome || []) {
    for (const l of r.outcome.logs || []) {
      if (l.startsWith("EVENT_JSON:")) events.push(JSON.parse(l.slice(11)));
    }
  }
  const failure = tx.status && tx.status.Failure ? JSON.stringify(tx.status.Failure) : null;
  return { hash: tx.transaction?.hash, events, failure };
}

let logFile = null;
export function startLog(name) {
  mkdirSync(join(ROOT, "demo-log"), { recursive: true });
  logFile = join(ROOT, "demo-log", `${name}-${new Date().toISOString().replace(/[:.]/g, "-")}.log`);
  return logFile;
}
export function say(...parts) {
  const line = parts.map((p) => (typeof p === "string" ? p : JSON.stringify(p))).join(" ");
  console.log(line);
  if (logFile) appendFileSync(logFile, line + "\n");
}
export const txLink = (h) => (h ? cfg.explorer + h : "(no tx)");
