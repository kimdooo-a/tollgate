//! Tollgate — an on-chain spending policy vault for AI agents.
//!
//! The vault account holds the funds. Each agent gets a *function-call access key*
//! on the vault account that may only call `spend`. The key itself is the agent's
//! identity (`env::signer_account_pk()`), so an agent can never transfer NEAR,
//! add keys or call any other method — the protocol enforces that, not the agent.
//!
//! Every `spend` goes through `check()`, which returns Allow / Warn / Block plus
//! reasons. Allow transfers immediately, Warn parks the request in a queue for the
//! human owner, Block refuses and records why. All three emit NEP-297 events, so
//! the audit trail survives even when nothing moves.

use near_sdk::json_types::U128;
use near_sdk::store::{IterableMap, LookupMap};
use near_sdk::{
    env, log, near, require, AccountId, Allowance, BorshStorageKey, NearToken, PanicOnDefault,
    Promise, PublicKey,
};

/// One day in nanoseconds — the rolling window for the daily cap.
const DAY_NS: u64 = 86_400 * 1_000_000_000;
/// Gas allowance attached to each agent key (0.25 NEAR). When it runs out the
/// key stops working, which is a second, protocol-level brake.
const KEY_GAS_ALLOWANCE: NearToken = NearToken::from_millinear(250);

#[derive(BorshStorageKey)]
#[near]
enum StorageKey {
    Agents,
    Blocklist,
    Pending,
    Allowlist { agent_hash: Vec<u8> },
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug, PartialEq)]
pub enum Verdict {
    Allow,
    Warn,
    Block,
}

#[near(serializers = [json, borsh])]
#[derive(Clone, Debug)]
pub struct PolicyInput {
    /// Largest single payment that goes through without a human.
    pub per_tx_max: U128,
    /// Total the agent may move in a rolling 24h window without a human.
    pub daily_max: U128,
    /// If true, receivers outside the agent's allowlist are Warn (human decides).
    pub allowlist_only: bool,
    /// Human-readable label shown in events and the dashboard.
    pub label: String,
}

#[near(serializers = [borsh])]
pub struct Agent {
    pub label: String,
    pub per_tx_max: u128,
    pub daily_max: u128,
    pub allowlist_only: bool,
    pub frozen: bool,
    pub window_start: u64,
    pub spent_in_window: u128,
    pub allowlist: LookupMap<AccountId, bool>,
}

#[near(serializers = [json])]
pub struct AgentView {
    pub public_key: PublicKey,
    pub label: String,
    pub per_tx_max: U128,
    pub daily_max: U128,
    pub allowlist_only: bool,
    pub frozen: bool,
    pub spent_in_window: U128,
}

#[near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct Report {
    pub reporter: AccountId,
    pub evidence: String,
    pub at: u64,
}

#[near(serializers = [json, borsh])]
#[derive(Clone)]
pub struct PendingSpend {
    pub id: u64,
    pub agent: PublicKey,
    pub receiver: AccountId,
    pub amount: U128,
    pub memo: String,
    pub reasons: Vec<String>,
    pub at: u64,
}

#[near(serializers = [json])]
pub struct CheckResult {
    pub verdict: Verdict,
    pub reasons: Vec<String>,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Tollgate {
    owner: AccountId,
    /// Accounts allowed to file blocklist reports (the owner always may).
    reporters: Vec<AccountId>,
    agents: LookupMap<PublicKey, Agent>,
    agent_keys: Vec<PublicKey>,
    blocklist: LookupMap<AccountId, Report>,
    pending: IterableMap<u64, PendingSpend>,
    next_id: u64,
}

#[near]
impl Tollgate {
    #[init]
    pub fn new(owner: AccountId) -> Self {
        Self {
            owner,
            reporters: vec![],
            agents: LookupMap::new(StorageKey::Agents),
            agent_keys: vec![],
            blocklist: LookupMap::new(StorageKey::Blocklist),
            pending: IterableMap::new(StorageKey::Pending),
            next_id: 0,
        }
    }

    // ───────────────────────── owner: agents ─────────────────────────

    /// Register an agent and install its scoped key on this vault account.
    /// The key may call only `spend` on this contract and carries a small gas
    /// allowance — it cannot transfer, add keys, or touch any other method.
    pub fn add_agent(&mut self, public_key: PublicKey, policy: PolicyInput) -> Promise {
        self.assert_owner();
        require!(!self.agents.contains_key(&public_key), "agent already registered");
        let agent_hash = env::sha256(&borsh_bytes(&public_key));
        self.agents.insert(
            public_key.clone(),
            Agent {
                label: policy.label.clone(),
                per_tx_max: policy.per_tx_max.0,
                daily_max: policy.daily_max.0,
                allowlist_only: policy.allowlist_only,
                frozen: false,
                window_start: env::block_timestamp(),
                spent_in_window: 0,
                allowlist: LookupMap::new(StorageKey::Allowlist { agent_hash }),
            },
        );
        self.agent_keys.push(public_key.clone());
        emit("agent_added", &format!(r#"{{"agent":"{}","label":{}}}"#, pk_str(&public_key), json_str(&policy.label)));
        Promise::new(env::current_account_id()).add_access_key_allowance_with_nonce(
            public_key,
            Allowance::limited(KEY_GAS_ALLOWANCE).unwrap(),
            env::current_account_id(),
            "spend".to_string(),
            0,
        )
    }

    pub fn set_policy(&mut self, public_key: PublicKey, policy: PolicyInput) {
        self.assert_owner();
        let a = self.agent_mut(&public_key);
        a.label = policy.label;
        a.per_tx_max = policy.per_tx_max.0;
        a.daily_max = policy.daily_max.0;
        a.allowlist_only = policy.allowlist_only;
        emit("policy_set", &format!(r#"{{"agent":"{}"}}"#, pk_str(&public_key)));
    }

    pub fn allow_receiver(&mut self, public_key: PublicKey, receiver: AccountId) {
        self.assert_owner();
        self.agent_mut(&public_key).allowlist.insert(receiver, true);
    }

    /// Kill switch: the key stays installed but every spend is Block.
    pub fn freeze(&mut self, public_key: PublicKey) {
        self.assert_owner();
        self.agent_mut(&public_key).frozen = true;
        emit("agent_frozen", &format!(r#"{{"agent":"{}"}}"#, pk_str(&public_key)));
    }

    pub fn unfreeze(&mut self, public_key: PublicKey) {
        self.assert_owner();
        self.agent_mut(&public_key).frozen = false;
        emit("agent_unfrozen", &format!(r#"{{"agent":"{}"}}"#, pk_str(&public_key)));
    }

    /// Remove the agent and delete its key from the vault account.
    pub fn revoke_agent(&mut self, public_key: PublicKey) -> Promise {
        self.assert_owner();
        require!(self.agents.remove(&public_key).is_some(), "unknown agent");
        self.agent_keys.retain(|k| k != &public_key);
        emit("agent_revoked", &format!(r#"{{"agent":"{}"}}"#, pk_str(&public_key)));
        Promise::new(env::current_account_id()).delete_key(public_key)
    }

    // ───────────────────────── shared blocklist ─────────────────────────

    pub fn add_reporter(&mut self, account: AccountId) {
        self.assert_owner();
        if !self.reporters.contains(&account) {
            self.reporters.push(account);
        }
    }

    /// File a report against a receiver. Evidence is required: a blocklist
    /// entry without a reason is a rumor, not a signal.
    pub fn report(&mut self, receiver: AccountId, evidence: String) {
        let who = env::predecessor_account_id();
        require!(who == self.owner || self.reporters.contains(&who), "not a reporter");
        require!(evidence.trim().len() >= 10, "evidence required (>= 10 chars)");
        emit("reported", &format!(r#"{{"receiver":"{}","reporter":"{}"}}"#, receiver, who));
        self.blocklist.insert(receiver, Report { reporter: who, evidence, at: env::block_timestamp() });
    }

    pub fn clear_report(&mut self, receiver: AccountId) {
        self.assert_owner();
        self.blocklist.remove(&receiver);
    }

    // ───────────────────────── the check ─────────────────────────

    /// Pure policy evaluation. Agents (and their off-chain wrappers) call this
    /// view first; `spend` calls it again on-chain, so skipping the view buys
    /// the agent nothing.
    pub fn check(&self, agent: PublicKey, receiver: AccountId, amount: U128) -> CheckResult {
        let mut reasons = vec![];
        let Some(a) = self.agents.get(&agent) else {
            return CheckResult { verdict: Verdict::Block, reasons: vec!["unknown agent key".into()] };
        };
        if a.frozen {
            return CheckResult { verdict: Verdict::Block, reasons: vec!["agent is frozen by owner".into()] };
        }
        if let Some(r) = self.blocklist.get(&receiver) {
            return CheckResult {
                verdict: Verdict::Block,
                reasons: vec![format!("receiver on shared blocklist (reported by {}): {}", r.reporter, r.evidence)],
            };
        }
        if receiver == env::current_account_id() {
            return CheckResult { verdict: Verdict::Block, reasons: vec!["receiver is the vault itself".into()] };
        }
        if amount.0 == 0 {
            return CheckResult { verdict: Verdict::Block, reasons: vec!["zero amount".into()] };
        }
        if amount.0 > a.per_tx_max {
            reasons.push(format!("amount {} exceeds per-tx max {}", amount.0, a.per_tx_max));
        }
        let spent = self.spent_now(a);
        if spent.saturating_add(amount.0) > a.daily_max {
            reasons.push(format!("would exceed 24h cap ({} spent + {} > {})", spent, amount.0, a.daily_max));
        }
        if a.allowlist_only && !a.allowlist.contains_key(&receiver) {
            reasons.push(format!("receiver {} not on this agent's allowlist", receiver));
        }
        let verdict = if reasons.is_empty() { Verdict::Allow } else { Verdict::Warn };
        CheckResult { verdict, reasons }
    }

    // ───────────────────────── agent entry point ─────────────────────────

    /// The only method an agent key can call. Returns the verdict it acted on.
    pub fn spend(&mut self, receiver: AccountId, amount: U128, memo: Option<String>) -> CheckResult {
        // Agent keys live on the vault account, so the call must come from it.
        require!(env::predecessor_account_id() == env::current_account_id(), "spend must be signed by an agent key on the vault");
        let agent = env::signer_account_pk();
        let memo = memo.unwrap_or_default();
        let res = self.check(agent.clone(), receiver.clone(), amount);
        match res.verdict {
            Verdict::Allow => {
                self.record_spend(&agent, amount.0);
                emit("spent", &format!(r#"{{"agent":"{}","receiver":"{}","amount":"{}","memo":{}}}"#, pk_str(&agent), receiver, amount.0, json_str(&memo)));
                let _ = Promise::new(receiver).transfer(NearToken::from_yoctonear(amount.0));
            }
            Verdict::Warn => {
                let id = self.next_id;
                self.next_id += 1;
                self.pending.insert(id, PendingSpend {
                    id, agent: agent.clone(), receiver: receiver.clone(), amount, memo,
                    reasons: res.reasons.clone(), at: env::block_timestamp(),
                });
                emit("queued", &format!(r#"{{"id":{},"agent":"{}","receiver":"{}","amount":"{}","reasons":{}}}"#, id, pk_str(&agent), receiver, amount.0, json_list(&res.reasons)));
            }
            Verdict::Block => {
                // No panic: a reverted call would erase the evidence of the attempt.
                emit("blocked", &format!(r#"{{"agent":"{}","receiver":"{}","amount":"{}","reasons":{}}}"#, pk_str(&agent), receiver, amount.0, json_list(&res.reasons)));
            }
        }
        res
    }

    // ───────────────────────── owner: approval queue ─────────────────────────

    pub fn approve(&mut self, id: u64) -> Promise {
        self.assert_owner();
        let p = self.pending.remove(&id).unwrap_or_else(|| env::panic_str("no such pending spend"));
        // The blocklist still wins over a human click made before a report landed.
        require!(!self.blocklist.contains_key(&p.receiver), "receiver was blocklisted after queuing");
        if self.agents.contains_key(&p.agent) {
            self.record_spend(&p.agent, p.amount.0);
        }
        emit("approved", &format!(r#"{{"id":{},"receiver":"{}","amount":"{}"}}"#, id, p.receiver, p.amount.0));
        Promise::new(p.receiver).transfer(NearToken::from_yoctonear(p.amount.0))
    }

    pub fn reject(&mut self, id: u64) {
        self.assert_owner();
        require!(self.pending.remove(&id).is_some(), "no such pending spend");
        emit("rejected", &format!(r#"{{"id":{}}}"#, id));
    }

    // ───────────────────────── views ─────────────────────────

    pub fn get_owner(&self) -> AccountId {
        self.owner.clone()
    }

    pub fn list_agents(&self) -> Vec<AgentView> {
        self.agent_keys
            .iter()
            .filter_map(|k| self.agents.get(k).map(|a| AgentView {
                public_key: k.clone(),
                label: a.label.clone(),
                per_tx_max: U128(a.per_tx_max),
                daily_max: U128(a.daily_max),
                allowlist_only: a.allowlist_only,
                frozen: a.frozen,
                spent_in_window: U128(self.spent_now(a)),
            }))
            .collect()
    }

    pub fn list_pending(&self) -> Vec<PendingSpend> {
        self.pending.values().cloned().collect()
    }

    pub fn get_report(&self, receiver: AccountId) -> Option<Report> {
        self.blocklist.get(&receiver).cloned()
    }

    // ───────────────────────── internals ─────────────────────────

    fn assert_owner(&self) {
        require!(env::predecessor_account_id() == self.owner, "owner only");
    }

    fn agent_mut(&mut self, k: &PublicKey) -> &mut Agent {
        self.agents.get_mut(k).unwrap_or_else(|| env::panic_str("unknown agent"))
    }

    fn spent_now(&self, a: &Agent) -> u128 {
        if env::block_timestamp().saturating_sub(a.window_start) >= DAY_NS { 0 } else { a.spent_in_window }
    }

    fn record_spend(&mut self, k: &PublicKey, amount: u128) {
        let now = env::block_timestamp();
        let a = self.agent_mut(k);
        if now.saturating_sub(a.window_start) >= DAY_NS {
            a.window_start = now;
            a.spent_in_window = 0;
        }
        a.spent_in_window = a.spent_in_window.saturating_add(amount);
    }
}

// ───────────────────────── helpers ─────────────────────────

fn emit(event: &str, data: &str) {
    log!(r#"EVENT_JSON:{{"standard":"tollgate","version":"1.0.0","event":"{}","data":[{}]}}"#, event, data);
}

fn pk_str(k: &PublicKey) -> String {
    String::from(k)
}

fn json_str(s: &str) -> String {
    near_sdk::serde_json::to_string(s).unwrap()
}

fn json_list(v: &[String]) -> String {
    near_sdk::serde_json::to_string(v).unwrap()
}

fn borsh_bytes(k: &PublicKey) -> Vec<u8> {
    near_sdk::borsh::to_vec(k).unwrap()
}

#[cfg(test)]
mod tests;
