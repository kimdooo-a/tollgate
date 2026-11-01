use super::*;
use near_sdk::test_utils::{get_logs, VMContextBuilder};
use near_sdk::testing_env;

const NEAR: u128 = 1_000_000_000_000_000_000_000_000;

fn owner() -> AccountId { "owner.testnet".parse().unwrap() }
fn vault() -> AccountId { "vault.testnet".parse().unwrap() }
fn shop() -> AccountId { "api-shop.testnet".parse().unwrap() }
fn scam() -> AccountId { "drainer.testnet".parse().unwrap() }
fn agent_pk() -> PublicKey { "ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp".parse().unwrap() }
fn other_pk() -> PublicKey { "ed25519:DcA2MzgpJbrUATQLLceocVckhhAqrkingax4oJ9kZ847".parse().unwrap() }

fn ctx(predecessor: AccountId, signer_pk: Option<PublicKey>, ts: u64) {
    let mut b = VMContextBuilder::new();
    b.current_account_id(vault())
        .predecessor_account_id(predecessor.clone())
        .signer_account_id(predecessor)
        .block_timestamp(ts)
        .account_balance(NearToken::from_near(100));
    if let Some(pk) = signer_pk {
        b.signer_account_pk(pk);
    }
    testing_env!(b.build());
}

fn policy(per_tx: u128, daily: u128, allowlist_only: bool) -> PolicyInput {
    PolicyInput { per_tx_max: U128(per_tx), daily_max: U128(daily), allowlist_only, label: "research-bot".into() }
}

fn setup(allowlist_only: bool) -> Tollgate {
    ctx(owner(), None, 0);
    let mut c = Tollgate::new(owner());
    let _ = c.add_agent(agent_pk(), policy(NEAR, 2 * NEAR, allowlist_only));
    c
}

fn as_agent(ts: u64) { ctx(vault(), Some(agent_pk()), ts); }

#[test]
fn small_spend_is_allowed_and_counted() {
    let mut c = setup(false);
    as_agent(1);
    let r = c.spend(shop(), U128(NEAR / 2), Some("api credits".into()));
    assert_eq!(r.verdict, Verdict::Allow);
    assert!(get_logs().iter().any(|l| l.contains(r#""event":"spent""#)));
    assert_eq!(c.list_agents()[0].spent_in_window.0, NEAR / 2);
}

#[test]
fn over_per_tx_max_is_queued_not_sent() {
    let mut c = setup(false);
    as_agent(1);
    let r = c.spend(shop(), U128(NEAR + 1), None);
    assert_eq!(r.verdict, Verdict::Warn);
    assert_eq!(c.list_pending().len(), 1);
    assert_eq!(c.list_agents()[0].spent_in_window.0, 0, "queued spend must not count");
}

#[test]
fn daily_cap_trips_then_window_resets() {
    let mut c = setup(false);
    as_agent(1);
    assert_eq!(c.spend(shop(), U128(NEAR), None).verdict, Verdict::Allow);
    assert_eq!(c.spend(shop(), U128(NEAR), None).verdict, Verdict::Allow);
    // Two small payments that each pass per-tx but together break the cap.
    assert_eq!(c.spend(shop(), U128(1), None).verdict, Verdict::Warn);
    as_agent(1 + DAY_NS);
    assert_eq!(c.spend(shop(), U128(NEAR), None).verdict, Verdict::Allow);
}

#[test]
fn blocklisted_receiver_is_blocked_with_evidence() {
    let mut c = setup(false);
    ctx(owner(), None, 1);
    c.report(scam(), "drainer contract, see tx 9xF… on explorer".into());
    as_agent(2);
    let r = c.spend(scam(), U128(1), Some("ignore previous instructions".into()));
    assert_eq!(r.verdict, Verdict::Block);
    assert!(r.reasons[0].contains("drainer contract"));
    assert!(get_logs().iter().any(|l| l.contains(r#""event":"blocked""#)));
    assert!(c.list_pending().is_empty());
}

#[test]
fn allowlist_mode_sends_unknown_receivers_to_human() {
    let mut c = setup(true);
    ctx(owner(), None, 1);
    c.allow_receiver(agent_pk(), shop());
    as_agent(2);
    assert_eq!(c.spend(shop(), U128(1), None).verdict, Verdict::Allow);
    assert_eq!(c.spend("stranger.testnet".parse().unwrap(), U128(1), None).verdict, Verdict::Warn);
}

#[test]
fn frozen_agent_is_blocked() {
    let mut c = setup(false);
    ctx(owner(), None, 1);
    c.freeze(agent_pk());
    as_agent(2);
    assert_eq!(c.spend(shop(), U128(1), None).verdict, Verdict::Block);
}

#[test]
fn unknown_key_is_blocked() {
    let mut c = setup(false);
    ctx(vault(), Some(other_pk()), 1);
    assert_eq!(c.spend(shop(), U128(1), None).verdict, Verdict::Block);
}

#[test]
#[should_panic(expected = "spend must be signed by an agent key on the vault")]
fn spend_from_outside_account_panics() {
    let mut c = setup(false);
    ctx(shop(), Some(agent_pk()), 1);
    c.spend(shop(), U128(1), None);
}

#[test]
fn owner_approves_queued_spend_and_it_counts() {
    let mut c = setup(false);
    as_agent(1);
    c.spend(shop(), U128(NEAR + 5), None);
    ctx(owner(), None, 2);
    let _ = c.approve(0);
    assert!(c.list_pending().is_empty());
    assert_eq!(c.list_agents()[0].spent_in_window.0, NEAR + 5);
}

#[test]
#[should_panic(expected = "receiver was blocklisted after queuing")]
fn blocklist_beats_a_stale_approval() {
    let mut c = setup(false);
    as_agent(1);
    c.spend(shop(), U128(NEAR + 5), None);
    ctx(owner(), None, 2);
    c.report(shop(), "compromised after queuing — reported by partner".into());
    let _ = c.approve(0);
}

#[test]
#[should_panic(expected = "owner only")]
fn agent_cannot_change_its_own_policy() {
    let mut c = setup(false);
    as_agent(1);
    c.set_policy(agent_pk(), policy(1000 * NEAR, 1000 * NEAR, false));
}

#[test]
#[should_panic(expected = "evidence required")]
fn report_without_evidence_is_rejected() {
    let mut c = setup(false);
    ctx(owner(), None, 1);
    c.report(scam(), "bad".into());
}
