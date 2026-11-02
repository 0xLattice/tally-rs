use lattice_tally::*;
use std::time::{Duration, Instant};
#[test]
fn canonical_identity_work() {
    let raw = "AB".repeat(32);
    let key = PeerId::new(&raw);
    assert_eq!(key, PeerId::new(format!("ED01{raw}")));
    assert_eq!(key.public_key(), "ab".repeat(32));
    assert_eq!(canonical_raw_hex("Ed01garbage"), "Ed01garbage");
    assert_eq!(canonical_raw_hex(&"G".repeat(64)), "G".repeat(64));
    assert_eq!(key_work_bits("hello"), 2);
}
#[test]
fn evidence_formula_decay_and_violation() {
    let p = PeerId::new("hello");
    let c = Config {
        decay_half_life: 10.,
        exchange_baseline: 100.,
        ..Config::default()
    };
    let t = Tally::new(c).unwrap();
    let now = Instant::now();
    assert_eq!(t.admission_score_at(&p, now), 0.);
    t.record_received_at(&p, 100, now);
    assert_eq!(t.admission_score_at(&p, now), 0.53125);
    assert_eq!(
        t.admission_score_at(&p, now + Duration::from_secs(10)),
        0.265625
    );
}
#[test]
fn token_bucket_and_rate_pressure() {
    let p = PeerId::new("p");
    let t = Tally::new(Config {
        per_peer_request_capacity: 2.,
        per_peer_request_refill_per_second: 1.,
        rate_limit_bytes_per_second: 100.,
        ..Config::default()
    })
    .unwrap();
    let n = Instant::now();
    assert!(t.should_allow_at(&p, n));
    assert!(t.should_allow_at(&p, n));
    assert!(!t.should_allow_at(&p, n));
    assert!(t.should_allow_at(&p, n + Duration::from_secs(1)));
    t.record_sent_at(&p, 100, n + Duration::from_secs(2));
    assert!(!t.should_allow_at(&p, n + Duration::from_secs(2)));
    assert!(t.should_allow_at(&p, n + Duration::from_secs(3)));
    assert_eq!(t.metrics().denied, 2);
}
#[test]
fn standing_survives_reset_eviction_and_saturates() {
    let t = Tally::new(Config {
        max_peers: Some(1),
        ..Config::default()
    })
    .unwrap();
    let p = PeerId::new("p");
    t.credit_standing(&p, i64::MAX);
    t.record_useful_received(&p, 1);
    for i in 0..9 {
        t.record_received(&PeerId::new(i.to_string()), 1)
    }
    assert_eq!(t.peer_count(), 4);
    t.reset_peer(&p);
    assert_eq!(t.standing(&p), i64::MAX);
    t.debit_standing(&p, i64::MAX);
    assert!(t.standings().is_empty());
    assert_eq!(t.metrics().total_useful_bytes_received, 1);
}
#[test]
fn challenge_binding_replay_tamper_expiry_and_reset() {
    let t = Tally::new(Config {
        challenge_difficulty: 0,
        ..Config::default()
    })
    .unwrap();
    let p = PeerId::new("p");
    let q = PeerId::new("q");
    let n = Instant::now();
    let c = t.issue_challenge_at(&p, vec![1; 32], n);
    assert!(!t.verify_challenge_at(&c, &[], &q, n));
    let mut forged = c.clone();
    forged.expires_after = Duration::from_secs(99);
    assert!(!t.verify_challenge_at(&forged, &[], &p, n));
    assert!(t.verify_challenge_at(&c, &[], &p, n));
    assert!(!t.verify_challenge_at(&c, &[], &p, n));
    let c = t.issue_challenge_at(&p, vec![2; 32], n);
    assert!(!t.verify_challenge_at(&c, &[], &p, n + Duration::from_secs(30)));
    let c = t.issue_challenge_at(&p, vec![3; 32], n);
    t.reset_peer(&p);
    assert!(!t.verify_challenge_at(&c, &[], &p, n));
}
#[test]
fn solve_real_challenge() {
    let t = Tally::new(Config {
        challenge_difficulty: 8,
        ..Config::default()
    })
    .unwrap();
    let p = PeerId::new("p");
    let c = t.issue_challenge(&p);
    let solution = c.solve().unwrap();
    assert!(t.verify_challenge(&c, &solution, &p));
    assert_eq!(t.metrics().challenges_verified, 1);
    assert!(t.admission_score(&p) > 0.);
}
#[test]
fn credit_line_extremes_and_growth() {
    let mut l = CreditLine::new(PeerId::new("a"), PeerId::new("b"), 100);
    l.adjust_balance(i64::MIN);
    l.adjust_balance(-1);
    assert_eq!(l.balance(), i64::MIN);
    assert_eq!(l.available_capacity(), 100 - i64::MAX);
    assert_eq!(l.debt_pressure(), 1.);
    l.record_partial_settlement(i64::MAX);
    assert_eq!(l.balance(), -1);
    l.record_partial_settlement(5);
    assert_eq!(l.balance(), 0);
    l.record_settlement();
    assert_eq!(l.threshold(), 200);
    l.record_settlement();
    assert_eq!(l.threshold(), 200);
    l.record_settlement();
    assert_eq!(l.threshold(), 300);
    l.record_missed_settlement();
    assert_eq!(l.threshold(), 150);
}
#[test]
fn shared_ledger_thread_safety() {
    let ledger = CreditLineLedger::new(PeerId::new("local"));
    let p = PeerId::new("remote");
    assert!(!ledger.charge_for_relay(&p, 1));
    ledger.establish(&p);
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let l = ledger.clone();
            let p = p.clone();
            std::thread::spawn(move || {
                for _ in 0..1000 {
                    l.earn_from_relay(&p, 1)
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(ledger.balance(&p), 8000);
    assert_eq!(ledger.credit_line(&p).unwrap().sequence(), 8000);
}
#[test]
fn invalid_configuration() {
    for c in [
        Config {
            decay_half_life: f64::NAN,
            ..Config::default()
        },
        Config {
            rate_window: f64::INFINITY,
            ..Config::default()
        },
        Config {
            max_peers: Some(0),
            ..Config::default()
        },
        Config {
            challenge_difficulty: 257,
            ..Config::default()
        },
    ] {
        assert!(Tally::new(c).is_err());
    }
}
#[test]
fn bounded_challenges_evict_oldest_without_erasing_standing() {
    let t = Tally::new(Config {
        max_peers: Some(1),
        challenge_difficulty: 0,
        ..Config::default()
    })
    .unwrap();
    let p = PeerId::new("peer");
    let now = Instant::now();
    let first = t.issue_challenge_at(&p, vec![0], now);
    for i in 1..=4 {
        t.issue_challenge_at(&p, vec![i], now);
    }
    assert!(!t.verify_challenge_at(&first, &[], &p, now));
    let last = t.issue_challenge_at(&p, vec![9], now);
    assert!(t.verify_challenge_at(&last, &[], &p, now));
}
#[test]
fn raw_traffic_never_grants_standing_and_violations_reduce_score() {
    let t = Tally::default();
    let p = PeerId::new("peer");
    t.record_received(&p, 100_000);
    t.record_sent(&p, 1000);
    assert_eq!(t.standing(&p), 0);
    let before = t.admission_score(&p);
    t.record_protocol_violation(&p);
    let after = t.admission_score(&p);
    assert!((after - before / 2.).abs() < 1e-6);
}
