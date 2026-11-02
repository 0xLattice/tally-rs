use base64::{Engine, engine::general_purpose::STANDARD};
use lattice_tally::*;
#[test]
fn swift_generated_identity_and_credit_vectors() {
    let mut line = None;
    let mut count = 0;
    for row in include_str!("fixtures/swift.tsv").lines() {
        let f: Vec<_> = row.split('\t').collect();
        match f[0] {
            "key" => {
                let key = String::from_utf8(STANDARD.decode(f[1]).unwrap()).unwrap();
                let canonical = String::from_utf8(STANDARD.decode(f[2]).unwrap()).unwrap();
                assert_eq!(canonical_raw_hex(&key), canonical);
                assert_eq!(key_work_bits(&key), f[3].parse::<u32>().unwrap());
                count += 1
            }
            "credit" => {
                let threshold = f[1].parse().unwrap();
                let i = f[2].parse::<i64>().unwrap();
                if i == 0 {
                    line = Some(CreditLine::new(
                        PeerId::new("a"),
                        PeerId::new("b"),
                        threshold,
                    ))
                }
                let l = line.as_mut().unwrap();
                match i % 5 {
                    0 => l.adjust_balance(i * 100 - 999),
                    1 => l.record_partial_settlement(100),
                    2 => l.record_settlement(),
                    3 => l.record_missed_settlement(),
                    _ => l.adjust_balance(i64::MAX),
                }
                assert_eq!(l.balance(), f[3].parse::<i64>().unwrap(), "{row}");
                assert_eq!(l.sequence(), f[4].parse::<u64>().unwrap());
                assert_eq!(l.threshold(), f[5].parse::<u64>().unwrap(), "{row}");
                assert_eq!(l.successful_settlements(), f[6].parse::<u64>().unwrap());
                assert_eq!(l.available_capacity(), f[7].parse::<i64>().unwrap());
                assert!((l.debt_pressure() - f[8].parse::<f64>().unwrap()).abs() < 1e-14);
                count += 1
            }
            _ => {}
        }
    }
    assert_eq!(count, 585);
}
#[test]
fn swift_generated_challenge_targets() {
    let mut count = 0;
    for row in include_str!("fixtures/swift.tsv")
        .lines()
        .filter(|r| r.starts_with("challenge\t"))
    {
        let f: Vec<_> = row.split('\t').collect();
        let challenge = Challenge {
            nonce: STANDARD.decode(f[2]).unwrap(),
            bound_peer: PeerId::new(format!("peer-{}", f[1])),
            difficulty: 8,
            issued_at: std::time::Instant::now(),
            expires_after: std::time::Duration::from_secs(30),
        };
        let solution = STANDARD.decode(f[3]).unwrap();
        assert!(challenge.meets_target(&solution), "{row}");
        let counter = u64::from_le_bytes(solution.as_slice().try_into().unwrap());
        for prior in 0..counter {
            assert!(!challenge.meets_target(&prior.to_le_bytes()));
        }
        count += 1;
    }
    assert_eq!(count, 100);
}
