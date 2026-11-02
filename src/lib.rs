//! Local peer evidence, admission, standing, and bilateral credit accounting.
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    hash::Hash,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
mod credit;
pub use credit::*;

pub fn canonical_raw_hex(presented: &str) -> String {
    let raw = if presented.len() == 68
        && presented
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case("ed01"))
    {
        &presented[4..]
    } else if presented.len() == 64 {
        presented
    } else {
        return presented.into();
    };
    if raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        raw.to_ascii_lowercase()
    } else {
        presented.into()
    }
}
pub fn trailing_zero_bits(text: &str) -> u32 {
    let hash = Sha256::digest(text.as_bytes());
    let mut bits = 0;
    for b in hash.iter().rev() {
        bits += b.trailing_zeros();
        if *b != 0 {
            break;
        }
    }
    bits
}
pub fn key_work_bits(text: &str) -> u32 {
    trailing_zero_bits(&canonical_raw_hex(text))
}
pub fn base_trust(text: &str, min: i32, max: i32) -> f64 {
    let bits = key_work_bits(text) as i32;
    if bits <= min {
        0.0
    } else if bits >= max {
        1.0
    } else {
        (bits - min) as f64 / (max - min) as f64
    }
}
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct PeerId {
    public_key: String,
    trailing_zero_bits: u32,
}
impl PeerId {
    pub fn public_key(&self) -> &str {
        &self.public_key
    }
    pub fn trailing_zero_bits(&self) -> u32 {
        self.trailing_zero_bits
    }
    pub fn new(key: impl AsRef<str>) -> Self {
        let public_key = canonical_raw_hex(key.as_ref());
        let trailing_zero_bits = trailing_zero_bits(&public_key);
        Self {
            public_key,
            trailing_zero_bits,
        }
    }
}
#[derive(Clone, Debug)]
pub struct Config {
    pub decay_half_life: f64,
    pub challenge_difficulty: u32,
    pub challenge_expiration: Duration,
    pub rate_limit_bytes_per_second: f64,
    pub rate_window: f64,
    pub per_peer_request_capacity: f64,
    pub per_peer_request_refill_per_second: f64,
    pub hardness_baseline: u32,
    pub exchange_baseline: f64,
    pub pow_baseline: u32,
    pub max_peers: Option<usize>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            decay_half_life: 3600.,
            challenge_difficulty: 16,
            challenge_expiration: Duration::from_secs(30),
            rate_limit_bytes_per_second: 10_000_000.,
            rate_window: 1.,
            per_peer_request_capacity: 200.,
            per_peer_request_refill_per_second: 50.,
            hardness_baseline: 160,
            exchange_baseline: 100_000.,
            pow_baseline: 16,
            max_peers: None,
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<(), &'static str> {
        let positive = [
            self.decay_half_life,
            self.rate_limit_bytes_per_second,
            self.rate_window,
            self.rate_limit_bytes_per_second * self.rate_window,
            self.exchange_baseline,
        ];
        if positive.iter().any(|x| !x.is_finite() || *x <= 0.)
            || self.challenge_difficulty > 256
            || self.challenge_expiration.is_zero()
            || !self.per_peer_request_capacity.is_finite()
            || self.per_peer_request_capacity < 1.
            || !self.per_peer_request_refill_per_second.is_finite()
            || self.per_peer_request_refill_per_second < 0.
            || self.hardness_baseline == 0
            || self.pow_baseline == 0
            || self.max_peers == Some(0)
        {
            Err("invalid Tally configuration")
        } else {
            Ok(())
        }
    }
    fn capacity(&self) -> usize {
        self.max_peers.map(|n| n.saturating_mul(4)).unwrap_or(4096)
    }
}
struct Bounded<K, V> {
    values: HashMap<K, (u128, V)>,
    serial: u128,
    capacity: usize,
}
impl<K: Hash + Eq + Clone, V> Bounded<K, V> {
    fn new(capacity: usize) -> Self {
        Self {
            values: HashMap::new(),
            serial: 0,
            capacity,
        }
    }
    fn get(&self, key: &K) -> Option<&V> {
        self.values.get(key).map(|(_, v)| v)
    }
    fn put(&mut self, k: K, v: V) {
        self.serial += 1;
        self.values.insert(k, (self.serial, v));
        if self.values.len() > self.capacity {
            let k = self
                .values
                .iter()
                .min_by_key(|(_, v)| v.0)
                .unwrap()
                .0
                .clone();
            self.values.remove(&k);
        }
    }
    fn remove(&mut self, k: &K) {
        self.values.remove(k);
    }
}
#[derive(Clone)]
struct Evidence {
    sent: f64,
    received: f64,
    violations: f64,
    work: f64,
    last: Instant,
}
impl Evidence {
    fn new(now: Instant) -> Self {
        Self {
            sent: 0.,
            received: 0.,
            violations: 0.,
            work: 0.,
            last: now,
        }
    }
    fn decay(&mut self, now: Instant, half: f64) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        if elapsed > 0. {
            let f = (-elapsed / half).exp2();
            self.sent *= f;
            self.received *= f;
            self.violations *= f;
            self.work *= f;
            self.last = now
        }
    }
    fn score(&self, peer: &PeerId, c: &Config) -> f64 {
        let exchange = self.sent + self.received;
        let confidence = (exchange / c.exchange_baseline).min(1.);
        let quality = (self.received + 1.) / (exchange + 1.);
        ((0.5 * confidence * quality
            + 0.25 * (self.work / c.hardness_baseline as f64).min(1.)
            + 0.25
                * confidence
                * (key_work_bits(&peer.public_key) as f64 / c.pow_baseline as f64).min(1.))
            / (1. + self.violations))
            .clamp(0., 1.)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub nonce: Vec<u8>,
    pub bound_peer: PeerId,
    pub difficulty: u32,
    pub issued_at: Instant,
    pub expires_after: Duration,
}
impl Challenge {
    pub fn new(
        bound_peer: PeerId,
        difficulty: u32,
        expires_after: Duration,
    ) -> Result<Self, &'static str> {
        if difficulty > 256 || expires_after.is_zero() {
            return Err("invalid challenge configuration");
        }
        use rand::RngCore;
        let mut nonce = vec![0; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Ok(Self {
            nonce,
            bound_peer,
            difficulty,
            issued_at: Instant::now(),
            expires_after,
        })
    }
    pub fn is_expired(&self) -> bool {
        self.is_expired_at(Instant::now())
    }
    pub fn verify(&self, solution: &[u8], peer: &PeerId) -> bool {
        self.verify_at(solution, peer, Instant::now())
    }

    pub fn is_expired_at(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.issued_at) >= self.expires_after
    }
    pub fn meets_target(&self, solution: &[u8]) -> bool {
        let mut hash = Sha256::new();
        hash.update(&self.nonce);
        hash.update(self.bound_peer.public_key.as_bytes());
        hash.update(solution);
        let mut bits = 0;
        for b in hash.finalize() {
            bits += b.leading_zeros();
            if b != 0 {
                break;
            }
        }
        bits >= self.difficulty
    }
    pub fn verify_at(&self, solution: &[u8], peer: &PeerId, now: Instant) -> bool {
        peer == &self.bound_peer && !self.is_expired_at(now) && self.meets_target(solution)
    }
    pub fn solve(&self) -> Option<Vec<u8>> {
        for counter in 0..=u64::MAX {
            if self.is_expired_at(Instant::now()) {
                return None;
            }
            let bytes = counter.to_le_bytes();
            if self.meets_target(&bytes) {
                return Some(bytes.to_vec());
            }
        }
        None
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Metrics {
    pub allowed: i64,
    pub denied: i64,
    pub total_bytes_sent: i64,
    pub total_bytes_received: i64,
    pub total_useful_bytes_received: i64,
    pub challenges_issued: i64,
    pub challenges_verified: i64,
}
struct State {
    evidence: Bounded<PeerId, Evidence>,
    buckets: Bounded<PeerId, (f64, Instant)>,
    challenges: Bounded<Vec<u8>, Challenge>,
    standing: HashMap<PeerId, i64>,
    window_bytes: i64,
    window_start: Instant,
    metrics: Metrics,
}
#[derive(Clone)]
pub struct Tally {
    config: Config,
    state: Arc<Mutex<State>>,
}
impl Tally {
    pub fn new(config: Config) -> Result<Self, &'static str> {
        config.validate()?;
        let cap = config.capacity();
        Ok(Self {
            config,
            state: Arc::new(Mutex::new(State {
                evidence: Bounded::new(cap),
                buckets: Bounded::new(cap),
                challenges: Bounded::new(cap),
                standing: HashMap::new(),
                window_bytes: 0,
                window_start: Instant::now(),
                metrics: Metrics::default(),
            })),
        })
    }
    fn mutate(&self, s: &mut State, p: &PeerId, now: Instant, f: impl FnOnce(&mut Evidence)) {
        let mut e = s
            .evidence
            .get(p)
            .cloned()
            .unwrap_or_else(|| Evidence::new(now));
        e.decay(now, self.config.decay_half_life);
        f(&mut e);
        s.evidence.put(p.clone(), e);
    }
    pub fn record_sent(&self, p: &PeerId, bytes: i64) {
        self.record_sent_at(p, bytes, Instant::now())
    }
    pub fn record_sent_at(&self, p: &PeerId, bytes: i64, now: Instant) {
        if bytes <= 0 {
            return;
        }
        let mut s = self.state.lock().unwrap();
        if now.saturating_duration_since(s.window_start).as_secs_f64() >= self.config.rate_window {
            s.window_bytes = bytes;
            s.window_start = now;
        } else {
            s.window_bytes = s.window_bytes.saturating_add(bytes);
        }
        self.mutate(&mut s, p, now, |e| e.sent += bytes as f64);
        s.metrics.total_bytes_sent = s.metrics.total_bytes_sent.saturating_add(bytes);
    }
    pub fn record_received(&self, p: &PeerId, bytes: i64) {
        self.record_received_at(p, bytes, Instant::now())
    }
    pub fn record_received_at(&self, p: &PeerId, bytes: i64, now: Instant) {
        if bytes <= 0 {
            return;
        }
        let mut s = self.state.lock().unwrap();
        self.mutate(&mut s, p, now, |e| e.received += bytes as f64);
        s.metrics.total_bytes_received = s.metrics.total_bytes_received.saturating_add(bytes);
    }
    pub fn record_protocol_violation(&self, p: &PeerId) {
        let mut s = self.state.lock().unwrap();
        self.mutate(&mut s, p, Instant::now(), |e| e.violations += 1.);
    }
    pub fn credit_standing(&self, p: &PeerId, bytes: i64) {
        if bytes > 0 {
            let mut s = self.state.lock().unwrap();
            let v = s.standing.entry(p.clone()).or_default();
            *v = v.saturating_add(bytes);
        }
    }
    pub fn record_useful_received(&self, p: &PeerId, bytes: i64) {
        if bytes > 0 {
            let mut s = self.state.lock().unwrap();
            let v = s.standing.entry(p.clone()).or_default();
            *v = v.saturating_add(bytes);
            s.metrics.total_useful_bytes_received =
                s.metrics.total_useful_bytes_received.saturating_add(bytes);
        }
    }
    pub fn debit_standing(&self, p: &PeerId, bytes: i64) {
        if bytes > 0 {
            let mut s = self.state.lock().unwrap();
            if let Some(v) = s.standing.get_mut(p) {
                *v = v.saturating_sub(bytes).max(0);
                if *v == 0 {
                    s.standing.remove(p);
                }
            }
        }
    }
    pub fn standing(&self, p: &PeerId) -> i64 {
        self.state
            .lock()
            .unwrap()
            .standing
            .get(p)
            .copied()
            .unwrap_or(0)
    }
    pub fn standings(&self) -> HashMap<PeerId, i64> {
        self.state.lock().unwrap().standing.clone()
    }
    pub fn serving_priority(&self, p: &PeerId) -> f64 {
        self.standing(p) as f64
    }
    fn score(&self, s: &mut State, p: &PeerId, now: Instant) -> f64 {
        if let Some(mut e) = s.evidence.get(p).cloned() {
            e.decay(now, self.config.decay_half_life);
            let score = e.score(p, &self.config);
            s.evidence.put(p.clone(), e);
            score
        } else {
            0.
        }
    }
    pub fn admission_score(&self, p: &PeerId) -> f64 {
        self.admission_score_at(p, Instant::now())
    }
    pub fn admission_score_at(&self, p: &PeerId, now: Instant) -> f64 {
        self.score(&mut self.state.lock().unwrap(), p, now)
    }
    fn pressure(&self, s: &mut State, now: Instant) -> f64 {
        if now.saturating_duration_since(s.window_start).as_secs_f64() >= self.config.rate_window {
            s.window_bytes = 0;
            s.window_start = now;
        }
        (s.window_bytes as f64
            / (self.config.rate_limit_bytes_per_second * self.config.rate_window))
            .min(2.)
    }
    pub fn rate_pressure(&self) -> f64 {
        self.pressure(&mut self.state.lock().unwrap(), Instant::now())
    }
    pub fn should_allow(&self, p: &PeerId) -> bool {
        self.should_allow_at(p, Instant::now())
    }
    pub fn should_allow_at(&self, p: &PeerId, now: Instant) -> bool {
        let mut s = self.state.lock().unwrap();
        let (mut tokens, mut last) = s
            .buckets
            .get(p)
            .copied()
            .unwrap_or((self.config.per_peer_request_capacity, now));
        let elapsed = now.saturating_duration_since(last).as_secs_f64();
        if elapsed > 0. {
            tokens = (tokens + elapsed * self.config.per_peer_request_refill_per_second)
                .min(self.config.per_peer_request_capacity);
            last = now;
        }
        let mut allowed = tokens >= 1.;
        if allowed {
            tokens -= 1.;
        }
        s.buckets.put(p.clone(), (tokens, last));
        if allowed {
            let pressure = self.pressure(&mut s, now);
            allowed = pressure < 0.5
                || self.score(&mut s, p, now) >= ((pressure - 0.5) * 1.6).clamp(0., 0.8);
        }
        let counter = if allowed {
            &mut s.metrics.allowed
        } else {
            &mut s.metrics.denied
        };
        *counter = counter.saturating_add(1);
        allowed
    }
    pub fn reset_peer(&self, p: &PeerId) {
        let mut s = self.state.lock().unwrap();
        s.evidence.remove(p);
        s.buckets.remove(p);
        s.challenges.values.retain(|_, (_, c)| &c.bound_peer != p);
    }
    pub fn peer_count(&self) -> usize {
        self.state.lock().unwrap().evidence.values.len()
    }
    pub fn metrics(&self) -> Metrics {
        self.state.lock().unwrap().metrics.clone()
    }
    pub fn issue_challenge(&self, p: &PeerId) -> Challenge {
        use rand::RngCore;
        let mut nonce = vec![0; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        self.issue_challenge_at(p, nonce, Instant::now())
    }
    pub fn issue_challenge_at(&self, p: &PeerId, nonce: Vec<u8>, now: Instant) -> Challenge {
        let c = Challenge {
            nonce,
            bound_peer: p.clone(),
            difficulty: self.config.challenge_difficulty,
            issued_at: now,
            expires_after: self.config.challenge_expiration,
        };
        let mut s = self.state.lock().unwrap();
        s.challenges
            .values
            .retain(|_, (_, c)| !c.is_expired_at(now));
        s.challenges.put(c.nonce.clone(), c.clone());
        s.metrics.challenges_issued = s.metrics.challenges_issued.saturating_add(1);
        c
    }
    pub fn verify_challenge(&self, c: &Challenge, solution: &[u8], p: &PeerId) -> bool {
        self.verify_challenge_at(c, solution, p, Instant::now())
    }
    pub fn verify_challenge_at(
        &self,
        c: &Challenge,
        solution: &[u8],
        p: &PeerId,
        now: Instant,
    ) -> bool {
        let mut s = self.state.lock().unwrap();
        s.challenges
            .values
            .retain(|_, (_, c)| !c.is_expired_at(now));
        if s.challenges.get(&c.nonce) != Some(c) || !c.verify_at(solution, p, now) {
            return false;
        }
        s.challenges.remove(&c.nonce);
        self.mutate(&mut s, p, now, |e| e.work += c.difficulty as f64);
        s.metrics.challenges_verified = s.metrics.challenges_verified.saturating_add(1);
        true
    }
}
impl Default for Tally {
    fn default() -> Self {
        Self::new(Config::default()).unwrap()
    }
}
impl std::fmt::Display for PeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.public_key.fmt(f)
    }
}

#[cfg(test)]
mod swift_evidence_vectors {
    use super::*;
    #[test]
    fn matches_swift_reference() {
        let c = Config {
            decay_half_life: 10.,
            exchange_baseline: 100.,
            ..Config::default()
        };
        let now = Instant::now();
        let mut count = 0;
        for row in include_str!("../tests/fixtures/swift.tsv")
            .lines()
            .filter(|r| r.starts_with("evidence\t"))
        {
            let f: Vec<_> = row.split('\t').collect();
            let i = f[1].parse::<u64>().unwrap();
            let mut evidence = Evidence {
                sent: (i * 3) as f64,
                received: (i * 11) as f64,
                violations: (i % 5) as f64,
                work: i as f64,
                last: now,
            };
            evidence.decay(now + Duration::from_secs(i), 10.);
            let score = evidence.score(&PeerId::new(format!("peer-{i}")), &c);
            let expected = f[2].parse::<f64>().unwrap();
            assert!((score - expected).abs() < 1e-14, "{row}: {score}");
            count += 1;
        }
        assert_eq!(count, 100);
    }
}
