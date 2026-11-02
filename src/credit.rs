use crate::{PeerId, base_trust};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreditLine {
    pub peer_a: PeerId,
    pub peer_b: PeerId,
    balance: i64,
    sequence: u64,
    threshold: u64,
    successful_settlements: u64,
}
impl CreditLine {
    pub fn new(peer_a: PeerId, peer_b: PeerId, threshold: u64) -> Self {
        Self {
            peer_a,
            peer_b,
            balance: 0,
            sequence: 0,
            threshold,
            successful_settlements: 0,
        }
    }
    pub fn initial_threshold(trust: f64, multiplier: u64) -> u64 {
        if !trust.is_finite() || trust <= 0. {
            0
        } else if trust >= 1. {
            multiplier
        } else {
            (trust * multiplier as f64) as u64
        }
    }
    pub fn balance(&self) -> i64 {
        self.balance
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn threshold(&self) -> u64 {
        self.threshold
    }
    pub fn successful_settlements(&self) -> u64 {
        self.successful_settlements
    }
    fn magnitude(&self) -> i64 {
        self.balance.unsigned_abs().min(i64::MAX as u64) as i64
    }
    fn clamped_threshold(&self) -> i64 {
        self.threshold.min(i64::MAX as u64) as i64
    }
    pub fn needs_settlement(&self) -> bool {
        self.magnitude() >= self.clamped_threshold()
    }
    pub fn available_capacity(&self) -> i64 {
        self.clamped_threshold() - self.magnitude()
    }
    pub fn debt_pressure(&self) -> f64 {
        if self.clamped_threshold() == 0 {
            1.
        } else {
            (self.magnitude() as f64 / self.clamped_threshold() as f64).min(1.)
        }
    }
    pub fn adjust_balance(&mut self, amount: i64) {
        self.balance = self.balance.saturating_add(amount);
        self.sequence = self.sequence.saturating_add(1);
    }
    pub fn record_settlement(&mut self) {
        self.balance = 0;
        self.successful_settlements = self.successful_settlements.saturating_add(1);
        let scale = |n: u64| (1. + (n as f64).log2()) as u64;
        let current = scale(self.successful_settlements);
        let next = scale(self.successful_settlements.saturating_add(1));
        let initial =
            (self.threshold / current + u64::from(!self.threshold.is_multiple_of(current))).max(1);
        self.threshold = initial.saturating_mul(next);
    }
    pub fn record_partial_settlement(&mut self, work: i64) {
        if work <= 0 {
            return;
        }
        self.balance = if self.balance > 0 {
            (self.balance - work).max(0)
        } else {
            (self.balance + work).min(0)
        };
        self.sequence = self.sequence.saturating_add(1);
    }
    pub fn record_missed_settlement(&mut self) {
        self.threshold /= 2;
    }
}
#[derive(Clone)]
pub struct CreditLineLedger {
    local_id: PeerId,
    multiplier: u64,
    min: i32,
    max: i32,
    lines: Arc<Mutex<HashMap<PeerId, CreditLine>>>,
}
impl CreditLineLedger {
    pub fn new(local_id: PeerId) -> Self {
        Self::with_config(local_id, 100, 0, 32)
    }
    pub fn with_config(local_id: PeerId, multiplier: u64, min: i32, max: i32) -> Self {
        Self {
            local_id,
            multiplier,
            min,
            max,
            lines: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    pub fn establish(&self, peer: &PeerId) -> CreditLine {
        let mut lines = self.lines.lock().unwrap();
        lines
            .entry(peer.clone())
            .or_insert_with(|| {
                CreditLine::new(
                    self.local_id.clone(),
                    peer.clone(),
                    CreditLine::initial_threshold(
                        base_trust(&peer.public_key, self.min, self.max),
                        self.multiplier,
                    )
                    .max(1),
                )
            })
            .clone()
    }
    pub fn credit_line(&self, peer: &PeerId) -> Option<CreditLine> {
        self.lines.lock().unwrap().get(peer).cloned()
    }
    pub fn charge_for_relay(&self, peer: &PeerId, amount: i64) -> bool {
        if amount <= 0 {
            return false;
        }
        let mut lines = self.lines.lock().unwrap();
        if let Some(line) = lines.get_mut(peer) {
            line.adjust_balance(-amount);
            true
        } else {
            false
        }
    }
    fn mutate(&self, peer: &PeerId, update: impl FnOnce(&mut CreditLine)) {
        if let Some(line) = self.lines.lock().unwrap().get_mut(peer) {
            update(line)
        }
    }
    pub fn earn_from_relay(&self, peer: &PeerId, amount: i64) {
        if amount > 0 {
            self.mutate(peer, |l| l.adjust_balance(amount));
        }
    }
    pub fn needs_settlement(&self, peer: &PeerId) -> bool {
        self.credit_line(peer).is_some_and(|l| l.needs_settlement())
    }
    pub fn debt_pressure(&self, peer: &PeerId) -> f64 {
        self.credit_line(peer)
            .map(|l| l.debt_pressure())
            .unwrap_or(0.)
    }
    pub fn record_settlement(&self, peer: &PeerId) {
        self.mutate(peer, |l| l.record_settlement());
    }
    pub fn record_partial_settlement(&self, peer: &PeerId, work: i64) {
        self.mutate(peer, |l| l.record_partial_settlement(work));
    }
    pub fn record_missed_settlement(&self, peer: &PeerId) {
        self.mutate(peer, |l| l.record_missed_settlement());
    }
    pub fn remove_line(&self, peer: &PeerId) -> Option<CreditLine> {
        self.lines.lock().unwrap().remove(peer)
    }
    pub fn all_lines(&self) -> HashMap<PeerId, CreditLine> {
        self.lines.lock().unwrap().clone()
    }
    pub fn balance(&self, peer: &PeerId) -> i64 {
        self.credit_line(peer).map(|l| l.balance()).unwrap_or(0)
    }
    pub fn threshold(&self, peer: &PeerId) -> u64 {
        self.credit_line(peer).map(|l| l.threshold()).unwrap_or(0)
    }
}
