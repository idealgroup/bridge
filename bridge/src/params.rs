use bitcoin::Amount;
use bitcoin::blockdata::transaction::Sequence;

#[derive(Clone)]
pub struct Params {
    pub deposit_size: Amount,
    pub dust_amount: Amount,
    pub proof_size: usize,
    pub deposit_count: usize,
    pub operator_count: usize,
    pub committee_size: usize,
    pub fanout_branching: usize,
    pub fanout_depth: usize,
    pub lamport_chunks_per_slot: usize,
    pub kickoff_timeout: Sequence,
    pub deposit_timeout: Sequence,
}

impl Default for Params {
    fn default() -> Self {
        let p = Self {
            deposit_size: Amount::from_int_btc(1),
            dust_amount: Amount::from_sat(546),
            proof_size: 256,
            deposit_count: 10_000,
            operator_count: 50,
            committee_size: 10,
            fanout_branching: 10,
            fanout_depth: 4,
            lamport_chunks_per_slot: 3,
            // ~3 days in 512-second intervals: 3*24*60*60/512 ≈ 507
            kickoff_timeout: Sequence::from_512_second_intervals(507),
            // ~1 hour in 512-second intervals: 3600/512 ≈ 7
            deposit_timeout: Sequence::from_512_second_intervals(7),
        };
        p.validate().expect("default params must be valid");
        p
    }
}

impl Params {
    pub fn test_defaults() -> Self {
        let p = Self {
            deposit_size: Amount::from_sat(100_000),
            dust_amount: Amount::from_sat(546),
            proof_size: 256,
            deposit_count: 4,
            operator_count: 2,
            committee_size: 2,
            fanout_branching: 2,
            fanout_depth: 2,
            lamport_chunks_per_slot: 3,
            kickoff_timeout: Sequence::from_height(10),
            deposit_timeout: Sequence::from_height(5),
        };
        p.validate().expect("test params must be valid");
        p
    }

    /// Validate that derived parameters are consistent.
    pub fn validate(&self) -> Result<(), crate::BridgeError> {
        if self.deposit_count == 0 {
            return Err(crate::BridgeError::InvalidParams(
                "deposit_count must be > 0".into(),
            ));
        }
        if self.fanout_branching <= 1 {
            return Err(crate::BridgeError::InvalidParams(
                "fanout_branching must be > 1".into(),
            ));
        }
        if self.fanout_depth == 0 {
            return Err(crate::BridgeError::InvalidParams(
                "fanout_depth must be > 0".into(),
            ));
        }
        if self.proof_size == 0 {
            return Err(crate::BridgeError::InvalidParams(
                "proof_size must be > 0".into(),
            ));
        }
        let total_bits = self.proof_size * 8;
        let expected_chunks =
            total_bits.div_ceil(lamport::MAX_BITS_PER_CHUNK);
        if self.lamport_chunks_per_slot != expected_chunks {
            return Err(crate::BridgeError::InvalidParams(format!(
                "lamport_chunks_per_slot is {} but proof_size {} requires {}",
                self.lamport_chunks_per_slot, self.proof_size, expected_chunks,
            )));
        }
        // Each leaf tx handles `branching` slots, and there are branching^(depth-1)
        // leaf txs, so total capacity = branching^depth.
        let capacity = self.fanout_branching
            .checked_pow(self.fanout_depth as u32)
            .ok_or_else(|| crate::BridgeError::InvalidParams(
                "fanout_branching^fanout_depth overflows".into(),
            ))?;
        if capacity < self.deposit_count {
            return Err(crate::BridgeError::InvalidParams(format!(
                "fanout_branching^fanout_depth = {} < deposit_count {}",
                capacity, self.deposit_count,
            )));
        }
        Ok(())
    }

    /// Returns the (start_bit, end_bit) range for a given Lamport chunk index.
    pub fn lamport_chunk_range(&self, chunk: usize) -> (usize, usize) {
        let total_bits = self.proof_size * 8;
        let start = chunk * lamport::MAX_BITS_PER_CHUNK;
        let end = ((chunk + 1) * lamport::MAX_BITS_PER_CHUNK).min(total_bits);
        (start, end)
    }

    /// Output value for each fanout intermediate tx output at a given depth.
    ///
    /// Leaf outputs (at depth == fanout_depth - 1) use dust_amount.
    /// Intermediate outputs carry enough value to fund their entire subtree.
    pub fn fanout_output_value(&self, depth: usize) -> Amount {
        if depth >= self.fanout_depth - 1 {
            return self.dust_amount;
        }
        let child_depth = depth + 1;
        if child_depth == self.fanout_depth - 1 {
            // Next level is leaf: each leaf tx produces branching * chunks outputs of dust
            let leaf_total = self.fanout_branching * self.lamport_chunks_per_slot;
            Amount::from_sat(leaf_total as u64 * self.dust_amount.to_sat())
        } else {
            // Next level is intermediate: each child output has fanout_output_value(child_depth)
            let child_value = self.fanout_output_value(child_depth);
            Amount::from_sat(self.fanout_branching as u64 * child_value.to_sat())
        }
    }

    /// Total input value needed for the operator's init_utxo to fund the whole fanout tree.
    pub fn fanout_init_value(&self) -> Amount {
        Amount::from_sat(self.fanout_branching as u64 * self.fanout_output_value(0).to_sat())
    }

    /// Value the depositor must fund into their request UTXO.
    ///
    /// Equals `deposit_size + dust_amount`. The `dust_amount` surplus is
    /// what the committee's `depositTx` burns as its own fee (depositTx
    /// input = `deposit_size + dust_amount`, output = `deposit_size`).
    ///
    /// NOTE: the `requestTx` built on top of this UTXO pays **zero fee**
    /// (output0 carries the full input amount, output1 is a zero-value
    /// OP_RETURN). This is a regtest-only shortcut — the test node runs
    /// with `minrelaytxfee=0`. A production deployment must either:
    /// - Add a second input to `requestTx` that pays the relay fee
    ///   (`output[0]` stays the same so the committee's presigned depositTx
    ///   sighash is unaffected), or
    /// - Bump `requestTx` via CPFP from a wallet-owned output.
    pub fn request_input_value(&self) -> Amount {
        self.deposit_size + self.dust_amount
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_ranges() {
        let p = Params::default();
        assert_eq!(p.lamport_chunk_range(0), (0, 998));
        assert_eq!(p.lamport_chunk_range(1), (998, 1996));
        assert_eq!(p.lamport_chunk_range(2), (1996, 2048));
    }

    #[test]
    fn test_test_defaults() {
        let p = Params::test_defaults();
        assert_eq!(p.deposit_count, 4);
        assert_eq!(p.fanout_branching, 2);
        assert_eq!(p.fanout_depth, 2);
    }

    #[test]
    fn test_validate_defaults() {
        Params::default().validate().unwrap();
        Params::test_defaults().validate().unwrap();
    }

    #[test]
    fn test_validate_wrong_chunks() {
        let mut p = Params::test_defaults();
        p.lamport_chunks_per_slot = 5;
        assert!(p.validate().is_err());
    }

    #[test]
    fn test_validate_insufficient_fanout() {
        let mut p = Params::test_defaults();
        p.fanout_depth = 1; // branching^0 = 1 < deposit_count=4
        assert!(p.validate().is_err());
    }
}
