use bitcoin::Amount;
use bitcoin::blockdata::transaction::Sequence;

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
        Self {
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
        }
    }
}

impl Params {
    pub fn test_defaults() -> Self {
        Self {
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
        }
    }

    /// Returns the (start_bit, end_bit) range for a given Lamport chunk index.
    pub fn lamport_chunk_range(&self, chunk: usize) -> (usize, usize) {
        let total_bits = self.proof_size * 8;
        let start = chunk * lamport::MAX_BITS_PER_CHUNK;
        let end = ((chunk + 1) * lamport::MAX_BITS_PER_CHUNK).min(total_bits);
        (start, end)
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
}
