pub mod fanout;
pub mod request;
pub mod kickoff;
pub mod cancel;
pub mod deposit;
pub mod disprove;
pub mod withdraw;

#[cfg(test)]
mod flow_tests {
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::Secp256k1;
    use bitcoin::transaction::TxOut;
    use bitcoin::{Address, Network, OutPoint, ScriptBuf, Txid};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use crate::actor::{Committee, Depositor, Operator};
    use crate::network::BITCOIN_NETWORK;
    use crate::params::Params;
    use crate::scripts;
    use super::{cancel, deposit, disprove, fanout, kickoff, request, withdraw};

    // Helper: create depositor with funded UTXO
    fn setup_depositor(secp: &Secp256k1<bitcoin::secp256k1::All>, params: &Params) -> (Depositor, Committee, StdRng) {
        let mut rng = StdRng::seed_from_u64(42);
        let mut depositor = Depositor::new(&mut rng, secp, 0, OutPoint::new(Txid::all_zeros(), 0));
        depositor.request_utxo = BITCOIN_NETWORK.fund_p2tr(secp, depositor.pubkey, params.deposit_size);
        let committee = Committee::new(&mut rng, secp);
        (depositor, committee, rng)
    }

    // Helper: build signed request_tx and confirm it
    fn build_and_confirm_request(
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        depositor: &Depositor,
        committee: &Committee,
        params: &Params,
    ) -> bitcoin::Transaction {
        let mut request_tx = request::build_request_tx(secp, depositor, committee, params).unwrap();
        let depositor_prevout = TxOut {
            value: params.deposit_size,
            script_pubkey: Address::p2tr(secp, depositor.pubkey, None, Network::Bitcoin).script_pubkey(),
        };
        request::sign_request_tx(secp, &mut request_tx, &depositor.keypair, &[depositor_prevout]).unwrap();
        BITCOIN_NETWORK.confirm_tx(&request_tx);
        request_tx
    }

    // Helper: create operator with funded UTXO, build+sign+confirm fanout tree
    fn setup_operator_with_fanout(
        secp: &Secp256k1<bitcoin::secp256k1::All>,
        rng: &mut StdRng,
        params: &Params,
    ) -> (Operator, fanout::FanoutTree) {
        let mut operator = Operator::new(rng, secp, OutPoint::new(Txid::all_zeros(), 0), params.deposit_count);
        operator.init_utxo = BITCOIN_NETWORK.fund_p2tr(secp, operator.pubkey, params.fanout_init_value());

        let mut tree = fanout::build_fanout_tree(secp, &operator, params).unwrap();
        let init_txout = TxOut {
            value: params.fanout_init_value(),
            script_pubkey: Address::p2tr(secp, operator.pubkey, None, Network::Bitcoin).script_pubkey(),
        };
        fanout::sign_fanout_tree(secp, &mut tree, &operator.keypair, &init_txout, params).unwrap();
        for level in &tree.levels {
            for tx in level {
                BITCOIN_NETWORK.confirm_tx(tx);
            }
        }
        (operator, tree)
    }

    #[test]
    fn test_request_to_deposit_flow() {
        let secp = Secp256k1::new();
        let params = Params::test_defaults();
        let (depositor, committee, _) = setup_depositor(&secp, &params);

        let request_tx = build_and_confirm_request(&secp, &depositor, &committee, &params);
        let request_txid = request_tx.compute_txid();

        let request_spend_info = scripts::request_spend_info(
            &secp, committee.pubkey, depositor.pubkey,
            depositor.deposit_secret_hash(), params.deposit_timeout,
        ).unwrap();

        let mut deposit_tx = deposit::build_deposit_tx(&secp, request_txid, &committee, &params).unwrap();
        let prevouts = [request_tx.output[0].clone()];
        deposit::presign_deposit_tx(
            &secp, &mut deposit_tx, &committee.keypair,
            &request_spend_info, &prevouts,
        ).unwrap();

        BITCOIN_NETWORK.verify_input(&deposit_tx, 0, &prevouts).unwrap();
    }

    #[test]
    fn test_request_to_cancel_flow() {
        let secp = Secp256k1::new();
        let params = Params::test_defaults();
        let (depositor, committee, _) = setup_depositor(&secp, &params);

        let request_tx = build_and_confirm_request(&secp, &depositor, &committee, &params);
        BITCOIN_NETWORK.mine_blocks(params.deposit_timeout.to_consensus_u32() as u64);
        let request_txid = request_tx.compute_txid();

        let request_spend_info = scripts::request_spend_info(
            &secp, committee.pubkey, depositor.pubkey,
            depositor.deposit_secret_hash(), params.deposit_timeout,
        ).unwrap();

        let mut cancel_tx = cancel::build_cancel_tx(&secp, &depositor, request_txid, &params).unwrap();
        let prevouts = [request_tx.output[0].clone()];

        cancel::sign_cancel_tx(
            &secp, &mut cancel_tx, &depositor.keypair,
            &depositor.deposit_secret, &request_spend_info,
            depositor.pubkey, depositor.deposit_secret_hash(),
            params.deposit_timeout, &prevouts,
        ).unwrap();

        BITCOIN_NETWORK.verify_input(&cancel_tx, 0, &prevouts).unwrap();
    }

    #[test]
    fn test_fanout_to_kickoff_flow() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();

        let (operator, tree) = setup_operator_with_fanout(&secp, &mut rng, &params);

        let slot = 0;
        let disprove_hash = [0xaa; 32];
        let mut kickoff_tx = kickoff::build_kickoff_tx(
            &secp, &operator, slot, &tree, disprove_hash, &params,
        ).unwrap();

        let prevouts = tree.kickoff_prevouts(&params, slot);

        let msg = [0xbb; lamport::MSG_LEN];
        let lamport_sig = operator.lamport_keys[slot].sign(&msg);
        let lamport_pk = operator.lamport_pubkey(slot).unwrap();

        kickoff::sign_kickoff_tx(
            &secp, &mut kickoff_tx, &operator.keypair,
            &lamport_sig, &lamport_pk, &prevouts, &params,
        ).unwrap();

        for i in 0..params.lamport_chunks_per_slot {
            BITCOIN_NETWORK.verify_input(&kickoff_tx, i, &prevouts).unwrap();
        }
    }

    #[test]
    fn test_deposit_kickoff_to_withdraw_flow() {
        let secp = Secp256k1::new();
        let params = Params::test_defaults();
        let (depositor, committee, mut rng) = setup_depositor(&secp, &params);

        // Build request → deposit chain
        let request_tx = build_and_confirm_request(&secp, &depositor, &committee, &params);
        let request_txid = request_tx.compute_txid();
        let request_spend_info = scripts::request_spend_info(
            &secp, committee.pubkey, depositor.pubkey,
            depositor.deposit_secret_hash(), params.deposit_timeout,
        ).unwrap();
        let mut deposit_tx = deposit::build_deposit_tx(&secp, request_txid, &committee, &params).unwrap();
        deposit::presign_deposit_tx(
            &secp, &mut deposit_tx, &committee.keypair,
            &request_spend_info, &[request_tx.output[0].clone()],
        ).unwrap();
        BITCOIN_NETWORK.confirm_tx(&deposit_tx);

        // Build fanout → kickoff chain
        let (operator, tree) = setup_operator_with_fanout(&secp, &mut rng, &params);

        let slot = 0;
        let disprove_secret = [0xab; 20];
        let disprove_hash = sha256::Hash::hash(&disprove_secret).to_byte_array();
        let mut kickoff_tx = kickoff::build_kickoff_tx(
            &secp, &operator, slot, &tree, disprove_hash, &params,
        ).unwrap();
        let kickoff_prevouts = tree.kickoff_prevouts(&params, slot);
        let msg = [0xbb; lamport::MSG_LEN];
        let lamport_sig = operator.lamport_keys[slot].sign(&msg);
        let lamport_pk = operator.lamport_pubkey(slot).unwrap();
        kickoff::sign_kickoff_tx(
            &secp, &mut kickoff_tx, &operator.keypair,
            &lamport_sig, &lamport_pk, &kickoff_prevouts, &params,
        ).unwrap();
        BITCOIN_NETWORK.confirm_tx(&kickoff_tx);
        BITCOIN_NETWORK.mine_blocks(params.kickoff_timeout.to_consensus_u32() as u64);

        // Build withdraw tx chaining deposit + kickoff
        let deposit_txid = deposit_tx.compute_txid();
        let kickoff_txid = kickoff_tx.compute_txid();
        let mut withdraw_tx = withdraw::build_withdraw_tx(
            &secp, deposit_txid, kickoff_txid, &operator, &params,
        ).unwrap();
        let withdraw_prevouts = vec![
            deposit_tx.output[0].clone(),
            kickoff_tx.output[0].clone(),
        ];

        withdraw::presign_withdraw_input0(
            &secp, &mut withdraw_tx, &committee.keypair, &withdraw_prevouts,
        ).unwrap();

        let connector_info = scripts::connector_spend_info(
            &secp, operator.pubkey, disprove_hash,
        ).unwrap();
        withdraw::sign_withdraw_input1(
            &secp, &mut withdraw_tx, &operator.keypair,
            &connector_info, &withdraw_prevouts,
        ).unwrap();

        BITCOIN_NETWORK.verify_input(&withdraw_tx, 0, &withdraw_prevouts).unwrap();
        BITCOIN_NETWORK.verify_input(&withdraw_tx, 1, &withdraw_prevouts).unwrap();
    }

    #[test]
    fn test_kickoff_to_disprove_flow() {
        let secp = Secp256k1::new();
        let mut rng = StdRng::seed_from_u64(42);
        let params = Params::test_defaults();

        let (operator, tree) = setup_operator_with_fanout(&secp, &mut rng, &params);

        let slot = 0;
        let disprove_secret = [0xab; 20];
        let disprove_hash = sha256::Hash::hash(&disprove_secret).to_byte_array();

        let mut kickoff_tx = kickoff::build_kickoff_tx(
            &secp, &operator, slot, &tree, disprove_hash, &params,
        ).unwrap();
        let kickoff_prevouts = tree.kickoff_prevouts(&params, slot);
        let msg = [0xbb; lamport::MSG_LEN];
        let lamport_sig = operator.lamport_keys[slot].sign(&msg);
        let lamport_pk = operator.lamport_pubkey(slot).unwrap();
        kickoff::sign_kickoff_tx(
            &secp, &mut kickoff_tx, &operator.keypair,
            &lamport_sig, &lamport_pk, &kickoff_prevouts, &params,
        ).unwrap();
        BITCOIN_NETWORK.confirm_tx(&kickoff_tx);

        let kickoff_txid = kickoff_tx.compute_txid();

        let connector_info = scripts::connector_spend_info(
            &secp, operator.pubkey, disprove_hash,
        ).unwrap();

        let mut disprove_tx = disprove::build_disprove_tx(kickoff_txid);
        disprove::witness_disprove_tx(
            &mut disprove_tx, disprove_secret, disprove_hash, &connector_info,
        ).unwrap();

        let prevouts = [kickoff_tx.output[0].clone()];
        BITCOIN_NETWORK.verify_input(&disprove_tx, 0, &prevouts).unwrap();
    }

    #[test]
    fn test_non_committee_cannot_spend_deposit_output() {
        let secp = Secp256k1::new();
        let params = Params::test_defaults();
        let (depositor, committee, mut rng) = setup_depositor(&secp, &params);
        let attacker = Committee::new(&mut rng, &secp);

        // Build request → deposit chain
        let request_tx = build_and_confirm_request(&secp, &depositor, &committee, &params);
        let request_txid = request_tx.compute_txid();
        let request_spend_info = scripts::request_spend_info(
            &secp, committee.pubkey, depositor.pubkey,
            depositor.deposit_secret_hash(), params.deposit_timeout,
        ).unwrap();
        let mut deposit_tx = deposit::build_deposit_tx(&secp, request_txid, &committee, &params).unwrap();
        deposit::presign_deposit_tx(
            &secp, &mut deposit_tx, &committee.keypair,
            &request_spend_info, &[request_tx.output[0].clone()],
        ).unwrap();
        BITCOIN_NETWORK.confirm_tx(&deposit_tx);

        // Try to spend deposit output with attacker's key
        let init_utxo = OutPoint::new(Txid::all_zeros(), 1);
        let operator = Operator::new(&mut rng, &secp, init_utxo, params.deposit_count);
        let deposit_txid = deposit_tx.compute_txid();
        let kickoff_txid = Txid::all_zeros();
        let mut withdraw_tx = withdraw::build_withdraw_tx(
            &secp, deposit_txid, kickoff_txid, &operator, &params,
        ).unwrap();

        let disprove_hash = [0xaa; 32];
        let connector_info = scripts::connector_spend_info(
            &secp, operator.pubkey, disprove_hash,
        ).unwrap();
        let prevouts = vec![
            deposit_tx.output[0].clone(),
            TxOut {
                value: params.dust_amount,
                script_pubkey: ScriptBuf::new_p2tr_tweaked(connector_info.output_key()),
            },
        ];

        // Attacker signs instead of committee
        withdraw::presign_withdraw_input0(
            &secp, &mut withdraw_tx, &attacker.keypair, &prevouts,
        ).unwrap();

        assert!(
            BITCOIN_NETWORK.verify_input(&withdraw_tx, 0, &prevouts).is_err(),
            "non-committee key should be rejected"
        );
    }
}
