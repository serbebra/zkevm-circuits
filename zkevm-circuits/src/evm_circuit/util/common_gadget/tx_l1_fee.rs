use super::{CachedRegion, Cell};
use crate::{
    evm_circuit::{
        param::N_BYTES_U64,
        util::{constraint_builder::EVMConstraintBuilder, from_bytes, U64Word},
    },
    util::Expr,
};
use bus_mapping::{circuit_input_builder::TxL1Fee, l2_predeployed::l1_gas_price_oracle};
use eth_types::{Field, ToLittleEndian, ToScalar};
use halo2_proofs::plonk::{Error, Expression};

/// Transaction L1 fee gadget for L1GasPriceOracle contract
#[derive(Clone, Debug)]
pub(crate) struct TxL1FeeGadget<F> {
    /// Current value of L1 base fee
    base_fee: U64Word<F>,
    /// Current value of L1 fee overhead
    fee_overhead: U64Word<F>,
    /// Current value of L1 fee scalar
    fee_scalar: U64Word<F>,
    /// Committed value of L1 base fee
    base_fee_committed: Cell<F>,
    /// Committed value of L1 fee overhead
    fee_overhead_committed: Cell<F>,
    /// Committed value of L1 fee scalar
    fee_scalar_committed: Cell<F>,
}

impl<F: Field> TxL1FeeGadget<F> {
    pub(crate) fn construct(cb: &mut EVMConstraintBuilder<F>, tx_id: Expression<F>) -> Self {
        let this = Self::raw_construct(cb);

        let l1_fee_address = Expression::Constant(l1_gas_price_oracle::ADDRESS.to_scalar().expect(
            "Unexpected address of l2 gasprice oracle contract -> Scalar conversion failure",
        ));

        let [base_fee_slot, overhead_slot, scalar_slot] = [
            &l1_gas_price_oracle::BASE_FEE_SLOT,
            &l1_gas_price_oracle::OVERHEAD_SLOT,
            &l1_gas_price_oracle::SCALAR_SLOT,
        ]
        .map(|slot| cb.word_rlc(slot.to_le_bytes().map(|b| b.expr())));

        // Read L1 base fee
        cb.account_storage_read(
            l1_fee_address.expr(),
            base_fee_slot,
            this.base_fee.expr(),
            tx_id.expr(),
            this.base_fee_committed.expr(),
        );

        // Read L1 fee overhead
        cb.account_storage_read(
            l1_fee_address.expr(),
            overhead_slot,
            this.fee_overhead.expr(),
            tx_id.expr(),
            this.fee_overhead_committed.expr(),
        );

        // Read L1 fee scalar
        cb.account_storage_read(
            l1_fee_address,
            scalar_slot,
            this.fee_scalar.expr(),
            tx_id,
            this.fee_scalar_committed.expr(),
        );

        this
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        l1_fee: TxL1Fee,
        l1_fee_committed: TxL1Fee,
    ) -> Result<(), Error> {
        self.base_fee
            .assign(region, offset, Some(l1_fee.base_fee.to_le_bytes()))?;
        self.fee_overhead
            .assign(region, offset, Some(l1_fee.fee_overhead.to_le_bytes()))?;
        self.fee_scalar
            .assign(region, offset, Some(l1_fee.fee_scalar.to_le_bytes()))?;
        self.base_fee_committed.assign(
            region,
            offset,
            region.word_rlc(l1_fee_committed.base_fee.into()),
        )?;
        self.fee_overhead_committed.assign(
            region,
            offset,
            region.word_rlc(l1_fee_committed.fee_overhead.into()),
        )?;
        self.fee_scalar_committed.assign(
            region,
            offset,
            region.word_rlc(l1_fee_committed.fee_scalar.into()),
        )?;

        Ok(())
    }

    pub(crate) fn rw_delta(&self) -> Expression<F> {
        // L1 base fee Read
        // L1 fee overhead Read
        // L1 fee scalar Read
        3.expr()
    }

    pub(crate) fn tx_l1_fee(&self, tx_call_data_gas_cost: Expression<F>) -> Expression<F> {
        let [base_fee, fee_overhead, fee_scalar] =
            [&self.base_fee, &self.fee_overhead, &self.fee_scalar]
                .map(|word| from_bytes::expr(&word.cells[..N_BYTES_U64]));

        // <https://github.com/scroll-tech/go-ethereum/blob/49192260a177f1b63fc5ea3b872fb904f396260c/rollup/fees/rollup_fee.go#L118>
        let tx_l1_gas = tx_call_data_gas_cost + 1088.expr() + fee_overhead;
        fee_scalar * 1_000_000_000.expr() * base_fee * tx_l1_gas
    }

    fn raw_construct(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let base_fee = cb.query_word_rlc();
        let fee_overhead = cb.query_word_rlc();
        let fee_scalar = cb.query_word_rlc();

        let base_fee_committed = cb.query_cell_phase2();
        let fee_overhead_committed = cb.query_cell_phase2();
        let fee_scalar_committed = cb.query_cell_phase2();

        Self {
            base_fee,
            fee_overhead,
            fee_scalar,
            base_fee_committed,
            fee_overhead_committed,
            fee_scalar_committed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm_circuit::util::{
        constraint_builder::ConstrainBuilderCommon,
        math_gadget::test_util::{test_math_gadget_container, try_test, MathGadgetContainer},
    };
    use eth_types::{ToScalar, U256};
    use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};

    // <https://github.com/scroll-tech/go-ethereum/blob/develop/rollup/fees/rollup_fee_test.go>
    const TEST_BASE_FEE: u64 = 15_000_000;
    const TEST_FEE_OVERHEAD: u64 = 100;
    const TEST_FEE_SCALAR: u64 = 10;
    const TEST_TX_CALL_DATA_GAS_COST: u64 = 40; // 2 (zeros) * 8 + 2 (non-zeros) * 16
    const TEST_TX_L1_FEE: u128 = 184_200_000_000_000_000_000;

    #[test]
    fn test_tx_l1_fee_with_right_values() {
        let witnesses = [
            TEST_BASE_FEE.into(),
            TEST_FEE_OVERHEAD.into(),
            TEST_FEE_SCALAR.into(),
            TEST_TX_CALL_DATA_GAS_COST.into(),
            TEST_TX_L1_FEE,
        ]
        .map(U256::from);

        try_test!(TxL1FeeGadgetTestContainer<Fr>, witnesses, true);
    }

    #[test]
    fn test_tx_l1_fee_with_wrong_values() {
        let witnesses = [
            TEST_BASE_FEE.into(),
            TEST_FEE_OVERHEAD.into(),
            TEST_FEE_SCALAR.into(),
            TEST_TX_CALL_DATA_GAS_COST.into(),
            TEST_TX_L1_FEE + 1,
        ]
        .map(U256::from);

        try_test!(TxL1FeeGadgetTestContainer<Fr>, witnesses, false);
    }

    #[derive(Clone)]
    struct TxL1FeeGadgetTestContainer<F> {
        gadget: TxL1FeeGadget<F>,
        tx_call_data_gas_cost: Cell<F>,
        expected_tx_l1_fee: Cell<F>,
    }

    impl<F: Field> MathGadgetContainer<F> for TxL1FeeGadgetTestContainer<F> {
        fn configure_gadget_container(cb: &mut EVMConstraintBuilder<F>) -> Self {
            let gadget = TxL1FeeGadget::<F>::raw_construct(cb);
            let tx_call_data_gas_cost = cb.query_cell();
            let expected_tx_l1_fee = cb.query_cell();

            cb.require_equal(
                "tx_l1_fee must be correct",
                gadget.tx_l1_fee(tx_call_data_gas_cost.expr()),
                expected_tx_l1_fee.expr(),
            );

            TxL1FeeGadgetTestContainer {
                gadget,
                tx_call_data_gas_cost,
                expected_tx_l1_fee,
            }
        }

        fn assign_gadget_container(
            &self,
            witnesses: &[U256],
            region: &mut CachedRegion<'_, '_, F>,
        ) -> Result<(), Error> {
            let [base_fee, fee_overhead, fee_scalar] = [0, 1, 2].map(|i| witnesses[i].as_u64());
            let l1_fee = TxL1Fee {
                base_fee,
                fee_overhead,
                fee_scalar,
            };
            self.gadget.assign(region, 0, l1_fee, TxL1Fee::default())?;
            self.tx_call_data_gas_cost.assign(
                region,
                0,
                Value::known(witnesses[3].to_scalar().unwrap()),
            )?;
            self.expected_tx_l1_fee.assign(
                region,
                0,
                Value::known(witnesses[4].to_scalar().unwrap()),
            )?;

            Ok(())
        }
    }
}
