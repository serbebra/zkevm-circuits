use super::{CachedRegion, Cell};
use crate::{
    evm_circuit::util::{constraint_builder::EVMConstraintBuilder, U64Word},
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
        let l1_fee_address = Expression::Constant(l1_gas_price_oracle::ADDRESS.to_scalar().expect(
            "Unexpected address of l2 gasprice oracle contract -> Scalar conversion failure",
        ));

        let [base_fee_slot, overhead_slot, scalar_slot] = [
            &l1_gas_price_oracle::BASE_FEE_SLOT,
            &l1_gas_price_oracle::OVERHEAD_SLOT,
            &l1_gas_price_oracle::SCALAR_SLOT,
        ]
        .map(|slot| cb.word_rlc(slot.to_le_bytes().map(|b| b.expr())));

        let base_fee = cb.query_word_rlc();
        let fee_overhead = cb.query_word_rlc();
        let fee_scalar = cb.query_word_rlc();

        let base_fee_committed = cb.query_cell_phase2();
        let fee_overhead_committed = cb.query_cell_phase2();
        let fee_scalar_committed = cb.query_cell_phase2();

        // Read L1 base fee
        cb.account_storage_read(
            l1_fee_address.expr(),
            base_fee_slot,
            base_fee.expr(),
            tx_id.expr(),
            base_fee_committed.expr(),
        );

        // Read L1 fee overhead
        cb.account_storage_read(
            l1_fee_address.expr(),
            overhead_slot,
            fee_overhead.expr(),
            tx_id.expr(),
            fee_overhead_committed.expr(),
        );

        // Read L1 fee scalar
        cb.account_storage_read(
            l1_fee_address,
            scalar_slot,
            fee_scalar.expr(),
            tx_id,
            fee_scalar_committed.expr(),
        );

        Self {
            base_fee,
            fee_overhead,
            fee_scalar,
            base_fee_committed,
            fee_overhead_committed,
            fee_scalar_committed,
        }
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
        // <https://github.com/scroll-tech/go-ethereum/blob/49192260a177f1b63fc5ea3b872fb904f396260c/rollup/fees/rollup_fee.go#L118>
        let tx_l1_gas = tx_call_data_gas_cost + 1088.expr() + self.fee_overhead.expr();
        self.fee_scalar.expr() * 1_000_000_000.expr() * self.base_fee.expr() * tx_l1_gas
    }
}
