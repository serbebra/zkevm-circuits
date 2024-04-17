use crate::{
    evm_circuit::{
        param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_MEMORY_WORD_SIZE, N_BYTES_U64},
        step::ExecutionState,
        util::{
            common_gadget::{SameContextGadget, WordByteCapGadget},
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, ReversionInfo, StepStateTransition,
                Transition,
            },
            from_bytes,
            math_gadget::IsZeroGadget,
            memory_gadget::{
                CommonMemoryAddressGadget, MemoryAddressGadget, MemoryCopierGasGadget,
                MemoryExpansionGadget,
            },
            not, select, CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag},
};
use bus_mapping::circuit_input_builder::CopyDataType;
use eth_types::{evm_types::GasCost, Field, ToLittleEndian, ToScalar};
use gadgets::util::Expr;
use halo2_proofs::{circuit::Value, plonk::Error};

use super::ExecutionGadget;

#[derive(Clone, Debug)]
pub(crate) struct MCopyGadget<F> {
    same_context: SameContextGadget<F>,
    memory_address: MemoryAddressGadget<F>,
    tx_id: Cell<F>,
    copy_rwc_inc: Cell<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    memory_copier_gas: MemoryCopierGasGadget<F, { GasCost::COPY }>,
}

impl<F: Field> ExecutionGadget<F> for MCopyGadget<F> {
    const NAME: &'static str = "MCOPY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::EXTCODECOPY;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let src_offset = cb.query_cell_phase2();
        let dest_offset = cb.query_cell_phase2();
        let memory_length = cb.query_word_rlc();

        cb.stack_pop(dest_offset.expr());
        cb.stack_pop(src_offset.expr());
        cb.stack_pop(memory_length.expr());

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);

        let memory_address = MemoryAddressGadget::construct(cb, src_offset, memory_length);
        let memory_expansion = MemoryExpansionGadget::construct(cb, [memory_address.end_offset()]);
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            memory_address.length(),
            memory_expansion.gas_cost(),
        );
        let gas_cost = memory_copier_gas.gas_cost();

        let copy_rwc_inc = cb.query_cell();
        cb.condition(memory_address.has_length(), |cb| {
            cb.copy_table_lookup(
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                memory_address.offset(),
                memory_address.end_offset(),
                // memory_address.offset(),
                dest_offset.expr(),
                memory_address.length(),
                0.expr(),
                copy_rwc_inc.expr(),
            );
        });

        cb.condition(not::expr(memory_address.has_length()), |cb| {
            cb.require_zero(
                "if no bytes to copy, copy table rwc inc == 0",
                copy_rwc_inc.expr(),
            );
        });

        let step_state_transition = StepStateTransition {
            rw_counter: Transition::Delta(cb.rw_counter_offset()),
            program_counter: Transition::Delta(1.expr()),
            stack_pointer: Transition::Delta(4.expr()),
            memory_word_size: Transition::To(memory_expansion.next_memory_word_size()),
            gas_left: Transition::Delta(-gas_cost),
            reversible_write_counter: Transition::Delta(1.expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            memory_address,
            tx_id,
            copy_rwc_inc,
            memory_expansion,
            memory_copier_gas,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        transaction: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let [external_address, memory_offset, code_offset, memory_length] =
            [0, 1, 2, 3].map(|idx| block.rws[step.rw_indices[idx]].stack_value());
        let memory_address =
            self.memory_address
                .assign(region, offset, memory_offset, memory_length)?;

        self.tx_id
            .assign(region, offset, Value::known(F::from(transaction.id as u64)))?;

        self.copy_rwc_inc.assign(
            region,
            offset,
            Value::known(
                step.copy_rw_counter_delta
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        let (_, memory_expansion_gas_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [memory_address],
        )?;

        self.memory_copier_gas.assign(
            region,
            offset,
            memory_length.as_u64(),
            memory_expansion_gas_cost,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_bytes_array, test_util::CircuitTestBuilder};
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{
        address, bytecode, geth_types::Account, Address, Bytecode, Bytes, ToWord, Word,
    };
    use mock::TestContext;
    use std::sync::LazyLock;

    static EXTERNAL_ADDRESS: LazyLock<Address> =
        LazyLock::new(|| address!("0xaabbccddee000000000000000000000000000000"));

    fn test_ok(
        dest_offset: Word,
        memory_offset: Word,
        length: usize,
    ) {
      
        let mut code = Bytecode::default();
        code.append(&bytecode! {
            // TODO: prepare memory values by mstore
            PUSH32(length)
            PUSH32(dest_offset)
            PUSH32(memory_offset)
            #[start]
            MCOPY
            STOP
        });

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .code(code);
                accs[1]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(1u64 << 20));
            },
            |mut txs, accs| {
                txs[0]
                    .to(accs[0].address)
                    .from(accs[1].address)
                    .gas(1_000_000.into());
            },
            |block, _tx| block.number(0x1111111),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
                max_copy_rows: 1750,
                ..Default::default()
            })
            .run();
    }

    #[test]
    fn mcopy_empty() {
        test_ok(Word::from("0x20"), Word::zero(), 0x05); // single slot
        test_ok(Word::from("0x10"), Word::zero(), 0x22); // multi slots
    }

    #[test]
    fn extcodecopy_nonempty() {
        test_ok(
            Some(Account {
                address: *EXTERNAL_ADDRESS,
                code: Bytes::from([10, 40]),
                ..Default::default()
            }),
            Word::zero(),
            Word::zero(),
            0x36,
            true,
        ); // warm account
    }

    // TODO: add mcopy OOG cases
}
