use crate::evm_circuit::{
    param::{N_BYTES_MEMORY_ADDRESS, N_BYTES_MEMORY_WORD_SIZE},
    step::ExecutionState,
    util::{
        common_gadget::SameContextGadget,
        constraint_builder::{
            ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition, Transition,
        },
        from_bytes,
        math_gadget::MinMaxGadget,
        memory_gadget::{
            CommonMemoryAddressGadget, MemoryAddressGadget, MemoryCopierGasGadget,
            MemoryExpansionGadget, MemoryWordSizeGadget,
        },
        not, select, CachedRegion, Cell, Word,
    },
    witness::{Block, Call, ExecStep, Transaction},
};
use bus_mapping::{circuit_input_builder::CopyDataType, evm::OpcodeId};
use eth_types::{evm_types::GasCost, Field, ToScalar};
use gadgets::util::Expr;
use halo2_proofs::{circuit::Value, plonk::Error};

use super::ExecutionGadget;

// Gadget for MCOPY opcode
#[derive(Clone, Debug)]
pub(crate) struct MCopyGadget<F> {
    same_context: SameContextGadget<F>,
    memory_address: MemoryAddressGadget<F>,
    copy_rwc_inc: Cell<F>,
    dest_offset: Cell<F>,
    // indicate which address memory expand from, can be src_offset or dest_offset
    expand_from_addr: MinMaxGadget<F, N_BYTES_MEMORY_ADDRESS>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    memory_copier_gas: MemoryCopierGasGadget<F, { GasCost::COPY }>,
}

impl<F: Field> ExecutionGadget<F> for MCopyGadget<F> {
    const NAME: &'static str = "MCOPY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::MCOPY;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let src_offset = cb.query_cell_phase2();
        let dest_offset = cb.query_cell_phase2();
        let length = cb.query_word_rlc();

        cb.stack_pop(dest_offset.expr());
        cb.stack_pop(src_offset.clone().expr());
        cb.stack_pop(length.expr());

        let memory_address = MemoryAddressGadget::construct(cb, src_offset.clone(), length.clone());
        // notice that dest_offset may not greater than src_offset
        let expand_from_addr = MinMaxGadget::construct(cb, src_offset.expr(), dest_offset.expr());
        let expand_end_addr = select::expr(
            memory_address.has_length(),
            expand_from_addr.max() + from_bytes::expr(&length.cells[..N_BYTES_MEMORY_ADDRESS]),
            0.expr(),
        );

        let memory_expansion = MemoryExpansionGadget::construct(cb, [expand_end_addr.clone()]);
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            memory_address.length(),
            memory_expansion.gas_cost(),
        );

        // if no acutal copy happens, memory_word_size doesn't change.
        let dest_word_size = select::expr(
            memory_address.has_length(),
            memory_expansion.next_memory_word_size(),
            cb.curr.state.memory_word_size.expr(),
        );

        // dynamic cost + constant cost
        let gas_cost = memory_copier_gas.gas_cost() + OpcodeId::MCOPY.constant_gas_cost().expr();

        // copy_rwc_inc used in copy circuit lookup.
        let copy_rwc_inc = cb.query_cell();
        cb.condition(memory_address.has_length(), |cb| {
            cb.copy_table_lookup(
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                // src_addr
                memory_address.offset(),
                // src_addr_end
                memory_address.end_offset(),
                // dest_addr
                dest_offset.expr(),
                memory_address.length(),
                // rlc_acc is 0 here.
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
            stack_pointer: Transition::Delta(3.expr()),
            memory_word_size: Transition::To(dest_word_size),

            gas_left: Transition::Delta(-gas_cost),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            memory_address,
            copy_rwc_inc,
            dest_offset,
            expand_from_addr,
            memory_expansion,
            memory_copier_gas,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _transaction: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let [dest_offset, src_offset, length] =
            [0, 1, 2].map(|idx| block.rws[step.rw_indices[idx]].stack_value());
        self.memory_address
            .assign(region, offset, src_offset, length)?;

        self.copy_rwc_inc.assign(
            region,
            offset,
            Value::known(
                step.copy_rw_counter_delta
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        let dest_offset_u64 = dest_offset.as_u64();
        let src_offset_u64 = src_offset.as_u64();

        self.dest_offset
            .assign(region, offset, Value::known(F::from(dest_offset_u64)))?;
        let (_, expand_adress) = self.expand_from_addr.assign(
            region,
            offset,
            F::from(src_offset_u64),
            F::from(dest_offset_u64),
        )?;

        // todo: will remove later
        println!("expand_adress {},", expand_adress.get_lower_64(),);
        let memory_expand_address = if length.is_zero() {
            0u64
        } else {
            expand_adress.get_lower_64() + length.as_u64()
        };

        let (next_memory_word_size, memory_expansion_gas_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [memory_expand_address],
        )?;

        self.memory_copier_gas.assign(
            region,
            offset,
            length.as_u64(),
            memory_expansion_gas_cost,
        )?;

        // todo: will remove later
        println!(
            "next_memory_word_size {}, memory_expansion_gas_cost {}",
            next_memory_word_size, memory_expansion_gas_cost
        );
        for _step in _transaction.steps.clone() {
            println!(
                "step {}, memory_word_size {}",
                _step.execution_state,
                _step.memory_word_size()
            )
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_bytes_array, test_util::CircuitTestBuilder};
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{address, bytecode, Address, Bytecode, Bytes, ToWord, Word};
    use mock::TestContext;
    use std::sync::LazyLock;

    static EXTERNAL_ADDRESS: LazyLock<Address> =
        LazyLock::new(|| address!("0xaabbccddee000000000000000000000000000000"));

    fn test_ok(src_offset: Word, dest_offset: Word, length: usize) {
        let mut code = Bytecode::default();
        code.append(&bytecode! {
            // prepare memory values by mstore
            PUSH10(0x6040ef28)
            PUSH2(0x20)
            MSTORE
            PUSH32(length)
            PUSH32(src_offset)
            PUSH32(dest_offset)
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

    // tests for zero copy length
    #[test]
    fn mcopy_empty() {
        test_ok(Word::from("0x20"), Word::zero(), 0x0);
        test_ok(Word::from("0xa8"), Word::from("0x2f"), 0x0);
    }

    // tests for real copy
    #[test]
    fn mcopy_non_empty() {
        // copy within one slot
        test_ok(Word::from("0x20"), Word::from("0x39"), 0x01);
        // copy across multi slots
        test_ok(Word::from("0x30"), Word::from("0x30"), 0xA0);
        test_ok(Word::from("0x40"), Word::from("0x40"), 0xE4);
    }

    // mcopy OOG cases added in ./execution/error_oog_memory_copy.rs
}
