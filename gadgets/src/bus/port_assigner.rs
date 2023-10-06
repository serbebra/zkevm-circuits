use super::{
    bus_builder::BusAssigner, bus_codec::BusMessageF, bus_port::BusOpA, util::HelperBatch, Field,
};
use halo2_proofs::circuit::{Region, Value};
use std::{
    collections::{
        hash_map::Entry::{Occupied, Vacant},
        HashMap,
    },
    marker::PhantomData,
};

/// Assigners are used to delay the assignment until helper values are computed.
pub trait Assigner<F: Field> {
    /// Given the helper value, assign ports and return (offset, term).
    #[must_use = "terms must be added to the bus"]
    fn assign(&self, region: &mut Region<'_, F>, helper: F) -> (usize, F);
}

/// PortAssigner computes and assigns terms into helper cells and the bus.
pub struct PortAssigner<F, M> {
    assigners: HelperBatch<F, Box<dyn Assigner<F>>>,
    _marker: PhantomData<M>,
}

impl<F: Field, M: BusMessageF<F>> PortAssigner<F, M> {
    /// Create a new PortAssigner.
    pub fn new() -> Self {
        Self {
            assigners: HelperBatch::new(),
            _marker: PhantomData,
        }
    }

    /// Execute an assignment later, with the inverse of `denom`.
    pub fn assign_later(&mut self, cmd: Box<dyn Assigner<F>>, denom: Value<F>) {
        self.assigners.add_denom(denom, cmd)
    }

    /// Assign the helper cells and report the terms to the bus.
    pub fn finish(self, region: &mut Region<'_, F>, bus_assigner: &mut BusAssigner<F, M>) {
        self.assigners.invert().map(|commands| {
            for (helper, command) in commands {
                let (offset, term) = command.assign(region, helper);
                bus_assigner.add_term(offset, Value::known(term));
                // TODO: Ensure this is a global offset (need Halo2 support).
            }
        });
    }

    pub fn len(&self) -> usize {
        self.assigners.len()
    }
}

/// OpCounter tracks the messages taken, to help generating the puts.
#[derive(Clone, Debug)]
pub struct BusOpCounter<F, M> {
    counts: HashMap<M, isize>,
    _marker: PhantomData<(F, M)>,
}

impl<F: Field, M: BusMessageF<F>> BusOpCounter<F, M> {
    /// Create a new BusOpCounter.
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
            _marker: PhantomData,
        }
    }

    /// Report an operation.
    pub fn track_op(&mut self, op: &BusOpA<M>) {
        if op.count() == 0 {
            return;
        }
        match self.counts.entry(op.message()) {
            Occupied(mut entry) => {
                let count = entry.get_mut();
                *count += op.count();
                if *count == 0 {
                    entry.remove();
                }
            }
            Vacant(entry) => {
                entry.insert(op.count());
            }
        };
    }

    /// Count how many times a message was taken (net of puts).
    pub fn count_takes(&self, message: &M) -> isize {
        (-self.count_ops(message)).max(0)
    }

    /// Count how many times a message was put (net of takes).
    pub fn count_puts(&self, message: &M) -> isize {
        self.count_ops(message).max(0)
    }

    /// Count how many times a message was put (net positive) or taken (net negative).
    fn count_ops(&self, message: &M) -> isize {
        *self.counts.get(message).unwrap_or(&0)
    }
}
