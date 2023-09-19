use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::Value,
    plonk::{ConstraintSystem, Expression},
};

use super::bus_chip::BusTerm;

/// BusPort prepares a term to be added to the bus.
pub trait BusPort<F: FieldExt> {
    /// The term to add to the bus. This expression must be fully constrained on all rows.
    fn create_term(&self, meta: &mut ConstraintSystem<F>, rand: Expression<F>) -> BusTerm<F>;
}

/// BusBuilder
pub struct BusBuilder<F> {
    rand: Expression<F>,
    terms: Vec<BusTerm<F>>,
}

impl<F: FieldExt> BusBuilder<F> {
    /// Create a new bus.
    pub fn new(rand: Expression<F>) -> Self {
        Self {
            rand,
            terms: vec![],
        }
    }

    /// Connect a port to the bus.
    pub fn connect_port<BP: BusPort<F>>(&mut self, meta: &mut ConstraintSystem<F>, port: &BP) {
        let term = port.create_term(meta, self.rand.clone());
        self.terms.push(term);
    }

    /// Return the collected terms.
    pub fn build(self) -> Vec<BusTerm<F>> {
        self.terms
    }
}

/// BusAssigner
pub struct BusAssigner<F> {
    terms: Vec<F>,
    all_assigned: bool,
}

impl<F: FieldExt> BusAssigner<F> {
    /// Create a new bus assigner with a maximum number of rows.
    pub fn new(n_rows: usize) -> Self {
        Self {
            terms: vec![F::zero(); n_rows],
            all_assigned: true,
        }
    }

    /// Put a term value to the bus.
    pub fn put_term(&mut self, offset: usize, term: Value<F>) {
        assert!(
            offset < self.terms.len(),
            "offset={offset} out of bounds n_rows={}",
            self.terms.len()
        );
        if term.is_none() {
            self.all_assigned = false;
        }
        term.map(|t| self.terms[offset] += t);
    }

    /// Take a term value from the bus.
    pub fn take_term(&mut self, offset: usize, term: Value<F>) {
        self.put_term(offset, -term);
    }

    /// Return the collected terms.
    pub fn terms(&self) -> Value<&[F]> {
        if self.all_assigned {
            Value::known(&self.terms)
        } else {
            Value::unknown()
        }
    }
}
