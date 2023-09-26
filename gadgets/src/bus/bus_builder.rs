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
#[derive(Debug)]
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

    /// The random challenge used to encode messages.
    pub fn rand(&self) -> Expression<F> {
        self.rand.clone()
    }

    /// Add a term to the bus.
    pub fn add_term(&mut self, term: BusTerm<F>) {
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
    unknown: bool,
}

impl<F: FieldExt> BusAssigner<F> {
    /// Create a new bus assigner with a maximum number of rows.
    pub fn new(n_rows: usize) -> Self {
        Self {
            terms: vec![F::zero(); n_rows],
            unknown: false,
        }
    }

    /// Put a term value to the bus.
    pub fn put_term(&mut self, offset: usize, term: Value<F>) {
        assert!(
            offset < self.terms.len(),
            "offset={offset} out of bounds n_rows={}",
            self.terms.len()
        );
        if self.unknown {
            return;
        }
        if term.is_none() {
            self.unknown = true;
            self.terms.clear();
        } else {
            term.map(|t| self.terms[offset] += t);
        }
    }

    /// Take a term value from the bus.
    pub fn take_term(&mut self, offset: usize, term: Value<F>) {
        self.put_term(offset, -term);
    }

    /// Return the collected terms.
    pub fn terms(&self) -> Value<&[F]> {
        if self.unknown {
            Value::unknown()
        } else {
            Value::known(&self.terms)
        }
    }
}
