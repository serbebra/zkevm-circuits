use halo2_proofs::{arithmetic::FieldExt, circuit::Value, plonk::Expression};

use super::{
    bus_chip::BusTerm,
    bus_codec::{BusCodecExpr, BusCodecVal},
};

/// BusBuilder
#[derive(Debug)]
pub struct BusBuilder<F> {
    codec: BusCodecExpr<F>,
    terms: Vec<BusTerm<F>>,
}

impl<F: FieldExt> BusBuilder<F> {
    /// Create a new bus.
    pub fn new(rand: Expression<F>) -> Self {
        Self {
            codec: BusCodecExpr::new(rand),
            terms: vec![],
        }
    }

    /// Return the codec for messages on this bus.
    pub fn codec(&self) -> &BusCodecExpr<F> {
        &self.codec
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
    codec: BusCodecVal<F>,
    terms: Vec<F>,
    unknown: bool,
}

impl<F: FieldExt> BusAssigner<F> {
    /// Create a new bus assigner with a maximum number of rows.
    pub fn new(n_rows: usize, codec: BusCodecVal<F>) -> Self {
        Self {
            codec,
            terms: vec![F::zero(); n_rows],
            unknown: false,
        }
    }

    /// Return the codec for messages on this bus.
    pub fn codec(&self) -> &BusCodecVal<F> {
        &self.codec
    }

    /// Add a term value to the bus.
    pub fn add_term(&mut self, offset: usize, term: Value<F>) {
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

    /// Return the collected terms.
    pub fn terms(&self) -> Value<&[F]> {
        if self.unknown {
            Value::unknown()
        } else {
            Value::known(&self.terms)
        }
    }
}
