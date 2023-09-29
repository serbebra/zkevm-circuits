use halo2_proofs::{arithmetic::FieldExt, circuit::Value};

use super::{
    bus_chip::BusTerm,
    bus_codec::{BusCodecExpr, BusCodecVal},
};

/// BusBuilder
#[derive(Debug)]
pub struct BusBuilder<F, M> {
    codec: BusCodecExpr<F, M>,
    terms: Vec<BusTerm<F>>,
}

impl<F: FieldExt, M> BusBuilder<F, M> {
    /// Create a new bus.
    pub fn new(codec: BusCodecExpr<F, M>) -> Self {
        Self {
            codec,
            terms: vec![],
        }
    }

    /// Return the codec for messages on this bus.
    pub fn codec(&self) -> &BusCodecExpr<F, M> {
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
pub struct BusAssigner<F, M> {
    codec: BusCodecVal<F, M>,
    terms: Vec<F>,
    unknown: bool,
}

impl<F: FieldExt, M> BusAssigner<F, M> {
    /// Create a new bus assigner with a maximum number of rows.
    pub fn new(codec: BusCodecVal<F, M>, n_rows: usize) -> Self {
        Self {
            codec,
            terms: vec![F::zero(); n_rows],
            unknown: false,
        }
    }

    /// Return the codec for messages on this bus.
    pub fn codec(&self) -> &BusCodecVal<F, M> {
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
