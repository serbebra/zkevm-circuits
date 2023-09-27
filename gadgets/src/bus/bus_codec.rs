use std::{
    marker::PhantomData,
    ops::{Add, Mul},
};

use halo2_proofs::{circuit::Value, plonk::Expression};

/// A simple message encoder (expressions).
pub type BusCodecExpr<F> = BusCodec<Expression<F>, Vec<Expression<F>>>;

/// A simple message encoder (values).
pub type BusCodecVal<F> = BusCodec<Value<F>, Vec<Value<F>>>;

/// A message codec that adds a random value to the message.
#[derive(Clone, Debug)]
pub struct BusCodec<T, M> {
    rand: T,
    _marker: PhantomData<M>,
}

impl<T, M> BusCodec<T, M>
where
    T: Clone + Add<T, Output = T> + Mul<T, Output = T>,
    M: IntoIterator<Item = T>,
{
    /// Create a new message codec.
    pub fn new(rand: T) -> Self {
        Self {
            rand,
            _marker: PhantomData,
        }
    }

    /// Encode a message.
    pub fn encode(&self, msg: M) -> T {
        // TODO: support multiple values.
        let first = msg.into_iter().next().unwrap();
        self.rand.clone() + first
    }
}
