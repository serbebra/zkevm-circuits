use std::ops::{Add, Mul};

use halo2_proofs::{circuit::Value, plonk::Expression};

/// A simple message encoder (expressions).
pub type BusCodecExpr<F> = BusCodec<Expression<F>>;

/// A simple message encoder (values).
pub type BusCodecVal<F> = BusCodec<Value<F>>;

/// A message codec that adds a random value to the message.
#[derive(Clone, Debug)]
pub struct BusCodec<T> {
    rand: T,
}

impl<T> BusCodec<T>
where
    T: Clone + Add<T, Output = T> + Mul<T, Output = T>,
{
    /// Create a new message codec.
    pub fn new(rand: T) -> Self {
        Self { rand }
    }

    /// Encode a message.
    pub fn encode(&self, msg: T) -> T {
        self.rand.clone() + msg
    }
}
