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
    M: BusMessage<T>,
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
        let first = msg.into_items().next().unwrap().into();
        self.rand.clone() + first
    }
}

/// A trait for messages that can be encoded.
pub trait BusMessage<T> {
    /// The item iterator type.
    type IntoIter: Iterator<Item = T>;

    /// Convert the message into an iterator.
    fn into_items(self) -> Self::IntoIter;
}

// The default implementation of `BusMessage` for iterators of compatible types.
impl<T, I> BusMessage<T> for I
where
    I: IntoIterator,
    I::Item: Into<T>,
{
    type IntoIter = std::iter::Map<I::IntoIter, fn(I::Item) -> T>;

    fn into_items(self) -> Self::IntoIter {
        self.into_iter().map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::halo2curves::bn256::Fr;

    use super::*;

    #[derive(Clone, Debug)]
    struct TestMessage {
        a: u64,
        b: u64,
    }

    impl<T: From<u64>> BusMessage<T> for TestMessage {
        type IntoIter = std::array::IntoIter<T, 2>;

        fn into_items(self) -> Self::IntoIter {
            [self.a.into(), self.b.into()].into_iter()
        }
    }

    #[test]
    fn test_codec() {
        {
            // Using vectors as message type.
            let codec = BusCodec::new(Fr::one());
            let msg = vec![1u64, 2u64, 3u64];
            assert_eq!(codec.encode(msg), Fr::from(2));
        }
        {
            // Using a custom message type.
            let codec = BusCodec::new(Fr::one());
            let msg = TestMessage { a: 1, b: 2 };
            assert_eq!(codec.encode(msg.clone()), Fr::from(2));
        }
    }
}
