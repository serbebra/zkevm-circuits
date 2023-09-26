use std::ops::Neg;

/// Convert an isize to a field element.
pub fn from_isize<F: From<u64> + Neg<Output = F>>(x: isize) -> F {
    if x < 0 {
        -F::from((-x) as u64)
    } else {
        F::from(x as u64)
    }
}
