//! Bus module.

/// Bus chip that check the integrity of all bus accesses.
pub mod bus_chip;

/// A chip to access the bus.
pub mod bus_port;

/// A variant of bus port for mutually exclusive accesses.
pub mod bus_multi;

#[cfg(test)]
mod tests;

/*

sum( (1 / item) for each value ) == 0

item = RLC(beta, [ 1, circuit_tag, RLC(alpha, x), y, z, … ] )
                   1,    RW,  address, value
                   1,   COPY, src, dst, len
                   …

+0*item
+3*item
-item
-item
-item


Bus Check:
- on each row, sum_next = sum_current + term_circuit1 + term_circuit2 + … + term_circut10
- if is_last, sum_current == 0

Circuit 1:
term_circuit1 * value == 1

*/
