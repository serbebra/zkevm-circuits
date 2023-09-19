//! Bus module.

/// Bus chip that check the integrity of all bus accesses.
pub mod bus_chip;

/// The bus builder collects all the ports into a bus.
pub mod bus_builder;

/// A chip to access the bus.
pub mod bus_port;

#[cfg(test)]
mod tests;
