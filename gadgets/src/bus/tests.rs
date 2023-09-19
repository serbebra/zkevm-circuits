use crate::util::{query_expression, Expr};
use eth_types::Field;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Region, SimpleFloorPlanner, Value},
    dev::MockProver,
    halo2curves::bn256::Fr,
    plonk::{
        Advice, Column, ConstraintSystem, Error, Expression, FirstPhase, Fixed, Phase, VirtualCells,
    },
    poly::Rotation,
};
use std::marker::PhantomData;

use super::{bus_chip::*, bus_multi::*, bus_port::*};

#[test]
fn test_bus() {
    let cs = &mut ConstraintSystem::<Fr>::default();
    cs.advice_column(); // Bypass illogical validation.

    let rand = cs.challenge_usable_after(FirstPhase);
    let rand_expr = query_expression(cs, |cs| cs.query_challenge(rand));
    let mut bus_builder = BusBuilder::<Fr>::new(rand_expr);

    // Circuit 1.
    let port = BusPortColumn::put(cs, BusOp::put(1.expr(), 2.expr()));
    bus_builder.connect_port(cs, &port);

    // Circuit 2.
    let port = BusPortColumn::put(cs, BusOp::put(1.expr(), 2.expr()));
    bus_builder.connect_port(cs, &port);

    // Global bus connection.
    let bus_check = BusConfig::new(cs, &bus_builder.terms());
}
