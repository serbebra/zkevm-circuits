//! The ECC circuit is responsible for verifying ECC-related operations from precompiled contract
//! calls, namely, EcAdd, EcMul and EcPairing.

use std::marker::PhantomData;

use bus_mapping::circuit_input_builder::{EcAddOp, EcMulOp, EcPairingOp};
use eth_types::Field;
use halo2_base::utils::modulus;
use halo2_ecc::{
    ecc::EccChip,
    fields::{
        fp::{FpConfig, FpStrategy},
        fp12::Fp12Chip,
    },
};
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::bn256::{Fq, Fq12},
    plonk::{ConstraintSystem, Error, Expression},
};

use crate::{
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::Block,
};

/// TODO
#[derive(Clone, Debug)]
pub struct EccCircuitConfigArgs<F: Field> {
    /// zkEVM challenge API.
    pub challenges: Challenges<Expression<F>>,
}

/// TODO
#[derive(Clone, Debug)]
pub struct EccCircuitConfig<F: Field> {
    /// TODO
    fp_config: FpConfig<F, Fq>,

    _marker: PhantomData<F>,
}

impl<F: Field> SubCircuitConfig<F> for EccCircuitConfig<F> {
    type ConfigArgs = EccCircuitConfigArgs<F>;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs { challenges: _ }: Self::ConfigArgs,
    ) -> Self {
        let fp_config = FpConfig::configure(
            meta,
            FpStrategy::Simple,
            &[10, 1], // num advice
            &[17],    // num lookup advice
            1,        // num fixed
            13,       // lookup bits
            88,       // limb bits
            3,        // num limbs
            modulus::<Fq>(),
            0,
            10, // k
        );

        Self {
            fp_config,
            _marker: PhantomData,
        }
    }
}

/// The ECC Circuit is a sub-circuit of the super circuit, responsible for verifying the following
/// ECC operations:
/// 1. Point Addition (R = P + Q)
/// 2. Scalar Multiplication (R = s.P)
/// 3. Pairing-based bilinear function
///
/// We follow a strategy to pre-allocate maximum number of cells for each of the above ECC
/// operations, which means a witness that exceeds the pre-allocated number of cells for any of the
/// operations will be invalid.
#[derive(Clone, Debug)]
pub struct EccCircuit<F: Field> {
    /// Maximum number of EcAdd operations supported in one instance of the ECC Circuit.
    pub max_add_ops: usize,
    /// Maximum number of scalar multiplication operations supported in one instance of the ECC
    /// Circuit.
    pub max_mul_ops: usize,
    /// Maximum number of pairing operations supported in one instance of the ECC Circuit.
    pub max_pairing_ops: usize,

    /// EcAdd operations provided as witness data to the ECC circuit.
    pub add_ops: Vec<EcAddOp>,
    /// EcMul operations provided as witness data to the ECC circuit.
    pub mul_ops: Vec<EcMulOp>,
    /// EcPairing operations provided as witness data to the ECC circuit.
    pub pairing_ops: Vec<EcPairingOp>,

    _marker: PhantomData<F>,
}

impl<F: Field> EccCircuit<F> {
    pub(crate) fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        config: &<Self as SubCircuit<F>>::Config,
        add_ops: &[EcAddOp],
        mul_ops: &[EcMulOp],
        pairing_ops: &[EcPairingOp],
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        let fp_chip = EccChip::<F, FpConfig<F, Fq>>::construct(config.fp_config.clone());
        let fp12_chip =
            Fp12Chip::<F, FpConfig<F, Fq>, Fq12, 9>::construct(config.fp_config.clone());

        Ok(())
    }
}

impl<F: Field> SubCircuit<F> for EccCircuit<F> {
    type Config = EccCircuitConfig<F>;

    fn new_from_block(block: &Block<F>) -> Self {
        Self {
            max_add_ops: block.circuits_params.max_ec_ops.ec_add,
            max_mul_ops: block.circuits_params.max_ec_ops.ec_mul,
            max_pairing_ops: block.circuits_params.max_ec_ops.ec_pairing,
            add_ops: block.get_ec_add_ops(),
            mul_ops: block.get_ec_mul_ops(),
            pairing_ops: block.get_ec_pairing_ops(),
            _marker: PhantomData,
        }
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.fp_config.range.load_lookup_table(layouter)?;
        self.assign(
            layouter,
            config,
            &self.add_ops,
            &self.mul_ops,
            &self.pairing_ops,
            challenges,
        )?;
        Ok(())
    }

    fn min_num_rows_block(block: &Block<F>) -> (usize, usize) {
        unimplemented!()
    }
}
