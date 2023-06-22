//! The ECC circuit is responsible for verifying ECC-related operations from precompiled contract
//! calls, namely, EcAdd, EcMul and EcPairing.

use std::{marker::PhantomData, ops::Mul};

use bus_mapping::circuit_input_builder::{EcAddOp, EcMulOp, EcPairingOp};
use eth_types::Field;
use halo2_base::utils::modulus;
use halo2_ecc::{
    bigint::CRTInteger,
    bn254::pairing::PairingChip,
    ecc::{EcPoint, EccChip},
    fields::{
        fp::{FpConfig, FpStrategy},
        fp12::Fp12Chip,
        fp2::Fp2Chip,
        FieldChip, FieldExtConstructor, FieldExtPoint,
    },
};
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::{
        bn256::{Bn256, Fq, Fq12, Fq2, Fr, Gt},
        pairing::Engine,
    },
    plonk::{ConstraintSystem, Error, Expression},
};
use itertools::Itertools;
use log::error;

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
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        if self.add_ops.len() > self.max_add_ops
            || self.mul_ops.len() > self.max_mul_ops
            || self.pairing_ops.len() > self.max_pairing_ops
        {
            error!(
                "add ops = {}, mul ops = {}, pairing ops = {} > max add ops = {}, max mul ops = {}, max pairing ops = {}",
                self.add_ops.len(),
                self.mul_ops.len(),
                self.pairing_ops.len(),
                self.max_add_ops,
                self.max_mul_ops,
                self.max_pairing_ops,
            );
            return Err(Error::Synthesis);
        }

        // for each pairing check input, we only allow up to 4 pairs, i.e. 4 * 192 bytes. The aim
        // is to simplify zkEVM implementation for now, not allowing dynamic length input for
        // EcPairing precompiled contract call.
        for pairing_op in self.pairing_ops.iter() {
            if pairing_op.inputs.len() > 4 {
                error!(
                    "pairing check inputs = {} max allowed = {}",
                    pairing_op.inputs.len(),
                    4,
                );
                return Err(Error::Synthesis);
            }
        }

        layouter.assign_region(
            || "ecc circuit",
            |region| {
                let mut ctx = config.fp_config.new_context(region);

                let fp_chip = EccChip::<F, FpConfig<F, Fq>>::construct(config.fp_config.clone());
                let fr_chip = FpConfig::<F, Fr>::construct(
                    config.fp_config.range.clone(),
                    88,
                    3,
                    modulus::<Fr>(),
                );
                let pairing_chip = PairingChip::construct(config.fp_config.clone());

                // P + Q == R
                for add_op in self
                    .add_ops
                    .iter()
                    .chain(std::iter::repeat(&EcAddOp::default()))
                    .take(self.max_add_ops)
                {
                    let point_p = fp_chip.load_private(
                        &mut ctx,
                        (Value::known(add_op.p.x), Value::known(add_op.p.y)),
                    );
                    let point_q = fp_chip.load_private(
                        &mut ctx,
                        (Value::known(add_op.q.x), Value::known(add_op.q.y)),
                    );
                    let point_r = fp_chip.add_unequal(
                        &mut ctx, &point_p, &point_q,
                        false, /* strict == false, as we do not check for whether or not P == Q */
                    );
                    let point_r_got = fp_chip.load_private(
                        &mut ctx,
                        (Value::known(add_op.r.x), Value::known(add_op.r.y)),
                    );
                    fp_chip.assert_equal(&mut ctx, &point_r, &point_r_got);
                }

                for mul_op in self
                    .mul_ops
                    .iter()
                    .chain(std::iter::repeat(&EcMulOp::default()))
                    .take(self.max_mul_ops)
                {
                    let point_p = fp_chip.load_private(
                        &mut ctx,
                        (Value::known(mul_op.p.x), Value::known(mul_op.p.y)),
                    );
                    let scalar_s = fr_chip.load_private(
                        &mut ctx,
                        FpConfig::<F, Fr>::fe_to_witness(&Value::known(mul_op.s)),
                    );
                    let point_r = fp_chip.scalar_mult(
                        &mut ctx,
                        &point_p,
                        &scalar_s.limbs().to_vec(),
                        fr_chip.limb_bits,
                        4, // TODO: window bits?
                    );
                    let point_r_got = fp_chip.load_private(
                        &mut ctx,
                        (Value::known(mul_op.r.x), Value::known(mul_op.r.y)),
                    );
                    fp_chip.assert_equal(&mut ctx, &point_r, &point_r_got);
                }

                for pairing_op in self
                    .pairing_ops
                    .iter()
                    .chain(std::iter::repeat(&EcPairingOp::default()))
                    .take(self.max_pairing_ops)
                {
                    let g1_points = pairing_op
                        .inputs
                        .iter()
                        .map(|i| pairing_chip.load_private_g1(&mut ctx, Value::known(i.0)))
                        .collect::<Vec<EcPoint<F, CRTInteger<F>>>>();
                    let g2_points = pairing_op
                        .inputs
                        .iter()
                        .map(|i| pairing_chip.load_private_g2(&mut ctx, Value::known(i.1)))
                        .collect::<Vec<EcPoint<F, FieldExtPoint<CRTInteger<F>>>>>();
                    let gt = pairing_chip.multi_miller_loop(
                        &mut ctx,
                        g1_points.iter().zip_eq(g2_points.iter()).collect_vec(),
                    );
                    let gt = pairing_chip.final_exp(&mut ctx, &gt);
                    let res_got = pairing_op.output;
                }

                Ok(())
            },
        )
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
        self.assign(layouter, config, challenges)?;
        Ok(())
    }

    fn min_num_rows_block(block: &Block<F>) -> (usize, usize) {
        unimplemented!()
    }
}
