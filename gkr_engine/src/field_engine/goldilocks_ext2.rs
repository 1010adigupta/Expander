use arith::ExtensionField;
use goldilocks::{Goldilocks, GoldilocksExt2, GoldilocksExt2x8, Goldilocksx8};

use crate::{FieldEngine, FieldType};

#[derive(Debug, Clone, PartialEq, Default)]
pub struct GoldilocksExtConfig;

impl FieldEngine for GoldilocksExtConfig {
    const FIELD_TYPE: FieldType = FieldType::Goldilocks;

    const SENTINEL: [u8; 32] = [
        1, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0,
    ];

    type CircuitField = Goldilocks;

    type SimdCircuitField = Goldilocksx8;

    type ChallengeField = GoldilocksExt2;

    type Field = GoldilocksExt2x8;

    #[inline(always)]
    fn challenge_mul_circuit_field(
        a: &Self::ChallengeField,
        b: &Self::CircuitField,
    ) -> Self::ChallengeField {
        a.mul_by_base_field(b)
    }

    #[inline(always)]
    fn field_mul_circuit_field(a: &Self::Field, b: &Self::CircuitField) -> Self::Field {
        *a * *b
    }

    #[inline(always)]
    fn field_add_circuit_field(a: &Self::Field, b: &Self::CircuitField) -> Self::Field {
        *a + *b
    }

    #[inline(always)]
    fn field_add_simd_circuit_field(a: &Self::Field, b: &Self::SimdCircuitField) -> Self::Field {
        a.add_by_base_field(b)
    }

    #[inline(always)]
    fn field_mul_simd_circuit_field(a: &Self::Field, b: &Self::SimdCircuitField) -> Self::Field {
        a.mul_by_base_field(b)
    }

    #[inline(always)]
    fn challenge_mul_field(a: &Self::ChallengeField, b: &Self::Field) -> Self::Field {
        let a_simd = Self::Field::from(*a);
        a_simd * b
    }

    #[inline(always)]
    fn circuit_field_into_field(a: &Self::SimdCircuitField) -> Self::Field {
        Self::Field::from(*a)
    }

    #[inline(always)]
    fn circuit_field_mul_simd_circuit_field(
        a: &Self::CircuitField,
        b: &Self::SimdCircuitField,
    ) -> Self::SimdCircuitField {
        Self::SimdCircuitField::from(*a) * *b
    }

    #[inline(always)]
    fn circuit_field_to_simd_circuit_field(a: &Self::CircuitField) -> Self::SimdCircuitField {
        Self::SimdCircuitField::from(*a)
    }

    #[inline(always)]
    fn simd_circuit_field_into_field(a: &Self::SimdCircuitField) -> Self::Field {
        Self::Field::from(*a)
    }

    #[inline(always)]
    fn simd_circuit_field_mul_challenge_field(
        a: &Self::SimdCircuitField,
        b: &Self::ChallengeField,
    ) -> Self::Field {
        let b_simd_ext = Self::Field::from(*b);
        Self::Field {
            c0: b_simd_ext.c0 * a,
            c1: b_simd_ext.c1 * a,
        }
    }
}
