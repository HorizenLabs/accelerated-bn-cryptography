// Copyright 2022 arkworks contributors
// Copyright 2024 Horizen Labs, Inc.
// SPDX-License-Identifier: Apache-2.0 or MIT

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![cfg(test)]

use crate::CurveHooks;
use ark_algebra_test_templates::*;
use ark_bn254::{g1::Config as ArkG1Config, g2::Config as ArkG2Config, Bn254 as ArkBn254};
use ark_ff::fields::Field;
use ark_models_ext::{
    pairing::{Pairing, PairingOutput},
    CurveConfig,
};

struct TestHooks;

type Bn254 = crate::Bn254<TestHooks>;
type G1Projective = crate::G1Projective<TestHooks>;
type G2Projective = crate::G2Projective<TestHooks>;
type G1Affine = crate::G1Affine<TestHooks>;
type G2Affine = crate::G2Affine<TestHooks>;
type G1Config = crate::g1::Config<TestHooks>;
type G2Config = crate::g2::Config<TestHooks>;

impl CurveHooks for TestHooks {
    fn bn254_multi_miller_loop(
        g1: impl Iterator<Item = <Bn254 as Pairing>::G1Prepared>,
        g2: impl Iterator<Item = <Bn254 as Pairing>::G2Prepared>,
    ) -> Result<<Bn254 as Pairing>::TargetField, ()> {
        test_utils::multi_miller_loop_generic::<Bn254, ArkBn254>(g1, g2)
    }

    fn bn254_final_exponentiation(
        target: <Bn254 as Pairing>::TargetField,
    ) -> Result<<Bn254 as Pairing>::TargetField, ()> {
        test_utils::final_exponentiation_generic::<Bn254, ArkBn254>(target)
    }

    fn bn254_msm_g1(
        bases: &[G1Affine],
        scalars: &[<G1Config as CurveConfig>::ScalarField],
    ) -> Result<G1Projective, ()> {
        test_utils::msm_sw_generic::<G1Config, ArkG1Config>(bases, scalars)
    }

    fn bn254_msm_g2(
        bases: &[G2Affine],
        scalars: &[<G2Config as CurveConfig>::ScalarField],
    ) -> Result<G2Projective, ()> {
        test_utils::msm_sw_generic::<G2Config, ArkG2Config>(bases, scalars)
    }

    fn bn254_mul_projective_g1(base: &G1Projective, scalar: &[u64]) -> Result<G1Projective, ()> {
        test_utils::mul_projective_sw_generic::<G1Config, ArkG1Config>(base, scalar)
    }

    fn bn254_mul_projective_g2(base: &G2Projective, scalar: &[u64]) -> Result<G2Projective, ()> {
        test_utils::mul_projective_sw_generic::<G2Config, ArkG2Config>(base, scalar)
    }
}

#[cfg(not(feature = "std"))]
extern crate std;

const fn iterations() -> usize {
    match std::option_env!("FAST_TESTS") {
        Some(_) => 2,
        _ => 500,
    }
}

test_group!(iterations(); g1; G1Projective; sw);
test_group!(iterations(); g2; G2Projective; sw);
test_group!(iterations(); pairing_output; PairingOutput<Bn254>; msm);
test_pairing!(pairing; crate::Bn254<super::TestHooks>);
