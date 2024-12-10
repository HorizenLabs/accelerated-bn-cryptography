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

use ark_bn254::Config as ArkConfig;
use ark_ec::bn::BnConfig as ArkBnConfig;
use ark_models_ext::{
    bn::{Bn, BnConfig, G1Prepared, G2Prepared, TwistType},
    pairing::{MillerLoopOutput, Pairing, PairingOutput},
    CurveConfig,
};
use ark_std::marker::PhantomData;

pub mod g1;
pub mod g2;

#[cfg(test)]
mod tests;

pub use self::{
    g1::{G1Affine, G1Projective},
    g2::{G2Affine, G2Projective},
};

/// Hooks for *BN-254* curve.
pub trait CurveHooks: 'static + Sized {
    /// Pairing multi Miller loop.
    fn bn254_multi_miller_loop(
        g1: impl Iterator<Item = <Bn254<Self> as Pairing>::G1Prepared>,
        g2: impl Iterator<Item = <Bn254<Self> as Pairing>::G2Prepared>,
    ) -> Result<<Bn254<Self> as Pairing>::TargetField, ()>;

    /// Pairing final exponentiation.
    fn bn254_final_exponentiation(
        target: <Bn254<Self> as Pairing>::TargetField,
    ) -> Result<<Bn254<Self> as Pairing>::TargetField, ()>;

    /// Multi scalar multiplication on G1.
    fn bn254_msm_g1(
        bases: &[g1::G1Affine<Self>],
        scalars: &[<g1::Config<Self> as CurveConfig>::ScalarField],
    ) -> Result<G1Projective<Self>, ()>;

    /// Multi scalar multiplication on G2.
    fn bn254_msm_g2(
        bases: &[g2::G2Affine<Self>],
        scalars: &[<g2::Config<Self> as CurveConfig>::ScalarField],
    ) -> Result<G2Projective<Self>, ()>;

    /// Projective multiplication on G1.
    fn bn254_mul_projective_g1(
        base: &G1Projective<Self>,
        scalar: &[u64],
    ) -> Result<G1Projective<Self>, ()>;

    /// Projective multiplication on G2.
    fn bn254_mul_projective_g2(
        base: &G2Projective<Self>,
        scalar: &[u64],
    ) -> Result<G2Projective<Self>, ()>;
}

#[derive(Clone, Copy)]
pub struct Config<H: CurveHooks>(PhantomData<fn() -> H>);

pub type Bn254<H> = Bn<Config<H>>;

impl<H: CurveHooks> BnConfig for Config<H> {
    const X: &'static [u64] = <ArkConfig as ArkBnConfig>::X;
    const X_IS_NEGATIVE: bool = <ArkConfig as ArkBnConfig>::X_IS_NEGATIVE;
    const TWIST_TYPE: TwistType = <ArkConfig as ArkBnConfig>::TWIST_TYPE;

    const ATE_LOOP_COUNT: &'static [i8] = <ArkConfig as ArkBnConfig>::ATE_LOOP_COUNT;

    // Configure Field Extension Tower
    type Fp = <ArkConfig as ArkBnConfig>::Fp;
    type Fp2Config = <ArkConfig as ArkBnConfig>::Fp2Config;
    type Fp6Config = <ArkConfig as ArkBnConfig>::Fp6Config;
    type Fp12Config = <ArkConfig as ArkBnConfig>::Fp12Config;

    // Configure groups G1 and G2
    type G1Config = g1::Config<H>;
    type G2Config = g2::Config<H>;

    /// Multi Miller loop jumping into the user-defined `multi_miller_loop` hook.
    ///
    /// For any internal error returns `TargetField::zero()`.
    #[inline(always)]
    fn multi_miller_loop(
        g1: impl IntoIterator<Item = impl Into<G1Prepared<Self>>>,
        g2: impl IntoIterator<Item = impl Into<G2Prepared<Self>>>,
    ) -> MillerLoopOutput<Bn<Self>> {
        let g1 = g1.into_iter().map(|item| item.into());
        let g2 = g2.into_iter().map(|item| item.into());
        let res = H::bn254_multi_miller_loop(g1, g2);
        MillerLoopOutput(res.unwrap_or_default())
    }

    /// Final exponentiation jumping into the user-defined `final_exponentiation` hook.
    ///
    /// For any internal error returns `None`.
    #[inline(always)]
    fn final_exponentiation(target: MillerLoopOutput<Bn<Self>>) -> Option<PairingOutput<Bn<Self>>> {
        let res = H::bn254_final_exponentiation(target.0);
        res.map(PairingOutput).ok()
    }
}
