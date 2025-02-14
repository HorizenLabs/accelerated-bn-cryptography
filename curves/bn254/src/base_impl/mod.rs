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

//! Implementations for test hooks.
//!
//! We just safely transmute from Arkworks-Ext types to Arkworks upstream types by
//! encoding and deconding and jump into the *Arkworks* upstream methods.

#![allow(clippy::result_unit_err)]

use ark_ec::{
    pairing::{MillerLoopOutput, Pairing},
    short_weierstrass::{Affine as SWAffine, Projective as SWProjective, SWCurveConfig},
    twisted_edwards::{Affine as TEAffine, Projective as TEProjective, TECurveConfig},
    CurveConfig, VariableBaseMSM,
};
use ark_scale::{
    ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate},
    scale::{Decode, Encode},
};
use ark_std::vec::Vec;

use crate::CurveHooks;
use ark_bn254::{g1::Config as ArkG1Config, g2::Config as ArkG2Config, Bn254 as ArkBn254};

#[cfg(feature = "scale-no-compress")]
const SCALE_COMPRESS: Compress = Compress::No;
#[cfg(not(feature = "scale-no-compress"))]
const SCALE_COMPRESS: Compress = Compress::Yes;

/// SCALE codec usage settings.
///
/// Determines whether compression and validation has been enabled for SCALE codec
/// with respect to ARK related types.
///
/// WARNING: usage of validation can be dangeruos in the hooks as it may re-enter
/// the same hook ad cause a stack-overflow.
const SCALE_USAGE: u8 = ark_scale::make_usage(SCALE_COMPRESS, Validate::No);

type ArkScale<T> = ark_scale::ArkScale<T, SCALE_USAGE>;

pub type Bn254 = crate::Bn254<()>;
pub type G1Projective = crate::G1Projective<()>;
pub type G2Projective = crate::G2Projective<()>;
pub type G1Affine = crate::G1Affine<()>;
pub type G2Affine = crate::G2Affine<()>;
pub type G1Config = crate::g1::Config<()>;
pub type G2Config = crate::g2::Config<()>;

trait TryTransmute {
    fn try_transmute<U: CanonicalDeserialize>(self) -> Result<U, ()>;
}

impl<T: CanonicalSerialize> TryTransmute for T {
    fn try_transmute<U: CanonicalDeserialize>(self) -> Result<U, ()> {
        let buf = ArkScale::from(self).encode();
        ArkScale::<U>::decode(&mut &buf[..])
            .map(|v| v.0)
            .map_err(|_| ())
    }
}

pub fn multi_miller_loop_generic<ExtPairing: Pairing, ArkPairing: Pairing>(
    g1: impl Iterator<Item = ExtPairing::G1Prepared>,
    g2: impl Iterator<Item = ExtPairing::G2Prepared>,
) -> Result<ExtPairing::TargetField, ()> {
    let g1: Vec<ArkPairing::G1Affine> = g1.collect::<Vec<_>>().try_transmute()?;
    let g2: Vec<ArkPairing::G2Affine> = g2.collect::<Vec<_>>().try_transmute()?;

    let res = ArkPairing::multi_miller_loop(g1, g2).0;
    res.try_transmute()
}

pub fn final_exponentiation_generic<ExtPairing: Pairing, ArkPairing: Pairing>(
    target: ExtPairing::TargetField,
) -> Result<ExtPairing::TargetField, ()> {
    let target: ArkPairing::TargetField = target.try_transmute()?;

    let res = ArkPairing::final_exponentiation(MillerLoopOutput(target)).ok_or(())?;
    res.try_transmute()
}

pub fn msm_sw_generic<ExtCurve: SWCurveConfig, ArkCurve: SWCurveConfig>(
    bases: &[SWAffine<ExtCurve>],
    scalars: &[ExtCurve::ScalarField],
) -> Result<SWProjective<ExtCurve>, ()> {
    let bases: Vec<SWAffine<ArkCurve>> = bases.try_transmute()?;
    let scalars: Vec<ArkCurve::ScalarField> = scalars.try_transmute()?;

    let res = <SWProjective<ArkCurve> as VariableBaseMSM>::msm(&bases, &scalars).map_err(|_| ())?;
    res.try_transmute()
}

#[allow(dead_code)]
pub fn msm_te_generic<ExtConfig: TECurveConfig, ArkConfig: TECurveConfig>(
    bases: &[TEAffine<ExtConfig>],
    scalars: &[ExtConfig::ScalarField],
) -> Result<TEProjective<ExtConfig>, ()> {
    let bases: Vec<TEAffine<ArkConfig>> = bases.try_transmute()?;
    let scalars: Vec<<ArkConfig as CurveConfig>::ScalarField> = scalars.try_transmute()?;

    let res =
        <TEProjective<ArkConfig> as VariableBaseMSM>::msm(&bases, &scalars).map_err(|_| ())?;
    res.try_transmute()
}

pub fn mul_projective_sw_generic<ExtConfig: SWCurveConfig, ArkConfig: SWCurveConfig>(
    base: &SWProjective<ExtConfig>,
    scalar: &[u64],
) -> Result<SWProjective<ExtConfig>, ()> {
    let base: SWProjective<ArkConfig> = base.try_transmute()?;

    let res = <ArkConfig as SWCurveConfig>::mul_projective(&base, scalar);
    res.try_transmute()
}

#[allow(dead_code)]
pub fn mul_projective_te_generic<ExtConfig: TECurveConfig, ArkConfig: TECurveConfig>(
    base: &TEProjective<ExtConfig>,
    scalar: &[u64],
) -> Result<TEProjective<ExtConfig>, ()> {
    let base: TEProjective<ArkConfig> = base.try_transmute()?;

    let res = <ArkConfig as TECurveConfig>::mul_projective(&base, scalar);
    res.try_transmute()
}

impl CurveHooks for () {
    fn bn254_multi_miller_loop(
        g1: impl Iterator<Item = <Bn254 as Pairing>::G1Prepared>,
        g2: impl Iterator<Item = <Bn254 as Pairing>::G2Prepared>,
    ) -> Result<<Bn254 as Pairing>::TargetField, ()> {
        multi_miller_loop_generic::<Bn254, ArkBn254>(g1, g2)
    }

    fn bn254_final_exponentiation(
        target: <Bn254 as Pairing>::TargetField,
    ) -> Result<<Bn254 as Pairing>::TargetField, ()> {
        final_exponentiation_generic::<Bn254, ArkBn254>(target)
    }

    fn bn254_msm_g1(
        bases: &[G1Affine],
        scalars: &[<G1Config as CurveConfig>::ScalarField],
    ) -> Result<G1Projective, ()> {
        msm_sw_generic::<G1Config, ArkG1Config>(bases, scalars)
    }

    fn bn254_msm_g2(
        bases: &[G2Affine],
        scalars: &[<G2Config as CurveConfig>::ScalarField],
    ) -> Result<G2Projective, ()> {
        msm_sw_generic::<G2Config, ArkG2Config>(bases, scalars)
    }

    fn bn254_mul_projective_g1(base: &G1Projective, scalar: &[u64]) -> Result<G1Projective, ()> {
        mul_projective_sw_generic::<G1Config, ArkG1Config>(base, scalar)
    }

    fn bn254_mul_projective_g2(base: &G2Projective, scalar: &[u64]) -> Result<G2Projective, ()> {
        mul_projective_sw_generic::<G2Config, ArkG2Config>(base, scalar)
    }
}
