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

use crate::base_impl::*;
use ark_algebra_test_templates::*;
use ark_models_ext::pairing::PairingOutput;

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
test_pairing!(pairing; crate::Bn254<()>);
