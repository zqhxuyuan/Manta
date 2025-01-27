// Copyright 2020-2022 Manta Network.
// This file is part of Manta.
//
// Manta is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Manta is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Manta.  If not, see <http://www.gnu.org/licenses/>.

//! Autogenerated weights for pallet_assets
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2022-08-10, STEPS: `50`, REPEAT: 20, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("dolphin-dev"), DB CACHE: 1024

// Executed Command:
// manta
// benchmark
// pallet
// --chain=dolphin-dev
// --pallet=pallet_assets
// --extrinsic=*
// --execution=Wasm
// --wasm-execution=Compiled
// --heap-pages=4096
// --repeat=20
// --steps=50
// --template=.github/resources/frame-weight-template.hbs
// --output=pallet_assets.rs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]
#![allow(clippy::unnecessary_cast)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use sp_std::marker::PhantomData;

/// Weight functions needed for pallet_assets.
pub trait WeightInfo {
    fn create() -> Weight;
    fn force_create() -> Weight;
    fn destroy(c: u32, s: u32, a: u32, ) -> Weight;
    fn mint() -> Weight;
    fn burn() -> Weight;
    fn transfer() -> Weight;
    fn transfer_keep_alive() -> Weight;
    fn force_transfer() -> Weight;
    fn freeze() -> Weight;
    fn thaw() -> Weight;
    fn freeze_asset() -> Weight;
    fn thaw_asset() -> Weight;
    fn transfer_ownership() -> Weight;
    fn set_team() -> Weight;
    fn set_metadata(n: u32, s: u32, ) -> Weight;
    fn clear_metadata() -> Weight;
    fn force_set_metadata(n: u32, s: u32, ) -> Weight;
    fn force_clear_metadata() -> Weight;
    fn force_asset_status() -> Weight;
    fn approve_transfer() -> Weight;
    fn transfer_approved() -> Weight;
    fn cancel_approval() -> Weight;
    fn force_cancel_approval() -> Weight;
}

/// Weights for pallet_assets using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> pallet_assets::WeightInfo for SubstrateWeight<T> {
    // Storage: Assets Asset (r:1 w:1)
    fn create() -> Weight {
        (17_626_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(1 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    fn force_create() -> Weight {
        (16_886_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(1 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Account (r:5002 w:5001)
    // Storage: System Account (r:5000 w:5000)
    // Storage: Assets Metadata (r:1 w:0)
    // Storage: Assets Approvals (r:501 w:500)
    fn destroy(c: u32, s: u32, a: u32, ) -> Weight {
        (0 as Weight)
            // Standard Error: 39_000
            .saturating_add((18_084_000 as Weight).saturating_mul(c as Weight))
            // Standard Error: 39_000
            .saturating_add((21_167_000 as Weight).saturating_mul(s as Weight))
            // Standard Error: 397_000
            .saturating_add((14_148_000 as Weight).saturating_mul(a as Weight))
            .saturating_add(T::DbWeight::get().reads(5 as Weight))
            .saturating_add(T::DbWeight::get().reads((2 as Weight).saturating_mul(c as Weight)))
            .saturating_add(T::DbWeight::get().reads((2 as Weight).saturating_mul(s as Weight)))
            .saturating_add(T::DbWeight::get().reads((1 as Weight).saturating_mul(a as Weight)))
            .saturating_add(T::DbWeight::get().writes(2 as Weight))
            .saturating_add(T::DbWeight::get().writes((2 as Weight).saturating_mul(c as Weight)))
            .saturating_add(T::DbWeight::get().writes((2 as Weight).saturating_mul(s as Weight)))
            .saturating_add(T::DbWeight::get().writes((1 as Weight).saturating_mul(a as Weight)))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Account (r:1 w:1)
    fn mint() -> Weight {
        (34_523_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(2 as Weight))
            .saturating_add(T::DbWeight::get().writes(2 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Account (r:1 w:1)
    fn burn() -> Weight {
        (39_065_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(2 as Weight))
            .saturating_add(T::DbWeight::get().writes(2 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Account (r:2 w:2)
    // Storage: System Account (r:1 w:1)
    fn transfer() -> Weight {
        (54_634_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(4 as Weight))
            .saturating_add(T::DbWeight::get().writes(4 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Account (r:2 w:2)
    // Storage: System Account (r:1 w:1)
    fn transfer_keep_alive() -> Weight {
        (42_387_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(4 as Weight))
            .saturating_add(T::DbWeight::get().writes(4 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Account (r:2 w:2)
    // Storage: System Account (r:1 w:1)
    fn force_transfer() -> Weight {
        (50_923_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(4 as Weight))
            .saturating_add(T::DbWeight::get().writes(4 as Weight))
    }
    // Storage: Assets Asset (r:1 w:0)
    // Storage: Assets Account (r:1 w:1)
    fn freeze() -> Weight {
        (21_546_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(2 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:0)
    // Storage: Assets Account (r:1 w:1)
    fn thaw() -> Weight {
        (22_879_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(2 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    fn freeze_asset() -> Weight {
        (18_993_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(1 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    fn thaw_asset() -> Weight {
        (18_850_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(1 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Metadata (r:1 w:0)
    fn transfer_ownership() -> Weight {
        (20_644_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(2 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    fn set_team() -> Weight {
        (19_107_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(1 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:0)
    // Storage: Assets Metadata (r:1 w:1)
    fn set_metadata(_n: u32, s: u32, ) -> Weight {
        (22_115_000 as Weight)
            // Standard Error: 1_000
            .saturating_add((2_000 as Weight).saturating_mul(s as Weight))
            .saturating_add(T::DbWeight::get().reads(2 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:0)
    // Storage: Assets Metadata (r:1 w:1)
    fn clear_metadata() -> Weight {
        (20_187_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(2 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:0)
    // Storage: Assets Metadata (r:1 w:1)
    fn force_set_metadata(_n: u32, s: u32, ) -> Weight {
        (20_575_000 as Weight)
            // Standard Error: 1_000
            .saturating_add((1_000 as Weight).saturating_mul(s as Weight))
            .saturating_add(T::DbWeight::get().reads(2 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:0)
    // Storage: Assets Metadata (r:1 w:1)
    fn force_clear_metadata() -> Weight {
        (20_186_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(2 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    fn force_asset_status() -> Weight {
        (18_294_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(1 as Weight))
            .saturating_add(T::DbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Approvals (r:1 w:1)
    fn approve_transfer() -> Weight {
        (26_029_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(2 as Weight))
            .saturating_add(T::DbWeight::get().writes(2 as Weight))
    }
    // Storage: Assets Approvals (r:1 w:1)
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Account (r:2 w:2)
    // Storage: System Account (r:1 w:1)
    fn transfer_approved() -> Weight {
        (55_972_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(5 as Weight))
            .saturating_add(T::DbWeight::get().writes(5 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Approvals (r:1 w:1)
    fn cancel_approval() -> Weight {
        (24_320_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(2 as Weight))
            .saturating_add(T::DbWeight::get().writes(2 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Approvals (r:1 w:1)
    fn force_cancel_approval() -> Weight {
        (28_003_000 as Weight)
            .saturating_add(T::DbWeight::get().reads(2 as Weight))
            .saturating_add(T::DbWeight::get().writes(2 as Weight))
    }
}

// For backwards compatibility and tests
impl WeightInfo for () {
    // Storage: Assets Asset (r:1 w:1)
    fn create() -> Weight {
        (17_626_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(1 as Weight))
            .saturating_add(RocksDbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    fn force_create() -> Weight {
        (16_886_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(1 as Weight))
            .saturating_add(RocksDbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Account (r:5002 w:5001)
    // Storage: System Account (r:5000 w:5000)
    // Storage: Assets Metadata (r:1 w:0)
    // Storage: Assets Approvals (r:501 w:500)
    fn destroy(c: u32, s: u32, a: u32, ) -> Weight {
        (0 as Weight)
            // Standard Error: 39_000
            .saturating_add((18_084_000 as Weight).saturating_mul(c as Weight))
            // Standard Error: 39_000
            .saturating_add((21_167_000 as Weight).saturating_mul(s as Weight))
            // Standard Error: 397_000
            .saturating_add((14_148_000 as Weight).saturating_mul(a as Weight))
            .saturating_add(RocksDbWeight::get().reads(5 as Weight))
            .saturating_add(RocksDbWeight::get().reads((2 as Weight).saturating_mul(c as Weight)))
            .saturating_add(RocksDbWeight::get().reads((2 as Weight).saturating_mul(s as Weight)))
            .saturating_add(RocksDbWeight::get().reads((1 as Weight).saturating_mul(a as Weight)))
            .saturating_add(RocksDbWeight::get().writes(2 as Weight))
            .saturating_add(RocksDbWeight::get().writes((2 as Weight).saturating_mul(c as Weight)))
            .saturating_add(RocksDbWeight::get().writes((2 as Weight).saturating_mul(s as Weight)))
            .saturating_add(RocksDbWeight::get().writes((1 as Weight).saturating_mul(a as Weight)))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Account (r:1 w:1)
    fn mint() -> Weight {
        (34_523_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(2 as Weight))
            .saturating_add(RocksDbWeight::get().writes(2 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Account (r:1 w:1)
    fn burn() -> Weight {
        (39_065_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(2 as Weight))
            .saturating_add(RocksDbWeight::get().writes(2 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Account (r:2 w:2)
    // Storage: System Account (r:1 w:1)
    fn transfer() -> Weight {
        (54_634_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(4 as Weight))
            .saturating_add(RocksDbWeight::get().writes(4 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Account (r:2 w:2)
    // Storage: System Account (r:1 w:1)
    fn transfer_keep_alive() -> Weight {
        (42_387_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(4 as Weight))
            .saturating_add(RocksDbWeight::get().writes(4 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Account (r:2 w:2)
    // Storage: System Account (r:1 w:1)
    fn force_transfer() -> Weight {
        (50_923_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(4 as Weight))
            .saturating_add(RocksDbWeight::get().writes(4 as Weight))
    }
    // Storage: Assets Asset (r:1 w:0)
    // Storage: Assets Account (r:1 w:1)
    fn freeze() -> Weight {
        (21_546_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(2 as Weight))
            .saturating_add(RocksDbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:0)
    // Storage: Assets Account (r:1 w:1)
    fn thaw() -> Weight {
        (22_879_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(2 as Weight))
            .saturating_add(RocksDbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    fn freeze_asset() -> Weight {
        (18_993_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(1 as Weight))
            .saturating_add(RocksDbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    fn thaw_asset() -> Weight {
        (18_850_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(1 as Weight))
            .saturating_add(RocksDbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Metadata (r:1 w:0)
    fn transfer_ownership() -> Weight {
        (20_644_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(2 as Weight))
            .saturating_add(RocksDbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    fn set_team() -> Weight {
        (19_107_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(1 as Weight))
            .saturating_add(RocksDbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:0)
    // Storage: Assets Metadata (r:1 w:1)
    fn set_metadata(_n: u32, s: u32, ) -> Weight {
        (22_115_000 as Weight)
            // Standard Error: 1_000
            .saturating_add((2_000 as Weight).saturating_mul(s as Weight))
            .saturating_add(RocksDbWeight::get().reads(2 as Weight))
            .saturating_add(RocksDbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:0)
    // Storage: Assets Metadata (r:1 w:1)
    fn clear_metadata() -> Weight {
        (20_187_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(2 as Weight))
            .saturating_add(RocksDbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:0)
    // Storage: Assets Metadata (r:1 w:1)
    fn force_set_metadata(_n: u32, s: u32, ) -> Weight {
        (20_575_000 as Weight)
            // Standard Error: 1_000
            .saturating_add((1_000 as Weight).saturating_mul(s as Weight))
            .saturating_add(RocksDbWeight::get().reads(2 as Weight))
            .saturating_add(RocksDbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:0)
    // Storage: Assets Metadata (r:1 w:1)
    fn force_clear_metadata() -> Weight {
        (20_186_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(2 as Weight))
            .saturating_add(RocksDbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    fn force_asset_status() -> Weight {
        (18_294_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(1 as Weight))
            .saturating_add(RocksDbWeight::get().writes(1 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Approvals (r:1 w:1)
    fn approve_transfer() -> Weight {
        (26_029_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(2 as Weight))
            .saturating_add(RocksDbWeight::get().writes(2 as Weight))
    }
    // Storage: Assets Approvals (r:1 w:1)
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Account (r:2 w:2)
    // Storage: System Account (r:1 w:1)
    fn transfer_approved() -> Weight {
        (55_972_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(5 as Weight))
            .saturating_add(RocksDbWeight::get().writes(5 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Approvals (r:1 w:1)
    fn cancel_approval() -> Weight {
        (24_320_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(2 as Weight))
            .saturating_add(RocksDbWeight::get().writes(2 as Weight))
    }
    // Storage: Assets Asset (r:1 w:1)
    // Storage: Assets Approvals (r:1 w:1)
    fn force_cancel_approval() -> Weight {
        (28_003_000 as Weight)
            .saturating_add(RocksDbWeight::get().reads(2 as Weight))
            .saturating_add(RocksDbWeight::get().writes(2 as Weight))
    }
}
