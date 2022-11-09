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

use crate::{
    mock::{
        new_test_ext, MantaAssetConfig, MantaAssetRegistry, MantaPayPallet, Origin as MockOrigin,
        Test,
    },
    types::{decode, encode, AssetId, AssetValue},
    Error, FungibleLedger, StandardAssetId,
};
use frame_support::{assert_noop, assert_ok};
use manta_accounting::transfer::test::value_distribution;
use manta_crypto::{
    merkle_tree::{forest::TreeArrayMerkleForest, full::Full},
    rand::{CryptoRng, OsRng, Rand, RngCore},
};
use manta_pay::{
    config::{
        utxo::v2::MerkleTreeConfiguration, ConstraintField, MultiProvingContext, Parameters,
        TransferPost, UtxoAccumulatorModel,
    },
    crypto::constraint::arkworks::Fp,
    parameters::{self, load_transfer_parameters, load_utxo_accumulator_model},
    test,
};
use manta_primitives::{
    assets::{
        AssetConfig, AssetRegistry, AssetRegistryMetadata, AssetStorageMetadata,
        FungibleLedger as _,
    },
    constants::TEST_DEFAULT_ASSET_ED,
};

/// UTXO Accumulator for Building Circuits
type UtxoAccumulator =
    TreeArrayMerkleForest<MerkleTreeConfiguration, Full<MerkleTreeConfiguration>, 256>;

lazy_static::lazy_static! {
    static ref PROVING_CONTEXT: MultiProvingContext = load_proving_context();
    static ref PARAMETERS: Parameters = load_transfer_parameters();
    static ref UTXO_ACCUMULATOR_MODEL: UtxoAccumulatorModel = load_utxo_accumulator_model();
}

/// Loop randomized tests at least 10 times to reduce the change of false positives.
const RANDOMIZED_TESTS_ITERATIONS: usize = 1;

pub const ALICE: sp_runtime::AccountId32 = sp_runtime::AccountId32::new([0u8; 32]);
pub const NATIVE_ASSET_ID: StandardAssetId =
    <MantaAssetConfig as AssetConfig<Test>>::NativeAssetId::get();

/// Loads the [`MultiProvingContext`].
#[inline]
fn load_proving_context() -> MultiProvingContext {
    parameters::load_proving_context(
        tempfile::tempdir()
            .expect("Unable to create temporary directory.")
            .path(),
    )
}

/// Samples a [`Mint`] transaction of `asset` with a random secret.
#[inline]
fn sample_to_private<R>(asset_id: AssetId, value: AssetValue, rng: &mut R) -> TransferPost
where
    R: CryptoRng + RngCore + ?Sized,
{
    TransferPost::from(test::payment::to_private::prove_full(
        &PROVING_CONTEXT.to_private,
        &PARAMETERS,
        &UTXO_ACCUMULATOR_MODEL,
        MantaPayPallet::id_from_field(asset_id).unwrap().into(),
        value,
        rng,
    ))
}

/// Mints many assets with the given `id` and `value`.
#[inline]
fn mint_private_tokens<R>(id: StandardAssetId, values: &[AssetValue], rng: &mut R)
where
    R: CryptoRng + RngCore + ?Sized,
{
    for value in values {
        assert_ok!(MantaPayPallet::to_private(
            MockOrigin::signed(ALICE),
            sample_to_private(MantaPayPallet::field_from_id(id), *value, rng).into()
        ));
    }
}

/// Builds `count`-many [`PrivateTransfer`] tests.
#[inline]
fn private_transfer_test<R>(
    count: usize,
    asset_id_option: Option<StandardAssetId>,
    rng: &mut R,
) -> Vec<TransferPost>
where
    R: CryptoRng + RngCore + ?Sized,
{
    let asset_id = match asset_id_option {
        Some(id) => id,
        None => rng.gen(),
    };
    let total_free_balance: AssetValue = rng.gen();
    let balances = value_distribution(count, total_free_balance, rng);
    initialize_test(asset_id, total_free_balance + TEST_DEFAULT_ASSET_ED);
    let mut utxo_accumulator = UtxoAccumulator::new(UTXO_ACCUMULATOR_MODEL.clone());
    let mut posts = Vec::new();
    for balance in balances {
        let ([to_private_0, to_private_1], private_transfer) =
            test::payment::private_transfer::prove_full(
                &PROVING_CONTEXT,
                &PARAMETERS,
                &mut utxo_accumulator,
                Fp::from(asset_id),
                // Divide by 2 in order to not exceed total_supply
                [balance / 2, balance / 2],
                rng,
            );
        assert_ok!(MantaPayPallet::to_private(
            MockOrigin::signed(ALICE),
            to_private_0.into()
        ));
        assert_ok!(MantaPayPallet::to_private(
            MockOrigin::signed(ALICE),
            to_private_1.into()
        ));
        assert_ok!(MantaPayPallet::private_transfer(
            MockOrigin::signed(ALICE),
            private_transfer.clone().into(),
        ));

        posts.push(private_transfer)
    }
    posts
}

/// Builds `count`-many [`Reclaim`] tests.
#[inline]
fn reclaim_test<R>(
    count: usize,
    total_supply: AssetValue,
    id_option: Option<StandardAssetId>,
    rng: &mut R,
) -> Vec<TransferPost>
where
    R: CryptoRng + RngCore + ?Sized,
{
    let asset_id = match id_option {
        Some(id) => id,
        None => rng.gen(),
    };
    let balances = value_distribution(count, total_supply, rng);
    initialize_test(asset_id, total_supply + TEST_DEFAULT_ASSET_ED);
    let mut utxo_accumulator = UtxoAccumulator::new(UTXO_ACCUMULATOR_MODEL.clone());
    let mut posts = Vec::new();
    for balance in balances {
        let ([to_private_0, to_private_1], to_public) = test::payment::to_public::prove_full(
            &PROVING_CONTEXT,
            &PARAMETERS,
            &mut utxo_accumulator,
            Fp::from(asset_id),
            // Divide by 2 in order to not exceed total_supply
            [balance / 2, balance / 2],
            rng,
        );
        assert_ok!(MantaPayPallet::to_private(
            MockOrigin::signed(ALICE),
            to_private_0.into()
        ));
        assert_ok!(MantaPayPallet::to_private(
            MockOrigin::signed(ALICE),
            to_private_1.into()
        ));
        assert_ok!(MantaPayPallet::to_public(
            MockOrigin::signed(ALICE),
            to_public.clone().into()
        ));
        posts.push(to_public);
    }
    posts
}

/// Initializes a test by allocating `value`-many assets of the given `id` to the default account.
#[inline]
fn initialize_test(id: StandardAssetId, value: AssetValue) {
    let metadata = AssetRegistryMetadata {
        metadata: AssetStorageMetadata {
            name: b"Calamari".to_vec(),
            symbol: b"KMA".to_vec(),
            decimals: 12,
            is_frozen: false,
        },
        min_balance: TEST_DEFAULT_ASSET_ED,
        is_sufficient: true,
    };
    assert_ok!(MantaAssetRegistry::create_asset(
        id,
        metadata.into(),
        TEST_DEFAULT_ASSET_ED,
        true
    ));
    assert_ok!(FungibleLedger::<Test>::deposit_minting(id, &ALICE, value));
    assert_ok!(FungibleLedger::<Test>::deposit_minting(
        id,
        &MantaPayPallet::account_id(),
        TEST_DEFAULT_ASSET_ED
    ));
}

/// Tests multiple to_private from some total supply.
#[test]
fn to_private_should_work() {
    let mut rng = OsRng;
    for _ in 0..RANDOMIZED_TESTS_ITERATIONS {
        new_test_ext().execute_with(|| {
            let asset_id = rng.gen();
            let total_free_supply = rng.gen();
            initialize_test(asset_id, total_free_supply + TEST_DEFAULT_ASSET_ED);
            mint_private_tokens(
                asset_id,
                &value_distribution(5, total_free_supply, &mut rng),
                &mut rng,
            );
        });
    }
}

///
#[test]
fn native_asset_to_private_should_work() {
    let mut rng = OsRng;
    for _ in 0..RANDOMIZED_TESTS_ITERATIONS {
        new_test_ext().execute_with(|| {
            let total_free_supply = rng.gen();
            initialize_test(NATIVE_ASSET_ID, total_free_supply + TEST_DEFAULT_ASSET_ED);
            mint_private_tokens(
                NATIVE_ASSET_ID,
                &value_distribution(5, total_free_supply, &mut rng),
                &mut rng,
            );
        });
    }
}

/// Tests a mint that would overdraw the total supply.
#[test]
fn overdrawn_mint_should_not_work() {
    let mut rng = OsRng;
    for _ in 0..RANDOMIZED_TESTS_ITERATIONS {
        new_test_ext().execute_with(|| {
            let asset_id = rng.gen();
            let total_supply: u128 = rng.gen();
            initialize_test(asset_id, total_supply + TEST_DEFAULT_ASSET_ED);
            assert_noop!(
                MantaPayPallet::to_private(
                    MockOrigin::signed(ALICE),
                    sample_to_private(
                        MantaPayPallet::field_from_id(asset_id),
                        total_supply + TEST_DEFAULT_ASSET_ED + 1,
                        &mut rng
                    )
                    .into()
                ),
                Error::<Test>::InvalidSourceAccount
            );
        });
    }
}

/// Tests a mint that would overdraw from a non-existent supply.
#[test]
fn to_private_without_init_should_not_work() {
    let mut rng = OsRng;
    for _ in 0..RANDOMIZED_TESTS_ITERATIONS {
        new_test_ext().execute_with(|| {
            assert_noop!(
                MantaPayPallet::to_private(
                    MockOrigin::signed(ALICE),
                    sample_to_private(MantaPayPallet::field_from_id(rng.gen()), 100, &mut rng)
                        .into()
                ),
                Error::<Test>::InvalidSourceAccount,
            );
        });
    }
}

/// Tests that a double-spent [`Mint`] will fail.
#[test]
fn mint_existing_coin_should_not_work() {
    let mut rng = OsRng;
    for _ in 0..RANDOMIZED_TESTS_ITERATIONS {
        new_test_ext().execute_with(|| {
            let asset_id = rng.gen();
            initialize_test(asset_id, AssetValue::from(32579u128));
            let mint_post =
                sample_to_private(MantaPayPallet::field_from_id(asset_id), 100, &mut rng);
            assert_ok!(MantaPayPallet::to_private(
                MockOrigin::signed(ALICE),
                mint_post.clone().into()
            ));
            assert_noop!(
                MantaPayPallet::to_private(MockOrigin::signed(ALICE), mint_post.into()),
                Error::<Test>::AssetRegistered
            );
        });
    }
}

/// Tests a [`PrivateTransfer`] transaction.
#[test]
fn private_transfer_should_work() {
    for _ in 0..RANDOMIZED_TESTS_ITERATIONS {
        new_test_ext().execute_with(|| private_transfer_test(1, None, &mut OsRng));
    }
}

/// Test a [`PrivateTransfer`] transaction with native currency
#[test]
fn private_transfer_native_asset_should_work() {
    for _ in 0..RANDOMIZED_TESTS_ITERATIONS {
        new_test_ext().execute_with(|| {
            private_transfer_test(1, Some(NATIVE_ASSET_ID), &mut OsRng);
        });
    }
}

/// Tests multiple [`PrivateTransfer`] transactions.
#[test]
fn private_transfer_10_times_should_work() {
    for _ in 0..RANDOMIZED_TESTS_ITERATIONS {
        new_test_ext().execute_with(|| private_transfer_test(10, None, &mut OsRng));
    }
}

/// Tests that a double-spent [`PrivateTransfer`] will fail.
#[test]
fn double_spend_in_private_transfer_should_not_work() {
    for _ in 0..RANDOMIZED_TESTS_ITERATIONS {
        new_test_ext().execute_with(|| {
            for private_transfer in private_transfer_test(1, None, &mut OsRng) {
                assert_noop!(
                    MantaPayPallet::private_transfer(
                        MockOrigin::signed(ALICE),
                        private_transfer.into()
                    ),
                    Error::<Test>::AssetSpent,
                );
            }
        });
    }
}

/// Tests a [`Reclaim`] transaction.
#[test]
fn reclaim_should_work() {
    let mut rng = OsRng;
    for _ in 0..RANDOMIZED_TESTS_ITERATIONS {
        new_test_ext().execute_with(|| reclaim_test(1, rng.gen(), None, &mut rng));
    }
}

/// Test a [`Reclaim`] of native currency
#[test]
fn reclaim_native_should_work() {
    let mut rng = OsRng;
    for _ in 0..RANDOMIZED_TESTS_ITERATIONS {
        new_test_ext().execute_with(|| reclaim_test(1, rng.gen(), Some(NATIVE_ASSET_ID), &mut rng));
    }
}

/// Tests multiple [`Reclaim`] transactions.
#[test]
fn reclaim_10_times_should_work() {
    let mut rng = OsRng;
    for _ in 0..RANDOMIZED_TESTS_ITERATIONS {
        new_test_ext().execute_with(|| reclaim_test(10, rng.gen(), None, &mut rng));
    }
}

/// Tests that a double-spent [`Reclaim`] will fail.
#[test]
fn double_spend_in_reclaim_should_not_work() {
    for _ in 0..RANDOMIZED_TESTS_ITERATIONS {
        new_test_ext().execute_with(|| {
            let mut rng = OsRng;
            let total_supply: u128 = rng.gen();
            // TODO: maybe change all teh count: 1 tests to count: 10
            for reclaim in reclaim_test(1, AssetValue::from(total_supply / 2), None, &mut rng) {
                assert_noop!(
                    MantaPayPallet::to_public(MockOrigin::signed(ALICE), reclaim.into()),
                    Error::<Test>::AssetSpent,
                );
            }
        });
    }
}

#[test]
fn check_number_conversions() {
    let mut rng = OsRng;

    let start = rng.gen();
    let expected = MantaPayPallet::field_from_id(start);

    let fp = Fp::<ConstraintField>::from(start);
    let encoded = encode(fp);

    assert_eq!(expected, encoded);

    let id_from_field = MantaPayPallet::id_from_field(encoded).unwrap();
    let decoded: Fp<ConstraintField> = decode(expected).unwrap();
    assert_eq!(start, id_from_field);
    assert_eq!(fp, decoded);
}
