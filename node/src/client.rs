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

//! RuntimeApi for client

use manta_primitives::types::{AccountId, Balance, Block, Index as Nonce};
use session_key_primitives::{AuraId, NimbusId};
use sp_runtime::traits::BlakeTwo256;

/// Common RuntimeApi trait bound
pub trait RuntimeApiCommon:
    sp_api::Metadata<Block>
    + sp_api::ApiExt<Block>
    + sp_block_builder::BlockBuilder<Block>
    + sp_offchain::OffchainWorkerApi<Block>
    + sp_session::SessionKeys<Block>
    + sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block>
where
    <Self as sp_api::ApiExt<Block>>::StateBackend: sp_api::StateBackend<BlakeTwo256>,
{
}

/// Extend RuntimeApi trait bound
pub trait RuntimeApiExtend:
    pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>
    + frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>
    + cumulus_primitives_core::CollectCollationInfo<Block>
    + nimbus_primitives::AuthorFilterAPI<Block, NimbusId>
    + nimbus_primitives::NimbusApi<Block>
    + sp_consensus_aura::AuraApi<Block, AuraId>
{
}

impl<Api> RuntimeApiCommon for Api
where
    Api: sp_api::Metadata<Block>
        + sp_api::ApiExt<Block>
        + sp_block_builder::BlockBuilder<Block>
        + sp_offchain::OffchainWorkerApi<Block>
        + sp_session::SessionKeys<Block>
        + sp_transaction_pool::runtime_api::TaggedTransactionQueue<Block>,
    <Self as sp_api::ApiExt<Block>>::StateBackend: sp_api::StateBackend<BlakeTwo256>,
{
}

impl<Api> RuntimeApiExtend for Api where
    Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>
        + frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>
        + cumulus_primitives_core::CollectCollationInfo<Block>
        + nimbus_primitives::AuthorFilterAPI<Block, NimbusId>
        + nimbus_primitives::NimbusApi<Block>
        + sp_consensus_aura::AuraApi<Block, AuraId>
{
}
