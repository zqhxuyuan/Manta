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

//! Aura wait for conesnsus

use crate::{
    client::RuntimeApiCommon,
    service::{Client, ImportQueue, StateBackend},
};

use codec::Codec;
use core::marker::PhantomData;
use futures::lock::Mutex;
pub use manta_primitives::types::{AccountId, Balance, Block, Hash, Header, Index as Nonce};
use std::sync::Arc;

use cumulus_client_consensus_common::{
    ParachainBlockImport, ParachainCandidate, ParachainConsensus,
};
use cumulus_client_consensus_relay_chain::Verifier as RelayChainVerifier;
use cumulus_primitives_core::relay_chain::v2::{Hash as PHash, PersistedValidationData};

use sc_consensus::{
    import_queue::{BasicQueue, Verifier as VerifierT},
    BlockImportParams,
};
use sc_service::{Configuration, Error, TaskManager};
use sc_telemetry::TelemetryHandle;
use sp_api::{ApiExt, ConstructRuntimeApi};
use sp_consensus::CacheKeyId;
use sp_consensus_aura::AuraApi;
use sp_core::crypto::Pair;
use sp_runtime::{app_crypto::AppKey, generic::BlockId, traits::Header as HeaderT};

pub enum BuildOnAccess<R> {
    Uninitialized(Option<Box<dyn FnOnce() -> R + Send + Sync>>),
    Initialized(R),
}

impl<R> BuildOnAccess<R> {
    fn get_mut(&mut self) -> &mut R {
        loop {
            match self {
                Self::Uninitialized(f) => {
                    *self = Self::Initialized((f.take().unwrap())());
                }
                Self::Initialized(ref mut r) => return r,
            }
        }
    }
}

/// Special [`ParachainConsensus`] implementation that waits for the upgrade from
/// shell to a parachain runtime that implements Aura.
pub struct WaitForAuraConsensus<Client, AuraId> {
    pub client: Arc<Client>,
    pub aura_consensus: Arc<Mutex<BuildOnAccess<Box<dyn ParachainConsensus<Block>>>>>,
    pub relay_chain_consensus: Arc<Mutex<Box<dyn ParachainConsensus<Block>>>>,
    pub _phantom: PhantomData<AuraId>,
}

impl<Client, AuraId> Clone for WaitForAuraConsensus<Client, AuraId> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            aura_consensus: self.aura_consensus.clone(),
            relay_chain_consensus: self.relay_chain_consensus.clone(),
            _phantom: PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl<Client, AuraId> ParachainConsensus<Block> for WaitForAuraConsensus<Client, AuraId>
where
    Client: sp_api::ProvideRuntimeApi<Block> + Send + Sync,
    Client::Api: AuraApi<Block, AuraId>,
    AuraId: Send + Codec + Sync,
{
    async fn produce_candidate(
        &mut self,
        parent: &Header,
        relay_parent: PHash,
        validation_data: &PersistedValidationData,
    ) -> Option<ParachainCandidate<Block>> {
        let block_id = BlockId::hash(parent.hash());
        if self
            .client
            .runtime_api()
            .has_api::<dyn AuraApi<Block, AuraId>>(&block_id)
            .unwrap_or(false)
        {
            self.aura_consensus
                .lock()
                .await
                .get_mut()
                .produce_candidate(parent, relay_parent, validation_data)
                .await
        } else {
            self.relay_chain_consensus
                .lock()
                .await
                .produce_candidate(parent, relay_parent, validation_data)
                .await
        }
    }
}

struct Verifier<Client, AuraId> {
    client: Arc<Client>,
    aura_verifier: BuildOnAccess<Box<dyn VerifierT<Block>>>,
    relay_chain_verifier: Box<dyn VerifierT<Block>>,
    _phantom: PhantomData<AuraId>,
}

#[async_trait::async_trait]
impl<Client, AuraId> VerifierT<Block> for Verifier<Client, AuraId>
where
    Client: sp_api::ProvideRuntimeApi<Block> + Send + Sync,
    Client::Api: AuraApi<Block, AuraId>,
    AuraId: Send + Sync + Codec,
{
    async fn verify(
        &mut self,
        block_import: BlockImportParams<Block, ()>,
    ) -> Result<
        (
            BlockImportParams<Block, ()>,
            Option<Vec<(CacheKeyId, Vec<u8>)>>,
        ),
        String,
    > {
        let block_id = BlockId::hash(*block_import.header.parent_hash());

        if self
            .client
            .runtime_api()
            .has_api::<dyn AuraApi<Block, AuraId>>(&block_id)
            .unwrap_or(false)
        {
            self.aura_verifier.get_mut().verify(block_import).await
        } else {
            self.relay_chain_verifier.verify(block_import).await
        }
    }
}

/// Build the import queue for the calamari/manta runtime.
pub fn build_import_queue<RuntimeApi, AuraId: AppKey>(
    client: Arc<Client<RuntimeApi>>,
    config: &Configuration,
    telemetry_handle: Option<TelemetryHandle>,
    task_manager: &TaskManager,
) -> Result<ImportQueue<RuntimeApi>, Error>
where
    RuntimeApi: ConstructRuntimeApi<Block, Client<RuntimeApi>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi: RuntimeApiCommon<StateBackend = StateBackend>
        + AuraApi<Block, <<AuraId as AppKey>::Pair as Pair>::Public>,
    <<AuraId as AppKey>::Pair as Pair>::Signature:
        TryFrom<Vec<u8>> + std::hash::Hash + sp_runtime::traits::Member + Codec,
{
    let client2 = client.clone();

    let aura_verifier = move || {
        let slot_duration = cumulus_client_consensus_aura::slot_duration(&*client2).unwrap();
        Box::new(cumulus_client_consensus_aura::build_verifier::<
            <AuraId as AppKey>::Pair,
            _,
            _,
            _,
        >(
            cumulus_client_consensus_aura::BuildVerifierParams {
                client: client2.clone(),
                create_inherent_data_providers: move |_, _| async move {
                    let time = sp_timestamp::InherentDataProvider::from_system_time();

                    let slot =
                        sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                            *time,
                            slot_duration,
                        );

                    Ok((time, slot))
                },
                can_author_with: sp_consensus::AlwaysCanAuthor,
                telemetry: telemetry_handle,
            },
        )) as Box<_>
    };

    let relay_chain_verifier = Box::new(RelayChainVerifier::new(client.clone(), |_, _| async {
        Ok(())
    }));

    let verifier = Verifier {
        client: client.clone(),
        relay_chain_verifier,
        aura_verifier: BuildOnAccess::Uninitialized(Some(Box::new(aura_verifier))),
        _phantom: PhantomData,
    };

    let registry = config.prometheus_registry();
    let spawner = task_manager.spawn_essential_handle();

    Ok(BasicQueue::new(
        verifier,
        Box::new(ParachainBlockImport::new(client)),
        None,
        &spawner,
        registry,
    ))
}
