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

//! Service builder

use crate::{
    client::{RuntimeApiCommon, RuntimeApiExtend},
    service::{Client, ImportQueue, StateBackend, TransactionPool},
};

use log::info;
use std::sync::Arc;

pub use manta_primitives::types::{AccountId, Balance, Block, Hash, Header, Index as Nonce};
use polkadot_service::CollatorPair;
use sc_consensus::LongestChain;
use sc_consensus_aura::{ImportQueueParams, StartAuraParams};
use sc_consensus_slots::SlotProportion;
use sc_network::NetworkService;
use sc_service::{Configuration, Error, KeystoreContainer, TFullBackend, TaskManager};
use sc_telemetry::{TelemetryHandle, TelemetryWorkerHandle};
use session_key_primitives::AuraId;
use sp_api::ConstructRuntimeApi;
use sp_blockchain::HeaderBackend;
use sp_consensus_aura::sr25519::AuthorityPair;
use sp_keystore::SyncCryptoStorePtr;
use substrate_prometheus_endpoint::Registry;

use cumulus_client_cli::CollatorOptions;
use cumulus_client_consensus_common::ParachainConsensus;
use cumulus_primitives_core::ParaId;
use cumulus_primitives_parachain_inherent::{
    MockValidationDataInherentDataProvider, MockXcmConfig,
};
use cumulus_relay_chain_inprocess_interface::build_inprocess_relay_chain;
use cumulus_relay_chain_interface::{RelayChainInterface, RelayChainResult};
use cumulus_relay_chain_rpc_interface::RelayChainRPCInterface;

use nimbus_consensus::{
    BuildNimbusConsensusParams, NimbusConsensus, NimbusManualSealConsensusDataProvider,
};

/// build relaychain interface when running as parachain node
pub async fn build_relay_chain_interface(
    polkadot_config: Configuration,
    parachain_config: &Configuration,
    telemetry_worker_handle: Option<TelemetryWorkerHandle>,
    task_manager: &mut TaskManager,
    collator_options: CollatorOptions,
    hwbench: Option<sc_sysinfo::HwBench>,
) -> RelayChainResult<(
    Arc<(dyn RelayChainInterface + 'static)>,
    Option<CollatorPair>,
)> {
    match collator_options.relay_chain_rpc_url {
        Some(relay_chain_url) => Ok((
            Arc::new(RelayChainRPCInterface::new(relay_chain_url).await?) as Arc<_>,
            None,
        )),
        None => build_inprocess_relay_chain(
            polkadot_config,
            parachain_config,
            telemetry_worker_handle,
            task_manager,
            hwbench,
        ),
    }
}

/// build parachain consensus
pub fn build_consensus<RuntimeApi>(
    id: ParaId,
    client: Arc<Client<RuntimeApi>>,
    prometheus_registry: Option<&Registry>,
    telemetry: Option<TelemetryHandle>,
    task_manager: &TaskManager,
    relay_chain_interface: Arc<dyn RelayChainInterface>,
    transaction_pool: Arc<TransactionPool<RuntimeApi>>,
    _sync_oracle: Arc<NetworkService<Block, Hash>>,
    keystore: SyncCryptoStorePtr,
    force_authoring: bool,
) -> Result<Box<dyn ParachainConsensus<Block>>, Error>
where
    RuntimeApi: ConstructRuntimeApi<Block, Client<RuntimeApi>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi: RuntimeApiCommon<StateBackend = StateBackend> + RuntimeApiExtend,
{
    let spawn_handle = task_manager.spawn_handle();
    let proposer_factory = sc_basic_authorship::ProposerFactory::with_proof_recording(
        spawn_handle,
        client.clone(),
        transaction_pool,
        prometheus_registry,
        telemetry,
    );

    // NOTE: In nimbus, author_id is unused as it is the RuntimeAPI that identifies the block author
    let provider = move |_, (relay_parent, validation_data, _author_id)| {
        let relay_chain_interface = relay_chain_interface.clone();
        async move {
            let parachain_inherent =
                cumulus_primitives_parachain_inherent::ParachainInherentData::create_at(
                    relay_parent,
                    &relay_chain_interface,
                    &validation_data,
                    id,
                )
                .await;

            let time = sp_timestamp::InherentDataProvider::from_system_time();

            let parachain_inherent = parachain_inherent.ok_or_else(|| {
                Box::<dyn std::error::Error + Send + Sync>::from(
                    "Failed to create parachain inherent",
                )
            })?;

            let nimbus_inherent = nimbus_primitives::InherentDataProvider;
            Ok((time, parachain_inherent, nimbus_inherent))
        }
    };

    Ok(NimbusConsensus::build(BuildNimbusConsensusParams {
        additional_digests_provider: (),
        para_id: id,
        proposer_factory,
        block_import: client.clone(),
        parachain_client: client,
        keystore,
        skip_prediction: force_authoring,
        create_inherent_data_providers: provider,
    }))
}

/// build import queue for different consensus
pub fn build_import_queue<RuntimeApi>(
    client: Arc<Client<RuntimeApi>>,
    config: &Configuration,
    telemetry_handle: Option<TelemetryHandle>,
    task_manager: &TaskManager,
    consensus_mode: Consensus,
) -> Result<ImportQueue<RuntimeApi>, Error>
where
    RuntimeApi: ConstructRuntimeApi<Block, Client<RuntimeApi>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi:
        RuntimeApiCommon<StateBackend = StateBackend> + sp_consensus_aura::AuraApi<Block, AuraId>,
{
    match consensus_mode {
        // Actually we don't need `dev` switch on `Nimbus` mode, as `Nimbus` is work both as standalone and parachain node.
        Consensus::Nimbus(_dev) => {
            Ok(crate::aura_or_nimbus_consensus::import_queue(
                // single step block import pipeline, after nimbus/aura seal, import block into client
                client.clone(),
                client.clone(),
                &task_manager.spawn_essential_handle(),
                config.prometheus_registry(),
                telemetry_handle,
            )?)
        }
        Consensus::Aura(dev) if dev => {
            let slot_duration = sc_consensus_aura::slot_duration(&*client)?;
            let client_for_cidp = client.clone();

            let import_queue = sc_consensus_aura::import_queue::<AuthorityPair, _, _, _, _, _, _>(
                ImportQueueParams {
                    block_import: client.clone(),
                    justification_import: None,
                    client: client.clone(),
                    create_inherent_data_providers: move |block: Hash, ()| {
                        let current_para_block = client_for_cidp
                            .number(block)
                            .expect("Header lookup should succeed")
                            .expect("Header passed in as parent should be present in backend.");
                        let client_for_xcm = client_for_cidp.clone();

                        async move {
                            let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

                            let slot = sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                                *timestamp,
                                slot_duration,
                            );

                            let mocked_parachain = MockValidationDataInherentDataProvider {
                                current_para_block,
                                relay_offset: 1000,
                                relay_blocks_per_para_block: 2,
                                xcm_config: MockXcmConfig::new(
                                    &*client_for_xcm,
                                    block,
                                    Default::default(),
                                    Default::default(),
                                ),
                                raw_downward_messages: vec![],
                                raw_horizontal_messages: vec![],
                            };

                            Ok((timestamp, slot, mocked_parachain))
                        }
                    },
                    spawner: &task_manager.spawn_essential_handle(),
                    registry: config.prometheus_registry(),
                    can_author_with: sp_consensus::AlwaysCanAuthor,
                    check_for_equivocation: Default::default(),
                    telemetry: telemetry_handle,
                },
            )?;
            Ok(import_queue)
        }
        _ => Err(Error::Other("Not supported consensus type!".to_string())),
    }
}

/// start dev consensus
pub fn start_dev_consensus<RuntimeApi>(
    client: Arc<Client<RuntimeApi>>,
    config: &Configuration,
    transaction_pool: Arc<TransactionPool<RuntimeApi>>,
    keystore_container: &KeystoreContainer,
    select_chain: LongestChain<TFullBackend<Block>, Block>,
    task_manager: &TaskManager,
    network: Arc<NetworkService<Block, Hash>>,
    consensus_mode: Consensus,
) -> Result<(), Error>
where
    RuntimeApi: ConstructRuntimeApi<Block, Client<RuntimeApi>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi: RuntimeApiCommon<StateBackend = StateBackend> + RuntimeApiExtend,
{
    use futures::{Stream, StreamExt};
    use sc_consensus_manual_seal::{run_manual_seal, EngineCommand, ManualSealParams};
    use sc_consensus_slots::BackoffAuthoringOnFinalizedHeadLagging;

    let proposer_factory = sc_basic_authorship::ProposerFactory::new(
        task_manager.spawn_handle(),
        client.clone(),
        transaction_pool.clone(),
        None,
        None,
    );

    match consensus_mode {
        Consensus::Nimbus(_dev) => {
            let commands_stream: Box<dyn Stream<Item = EngineCommand<Hash>> + Send + Sync + Unpin> =
                Box::new(
                    // This bit cribbed from the implementation of instant seal.
                    transaction_pool
                        .pool()
                        .validated_pool()
                        .import_notification_stream()
                        .map(|_| EngineCommand::SealNewBlock {
                            create_empty: false,
                            finalize: false,
                            parent_hash: None,
                            sender: None,
                        }),
                );

            let client_set_aside_for_cidp = client.clone();

            let consensus = run_manual_seal(ManualSealParams {
                block_import: client.clone(),
                env: proposer_factory,
                client: client.clone(),
                pool: transaction_pool.clone(),
                commands_stream,
                select_chain,
                consensus_data_provider: Some(Box::new(NimbusManualSealConsensusDataProvider {
                    keystore: keystore_container.sync_keystore(),
                    client: client.clone(),
                    additional_digests_provider: (),
                })),
                create_inherent_data_providers: move |block: Hash, ()| {
                    let current_para_block = client_set_aside_for_cidp
                        .number(block)
                        .expect("Header lookup should succeed")
                        .expect("Header passed in as parent should be present in backend.");

                    let client_for_xcm = client_set_aside_for_cidp.clone();
                    async move {
                        let time = sp_timestamp::InherentDataProvider::from_system_time();

                        let mocked_parachain = MockValidationDataInherentDataProvider {
                            current_para_block,
                            relay_offset: 1000,
                            relay_blocks_per_para_block: 2,
                            xcm_config: MockXcmConfig::new(
                                &*client_for_xcm,
                                block,
                                Default::default(),
                                Default::default(),
                            ),
                            raw_downward_messages: vec![],
                            raw_horizontal_messages: vec![],
                        };

                        Ok((time, mocked_parachain))
                    }
                },
            });

            task_manager.spawn_essential_handle().spawn_blocking(
                "authorship_task",
                Some("block-authoring"),
                consensus,
            );
        }
        Consensus::Aura(dev) if dev => {
            let slot_duration = sc_consensus_aura::slot_duration(&*client)?;
            let client_for_cidp = client.clone();

            let aura = sc_consensus_aura::start_aura::<
                AuthorityPair,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
                _,
            >(StartAuraParams {
                slot_duration: sc_consensus_aura::slot_duration(&*client)?,
                client: client.clone(),
                select_chain,
                block_import: client.clone(),
                proposer_factory,
                create_inherent_data_providers: move |block: Hash, ()| {
                    let current_para_block = client_for_cidp
                        .number(block)
                        .expect("Header lookup should succeed")
                        .expect("Header passed in as parent should be present in backend.");
                    let client_for_xcm = client_for_cidp.clone();

                    async move {
                        let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

                        let slot = sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                            *timestamp,
                            slot_duration,
                        );

                        let mocked_parachain = MockValidationDataInherentDataProvider {
                            current_para_block,
                            relay_offset: 1000,
                            relay_blocks_per_para_block: 2,
                            xcm_config: MockXcmConfig::new(
                                &*client_for_xcm,
                                block,
                                Default::default(),
                                Default::default(),
                            ),
                            raw_downward_messages: vec![],
                            raw_horizontal_messages: vec![],
                        };

                        Ok((timestamp, slot, mocked_parachain))
                    }
                },
                force_authoring: config.force_authoring,
                backoff_authoring_blocks: Some(BackoffAuthoringOnFinalizedHeadLagging::default()),
                keystore: keystore_container.sync_keystore(),
                can_author_with: sp_consensus::AlwaysCanAuthor,
                sync_oracle: network.clone(),
                justification_sync_link: network.clone(),
                // We got around 500ms for proposing
                block_proposal_slot_portion: SlotProportion::new(1f32 / 24f32),
                // And a maximum of 750ms if slots are skipped
                max_block_proposal_slot_portion: Some(SlotProportion::new(1f32 / 16f32)),
                telemetry: None,
            })?;
            task_manager.spawn_essential_handle().spawn_blocking(
                "aura",
                Some("block-authoring"),
                aura,
            );
            info!("Aura Consensus Started.")
        }
        _ => {}
    }

    Ok(())
}

/// Consensus type, the `bool` indicate whether is `dev` or not.
pub enum Consensus {
    /// Use aura consensus
    Aura(bool),
    /// Use nimbus consensus
    Nimbus(bool),
}
