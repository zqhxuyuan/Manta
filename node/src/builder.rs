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
    aura_wait_for_consensus::{BuildOnAccess, WaitForAuraConsensus},
    client::{RuntimeApiAura, RuntimeApiCommon, RuntimeApiNimbus},
    service::{Client, ImportQueue, StateBackend, TransactionPool},
};

use core::marker::PhantomData;
use futures::lock::Mutex;
use log::info;
pub use manta_primitives::types::{AccountId, Balance, Block, Hash, Header, Index as Nonce};
use polkadot_service::CollatorPair;
use session_key_primitives::AuraId;
use std::sync::Arc;

use sc_consensus::LongestChain;
use sc_consensus_aura::{ImportQueueParams, StartAuraParams};
use sc_consensus_slots::SlotProportion;
use sc_network::NetworkService;
use sc_service::{Configuration, Error, KeystoreContainer, TFullBackend, TaskManager};
use sc_telemetry::{TelemetryHandle, TelemetryWorkerHandle};
use sp_api::ConstructRuntimeApi;
use sp_application_crypto::AppKey;
use sp_blockchain::HeaderBackend;
use sp_consensus_aura::sr25519::AuthorityPair;
use sp_keystore::SyncCryptoStorePtr;
use substrate_prometheus_endpoint::Registry;

use cumulus_client_cli::CollatorOptions;
use cumulus_client_consensus_aura::{AuraConsensus, BuildAuraConsensusParams};
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

/// build parachain nimbus consensus
pub fn build_nimbus_consensus<RuntimeApi>(
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
    RuntimeApi::RuntimeApi: RuntimeApiCommon<StateBackend = StateBackend> + RuntimeApiNimbus,
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

/// build parachain aura consensus
pub fn build_aura_consensus<RuntimeApi>(
    id: ParaId,
    client: Arc<Client<RuntimeApi>>,
    prometheus_registry: Option<&Registry>,
    telemetry: Option<TelemetryHandle>,
    task_manager: &TaskManager,
    relay_chain_interface: Arc<dyn RelayChainInterface>,
    transaction_pool: Arc<TransactionPool<RuntimeApi>>,
    sync_oracle: Arc<NetworkService<Block, Hash>>,
    keystore: SyncCryptoStorePtr,
    force_authoring: bool,
) -> Result<Box<dyn ParachainConsensus<Block>>, Error>
where
    RuntimeApi: ConstructRuntimeApi<Block, Client<RuntimeApi>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi: RuntimeApiCommon<StateBackend = StateBackend> + RuntimeApiAura<AuraId>,
{
    let client2 = client.clone();
    let spawn_handle = task_manager.spawn_handle();
    let transaction_pool2 = transaction_pool.clone();
    let telemetry2 = telemetry.clone();
    let prometheus_registry2 = prometheus_registry.map(|r| (*r).clone());
    let relay_chain_for_aura = relay_chain_interface.clone();
    let aura_consensus = BuildOnAccess::Uninitialized(Some(Box::new(move || {
        let slot_duration = cumulus_client_consensus_aura::slot_duration(&*client2).unwrap();

        let proposer_factory = sc_basic_authorship::ProposerFactory::with_proof_recording(
            spawn_handle,
            client2.clone(),
            transaction_pool2,
            prometheus_registry2.as_ref(),
            telemetry2.clone(),
        );

        AuraConsensus::build::<<AuraId as AppKey>::Pair, _, _, _, _, _, _>(
            BuildAuraConsensusParams {
                proposer_factory,
                create_inherent_data_providers: move |_, (relay_parent, validation_data)| {
                    let relay_chain_for_aura = relay_chain_for_aura.clone();
                    async move {
                        let parachain_inherent =
                            cumulus_primitives_parachain_inherent::ParachainInherentData::create_at(
                                relay_parent,
                                &relay_chain_for_aura,
                                &validation_data,
                                id,
                            ).await;

                        let timestamp = sp_timestamp::InherentDataProvider::from_system_time();

                        let slot =
                            sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                                *timestamp,
                                slot_duration,
                            );

                        let parachain_inherent = parachain_inherent.ok_or_else(|| {
                            Box::<dyn std::error::Error + Send + Sync>::from(
                                "Failed to create parachain inherent",
                            )
                        })?;

                        Ok((timestamp, slot, parachain_inherent))
                    }
                },
                block_import: client2.clone(),
                para_client: client2.clone(),
                backoff_authoring_blocks: Option::<()>::None,
                sync_oracle,
                keystore,
                force_authoring,
                slot_duration,
                // We got around 500ms for proposing
                block_proposal_slot_portion: SlotProportion::new(1f32 / 24f32),
                // And a maximum of 750ms if slots are skipped
                max_block_proposal_slot_portion: Some(SlotProportion::new(1f32 / 16f32)),
                telemetry: telemetry2,
            },
        )
    })));

    let proposer_factory = sc_basic_authorship::ProposerFactory::with_proof_recording(
        task_manager.spawn_handle(),
        client.clone(),
        transaction_pool,
        prometheus_registry,
        telemetry,
    );

    let relay_chain_consensus = cumulus_client_consensus_relay_chain::build_relay_chain_consensus(
        cumulus_client_consensus_relay_chain::BuildRelayChainConsensusParams {
            para_id: id,
            proposer_factory,
            block_import: client.clone(),
            relay_chain_interface: relay_chain_interface.clone(),
            create_inherent_data_providers: move |_, (relay_parent, validation_data)| {
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
                    let parachain_inherent = parachain_inherent.ok_or_else(|| {
                        Box::<dyn std::error::Error + Send + Sync>::from(
                            "Failed to create parachain inherent",
                        )
                    })?;
                    Ok(parachain_inherent)
                }
            },
        },
    );

    let parachain_consensus = Box::new(WaitForAuraConsensus {
        client,
        aura_consensus: Arc::new(Mutex::new(aura_consensus)),
        relay_chain_consensus: Arc::new(Mutex::new(relay_chain_consensus)),
        _phantom: PhantomData,
    });

    Ok(parachain_consensus)
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
        Consensus::Aura(dev) if !dev => {
            Ok(crate::aura_wait_for_consensus::build_import_queue::<
                _,
                AuraId,
            >(
                client.clone(), config, telemetry_handle, task_manager
            )?)
        }
        _ => Err(Error::Other("Not supported consensus type!".to_string())),
    }
}

/// start dev consensus
pub fn start_dev_nimbus_instant_seal_consensus<RuntimeApi>(
    client: Arc<Client<RuntimeApi>>,
    transaction_pool: Arc<TransactionPool<RuntimeApi>>,
    keystore_container: &KeystoreContainer,
    select_chain: LongestChain<TFullBackend<Block>, Block>,
    task_manager: &TaskManager,
) -> Result<(), Error>
where
    RuntimeApi: ConstructRuntimeApi<Block, Client<RuntimeApi>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi: RuntimeApiCommon<StateBackend = StateBackend> + RuntimeApiNimbus,
{
    use futures::{Stream, StreamExt};
    use sc_consensus_manual_seal::{run_manual_seal, EngineCommand, ManualSealParams};

    let proposer_factory = sc_basic_authorship::ProposerFactory::new(
        task_manager.spawn_handle(),
        client.clone(),
        transaction_pool.clone(),
        None,
        None,
    );

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

    Ok(())
}

/// start dev aura consensus
pub fn start_dev_aura_consensus<RuntimeApi>(
    client: Arc<Client<RuntimeApi>>,
    config: &Configuration,
    transaction_pool: Arc<TransactionPool<RuntimeApi>>,
    keystore_container: &KeystoreContainer,
    select_chain: LongestChain<TFullBackend<Block>, Block>,
    task_manager: &TaskManager,
    network: Arc<NetworkService<Block, Hash>>,
) -> Result<(), Error>
where
    RuntimeApi: ConstructRuntimeApi<Block, Client<RuntimeApi>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi: RuntimeApiCommon<StateBackend = StateBackend> + RuntimeApiAura<AuraId>,
{
    use sc_consensus_slots::BackoffAuthoringOnFinalizedHeadLagging;

    let proposer_factory = sc_basic_authorship::ProposerFactory::new(
        task_manager.spawn_handle(),
        client.clone(),
        transaction_pool.clone(),
        None,
        None,
    );

    let slot_duration = sc_consensus_aura::slot_duration(&*client)?;
    let client_for_cidp = client.clone();

    let aura = sc_consensus_aura::start_aura::<AuthorityPair, _, _, _, _, _, _, _, _, _, _, _>(
        StartAuraParams {
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
        },
    )?;
    task_manager
        .spawn_essential_handle()
        .spawn_blocking("aura", Some("block-authoring"), aura);
    info!("Aura Consensus Started.");

    Ok(())
}

/// Consensus type, the `bool` indicate whether is `dev` or not.
pub enum Consensus {
    /// Use aura consensus
    Aura(bool),
    /// Use nimbus consensus
    Nimbus(bool),
}

/// Consensus builder
pub struct ConsensusBuilder {
    /// dev mode
    pub dev: bool,
    /// aura mode
    pub aura: bool,
}

impl ConsensusBuilder {
    /// default not use dev and aura
    pub fn default() -> Self {
        Self {
            dev: false,
            aura: false,
        }
    }

    /// set dev mode
    pub fn dev(mut self, dev: bool) -> Self {
        self.dev = dev;
        self
    }

    /// set aura mode
    pub fn aura(mut self, aura: bool) -> Self {
        self.aura = aura;
        self
    }

    /// build consensus
    pub fn build(self) -> Consensus {
        if self.aura {
            Consensus::Aura(self.dev)
        } else {
            Consensus::Nimbus(self.dev)
        }
    }
}
