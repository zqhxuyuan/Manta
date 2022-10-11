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

//! Nimbus-based Parachain Node Service

use crate::rpc;
use jsonrpsee::RpcModule;
use log::info;
pub use manta_primitives::types::{AccountId, Balance, Block, Hash, Header, Index as Nonce};
use polkadot_service::CollatorPair;
use session_key_primitives::{AuraId, NimbusId};
use std::sync::Arc;
use substrate_prometheus_endpoint::Registry;

use cumulus_client_cli::CollatorOptions;
use cumulus_client_consensus_common::ParachainConsensus;
use cumulus_client_network::BlockAnnounceValidator;
use cumulus_client_service::{
    prepare_node_config, start_collator, start_full_node, StartCollatorParams, StartFullNodeParams,
};
use cumulus_primitives_core::ParaId;
use cumulus_primitives_parachain_inherent::{
    MockValidationDataInherentDataProvider, MockXcmConfig,
};
use cumulus_relay_chain_inprocess_interface::build_inprocess_relay_chain;
use cumulus_relay_chain_interface::{RelayChainError, RelayChainInterface, RelayChainResult};
use cumulus_relay_chain_rpc_interface::RelayChainRPCInterface;

use nimbus_consensus::{
    BuildNimbusConsensusParams, NimbusConsensus, NimbusManualSealConsensusDataProvider,
};

use sc_consensus::LongestChain;
use sc_consensus_aura::{ImportQueueParams, StartAuraParams};
use sc_consensus_slots::SlotProportion;
use sc_executor::WasmExecutor;
use sc_network::NetworkService;
pub use sc_rpc::{DenyUnsafe, SubscriptionTaskExecutor};
use sc_service::{
    Configuration, Error, KeystoreContainer, Role, TFullBackend, TFullClient, TaskManager,
};
use sc_telemetry::{Telemetry, TelemetryHandle, TelemetryWorker, TelemetryWorkerHandle};

use sp_api::{ApiExt, ConstructRuntimeApi};
use sp_blockchain::HeaderBackend;
use sp_consensus_aura::sr25519::AuthorityPair;
use sp_keystore::SyncCryptoStorePtr;
use sp_offchain::OffchainWorkerApi;
use sp_runtime::traits::BlakeTwo256;
use sp_session::SessionKeys;
use sp_transaction_pool::runtime_api::TaggedTransactionQueue;

#[cfg(not(feature = "runtime-benchmarks"))]
type HostFunctions = sp_io::SubstrateHostFunctions;

#[cfg(feature = "runtime-benchmarks")]
type HostFunctions = (
    sp_io::SubstrateHostFunctions,
    frame_benchmarking::benchmarking::HostFunctions,
);

/// Native Calamari Parachain executor instance.
pub struct CalamariRuntimeExecutor;
impl sc_executor::NativeExecutionDispatch for CalamariRuntimeExecutor {
    type ExtendHostFunctions = frame_benchmarking::benchmarking::HostFunctions;

    fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
        calamari_runtime::api::dispatch(method, data)
    }

    fn native_version() -> sc_executor::NativeVersion {
        calamari_runtime::native_version()
    }
}

/// Native Dolphin Parachain executor instance.
pub struct DolphinRuntimeExecutor;
impl sc_executor::NativeExecutionDispatch for DolphinRuntimeExecutor {
    type ExtendHostFunctions = frame_benchmarking::benchmarking::HostFunctions;

    fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
        dolphin_runtime::api::dispatch(method, data)
    }

    fn native_version() -> sc_executor::NativeVersion {
        dolphin_runtime::native_version()
    }
}

/// We use wasm executor only now.
pub type DefaultExecutorType = WasmExecutor<HostFunctions>;

/// Full Client Implementation Type
pub type Client<RuntimeApi> = TFullClient<Block, RuntimeApi, DefaultExecutorType>;

/// Default Import Queue Type
pub type ImportQueue<RuntimeApi> = sc_consensus::DefaultImportQueue<Block, Client<RuntimeApi>>;

/// Full Transaction Pool Type
pub type TransactionPool<RuntimeApi> = sc_transaction_pool::FullPool<Block, Client<RuntimeApi>>;

/// Components Needed for Chain Ops Subcommands
pub type PartialComponents<RuntimeApi> = sc_service::PartialComponents<
    Client<RuntimeApi>,
    TFullBackend<Block>,
    (),
    ImportQueue<RuntimeApi>,
    TransactionPool<RuntimeApi>,
    (Option<Telemetry>, Option<TelemetryWorkerHandle>),
>;

/// State Backend Type
pub type StateBackend = sc_client_api::StateBackendFor<TFullBackend<Block>, Block>;

/// Starts a `ServiceBuilder` for a full service.
///
/// Use this macro if you don't actually need the full service, but just the builder in order to
/// be able to perform chain operations.
pub fn new_partial<RuntimeApi>(
    config: &Configuration,
    dev: bool,
    use_aura: bool,
) -> Result<PartialComponents<RuntimeApi>, Error>
where
    RuntimeApi: ConstructRuntimeApi<Block, Client<RuntimeApi>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi: TaggedTransactionQueue<Block>
        + sp_api::Metadata<Block>
        + SessionKeys<Block>
        + ApiExt<Block, StateBackend = StateBackend>
        + sp_consensus_aura::AuraApi<Block, AuraId>
        + OffchainWorkerApi<Block>
        + sp_block_builder::BlockBuilder<Block>,
    StateBackend: sp_api::StateBackend<BlakeTwo256>,
{
    let telemetry = config
        .telemetry_endpoints
        .clone()
        .filter(|x| !x.is_empty())
        .map(|endpoints| -> Result<_, sc_telemetry::Error> {
            let worker = TelemetryWorker::new(16)?;
            let telemetry = worker.handle().new_telemetry(endpoints);
            Ok((worker, telemetry))
        })
        .transpose()?;
    let executor = WasmExecutor::<HostFunctions>::new(
        config.wasm_method,
        config.default_heap_pages,
        config.max_runtime_instances,
        None,
        config.runtime_cache_size,
    );
    let (client, backend, keystore_container, task_manager) =
        sc_service::new_full_parts::<Block, RuntimeApi, _>(
            config,
            telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
            executor,
        )?;
    let client = Arc::new(client);
    let telemetry_worker_handle = telemetry.as_ref().map(|(worker, _)| worker.handle());
    let telemetry = telemetry.map(|(worker, telemetry)| {
        task_manager
            .spawn_handle()
            .spawn("telemetry", None, worker.run());
        telemetry
    });
    let transaction_pool = sc_transaction_pool::BasicPool::new_full(
        config.transaction_pool.clone(),
        config.role.is_authority().into(),
        config.prometheus_registry(),
        task_manager.spawn_essential_handle(),
        client.clone(),
    );

    let import_queue = build_import_queue(
        client.clone(),
        config,
        telemetry.as_ref().map(|telemetry| telemetry.handle()),
        &task_manager,
        if use_aura {
            Consensus::Aura(dev)
        } else {
            Consensus::Nimbus(dev)
        },
    )?;

    Ok(PartialComponents {
        backend,
        client,
        import_queue,
        keystore_container,
        task_manager,
        transaction_pool,
        select_chain: (),
        other: (telemetry, telemetry_worker_handle),
    })
}

async fn build_relay_chain_interface(
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

/// Start a node with the given parachain `Configuration` and relay chain `Configuration`.
///
/// This is the actual implementation that is abstract over the executor and the runtime api.
#[sc_tracing::logging::prefix_logs_with("Parachain")]
async fn start_node_impl<RuntimeApi, BIC, FullRpc>(
    parachain_config: Configuration,
    polkadot_config: Configuration,
    collator_options: CollatorOptions,
    id: ParaId,
    full_rpc: FullRpc,
    build_consensus: BIC,
    hwbench: Option<sc_sysinfo::HwBench>,
) -> sc_service::error::Result<(TaskManager, Arc<Client<RuntimeApi>>)>
where
    RuntimeApi: ConstructRuntimeApi<Block, Client<RuntimeApi>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi: TaggedTransactionQueue<Block>
        + sp_api::Metadata<Block>
        + SessionKeys<Block>
        + ApiExt<Block, StateBackend = StateBackend>
        + OffchainWorkerApi<Block>
        + sp_block_builder::BlockBuilder<Block>
        + cumulus_primitives_core::CollectCollationInfo<Block>
        + pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>
        + nimbus_primitives::AuthorFilterAPI<Block, NimbusId>
        + nimbus_primitives::NimbusApi<Block>
        + sp_consensus_aura::AuraApi<Block, AuraId>
        + frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>,
    StateBackend: sp_api::StateBackend<BlakeTwo256>,
    FullRpc: Fn(
            rpc::FullDeps<Client<RuntimeApi>, TransactionPool<RuntimeApi>>,
        ) -> Result<RpcModule<()>, Error>
        + 'static,
    BIC: FnOnce(
        Arc<Client<RuntimeApi>>,
        Option<&Registry>,
        Option<TelemetryHandle>,
        &TaskManager,
        Arc<dyn RelayChainInterface>,
        Arc<TransactionPool<RuntimeApi>>,
        Arc<NetworkService<Block, Hash>>,
        SyncCryptoStorePtr,
        bool,
    ) -> Result<Box<dyn ParachainConsensus<Block>>, Error>,
{
    if matches!(parachain_config.role, Role::Light) {
        return Err("Light client not supported!".into());
    }

    let parachain_config = prepare_node_config(parachain_config);

    let params = new_partial::<RuntimeApi>(&parachain_config, false, false)?;
    let (mut telemetry, telemetry_worker_handle) = params.other;

    let mut task_manager = params.task_manager;
    let (relay_chain_interface, collator_key) = build_relay_chain_interface(
        polkadot_config,
        &parachain_config,
        telemetry_worker_handle,
        &mut task_manager,
        collator_options.clone(),
        hwbench.clone(),
    )
    .await
    .map_err(|e| match e {
        RelayChainError::ServiceError(polkadot_service::Error::Sub(x)) => x,
        s => s.to_string().into(),
    })?;

    let client = params.client.clone();
    let backend = params.backend.clone();
    let block_announce_validator = BlockAnnounceValidator::new(relay_chain_interface.clone(), id);

    let force_authoring = parachain_config.force_authoring;
    let collator = parachain_config.role.is_authority();
    let prometheus_registry = parachain_config.prometheus_registry().cloned();
    let transaction_pool = params.transaction_pool.clone();
    let import_queue = cumulus_client_service::SharedImportQueue::new(params.import_queue);
    let (network, system_rpc_tx, start_network) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &parachain_config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            import_queue: import_queue.clone(),
            block_announce_validator_builder: Some(Box::new(|_| {
                Box::new(block_announce_validator)
            })),
            warp_sync: None,
        })?;

    let rpc_builder = {
        let client = client.clone();
        let transaction_pool = transaction_pool.clone();

        Box::new(move |deny_unsafe, _| {
            let deps = crate::rpc::FullDeps {
                client: client.clone(),
                pool: transaction_pool.clone(),
                deny_unsafe,
            };

            full_rpc(deps)
        })
    };

    sc_service::spawn_tasks(sc_service::SpawnTasksParams {
        rpc_builder,
        client: client.clone(),
        transaction_pool: transaction_pool.clone(),
        task_manager: &mut task_manager,
        config: parachain_config,
        keystore: params.keystore_container.sync_keystore(),
        backend: backend.clone(),
        network: network.clone(),
        system_rpc_tx,
        telemetry: telemetry.as_mut(),
    })?;

    let announce_block = {
        let network = network.clone();
        Arc::new(move |hash, data| network.announce_block(hash, data))
    };

    let relay_chain_slot_duration = core::time::Duration::from_secs(6);
    if collator {
        let parachain_consensus = build_consensus(
            client.clone(),
            prometheus_registry.as_ref(),
            telemetry.as_ref().map(|t| t.handle()),
            &task_manager,
            relay_chain_interface.clone(),
            transaction_pool,
            network,
            params.keystore_container.sync_keystore(),
            force_authoring,
        )?;
        let spawner = task_manager.spawn_handle();
        start_collator(StartCollatorParams {
            para_id: id,
            block_status: client.clone(),
            announce_block,
            client: client.clone(),
            task_manager: &mut task_manager,
            relay_chain_interface,
            spawner,
            parachain_consensus,
            import_queue,
            collator_key: collator_key.expect("Command line arguments do not allow this. qed"),
            relay_chain_slot_duration,
        })
        .await?;
    } else {
        start_full_node(StartFullNodeParams {
            client: client.clone(),
            announce_block,
            task_manager: &mut task_manager,
            para_id: id,
            relay_chain_interface,
            relay_chain_slot_duration,
            import_queue,
            collator_options,
        })?;
    }

    start_network.start_network();
    Ok((task_manager, client))
}

/// Start a calamari/dolphin parachain node.
pub async fn start_parachain_node<RuntimeApi, FullRpc>(
    parachain_config: Configuration,
    polkadot_config: Configuration,
    collator_options: CollatorOptions,
    id: ParaId,
    hwbench: Option<sc_sysinfo::HwBench>,
    full_rpc: FullRpc,
) -> sc_service::error::Result<(TaskManager, Arc<Client<RuntimeApi>>)>
where
    RuntimeApi: ConstructRuntimeApi<Block, Client<RuntimeApi>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi: TaggedTransactionQueue<Block>
        + sp_api::Metadata<Block>
        + SessionKeys<Block>
        + ApiExt<Block, StateBackend = StateBackend>
        + OffchainWorkerApi<Block>
        + sp_block_builder::BlockBuilder<Block>
        + cumulus_primitives_core::CollectCollationInfo<Block>
        + pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>
        + nimbus_primitives::AuthorFilterAPI<Block, NimbusId>
        + nimbus_primitives::NimbusApi<Block>
        + sp_consensus_aura::AuraApi<Block, AuraId>
        + frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>,
    StateBackend: sp_api::StateBackend<BlakeTwo256>,
    FullRpc: Fn(
            rpc::FullDeps<Client<RuntimeApi>, TransactionPool<RuntimeApi>>,
        ) -> Result<RpcModule<()>, Error>
        + 'static,
{
    start_node_impl::<RuntimeApi, _, _>(
        parachain_config,
        polkadot_config,
        collator_options,
        id,
        full_rpc,
        |client,
         prometheus_registry,
         telemetry,
         task_manager,
         relay_chain_interface,
         transaction_pool,
         _sync_oracle,
         keystore,
         force_authoring| {
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
        },
        hwbench,
    )
    .await
}

/// Start a calamari/dolphin dev node without relaychain attached.
pub async fn start_dev_node<RuntimeApi, FullRpc>(
    config: Configuration,
    full_rpc: FullRpc,
    use_aura: bool,
) -> sc_service::error::Result<(TaskManager, Arc<Client<RuntimeApi>>)>
where
    RuntimeApi: ConstructRuntimeApi<Block, Client<RuntimeApi>> + Send + Sync + 'static,
    RuntimeApi::RuntimeApi: TaggedTransactionQueue<Block>
        + sp_api::Metadata<Block>
        + SessionKeys<Block>
        + ApiExt<Block, StateBackend = StateBackend>
        + OffchainWorkerApi<Block>
        + sp_block_builder::BlockBuilder<Block>
        + cumulus_primitives_core::CollectCollationInfo<Block>
        + pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>
        + nimbus_primitives::AuthorFilterAPI<Block, NimbusId>
        + nimbus_primitives::NimbusApi<Block>
        + sp_consensus_aura::AuraApi<Block, AuraId>
        + frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>,
    StateBackend: sp_api::StateBackend<BlakeTwo256>,
    FullRpc: Fn(
            rpc::FullDeps<Client<RuntimeApi>, TransactionPool<RuntimeApi>>,
        ) -> Result<RpcModule<()>, Error>
        + 'static,
{
    let sc_service::PartialComponents {
        client,
        backend,
        mut task_manager,
        import_queue,
        keystore_container,
        select_chain: _maybe_select_chain,
        transaction_pool,
        other: (_, _),
    } = new_partial::<RuntimeApi>(&config, true, use_aura)?;

    let (network, system_rpc_tx, network_starter) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            import_queue,
            block_announce_validator_builder: None,
            warp_sync: None,
        })?;

    let role = config.role.clone();
    let select_chain = LongestChain::new(backend.clone());

    if role.is_authority() {
        start_dev_consensus(
            client.clone(),
            &config,
            transaction_pool.clone(),
            &keystore_container,
            select_chain,
            &task_manager,
            network.clone(),
            if use_aura {
                Consensus::Aura(true)
            } else {
                Consensus::Nimbus(true)
            },
        )?;
    }

    let rpc_builder = {
        let client = client.clone();
        let transaction_pool = transaction_pool.clone();

        Box::new(move |deny_unsafe, _| {
            let deps = crate::rpc::FullDeps {
                client: client.clone(),
                pool: transaction_pool.clone(),
                deny_unsafe,
            };

            full_rpc(deps)
        })
    };

    sc_service::spawn_tasks(sc_service::SpawnTasksParams {
        rpc_builder,
        client: client.clone(),
        transaction_pool,
        task_manager: &mut task_manager,
        config,
        keystore: keystore_container.sync_keystore(),
        backend,
        network,
        system_rpc_tx,
        telemetry: None,
    })?;

    network_starter.start_network();
    info!("Network started.");

    Ok((task_manager, client))
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
    RuntimeApi::RuntimeApi: TaggedTransactionQueue<Block>
        + sp_api::Metadata<Block>
        + SessionKeys<Block>
        + ApiExt<Block, StateBackend = StateBackend>
        + OffchainWorkerApi<Block>
        + sp_block_builder::BlockBuilder<Block>
        + sp_consensus_aura::AuraApi<Block, AuraId>,
    StateBackend: sp_api::StateBackend<BlakeTwo256>,
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
    RuntimeApi::RuntimeApi: TaggedTransactionQueue<Block>
        + sp_api::Metadata<Block>
        + SessionKeys<Block>
        + ApiExt<Block, StateBackend = StateBackend>
        + OffchainWorkerApi<Block>
        + sp_block_builder::BlockBuilder<Block>
        + cumulus_primitives_core::CollectCollationInfo<Block>
        + pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>
        + nimbus_primitives::AuthorFilterAPI<Block, NimbusId>
        + nimbus_primitives::NimbusApi<Block>
        + sp_consensus_aura::AuraApi<Block, AuraId>
        + frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>,
    StateBackend: sp_api::StateBackend<BlakeTwo256>,
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
