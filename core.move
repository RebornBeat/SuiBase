// core.move - Core module for SuiStack0X
module suistack0x::core {
    use sui::object::{Self, ID, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::table::{Self, Table};
    use sui::event;
    use sui::clock::{Self, Clock};
    use std::option::{Self, Option};
    use std::string::{Self, String};
    use std::vector;

    // Error codes
    const ENOT_AUTHORIZED: u64 = 0;
    const EINVALID_STAKE_AMOUNT: u64 = 1;
    const EINVALID_TEE_ATTESTATION: u64 = 2;
    const ENODE_NOT_FOUND: u64 = 3;
    const EINSUFFICIENT_STAKE: u64 = 4;
    const EINVALID_RESOURCE_ALLOCATION: u64 = 5;
    const ETEE_ATTESTATION_EXPIRED: u64 = 6;
    const EMODULE_NOT_ENABLED: u64 = 7;
    const ESTAKE_COOLING_PERIOD: u64 = 8;
    const EINVALID_UNSTAKE_AMOUNT: u64 = 9;
    const EINVALID_MODULE_ID: u64 = 10;

    // Constants for module identification
    const MODULE_COMPUTE: u8 = 0;
    const MODULE_EDGE: u8 = 1;
    const MODULE_INDEX: u8 = 2;
    const MODULE_DEPLOY: u8 = 3;

    // Constants for TEE platforms
    const TEE_PLATFORM_INTEL_SGX: u8 = 0;
    const TEE_PLATFORM_AMD_SEV: u8 = 1;
    const TEE_PLATFORM_ARM_TRUSTZONE: u8 = 2;
    const TEE_PLATFORM_AWS_NITRO: u8 = 3;

    // Constants for node status
    const NODE_STATUS_ACTIVE: u8 = 0;
    const NODE_STATUS_SLASHED: u8 = 1;
    const NODE_STATUS_INACTIVE: u8 = 2;
    const NODE_STATUS_EXITING: u8 = 3;

    // Core registry that manages all nodes and modules
    struct Registry has key {
        id: UID,
        nodes: Table<address, NodeInfo>,
        stake_manager: StakeManager,
        module_registries: ModuleRegistries,
        governance: Governance,
        treasury: Treasury,
        admin: address,
        config: RegistryConfig,
        created_at: u64,
        updated_at: u64
    }

    // Configuration parameters for the registry
    struct RegistryConfig has store {
        minimum_stake: u64,
        cooling_period: u64,
        tee_attestation_validity_period: u64,
        reward_distribution_period: u64,
        slashing_percentage: u64,
        heartbeat_period: u64,
        governance_voting_period: u64
    }

    // Information about a registered node
    struct NodeInfo has store {
        owner: address,
        endpoint: String,
        metadata: String,
        stake_amount: u64,
        active_stake: u64,
        cooling_stake: u64,
        cooling_end_epoch: u64,
        resources: ResourceAllocation,
        tee_attestation: TeeAttestation,
        reputation: ReputationScore,
        active_modules: vector<u8>,
        rewards_earned: u64,
        penalties_received: u64,
        joined_epoch: u64,
        last_heartbeat: u64,
        status: u8
    }

    // Resource allocation across different services
    struct ResourceAllocation has store, copy {
        compute_cores: u16,
        compute_memory: u64,
        storage_capacity: u64,
        bandwidth: u64,
        build_capacity: u16
    }

    // TEE attestation information
    struct TeeAttestation has store {
        platform_type: u8,
        attestation_report: vector<u8>,
        validation_timestamp: u64,
        expiration_timestamp: u64,
        verifier_signatures: vector<Signature>
    }

    // Cryptographic signature
    struct Signature has store, copy {
        signer: address,
        signature: vector<u8>,
        timestamp: u64
    }

    // Reputation scoring for a node
    struct ReputationScore has store {
        overall_score: u64,
        uptime_score: u64,
        performance_score: u64,
        verification_score: u64,
        history: vector<ReputationUpdate>
    }

    // Individual reputation update
    struct ReputationUpdate has store, copy {
        epoch: u64,
        old_score: u64,
        new_score: u64,
        reason: String
    }

    // All module registries
    struct ModuleRegistries has store {
        compute: ID, // ComputeRegistry ID
        edge: ID,    // EdgeRegistry ID
        index: ID,   // IndexRegistry ID
        deploy: ID   // DeployRegistry ID
    }

    // Staking and reward management
    struct StakeManager has store {
        total_stake: u64,
        active_stake: u64,
        cooling_stake: u64,
        stake_history: vector<StakeUpdate>,
        reward_pool: Balance<SUI>,
        last_reward_distribution: u64,
        epoch_rewards: vector<EpochReward>
    }

    // Historical stake update
    struct StakeUpdate has store, copy {
        epoch: u64,
        total_stake: u64,
        active_stake: u64,
        cooling_stake: u64
    }

    // Rewards for a specific epoch
    struct EpochReward has store, copy {
        epoch: u64,
        total_reward: u64,
        compute_reward: u64,
        edge_reward: u64,
        index_reward: u64,
        deploy_reward: u64
    }

    // Governance functionality
    struct Governance has store {
        proposals: Table<ID, Proposal>,
        parameters: GovernanceParameters,
        voting_power: Table<address, u64>,
        executed_proposals: vector<ID>
    }

    // Governance parameters
    struct GovernanceParameters has store {
        proposal_threshold: u64,
        voting_period: u64,
        execution_delay: u64,
        required_quorum: u64
    }

    // Governance proposal
    struct Proposal has key {
        id: UID,
        proposer: address,
        description: String,
        actions: vector<ProposalAction>,
        voting_starts: u64,
        voting_ends: u64,
        execution_epoch: u64,
        votes_for: u64,
        votes_against: u64,
        status: u8,
        votes: Table<address, bool>
    }

    // Action to be executed if proposal passes
    struct ProposalAction has store {
        action_type: u8,
        module: u8,
        parameters: vector<u8>
    }

    // Treasury management
    struct Treasury has store {
        balance: Balance<SUI>,
        allocations: vector<TreasuryAllocation>,
        controllers: vector<address>
    }

    // Treasury fund allocation
    struct TreasuryAllocation has store, copy {
        purpose: String,
        amount: u64,
        allocated_at: u64,
        expires_at: Option<u64>
    }

    // ======== Events ========

    // Node registration event
    struct NodeRegistered has copy, drop {
        node: address,
        stake_amount: u64,
        resources: ResourceAllocation,
        tee_platform: u8,
        active_modules: vector<u8>,
        epoch: u64
    }

    // Stake updated event
    struct StakeUpdated has copy, drop {
        node: address,
        old_stake: u64,
        new_stake: u64,
        action: String, // "increase", "decrease", "unstake_requested", "unstake_completed"
        epoch: u64
    }

    // Module activation event
    struct ModuleActivated has copy, drop {
        node: address,
        module: u8,
        epoch: u64
    }

    // TEE attestation updated event
    struct AttestationUpdated has copy, drop {
        node: address,
        platform_type: u8,
        expiration: u64,
        epoch: u64
    }

    // Reputation update event
    struct NodeReputationUpdated has copy, drop {
        node: address,
        old_score: u64,
        new_score: u64,
        reason: String,
        epoch: u64
    }

    // Node slashed event
    struct NodeSlashed has copy, drop {
        node: address,
        amount: u64,
        reason: String,
        epoch: u64
    }

    // Rewards distributed event
    struct RewardsDistributed has copy, drop {
        epoch: u64,
        total_amount: u64,
        node_count: u64
    }

    // ======== Core Functions ========

    // Initialize the registry
    fun init(ctx: &mut TxContext) {
        let registry = Registry {
            id: object::new(ctx),
            nodes: table::new(ctx),
            stake_manager: StakeManager {
                total_stake: 0,
                active_stake: 0,
                cooling_stake: 0,
                stake_history: vector::empty(),
                reward_pool: balance::zero(),
                last_reward_distribution: 0,
                epoch_rewards: vector::empty()
            },
            module_registries: ModuleRegistries {
                compute: object::id_from_address(@0x0), // Placeholder - will be updated
                edge: object::id_from_address(@0x0),
                index: object::id_from_address(@0x0),
                deploy: object::id_from_address(@0x0)
            },
            governance: Governance {
                proposals: table::new(ctx),
                parameters: GovernanceParameters {
                    proposal_threshold: 10000 * 1000000000, // 10,000 SUI
                    voting_period: 14 * 24 * 60 * 60 * 1000, // 14 days in ms
                    execution_delay: 2 * 24 * 60 * 60 * 1000, // 2 days in ms
                    required_quorum: 30 // 30% of total stake
                },
                voting_power: table::new(ctx),
                executed_proposals: vector::empty()
            },
            treasury: Treasury {
                balance: balance::zero(),
                allocations: vector::empty(),
                controllers: vector::singleton(tx_context::sender(ctx))
            },
            admin: tx_context::sender(ctx),
            config: RegistryConfig {
                minimum_stake: 1000 * 1000000000, // 1,000 SUI
                cooling_period: 7 * 24 * 60 * 60 * 1000, // 7 days in ms
                tee_attestation_validity_period: 30 * 24 * 60 * 60 * 1000, // 30 days in ms
                reward_distribution_period: 24 * 60 * 60 * 1000, // 1 day in ms
                slashing_percentage: 10, // 10% of stake
                heartbeat_period: 10 * 60 * 1000, // 10 minutes in ms
                governance_voting_period: 14 * 24 * 60 * 60 * 1000 // 14 days in ms
            },
            created_at: tx_context::epoch_timestamp_ms(ctx),
            updated_at: tx_context::epoch_timestamp_ms(ctx)
        };

        transfer::share_object(registry);
    }

    // Register a new node
    public fun register_node(
        registry: &mut Registry,
        stake: Coin<SUI>,
        endpoint: String,
        metadata: String,
        resources: ResourceAllocation,
        tee_attestation: vector<u8>,
        tee_platform: u8,
        active_modules: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let stake_amount = coin::value(&stake);

        // Validate stake amount
        assert!(stake_amount >= registry.config.minimum_stake, EINVALID_STAKE_AMOUNT);

        // Validate resource allocation
        validate_resource_allocation(&resources);

        // Validate modules
        validate_modules(&active_modules);

        // Create TEE attestation
        let attestation = create_tee_attestation(
            tee_platform,
            tee_attestation,
            clock::timestamp_ms(clock),
            clock::timestamp_ms(clock) + registry.config.tee_attestation_validity_period,
            ctx
        );

        // Create node info
        let node_info = NodeInfo {
            owner: tx_context::sender(ctx),
            endpoint,
            metadata,
            stake_amount,
            active_stake: stake_amount,
            cooling_stake: 0,
            cooling_end_epoch: 0,
            resources,
            tee_attestation: attestation,
            reputation: create_initial_reputation(),
            active_modules,
            rewards_earned: 0,
            penalties_received: 0,
            joined_epoch: tx_context::epoch(ctx),
            last_heartbeat: clock::timestamp_ms(clock),
            status: NODE_STATUS_ACTIVE
        };

        // Update stake manager
        registry.stake_manager.total_stake = registry.stake_manager.total_stake + stake_amount;
        registry.stake_manager.active_stake = registry.stake_manager.active_stake + stake_amount;

        // Record stake history
        vector::push_back(&mut registry.stake_manager.stake_history, StakeUpdate {
            epoch: tx_context::epoch(ctx),
            total_stake: registry.stake_manager.total_stake,
            active_stake: registry.stake_manager.active_stake,
            cooling_stake: registry.stake_manager.cooling_stake
        });

        // Add node to registry
        table::add(&mut registry.nodes, tx_context::sender(ctx), node_info);

        // Add stake to the pool
        let stake_balance = coin::into_balance(stake);
        balance::join(&mut registry.stake_manager.reward_pool, stake_balance);

        // Update voting power in governance
        if (table::contains(&registry.governance.voting_power, tx_context::sender(ctx))) {
            let voting_power = table::borrow_mut(&mut registry.governance.voting_power, tx_context::sender(ctx));
            *voting_power = *voting_power + stake_amount;
        } else {
            table::add(&mut registry.governance.voting_power, tx_context::sender(ctx), stake_amount);
        }

        // Emit registration event
        event::emit(NodeRegistered {
            node: tx_context::sender(ctx),
            stake_amount,
            resources,
            tee_platform,
            active_modules,
            epoch: tx_context::epoch(ctx)
        });

        registry.updated_at = clock::timestamp_ms(clock);
    }

    // Increase stake for an existing node
    public fun increase_stake(
        registry: &mut Registry,
        additional_stake: Coin<SUI>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);

        // Verify node exists
        assert!(table::contains(&registry.nodes, sender), ENODE_NOT_FOUND);

        let node = table::borrow_mut(&mut registry.nodes, sender);
        let stake_amount = coin::value(&additional_stake);

        // Update node stake
        node.stake_amount = node.stake_amount + stake_amount;
        node.active_stake = node.active_stake + stake_amount;

        // Update stake manager
        registry.stake_manager.total_stake = registry.stake_manager.total_stake + stake_amount;
        registry.stake_manager.active_stake = registry.stake_manager.active_stake + stake_amount;

        // Record stake history
        vector::push_back(&mut registry.stake_manager.stake_history, StakeUpdate {
            epoch: tx_context::epoch(ctx),
            total_stake: registry.stake_manager.total_stake,
            active_stake: registry.stake_manager.active_stake,
            cooling_stake: registry.stake_manager.cooling_stake
        });

        // Add stake to the pool
        let stake_balance = coin::into_balance(additional_stake);
        balance::join(&mut registry.stake_manager.reward_pool, stake_balance);

        // Update voting power
        let voting_power = table::borrow_mut(&mut registry.governance.voting_power, sender);
        *voting_power = *voting_power + stake_amount;

        // Emit stake update event
        event::emit(StakeUpdated {
            node: sender,
            old_stake: node.stake_amount - stake_amount,
            new_stake: node.stake_amount,
            action: string::utf8(b"increase"),
            epoch: tx_context::epoch(ctx)
        });

        registry.updated_at = clock::timestamp_ms(clock);
    }

    // Request to unstake from a node (initiates cooling period)
    public fun request_unstake(
        registry: &mut Registry,
        amount: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);

        // Verify node exists
        assert!(table::contains(&registry.nodes, sender), ENODE_NOT_FOUND);

        let node = table::borrow_mut(&mut registry.nodes, sender);

        // Validate unstake amount
        assert!(amount <= node.active_stake, EINVALID_UNSTAKE_AMOUNT);
        assert!(node.active_stake - amount >= registry.config.minimum_stake || amount == node.active_stake, EINVALID_UNSTAKE_AMOUNT);

        // Move stake from active to cooling
        node.active_stake = node.active_stake - amount;
        node.cooling_stake = node.cooling_stake + amount;
        node.cooling_end_epoch = clock::timestamp_ms(clock) + registry.config.cooling_period;

        // Update stake manager
        registry.stake_manager.active_stake = registry.stake_manager.active_stake - amount;
        registry.stake_manager.cooling_stake = registry.stake_manager.cooling_stake + amount;

        // Record stake history
        vector::push_back(&mut registry.stake_manager.stake_history, StakeUpdate {
            epoch: tx_context::epoch(ctx),
            total_stake: registry.stake_manager.total_stake,
            active_stake: registry.stake_manager.active_stake,
            cooling_stake: registry.stake_manager.cooling_stake
        });

        // Update voting power
        let voting_power = table::borrow_mut(&mut registry.governance.voting_power, sender);
        *voting_power = *voting_power - amount;

        // Emit stake update event
        event::emit(StakeUpdated {
            node: sender,
            old_stake: node.stake_amount,
            new_stake: node.stake_amount,
            action: string::utf8(b"unstake_requested"),
            epoch: tx_context::epoch(ctx)
        });

        // If all stake is being withdrawn, set node status to exiting
        if (node.active_stake == 0) {
            node.status = NODE_STATUS_EXITING;
        }

        registry.updated_at = clock::timestamp_ms(clock);
    }

    // Complete unstaking after cooling period
    public fun complete_unstake(
        registry: &mut Registry,
        clock: &Clock,
        ctx: &mut TxContext
    ): Coin<SUI> {
        let sender = tx_context::sender(ctx);

        // Verify node exists
        assert!(table::contains(&registry.nodes, sender), ENODE_NOT_FOUND);

        let node = table::borrow_mut(&mut registry.nodes, sender);

        // Verify cooling period has passed and there is stake to unstake
        assert!(node.cooling_stake > 0, EINVALID_UNSTAKE_AMOUNT);
        assert!(clock::timestamp_ms(clock) >= node.cooling_end_epoch, ESTAKE_COOLING_PERIOD);

        let unstake_amount = node.cooling_stake;

        // Update node
        node.stake_amount = node.stake_amount - unstake_amount;
        node.cooling_stake = 0;
        node.cooling_end_epoch = 0;

        // Update stake manager
        registry.stake_manager.total_stake = registry.stake_manager.total_stake - unstake_amount;
        registry.stake_manager.cooling_stake = registry.stake_manager.cooling_stake - unstake_amount;

        // Record stake history
        vector::push_back(&mut registry.stake_manager.stake_history, StakeUpdate {
            epoch: tx_context::epoch(ctx),
            total_stake: registry.stake_manager.total_stake,
            active_stake: registry.stake_manager.active_stake,
            cooling_stake: registry.stake_manager.cooling_stake
        });

        // Extract stake from pool
        let unstake_balance = balance::split(&mut registry.stake_manager.reward_pool, unstake_amount);
        let unstake_coin = coin::from_balance(unstake_balance, ctx);

        // Emit stake update event
        event::emit(StakeUpdated {
            node: sender,
            old_stake: node.stake_amount + unstake_amount,
            new_stake: node.stake_amount,
            action: string::utf8(b"unstake_completed"),
            epoch: tx_context::epoch(ctx)
        });

        // If node was exiting and now has no stake, remove it
        if (node.status == NODE_STATUS_EXITING && node.stake_amount == 0) {
            let removed_node = table::remove(&mut registry.nodes, sender);
            drop_node_info(removed_node);
        }

        registry.updated_at = clock::timestamp_ms(clock);

        unstake_coin
    }

    // Update node TEE attestation
    public fun update_attestation(
        registry: &mut Registry,
        tee_attestation: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);

        // Verify node exists
        assert!(table::contains(&registry.nodes, sender), ENODE_NOT_FOUND);

        let node = table::borrow_mut(&mut registry.nodes, sender);

        // Update attestation
        let new_attestation = create_tee_attestation(
            node.tee_attestation.platform_type,
            tee_attestation,
            clock::timestamp_ms(clock),
            clock::timestamp_ms(clock) + registry.config.tee_attestation_validity_period,
            ctx
        );

        node.tee_attestation = new_attestation;

        // Emit attestation update event
        event::emit(AttestationUpdated {
            node: sender,
            platform_type: node.tee_attestation.platform_type,
            expiration: node.tee_attestation.expiration_timestamp,
            epoch: tx_context::epoch(ctx)
        });

        registry.updated_at = clock::timestamp_ms(clock);
    }

    // Update node resource allocation
    public fun update_resources(
        registry: &mut Registry,
        resources: ResourceAllocation,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);

        // Verify node exists
        assert!(table::contains(&registry.nodes, sender), ENODE_NOT_FOUND);

        // Validate resource allocation
        validate_resource_allocation(&resources);

        let node = table::borrow_mut(&mut registry.nodes, sender);
        node.resources = resources;

        registry.updated_at = clock::timestamp_ms(clock);
    }

    // Activate a module for a node
    public fun activate_module(
        registry: &mut Registry,
        module: u8,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);

        // Verify node exists and module is valid
        assert!(table::contains(&registry.nodes, sender), ENODE_NOT_FOUND);
        assert!(module <= MODULE_DEPLOY, EINVALID_MODULE_ID);

        let node = table::borrow_mut(&mut registry.nodes, sender);

        // Check if module is already active
        let module_index = vector::index_of(&node.active_modules, &module);
        if (option::is_none(&module_index)) {
            vector::push_back(&mut node.active_modules, module);

            // Emit module activation event
            event::emit(ModuleActivated {
                node: sender,
                module,
                epoch: tx_context::epoch(ctx)
            });
        }

        registry.updated_at = clock::timestamp_ms(clock);
    }

    // Deactivate a module for a node
    public fun deactivate_module(
        registry: &mut Registry,
        module: u8,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);

        // Verify node exists and module is valid
        assert!(table::contains(&registry.nodes, sender), ENODE_NOT_FOUND);
        assert!(module <= MODULE_DEPLOY, EINVALID_MODULE_ID);

        let node = table::borrow_mut(&mut registry.nodes, sender);

        // Check if module is active and remove it
        let module_index = vector::index_of(&node.active_modules, &module);
        if (option::is_some(&module_index)) {
            vector::remove(&mut node.active_modules, option::extract(&mut module_index));
        }

        registry.updated_at = clock::timestamp_ms(clock);
    }

    // Node heartbeat to indicate active status
    public fun heartbeat(
        registry: &mut Registry,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);

        // Verify node exists
        assert!(table::contains(&registry.nodes, sender), ENODE_NOT_FOUND);

        let node = table::borrow_mut(&mut registry.nodes, sender);
        node.last_heartbeat = clock::timestamp_ms(clock);

        // Verify TEE attestation is still valid
        if (clock::timestamp_ms(clock) > node.tee_attestation.expiration_timestamp) {
            // Downgrade reputation for expired attestation
            update_reputation(
                &mut node.reputation,
                node.reputation.overall_score - 10,
                string::utf8(b"TEE attestation expired"),
                tx_context::epoch(ctx)
            );
        }
    }

    // ======== Helper Functions ========

    // Create initial reputation score
    fun create_initial_reputation(): ReputationScore {
        ReputationScore {
            overall_score: 50, // Start at neutral 50/100
            uptime_score: 100,
            performance_score: 50,
            verification_score: 100,
            history: vector::empty()
        }
    }

    // Create TEE attestation
    fun create_tee_attestation(
        platform_type: u8,
        attestation_report: vector<u8>,
        validation_timestamp: u64,
        expiration_timestamp: u64,
        ctx: &TxContext
    ): TeeAttestation {
        // Validate platform type
        assert!(
            platform_type == TEE_PLATFORM_INTEL_SGX ||
            platform_type == TEE_PLATFORM_AMD_SEV ||
            platform_type == TEE_PLATFORM_ARM_TRUSTZONE ||
            platform_type == TEE_PLATFORM_AWS_NITRO,
            EINVALID_TEE_ATTESTATION
        );

        // In production, attestation report should be cryptographically verified here

        TeeAttestation {
            platform_type,
            attestation_report,
            validation_timestamp,
            expiration_timestamp,
            verifier_signatures: vector::singleton(Signature {
                signer: tx_context::sender(ctx),
                signature: vector::empty(), // In production, this would be a real signature
                timestamp: validation_timestamp
            })
        }
    }

    // Update reputation score
    fun update_reputation(
        reputation: &mut ReputationScore,
        new_overall_score: u64,
        reason: String,
        epoch: u64
    ) {
        let old_score = reputation.overall_score;

        // Ensure score is within bounds (0-100)
        if (new_overall_score > 100) {
            reputation.overall_score = 100;
        } else {
            reputation.overall_score = new_overall_score;
        }

        // Record update in history
        vector::push_back(&mut reputation.history, ReputationUpdate {
            epoch,
            old_score,
            new_score: reputation.overall_score,
            reason
        });
    }

    // Validate resource allocation
    fun validate_resource_allocation(resources: &ResourceAllocation) {
        // Ensure resources are reasonable
        assert!(resources.compute_cores > 0, EINVALID_RESOURCE_ALLOCATION);
        assert!(resources.compute_memory > 0, EINVALID_RESOURCE_ALLOCATION);
        assert!(resources.storage_capacity > 0, EINVALID_RESOURCE_ALLOCATION);
        assert!(resources.bandwidth > 0, EINVALID_RESOURCE_ALLOCATION);
    }

    // Validate modules
    fun validate_modules(modules: &vector<u8>) {
        let i = 0;
        let len = vector::length(modules);

        while (i < len) {
            let module = *vector::borrow(modules, i);
            assert!(module <= MODULE_DEPLOY, EINVALID_MODULE_ID);
            i = i + 1;
        }
    }

    // Clean up node info when removed
    fun drop_node_info(node_info: NodeInfo) {
        let NodeInfo {
            owner: _,
            endpoint: _,
            metadata: _,
            stake_amount: _,
            active_stake: _,
            cooling_stake: _,
            cooling_end_epoch: _,
            resources: _,
            tee_attestation: _,
            reputation: _,
            active_modules: _,
            rewards_earned: _,
            penalties_received: _,
            joined_epoch: _,
            last_heartbeat: _,
            status: _
        } = node_info;
    }

    // ======== Governance Functions ========

    // Create a governance proposal
    public fun create_proposal(
        registry: &mut Registry,
        description: String,
        actions: vector<ProposalAction>,
        clock: &Clock,
        ctx: &mut TxContext
    ): ID {
        let sender = tx_context::sender(ctx);

        // Check if the sender has enough voting power to create a proposal
        assert!(
            table::contains(&registry.governance.voting_power, sender) &&
            *table::borrow(&registry.governance.voting_power, sender) >= registry.governance.parameters.proposal_threshold,
            EINSUFFICIENT_STAKE
        );

        // Validate actions
        validate_proposal_actions(&actions);

        // Create proposal
        let now = clock::timestamp_ms(clock);
        let proposal = Proposal {
            id: object::new(ctx),
            proposer: sender,
            description,
            actions,
            voting_starts: now,
            voting_ends: now + registry.governance.parameters.voting_period,
            execution_epoch: now + registry.governance.parameters.voting_period + registry.governance.parameters.execution_delay,
            votes_for: 0,
            votes_against: 0,
            status: 0, // Active
            votes: table::new(ctx)
        };

        let proposal_id = object::id(&proposal);
        table::add(&mut registry.governance.proposals, proposal_id, proposal);

        registry.updated_at = now;
        proposal_id
    }

    // Vote on a proposal
    public fun vote_on_proposal(
        registry: &mut Registry,
        proposal_id: ID,
        vote: bool,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);
        let now = clock::timestamp_ms(clock);

        // Ensure proposal exists and is in voting period
        assert!(table::contains(&registry.governance.proposals, proposal_id), 0);
        let proposal = table::borrow_mut(&mut registry.governance.proposals, proposal_id);

        assert!(now >= proposal.voting_starts && now <= proposal.voting_ends, 0);
        assert!(proposal.status == 0, 0); // Must be active

        // Check if sender has voting power
        assert!(table::contains(&registry.governance.voting_power, sender), EINSUFFICIENT_STAKE);
        let voting_power = *table::borrow(&registry.governance.voting_power, sender);

        // Check if already voted
        if (table::contains(&proposal.votes, sender)) {
            let previous_vote = *table::borrow(&proposal.votes, sender);

            // If vote hasn't changed, do nothing
            if (previous_vote == vote) {
                return
            }

            // Remove previous vote
            if (previous_vote) {
                proposal.votes_for = proposal.votes_for - voting_power;
            } else {
                proposal.votes_against = proposal.votes_against - voting_power;
            }

            // Update vote
            *table::borrow_mut(&mut proposal.votes, sender) = vote;
        } else {
            // Record new vote
            table::add(&mut proposal.votes, sender, vote);
        }

        // Count vote
        if (vote) {
            proposal.votes_for = proposal.votes_for + voting_power;
        } else {
            proposal.votes_against = proposal.votes_against + voting_power;
        }

        registry.updated_at = now;
    }

    // Execute a passed proposal
    public fun execute_proposal(
        registry: &mut Registry,
        proposal_id: ID,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let now = clock::timestamp_ms(clock);

        // Ensure proposal exists and voting period has ended
        assert!(table::contains(&registry.governance.proposals, proposal_id), 0);
        let proposal = table::borrow_mut(&mut registry.governance.proposals, proposal_id);

        assert!(now > proposal.voting_ends, 0);
        assert!(proposal.status == 0, 0); // Must be active

        // Check if proposal passed
        let total_votes = proposal.votes_for + proposal.votes_against;
        let quorum_reached = total_votes * 100 >= registry.stake_manager.active_stake * registry.governance.parameters.required_quorum;
        let proposal_passed = proposal.votes_for > proposal.votes_against && quorum_reached;

        if (proposal_passed) {
            // Mark as passed
            proposal.status = 1; // Passed

            // In a real implementation, you would execute the actions here
            // For this example, we'll just record the execution
            vector::push_back(&mut registry.governance.executed_proposals, proposal_id);
        } else {
            // Mark as failed
            proposal.status = 2; // Failed
        }

        registry.updated_at = now;
    }

    // Validate proposal actions
    fun validate_proposal_actions(actions: &vector<ProposalAction>) {
        let i = 0;
        let len = vector::length(actions);

        while (i < len) {
            let action = vector::borrow(actions, i);

            // Validate action type and module
            assert!(action.action_type <= 5, 0); // Assuming 5 action types
            assert!(action.module <= MODULE_DEPLOY, EINVALID_MODULE_ID);

            i = i + 1;
        }
    }

    // ======== Reward Distribution Functions ========

    // Distribute rewards to active nodes
    public fun distribute_rewards(
        registry: &mut Registry,
        reward: Coin<SUI>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let reward_amount = coin::value(&reward);
        let reward_balance = coin::into_balance(reward);
        balance::join(&mut registry.stake_manager.reward_pool, reward_balance);

        let now = clock::timestamp_ms(clock);
        let epoch = tx_context::epoch(ctx);

        // Ensure enough time has passed since last distribution
        assert!(
            now >= registry.stake_manager.last_reward_distribution + registry.config.reward_distribution_period,
            0
        );

        // Calculate module-specific rewards
        let compute_reward = reward_amount / 4; // 25%
        let edge_reward = reward_amount / 4;    // 25%
        let index_reward = reward_amount / 4;   // 25%
        let deploy_reward = reward_amount / 4;  // 25%

        // Record epoch reward
        vector::push_back(&mut registry.stake_manager.epoch_rewards, EpochReward {
            epoch,
            total_reward: reward_amount,
            compute_reward,
            edge_reward,
            index_reward,
            deploy_reward
        });

        // In a real implementation, rewards would be calculated based on
        // node performance and distributed to individual nodes

        registry.stake_manager.last_reward_distribution = now;

        // Emit reward distribution event
        let node_count = table::length(&registry.nodes);
        event::emit(RewardsDistributed {
            epoch,
            total_amount: reward_amount,
            node_count: (node_count as u64)
        });

        registry.updated_at = now;
    }

    // ======== Admin Functions ========

    // Update registry configuration
    public fun update_config(
        registry: &mut Registry,
        config: RegistryConfig,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Only admin can update config
        assert!(tx_context::sender(ctx) == registry.admin, ENOT_AUTHORIZED);

        registry.config = config;
        registry.updated_at = clock::timestamp_ms(clock);
    }

    // Update module registry addresses
    public fun update_module_registry(
        registry: &mut Registry,
        module: u8,
        registry_id: ID,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Only admin can update module registries
        assert!(tx_context::sender(ctx) == registry.admin, ENOT_AUTHORIZED);
        assert!(module <= MODULE_DEPLOY, EINVALID_MODULE_ID);

        // Update appropriate registry
        if (module == MODULE_COMPUTE) {
            registry.module_registries.compute = registry_id;
        } else if (module == MODULE_EDGE) {
            registry.module_registries.edge = registry_id;
        } else if (module == MODULE_INDEX) {
            registry.module_registries.index = registry_id;
        } else if (module == MODULE_DEPLOY) {
            registry.module_registries.deploy = registry_id;
        };

        registry.updated_at = clock::timestamp_ms(clock);
    }

    // Slash a node for misconduct
    public fun slash_node(
        registry: &mut Registry,
        node: address,
        reason: String,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Only admin can slash nodes
        assert!(tx_context::sender(ctx) == registry.admin, ENOT_AUTHORIZED);
        assert!(table::contains(&registry.nodes, node), ENODE_NOT_FOUND);

        let node_info = table::borrow_mut(&mut registry.nodes, node);
        let slash_amount = (node_info.active_stake * registry.config.slashing_percentage) / 100;

        // Update node state
        node_info.active_stake = node_info.active_stake - slash_amount;
        node_info.stake_amount = node_info.stake_amount - slash_amount;
        node_info.penalties_received = node_info.penalties_received + slash_amount;
        node_info.status = NODE_STATUS_SLASHED;

        // Move slashed funds to treasury
        let slashed_balance = balance::split(&mut registry.stake_manager.reward_pool, slash_amount);
        balance::join(&mut registry.treasury.balance, slashed_balance);

        // Update stake manager
        registry.stake_manager.total_stake = registry.stake_manager.total_stake - slash_amount;
        registry.stake_manager.active_stake = registry.stake_manager.active_stake - slash_amount;

        // Record stake history
        vector::push_back(&mut registry.stake_manager.stake_history, StakeUpdate {
            epoch: tx_context::epoch(ctx),
            total_stake: registry.stake_manager.total_stake,
            active_stake: registry.stake_manager.active_stake,
            cooling_stake: registry.stake_manager.cooling_stake
        });

        // Update reputation
        update_reputation(
            &mut node_info.reputation,
            node_info.reputation.overall_score / 2, // Significant reputation penalty
            reason,
            tx_context::epoch(ctx)
        );

        // Emit slashing event
        event::emit(NodeSlashed {
            node,
            amount: slash_amount,
            reason,
            epoch: tx_context::epoch(ctx)
        });

        registry.updated_at = clock::timestamp_ms(clock);
    }
}
