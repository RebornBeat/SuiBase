// compute.move - Compute module for SuiStack0X
module suistack0x::compute {
    use sui::object::{Self, ID, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::table::{Self, Table};
    use sui::event;
    use sui::clock::{Self, Clock};
    use std::option::{Self, Option};
    use std::string::{Self, String};
    use std::vector;
    use suistack0x::core::{Self, Registry};

    // Error codes
    const ENOT_AUTHORIZED: u64 = 0;
    const EFUNCTION_NOT_FOUND: u64 = 1;
    const EINVALID_RUNTIME: u64 = 2;
    const EINVALID_MEMORY_SIZE: u64 = 3;
    const EINVALID_TIMEOUT: u64 = 4;
    const ENODE_NOT_ACTIVE: u64 = 5;
    const EFUNCTION_ALREADY_EXISTS: u64 = 6;

    // Runtime types
    const RUNTIME_NODEJS: u8 = 0;
    const RUNTIME_PYTHON: u8 = 1;
    const RUNTIME_RUST: u8 = 2;
    const RUNTIME_GO: u8 = 3;
    const RUNTIME_WASM: u8 = 4;

    // Execution result status
    const EXECUTION_SUCCESS: u8 = 0;
    const EXECUTION_FAILURE: u8 = 1;
    const EXECUTION_TIMEOUT: u8 = 2;

    // Function registry for compute module
    struct ComputeRegistry has key {
        id: UID,
        functions: Table<ID, FunctionInfo>,
        runtimes: vector<Runtime>,
        executions: Table<ID, ExecutionRecord>,
        providers: Table<address, ProviderInfo>,
        pricing: PricingPolicy,
        admin: address,
        tee_required: bool,
        created_at: u64,
        updated_at: u64
    }

    // Function information
    struct FunctionInfo has key, store {
        id: UID,
        owner: address,
        name: String,
        code_cid: String,
        runtime: u8,
        memory_size: u64,
        timeout: u64,
        env_variables: vector<EnvVariable>,
        permissions: Permissions,
        is_private: bool,
        version: u64,
        total_executions: u64,
        created_at: u64,
        updated_at: u64
    }

    // Environment variable
    struct EnvVariable has store, copy {
        name: String,
        value: String,
        is_secret: bool
    }

    // Function permissions
    struct Permissions has store {
        read_objects: vector<ID>,
        write_objects: vector<ID>,
        packages: vector<ID>,
        external_urls: vector<String>
    }

    // Runtime information
    struct Runtime has store {
        id: u8,
        name: String,
        version: String,
        is_active: bool
    }

    // Execution record
    struct ExecutionRecord has key, store {
        id: UID,
        function_id: ID,
        executor: address,
        requester: address,
        input_digest: vector<u8>,
        output_digest: Option<vector<u8>>,
        execution_time: u64,
        memory_used: u64,
        cpu_time: u64,
        status: u8,
        error_message: Option<String>,
        verification_status: u8,
        verifier_signatures: vector<VerifierSignature>,
        price_paid: u64,
        started_at: u64,
        completed_at: Option<u64>
    }

    // Verifier signature
    struct VerifierSignature has store, copy {
        verifier: address,
        signature: vector<u8>,
        timestamp: u64
    }

    // Provider information
    struct ProviderInfo has store {
        address: address,
        supported_runtimes: vector<u8>,
        max_memory: u64,
        max_cpu_cores: u8,
        pricing_multiplier: u64,
        is_active: bool,
        reputation_score: u64,
        total_executions: u64,
        successful_executions: u64,
        failed_executions: u64,
        joined_at: u64,
        last_execution: u64
    }

    // Pricing policy
    struct PricingPolicy has store {
        base_price_per_ms: u64,
        memory_price_per_mb: u64,
        private_execution_multiplier: u64,
        high_priority_multiplier: u64,
        discount_rate: u64, // percentage
        minimum_price: u64
    }

    // Events
    struct FunctionCreated has copy, drop {
        function_id: ID,
        owner: address,
        name: String,
        runtime: u8,
        memory_size: u64,
        is_private: bool,
        timestamp: u64
    }

    struct FunctionUpdated has copy, drop {
        function_id: ID,
        old_code_cid: String,
        new_code_cid: String,
        version: u64,
        timestamp: u64
    }

    struct ExecutionStarted has copy, drop {
        execution_id: ID,
        function_id: ID,
        executor: address,
        requester: address,
        price: u64,
        timestamp: u64
    }

    struct ExecutionCompleted has copy, drop {
        execution_id: ID,
        function_id: ID,
        status: u8,
        execution_time: u64,
        memory_used: u64,
        timestamp: u64
    }

    // Initialize compute registry
    fun init(ctx: &mut TxContext) {
        let compute_registry = ComputeRegistry {
            id: object::new(ctx),
            functions: table::new(ctx),
            runtimes: initialize_runtimes(),
            executions: table::new(ctx),
            providers: table::new(ctx),
            pricing: initialize_pricing_policy(),
            admin: tx_context::sender(ctx),
            tee_required: true,
            created_at: tx_context::epoch_timestamp_ms(ctx),
            updated_at: tx_context::epoch_timestamp_ms(ctx)
        };

        transfer::share_object(compute_registry);
    }

    // Initialize default runtimes
    fun initialize_runtimes(): vector<Runtime> {
        let runtimes = vector::empty<Runtime>();

        vector::push_back(&mut runtimes, Runtime {
            id: RUNTIME_NODEJS,
            name: string::utf8(b"NodeJS"),
            version: string::utf8(b"18.x"),
            is_active: true
        });

        vector::push_back(&mut runtimes, Runtime {
            id: RUNTIME_PYTHON,
            name: string::utf8(b"Python"),
            version: string::utf8(b"3.10"),
            is_active: true
        });

        vector::push_back(&mut runtimes, Runtime {
            id: RUNTIME_RUST,
            name: string::utf8(b"Rust"),
            version: string::utf8(b"1.68"),
            is_active: true
        });

        vector::push_back(&mut runtimes, Runtime {
            id: RUNTIME_GO,
            name: string::utf8(b"Go"),
            version: string::utf8(b"1.20"),
            is_active: true
        });

        vector::push_back(&mut runtimes, Runtime {
            id: RUNTIME_WASM,
            name: string::utf8(b"WebAssembly"),
            version: string::utf8(b"1.0"),
            is_active: true
        });

        runtimes
    }

    // Initialize default pricing policy
    fun initialize_pricing_policy(): PricingPolicy {
        PricingPolicy {
            base_price_per_ms: 1, // 1 MIST per ms
            memory_price_per_mb: 10, // 10 MIST per MB
            private_execution_multiplier: 150, // 1.5x price for private execution
            high_priority_multiplier: 200, // 2x price for high priority
            discount_rate: 10, // 10% discount for bulk usage
            minimum_price: 1000 // 1000 MIST minimum
        }
    }

    // Register as a compute provider
    public fun register_provider(
        registry: &Registry,
        compute_registry: &mut ComputeRegistry,
        supported_runtimes: vector<u8>,
        max_memory: u64,
        max_cpu_cores: u8,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);

        // Verify node is registered in core registry and has compute module active
        assert!(core::is_active_compute_node(registry, sender), ENODE_NOT_ACTIVE);

        // Validate runtimes
        validate_runtimes(&supported_runtimes);

        // Create provider info
        let provider = ProviderInfo {
            address: sender,
            supported_runtimes,
            max_memory,
            max_cpu_cores,
            pricing_multiplier: 100, // Default 1.0x multiplier (100%)
            is_active: true,
            reputation_score: 50, // Start at neutral 50/100
            total_executions: 0,
            successful_executions: 0,
            failed_executions: 0,
            joined_at: clock::timestamp_ms(clock),
            last_execution: 0
        };

        // Add provider to registry
        table::add(&mut compute_registry.providers, sender, provider);

        compute_registry.updated_at = clock::timestamp_ms(clock);
    }

    // Deploy a function
    public fun deploy_function(
        compute_registry: &mut ComputeRegistry,
        name: String,
        code_cid: String,
        runtime: u8,
        memory_size: u64,
        timeout: u64,
        env_variables: vector<EnvVariable>,
        permissions: Permissions,
        is_private: bool,
        clock: &Clock,
        ctx: &mut TxContext
    ): ID {
        // Validate inputs
        validate_runtime(compute_registry, runtime);
        validate_memory_size(memory_size);
        validate_timeout(timeout);

        let function = FunctionInfo {
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            name,
            code_cid,
            runtime,
            memory_size,
            timeout,
            env_variables,
            permissions,
            is_private,
            version: 1,
            total_executions: 0,
            created_at: clock::timestamp_ms(clock),
            updated_at: clock::timestamp_ms(clock)
        };

        let function_id = object::id(&function);

        // Emit function created event
        event::emit(FunctionCreated {
            function_id,
            owner: tx_context::sender(ctx),
            name,
            runtime,
            memory_size,
            is_private,
            timestamp: clock::timestamp_ms(clock)
        });

        // Add function to registry
        table::add(&mut compute_registry.functions, function_id, function);

        compute_registry.updated_at = clock::timestamp_ms(clock);

        function_id
    }

    // Update a function
    public fun update_function(
        compute_registry: &mut ComputeRegistry,
        function_id: ID,
        new_code_cid: String,
        new_env_variables: Option<vector<EnvVariable>>,
        new_permissions: Option<Permissions>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);

        // Verify function exists
        assert!(table::contains(&compute_registry.functions, function_id), EFUNCTION_NOT_FOUND);
        let function = table::borrow_mut(&mut compute_registry.functions, function_id);

        // Verify ownership
        assert!(function.owner == sender, ENOT_AUTHORIZED);

        let old_code_cid = function.code_cid;
        function.code_cid = new_code_cid;
        function.version = function.version + 1;
        function.updated_at = clock::timestamp_ms(clock);

        // Update env variables if provided
        if (option::is_some(&new_env_variables)) {
            function.env_variables = option::extract(&mut new_env_variables);
        };

        // Update permissions if provided
        if (option::is_some(&new_permissions)) {
            function.permissions = option::extract(&mut new_permissions);
        };

        // Emit function updated event
        event::emit(FunctionUpdated {
            function_id,
            old_code_cid,
            new_code_cid,
            version: function.version,
            timestamp: clock::timestamp_ms(clock)
        });

        compute_registry.updated_at = clock::timestamp_ms(clock);
    }

    // Execute a function
    public fun execute_function(
        registry: &Registry,
        compute_registry: &mut ComputeRegistry,
        function_id: ID,
        input_digest: vector<u8>,
        high_priority: bool,
        clock: &Clock,
        ctx: &mut TxContext
    ): ID {
        let sender = tx_context::sender(ctx);

        // Verify function exists
        assert!(table::contains(&compute_registry.functions, function_id), EFUNCTION_NOT_FOUND);
        let function = table::borrow_mut(&mut compute_registry.functions, function_id);

        // Verify executor is a compute provider
        assert!(table::contains(&compute_registry.providers, sender), ENODE_NOT_ACTIVE);
        let provider = table::borrow_mut(&mut compute_registry.providers, sender);
        assert!(provider.is_active, ENODE_NOT_ACTIVE);

        // Verify provider supports the runtime
        assert!(vector::contains(&provider.supported_runtimes, &function.runtime), EINVALID_RUNTIME);

        // Calculate price
        let base_price = compute_registry.pricing.base_price_per_ms * function.timeout;
        let memory_price = compute_registry.pricing.memory_price_per_mb * (function.memory_size / (1024 * 1024));
        let mut price = base_price + memory_price;

        // Apply multipliers
        if (function.is_private) {
            price = price * compute_registry.pricing.private_execution_multiplier / 100;
        };

        if (high_priority) {
            price = price * compute_registry.pricing.high_priority_multiplier / 100;
        };

        // Apply provider-specific multiplier
        price = price * provider.pricing_multiplier / 100;

        // Ensure price meets minimum
        if (price < compute_registry.pricing.minimum_price) {
            price = compute_registry.pricing.minimum_price;
        };

        // Create execution record
        let execution = ExecutionRecord {
            id: object::new(ctx),
            function_id,
            executor: sender,
            requester: tx_context::sender(ctx),
            input_digest,
            output_digest: option::none(),
            execution_time: 0,
            memory_used: 0,
            cpu_time: 0,
            status: 0, // Pending
            error_message: option::none(),
            verification_status: 0, // Pending
            verifier_signatures: vector::empty(),
            price_paid: price,
            started_at: clock::timestamp_ms(clock),
            completed_at: option::none()
        };

        let execution_id = object::id(&execution);

        // Update provider stats
        provider.total_executions = provider.total_executions + 1;
        provider.last_execution = clock::timestamp_ms(clock);

        // Update function stats
        function.total_executions = function.total_executions + 1;

        // Emit execution started event
        event::emit(ExecutionStarted {
            execution_id,
            function_id,
            executor: sender,
            requester: tx_context::sender(ctx),
            price,
            timestamp: clock::timestamp_ms(clock)
        });

        // Add execution to registry
        table::add(&mut compute_registry.executions, execution_id, execution);

        compute_registry.updated_at = clock::timestamp_ms(clock);

        execution_id
    }

    // Complete function execution
    public fun complete_execution(
        compute_registry: &mut ComputeRegistry,
        execution_id: ID,
        output_digest: vector<u8>,
        execution_time: u64,
        memory_used: u64,
        cpu_time: u64,
        status: u8,
        error_message: Option<String>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);

        // Verify execution exists
        assert!(table::contains(&compute_registry.executions, execution_id), 0);
        let execution = table::borrow_mut(&mut compute_registry.executions, execution_id);

        // Verify executor is completing their own execution
        assert!(execution.executor == sender, ENOT_AUTHORIZED);

        // Update execution record
        execution.output_digest = option::some(output_digest);
        execution.execution_time = execution_time;
        execution.memory_used = memory_used;
        execution.cpu_time = cpu_time;
        execution.status = status;
        execution.error_message = error_message;
        execution.completed_at = option::some(clock::timestamp_ms(clock));

        // Update provider stats
        let provider = table::borrow_mut(&mut compute_registry.providers, sender);
        if (status == EXECUTION_SUCCESS) {
            provider.successful_executions = provider.successful_executions + 1;
        } else {
            provider.failed_executions = provider.failed_executions + 1;
        };

        // Emit execution completed event
        event::emit(ExecutionCompleted {
            execution_id,
            function_id: execution.function_id,
            status,
            execution_time,
            memory_used,
            timestamp: clock::timestamp_ms(clock)
        });

        compute_registry.updated_at = clock::timestamp_ms(clock);
    }

    // Verify execution result
    public fun verify_execution(
        compute_registry: &mut ComputeRegistry,
        execution_id: ID,
        verification_result: bool,
        signature: vector<u8>,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        let sender = tx_context::sender(ctx);

        // Verify execution exists
        assert!(table::contains(&compute_registry.executions, execution_id), 0);
        let execution = table::borrow_mut(&mut compute_registry.executions, execution_id);

        // Add verifier signature
        vector::push_back(&mut execution.verifier_signatures, VerifierSignature {
            verifier: sender,
            signature,
            timestamp: clock::timestamp_ms(clock)
        });

        // Update verification status if this is the first verification
        if (execution.verification_status == 0) {
            execution.verification_status = if (verification_result) 1 else 2;
        };

        compute_registry.updated_at = clock::timestamp_ms(clock);
    }

    // Get execution details
    public fun get_execution_details(compute_registry: &ComputeRegistry, execution_id: ID): (
        ID, // function_id
        address, // executor
        address, // requester
        Option<vector<u8>>, // output_digest
        u64, // execution_time
        u64, // memory_used
        u8, // status
        u8, // verification_status
        u64, // started_at
        Option<u64> // completed_at
    ) {
        assert!(table::contains(&compute_registry.executions, execution_id), 0);
        let execution = table::borrow(&compute_registry.executions, execution_id);

        (
            execution.function_id,
            execution.executor,
            execution.requester,
            execution.output_digest,
            execution.execution_time,
            execution.memory_used,
            execution.status,
            execution.verification_status,
            execution.started_at,
            execution.completed_at
        )
    }

    // Get function details
    public fun get_function_details(compute_registry: &ComputeRegistry, function_id: ID): (
        address, // owner
        String, // name
        String, // code_cid
        u8, // runtime
        u64, // memory_size
        u64, // timeout
        bool, // is_private
        u64, // version
        u64, // total_executions
        u64, // created_at
        u64  // updated_at
    ) {
        assert!(table::contains(&compute_registry.functions, function_id), EFUNCTION_NOT_FOUND);
        let function = table::borrow(&compute_registry.functions, function_id);

        (
            function.owner,
            function.name,
            function.code_cid,
            function.runtime,
            function.memory_size,
            function.timeout,
            function.is_private,
            function.version,
            function.total_executions,
            function.created_at,
            function.updated_at
        )
    }

    // ======== Helper Functions ========

    // Validate runtime
    fun validate_runtime(compute_registry: &ComputeRegistry, runtime: u8) {
        let is_valid = false;
        let i = 0;
        let len = vector::length(&compute_registry.runtimes);

        while (i < len) {
            let r = vector::borrow(&compute_registry.runtimes, i);
            if (r.id == runtime && r.is_active) {
                is_valid = true;
                break
            };
            i = i + 1;
        };

        assert!(is_valid, EINVALID_RUNTIME);
    }

    // Validate runtimes
    fun validate_runtimes(runtimes: &vector<u8>) {
        let i = 0;
        let len = vector::length(runtimes);

        while (i < len) {
            let runtime = *vector::borrow(runtimes, i);
            assert!(
                runtime == RUNTIME_NODEJS ||
                runtime == RUNTIME_PYTHON ||
                runtime == RUNTIME_RUST ||
                runtime == RUNTIME_GO ||
                runtime == RUNTIME_WASM,
                EINVALID_RUNTIME
            );
            i = i + 1;
        }
    }

    // Validate memory size
    fun validate_memory_size(memory_size: u64) {
        // Memory must be between 128MB and 10GB
        assert!(memory_size >= 128 * 1024 * 1024 && memory_size <= 10 * 1024 * 1024 * 1024, EINVALID_MEMORY_SIZE);
    }

    // Validate timeout
    fun validate_timeout(timeout: u64) {
        // Timeout must be between 1 second and 15 minutes
        assert!(timeout >= 1000 && timeout <= 15 * 60 * 1000, EINVALID_TIMEOUT);
    }

    // ======== Admin Functions ========

    // Update pricing policy
    public fun update_pricing_policy(
        compute_registry: &mut ComputeRegistry,
        pricing: PricingPolicy,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Only admin can update pricing
        assert!(tx_context::sender(ctx) == compute_registry.admin, ENOT_AUTHORIZED);

        compute_registry.pricing = pricing;
        compute_registry.updated_at = clock::timestamp_ms(clock);
    }

    // Add new runtime
    public fun add_runtime(
        compute_registry: &mut ComputeRegistry,
        name: String,
        version: String,
        clock: &Clock,
        ctx: &mut TxContext
    ): u8 {
        // Only admin can add runtimes
        assert!(tx_context::sender(ctx) == compute_registry.admin, ENOT_AUTHORIZED);

        let id = (vector::length(&compute_registry.runtimes) as u8);

        vector::push_back(&mut compute_registry.runtimes, Runtime {
            id,
            name,
            version,
            is_active: true
        });

        compute_registry.updated_at = clock::timestamp_ms(clock);
        id
    }

    // Update runtime status
    public fun update_runtime_status(
        compute_registry: &mut ComputeRegistry,
        runtime_id: u8,
        is_active: bool,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Only admin can update runtime status
        assert!(tx_context::sender(ctx) == compute_registry.admin, ENOT_AUTHORIZED);

        let i = 0;
        let len = vector::length(&compute_registry.runtimes);

        while (i < len) {
            let runtime = vector::borrow_mut(&mut compute_registry.runtimes, i);
            if (runtime.id == runtime_id) {
                runtime.is_active = is_active;
                break
            };
            i = i + 1;
        };

        compute_registry.updated_at = clock::timestamp_ms(clock);
    }

    // Update TEE requirement
    public fun update_tee_requirement(
        compute_registry: &mut ComputeRegistry,
        required: bool,
        clock: &Clock,
        ctx: &mut TxContext
    ) {
        // Only admin can update TEE requirement
        assert!(tx_context::sender(ctx) == compute_registry.admin, ENOT_AUTHORIZED);

        compute_registry.tee_required = required;
        compute_registry.updated_at = clock::timestamp_ms(clock);
    }
}
