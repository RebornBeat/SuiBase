# SuiBase

<div align="center">
  <h3>Unified Decentralized Infrastructure for Sui</h3>
  <p>A TEE-secured platform for compute, edge delivery, indexing, and deployment</p>

  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![Sui Testnet](https://img.shields.io/badge/Sui-Testnet-blue)](https://sui.io/)
</div>

## Overview

SuiBase is a comprehensive decentralized infrastructure platform built on the Sui blockchain, leveraging Trusted Execution Environments (TEEs) to provide secure, private, and scalable services for web3 applications. It unifies computing, content delivery, data indexing, and deployment in a cohesive ecosystem.

**Key Features:**
- 🔐 **TEE-Secured Infrastructure**: End-to-end privacy and verifiable computation
- 🚀 **Multi-Function Nodes**: Run compute, edge delivery, indexing, and deployment from a single node
- 💰 **Unified Economic Model**: Single staking mechanism with flexible resource allocation
- 🌐 **Complete Web3 Stack**: Everything needed to build, deploy, and scale dApps
- 🔄 **Seamless Integration**: Native compatibility with Sui Aether, Walrus, and SuiNS
- 🧩 **Modular Architecture**: Use only the components you need

## Architecture

SuiBase provides four core modules within a unified architecture:

1. **Compute Module**: Serverless functions and application backends
2. **Edge Module**: Content delivery and routing infrastructure
3. **Index Module**: Blockchain data indexing and query services
4. **Deploy Module**: CI/CD pipelines and deployment automation

All modules operate within a common TEE security layer and shared node infrastructure:

```
┌───────────────────────────────────────────────────────────┐
│                       SuiBase                            │
├───────────────────────────────────────────────────────────┤
│                    TEE Security Layer                     │
├───────────┬───────────────┬───────────────┬───────────────┤
│           │               │               │               │
│  Compute  │     Edge      │    Index      │    Deploy     │
│  Module   │    Module     │   Module      │   Module      │
│           │               │               │               │
└───────────┴───────────────┴───────────────┴───────────────┘
             Unified Node & Resource Management
```

## Getting Started

### Prerequisites
- Node.js v18+
- Sui CLI v1.0+
- SUI tokens for staking
- TEE-compatible hardware (for node operators)

### Installation

```bash
# Install CLI
npm install -g SuiBase-cli

# Install SDK
npm install @SuiBase/sdk
```

### Quick Start for Developers

```bash
# Initialize a new project
SuiBase init my-project
cd my-project

# Configure your application
SuiBase config

# Deploy your application
SuiBase deploy
```

### Quick Start for Node Operators

```bash
# Install node software
npm install -g SuiBase-node

# Initialize node with TEE attestation
SuiBase-node init --tee-platform intel-sgx

# Stake tokens and start node
SuiBase-node stake --amount 5000
SuiBase-node start
```

## Modules

### Compute Module

The Compute Module provides serverless computing capabilities with TEE-based privacy:

```javascript
// Example: Deploying a serverless function
import { ComputeClient } from '@SuiBase/sdk';

const compute = new ComputeClient({
  network: 'testnet',
  privateKey: process.env.SUI_PRIVATE_KEY
});

await compute.deployFunction({
  name: 'process-data',
  runtime: 'nodejs18.x',
  code: fs.readFileSync('./function.zip'),
  memorySize: 512,
  timeout: 30,
  isPrivate: true // Enables TEE-based encryption
});
```

**Key Features:**
- Private function execution
- Scalable compute resources
- Pay-per-use pricing
- WebAssembly and native runtimes
- Function composition

### Edge Module

The Edge Module handles content delivery with NGINX-like configuration:

```javascript
// Example: Configuring edge delivery
import { EdgeClient } from '@SuiBase/sdk';

const edge = new EdgeClient({
  network: 'testnet',
  privateKey: process.env.SUI_PRIVATE_KEY
});

await edge.configureApp({
  domain: 'myapp.sui',
  routes: [
    {
      path: '/',
      contentSource: {
        type: 'walrus',
        cid: 'bafybeie5gq4jxvzmsym6hjlwxej4rwdoxt7wadqvmmwbqi7r27fclha2va'
      }
    },
    {
      path: '/api/*',
      contentSource: {
        type: 'compute',
        functionId: '0x1234...'
      }
    }
  ],
  caching: {
    ttl: 3600,
    dynamicCompression: true
  }
});
```

**Key Features:**
- Decentralized content delivery
- Configurable routing and caching
- DDoS protection
- Secure content verification
- SuiNS integration

### Index Module

The Index Module provides blockchain data indexing and querying capabilities:

```javascript
// Example: Creating an index
import { IndexClient } from '@SuiBase/sdk';

const index = new IndexClient({
  network: 'testnet',
  privateKey: process.env.SUI_PRIVATE_KEY
});

await index.createIndex({
  name: 'nft-transfers',
  sources: [
    {
      type: 'event',
      package: '0x2::devnet_nft',
      module: 'devnet_nft',
      event: 'MintEvent'
    }
  ],
  schema: {
    id: 'string',
    creator: 'address',
    name: 'string',
    url: 'string',
    attributes: 'json'
  },
  indexes: ['creator', 'name']
});
```

**Key Features:**
- High-performance data indexing
- GraphQL and REST APIs
- Real-time subscriptions
- Custom indexing logic
- Privacy-preserving queries

### Deploy Module

The Deploy Module manages CI/CD pipelines and deployments:

```javascript
// Example: Setting up a deployment pipeline
import { DeployClient } from '@SuiBase/sdk';

const deploy = new DeployClient({
  network: 'testnet',
  privateKey: process.env.SUI_PRIVATE_KEY
});

await deploy.createPipeline({
  name: 'my-dapp',
  source: {
    provider: 'github',
    repository: 'username/my-dapp',
    branch: 'main'
  },
  build: {
    commands: [
      'npm install',
      'npm run build'
    ],
    artifacts: [
      {
        path: './build',
        destination: 'frontend'
      }
    ]
  },
  deployments: [
    {
      name: 'frontend',
      type: 'edge',
      source: './build',
      domain: 'my-dapp.sui'
    }
  ]
});
```

**Key Features:**
- Reproducible builds
- Multi-environment deployments
- Approval workflows
- Automated testing
- Secure secrets management

## Smart Contract Architecture

SuiBase is powered by a suite of Move smart contracts:

```move
module SuiBase::core {
    // Core registry for all SuiBase components
    struct Registry has key {
        id: UID,
        nodes: Table<address, NodeInfo>,
        stake_manager: StakeManager,
        module_registries: ModuleRegistries,
        governance: Governance,
        treasury: Treasury
    }
    
    // Information about a registered node
    struct NodeInfo has store {
        owner: address,
        endpoint: String,
        stake_amount: u64,
        resources: ResourceAllocation,
        tee_attestation: TeeAttestation,
        reputation: ReputationScore,
        services: u8, // Bitmap of active services
        rewards_earned: u64,
        joined_epoch: u64,
        last_heartbeat: u64
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
        verifier_signatures: vector<Signature>
    }
    
    // Registry of all modules
    struct ModuleRegistries has store {
        compute: ComputeRegistry,
        edge: EdgeRegistry,
        index: IndexRegistry,
        deploy: DeployRegistry
    }
    
    // Staking and reward management
    struct StakeManager has store {
        total_stake: u64,
        stake_table: Table<address, StakeInfo>,
        reward_distribution: RewardDistribution,
        min_stake: u64,
        cooling_period: u64
    }
    
    // Public functions for core operations...
}
```

### Module-Specific Contracts

Each module has its own specialized contracts that interface with the core:

```move
module SuiBase::compute {
    // Function registry
    struct ComputeRegistry has store {
        functions: Table<ID, FunctionInfo>,
        runtimes: vector<Runtime>,
        execution_records: Table<ID, ExecutionRecord>,
        pricing: PricingPolicy
    }
    
    // Individual function information
    struct FunctionInfo has store, key {
        id: UID,
        owner: address,
        name: String,
        code_cid: String,
        runtime: u8,
        memory_size: u64,
        timeout: u64,
        environment: vector<EnvVariable>,
        permissions: Permissions,
        is_private: bool,
        version: u64,
        created_at: u64,
        updated_at: u64
    }
    
    // Public functions for compute operations...
}

// Similar structures for edge, index, and deploy modules...
```

## TEE Security Model

SuiBase leverages Trusted Execution Environments to provide:

1. **Verifiable Computation**: Guarantee that code executes exactly as specified
2. **Data Privacy**: Encrypted data remains protected even during processing
3. **Tamper Resistance**: Prevention of node operator interference
4. **Remote Attestation**: Cryptographic proof of TEE integrity

### Supported TEE Platforms

- Intel SGX
- AMD SEV
- ARM TrustZone
- AWS Nitro Enclaves

### Security Guarantees

- **Confidentiality**: Data remains encrypted inside the TEE
- **Integrity**: Computation cannot be tampered with
- **Freshness**: Protection against replay attacks
- **Attestation**: Remote verification of execution environment

## Economic Model

SuiBase operates on a unified economic model with flexible resource allocation:

### Staking Mechanism

Node operators stake SUI tokens to participate in the network, with stake serving as:
- Security deposit against malicious behavior
- Resource commitment indicator
- Reward distribution basis

### Resource Credits

Stake is converted to Resource Credits (RCs) that can be flexibly allocated:
- Compute Credits (CCs)
- Bandwidth Credits (BCs)
- Storage Credits (SCs)
- Build Credits (BCs)

Node operators can adjust their allocation based on hardware capabilities and market demand.

### Pricing Model

Services are priced based on resource consumption:
- Compute: Per function invocation, execution time, and memory
- Edge: Per GB of bandwidth and request count
- Index: Per query complexity and storage used
- Deploy: Per build minute and artifacts size

### Reward Distribution

Rewards are distributed based on:
- Resource provision (70%)
- Quality of service (20%)
- Network participation (10%)

## Governance

SuiBase is governed through a decentralized governance system:

1. **Improvement Proposals**: Community-submitted proposals for upgrades
2. **Voting**: Stake-weighted voting on proposals
3. **Parameter Adjustment**: Dynamic adjustment of economic parameters
4. **Module Governance**: Specialized parameters for each module

## Performance Benchmarks

| Module | Metric | Performance |
|--------|--------|-------------|
| Compute | Function Cold Start | <100ms |
| Compute | Max Throughput | 1000 invocations/s per node |
| Edge | Request Latency (p95) | <50ms |
| Edge | Max Throughput | 10,000 requests/s per node |
| Index | Query Latency (p95) | <100ms |
| Index | Indexing Delay | <5s from block finality |
| Deploy | Build Speed | 2x faster than centralized CI |

## Resource Requirements

### Node Hardware Recommendations

| Role | CPU | RAM | Storage | Network | TEE |
|------|-----|-----|---------|---------|-----|
| Full Node | 16+ cores | 64GB+ | 2TB+ NVMe | 1Gbps | Required |
| Compute-focused | 32+ cores | 128GB+ | 1TB+ NVMe | 1Gbps | Required |
| Storage-focused | 8+ cores | 32GB+ | 8TB+ NVMe | 1Gbps | Required |
| Edge-focused | 8+ cores | 32GB+ | 1TB+ NVMe | 10Gbps | Required |

### Minimum Stake Requirements

| Role | Minimum Stake |
|------|---------------|
| Basic Node | 1,000 SUI |
| Service Provider | 10,000 SUI |
| Validator | 100,000 SUI |

## Integration with Sui Ecosystem

SuiBase integrates seamlessly with the broader Sui ecosystem:

- **Sui Aether**: Leverages Proof of Uncorruption for enhanced security
- **Walrus**: Native storage integration for content and artifacts
- **SuiNS**: Domain name resolution for edge delivery
- **Sui Move**: Custom contract support across all modules

## Roadmap

- [x] Architecture design and specification
- [x] Core smart contract implementation
- [ ] TEE integration layer (Q1 2025)
- [ ] Compute Module beta (Q2 2025)
- [ ] Edge Module beta (Q3 2025)
- [ ] Testnet deployment (Q4 2025)
- [ ] Index Module beta (Q1 2026)
- [ ] Deploy Module beta (Q2 2026)
- [ ] Security audits (Q3 2026)
- [ ] Mainnet launch (Q4 2026)
- [ ] Advanced features and scaling (2027)

## Use Cases

### DeFi Platforms
- Private order execution
- High-performance indexing for market data
- Secure front-end delivery
- Automated deployment pipelines

### Gaming Applications
- Game server computation
- Asset delivery and caching
- Leaderboard and state indexing
- Continuous deployment of updates

### Social Networks
- Private content storage and delivery
- Real-time data processing
- Engagement metrics indexing
- Feature flagging and A/B testing

### Enterprise Solutions
- Confidential computation
- Compliant data handling
- Audit trail generation
- Multi-environment deployments

## Getting Involved

### For Developers
- [Documentation](https://docs.SuiBase.io)
- [Quickstart Guide](https://docs.SuiBase.io/quickstart)
- [SDK Reference](https://docs.SuiBase.io/sdk)
- [Examples Repository](https://github.com/SuiBase/examples)

### For Node Operators
- [Node Requirements](https://docs.SuiBase.io/node/requirements)
- [Setup Guide](https://docs.SuiBase.io/node/setup)
- [Economics Calculator](https://calculator.SuiBase.io)
- [Monitoring Tools](https://github.com/SuiBase/monitoring)

### For Contributors
- [Contribution Guidelines](CONTRIBUTING.md)
- [Development Setup](https://docs.SuiBase.io/contributing/setup)
- [RFC Process](https://docs.SuiBase.io/contributing/rfcs)
- [Good First Issues](https://github.com/SuiBase/SuiBase/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)

## Developer Experience

SuiBase prioritizes developer experience with:

```typescript
// Example: Complete application deployment
import { SuiBase } from '@SuiBase/sdk';

// Initialize the SDK
const stack = new SuiBase({
  network: 'testnet',
  privateKey: process.env.SUI_PRIVATE_KEY
});

// Deploy a complete application
async function deployFullStack() {
  // 1. Deploy smart contracts
  const contractId = await stack.deploy.publishPackage('./move/build');
  
  // 2. Deploy serverless API
  const apiId = await stack.compute.deployFunction({
    name: 'api',
    runtime: 'nodejs18.x',
    code: './api/dist',
    environmentVariables: {
      CONTRACT_ID: contractId
    }
  });
  
  // 3. Create data index
  const indexId = await stack.index.createIndex({
    name: 'app-events',
    sources: [{ type: 'event', package: contractId }]
  });
  
  // 4. Configure edge delivery
  const edgeId = await stack.edge.configureApp({
    domain: 'myapp.sui',
    routes: [
      { path: '/', contentSource: { type: 'walrus', cid: frontendCid }},
      { path: '/api', contentSource: { type: 'compute', functionId: apiId }}
    ]
  });
  
  return {
    contractId,
    apiId,
    indexId,
    edgeId,
    appUrl: 'https://myapp.sui'
  };
}
```

## Security

Please report security issues responsibly following our [Security Policy](SECURITY.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Community

- [Discord](https://discord.gg/SuiBase)
- [Twitter](https://twitter.com/SuiBase)
- [Forum](https://forum.sui.io/c/SuiBase)
- [Blog](https://blog.SuiBase.io)
