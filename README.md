# LDK Server

**LDK Server** is a fully-functional Lightning node in daemon form, built on top of
[LDK Node](https://github.com/lightningdevkit/ldk-node), which itself provides a powerful abstraction over the
[Lightning Development Kit (LDK)](https://github.com/lightningdevkit/rust-lightning) and uses a built-in
[Bitcoin Development Kit (BDK)](https://bitcoindevkit.org/) wallet.

The primary goal of LDK Server is to provide an efficient, stable, and API-first solution for deploying and managing
a Lightning Network node. With its streamlined setup, LDK Server enables users to easily set up, configure, and run
a Lightning node while exposing a robust, language-agnostic API via [Protocol Buffers (Protobuf)](https://protobuf.dev/).

### Features

- **Out-of-the-Box Lightning Node**:
    - Deploy a Lightning Network node with minimal configuration, no coding required.

- **API-First Design**:
    - Exposes a well-defined API using Protobuf, allowing seamless integration with HTTP-clients or applications.

- **Powered by LDK**:
    - Built on top of LDK-Node, leveraging the modular, reliable, and high-performance architecture of LDK.

- **Effortless Integration**:
    - Ideal for embedding Lightning functionality into payment processors, self-hosted nodes, custodial wallets, or other Lightning-enabled
      applications.

### Project Status

🚧 **Work in Progress**:
- **APIs Under Development**: Expect breaking changes as the project evolves.
- **Potential Bugs and Inconsistencies**: While progress is being made toward stability, unexpected behavior may occur.
- **Improved Logging and Error Handling Coming Soon**: Current error handling is rudimentary (specially for CLI), and usability improvements are actively being worked on.
- **Pending Testing**: Not tested, hence don't use it for production!

We welcome your feedback and contributions to help shape the future of LDK Server!


### Configuration
Refer `./ldk-server/ldk-server-config.toml` to see available configuration options.

You can configure the node via a TOML file, environment variables, or CLI arguments. All options are optional — values provided via CLI override environment variables, which override the values in the TOML file.

### Building
```
git clone https://github.com/lightningdevkit/ldk-server.git
cargo build
```

### Running
- Using a config file:
```
cargo run --bin ldk-server ./ldk-server/ldk-server-config.toml
```

- Using environment variables (all optional):
```
export LDK_SERVER_NODE_NETWORK=regtest
export LDK_SERVER_NODE_LISTENING_ADDRESS=localhost:3001
export LDK_SERVER_NODE_REST_SERVICE_ADDRESS=127.0.0.1:3002
export LDK_SERVER_NODE_ALIAS=LDK-Server
export LDK_SERVER_BITCOIND_RPC_HOST=127.0.0.1
export LDK_SERVER_BITCOIND_RPC_PORT=18443
export LDK_SERVER_BITCOIND_RPC_USER=your-rpc-user
export LDK_SERVER_BITCOIND_RPC_PASSWORD=your-rpc-password
export LDK_SERVER_STORAGE_DIR_PATH=/path/to/storage
cargo run --bin ldk-server
```

- Using CLI arguments (all optional):
```
cargo run --bin ldk-server -- \
  --node-network regtest \
  --node-listening-address localhost:3001 \
  --node-rest-service-address 127.0.0.1:3002 \
  --node-alias LDK-Server \
  --bitcoind-rpc-host 127.0.0.1 \
  --bitcoind-rpc-port 18443 \
  --bitcoind-rpc-user your-rpc-user \
  --bitcoind-rpc-password your-rpc-password \
  --storage-dir-path /path/to/storage
```

- Mixed configuration example (config file + overrides):
```
# config file sets listening_address = "localhost:3001"
cargo run --bin ldk-server ./ldk-server/ldk-server-config.toml  --node-listening-address localhost:3009
# Result: `localhost:3009` will be used because CLI overrides the config file
```

### Interacting with the Node

Once running, use the CLI client:
```
# Generate an on-chain receive address
./target/debug/ldk-server-cli -b localhost:3002 onchain-receive

# View commands
./target/debug/ldk-server-cli -b localhost:3002 help
```
