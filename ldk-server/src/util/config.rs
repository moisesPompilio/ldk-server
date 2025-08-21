use clap::Parser;
use ldk_node::bitcoin::Network;
use ldk_node::lightning::ln::msgs::SocketAddress;
use ldk_node::lightning::routing::gossip::NodeAlias;
use ldk_node::liquidity::LSPS2ServiceConfig;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::str::FromStr;
use std::{fs, io};

/// Configuration for LDK Server.
#[derive(Debug)]
pub struct Config {
	pub listening_addr: SocketAddress,
	pub alias: Option<NodeAlias>,
	pub network: Network,
	pub rest_service_addr: SocketAddr,
	pub storage_dir_path: String,
	pub bitcoind_rpc_host: String,
	pub bitcoind_rpc_port: u16,
	pub bitcoind_rpc_user: String,
	pub bitcoind_rpc_password: String,
	pub rabbitmq_connection_string: String,
	pub rabbitmq_exchange_name: String,
	pub lsps2_service_config: Option<LSPS2ServiceConfig>,
}

/// Configuration loaded from a TOML file.
#[derive(Deserialize, Serialize)]
pub struct TomlConfig {
	node: Option<NodeConfig>,
	storage: Option<StorageConfig>,
	bitcoind: Option<BitcoindConfig>,
	rabbitmq: Option<RabbitmqConfig>,
	liquidity: Option<LiquidityConfig>,
}

#[derive(Deserialize, Serialize)]
struct NodeConfig {
	network: Option<Network>,
	listening_address: Option<String>,
	rest_service_address: Option<String>,
	alias: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct StorageConfig {
	disk: DiskConfig,
}

#[derive(Deserialize, Serialize)]
struct DiskConfig {
	dir_path: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct BitcoindConfig {
	rpc_host: Option<String>,
	rpc_port: Option<u16>,
	rpc_user: Option<String>,
	rpc_password: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct RabbitmqConfig {
	connection_string: String,
	exchange_name: String,
}

#[derive(Deserialize, Serialize)]
struct LiquidityConfig {
	lsps2_service: Option<LSPS2ServiceTomlConfig>,
}

#[derive(Deserialize, Serialize, Debug)]
struct LSPS2ServiceTomlConfig {
	advertise_service: bool,
	channel_opening_fee_ppm: u32,
	channel_over_provisioning_ppm: u32,
	min_channel_opening_fee_msat: u64,
	min_channel_lifetime: u32,
	max_client_to_self_delay: u32,
	min_payment_size_msat: u64,
	max_payment_size_msat: u64,
	require_token: Option<String>,
}

impl Into<LSPS2ServiceConfig> for LSPS2ServiceTomlConfig {
	fn into(self) -> LSPS2ServiceConfig {
		match self {
			LSPS2ServiceTomlConfig {
				advertise_service,
				channel_opening_fee_ppm,
				channel_over_provisioning_ppm,
				min_channel_opening_fee_msat,
				min_channel_lifetime,
				max_client_to_self_delay,
				min_payment_size_msat,
				max_payment_size_msat,
				require_token,
			} => LSPS2ServiceConfig {
				advertise_service,
				channel_opening_fee_ppm,
				channel_over_provisioning_ppm,
				min_channel_opening_fee_msat,
				min_channel_lifetime,
				min_payment_size_msat,
				max_client_to_self_delay,
				max_payment_size_msat,
				require_token,
			},
		}
	}
}

#[derive(Parser, Debug)]
#[command(version, about = "LDK Node Configuration", long_about = None)]
pub struct ArgsConfig {
	#[arg(required = false)]
	config_file: Option<String>,

	#[arg(long, env = "LDK_SERVER_NODE_NETWORK")]
	node_network: Option<Network>,

	#[arg(long, env = "LDK_SERVER_NODE_LISTENING_ADDRESS")]
	node_listening_address: Option<String>,

	#[arg(long, env = "LDK_SERVER_NODE_REST_SERVICE_ADDRESS")]
	node_rest_service_address: Option<String>,

	#[arg(long, env = "LDK_SERVER_NODE_ALIAS")]
	node_alias: Option<String>,

	#[arg(long, env = "LDK_SERVER_BITCOIND_RPC_HOST")]
	bitcoind_rpc_host: Option<String>,

	#[arg(long, env = "LDK_SERVER_BITCOIND_RPC_PORT")]
	bitcoind_rpc_port: Option<u16>,

	#[arg(long, env = "LDK_SERVER_BITCOIND_RPC_USER")]
	bitcoind_rpc_user: Option<String>,

	#[arg(long, env = "LDK_SERVER_BITCOIND_RPC_PASSWORD")]
	bitcoind_rpc_password: Option<String>,

	#[arg(long, env = "LDK_SERVER_STORAGE_DIR_PATH")]
	storage_dir_path: Option<String>,
}

pub fn load_config(args_config: &ArgsConfig) -> io::Result<Config> {
	let toml_config = if let Some(config_path) = &args_config.config_file {
		let file_contents = fs::read_to_string(config_path).map_err(|e| {
			io::Error::new(e.kind(), format!("Failed to read config file '{}': {}", config_path, e))
		})?;

		Some(toml::from_str::<TomlConfig>(&file_contents).map_err(|e| {
			io::Error::new(
				io::ErrorKind::InvalidData,
				format!("Config file contains invalid TOML format: {}", e),
			)
		})?)
	} else {
		#[cfg(feature = "events-rabbitmq")]
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			"To use the `events-rabbitmq` feature, you must provide a configuration file.",
		));

		#[cfg(feature = "experimental-lsps2-support")]
		return Err(io::Error::new(
			io::ErrorKind::InvalidInput,
			"To use the `experimental-lsps2-support` feature, you must provide a configuration file.",
		));

		None
	};

	macro_rules! pick {
		($cli:expr, $toml:expr, $err_msg:expr) => {
			$cli.or($toml).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, $err_msg))
		};
	}

	fn missing_field_msg(field: &str) -> String {
		format!(
			"Missing `{}`. Please provide it via config file, CLI argument, or environment variable.",
			field
		)
	}

	// Node
	let node = toml_config.as_ref().and_then(|t| t.node.as_ref());
	let network = pick!(
		args_config.node_network,
		node.and_then(|n| n.network),
		missing_field_msg("network")
	)?;
	let listening_addr_str = pick!(
		args_config.node_listening_address.as_deref(),
		node.and_then(|n| n.listening_address.as_deref()),
		missing_field_msg("node_listening_address")
	)?;
	let listening_addr = SocketAddress::from_str(listening_addr_str).map_err(|e| {
		io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid listening address: {}", e))
	})?;

	let rest_service_addr_str = pick!(
		args_config.node_rest_service_address.as_deref(),
		node.and_then(|n| n.rest_service_address.as_deref()),
		missing_field_msg("rest_service_address")
	)?;
	let rest_service_addr = rest_service_addr_str.parse().map_err(|e| {
		io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid rest service address: {}", e))
	})?;

	let alias = {
		let alias_source =
			args_config.node_alias.as_deref().or(node.and_then(|n| n.alias.as_deref()));
		if let Some(alias_str) = alias_source {
			let mut bytes = [0u8; 32];
			let alias_bytes = alias_str.trim().as_bytes();
			if alias_bytes.len() > 32 {
				return Err(io::Error::new(
					io::ErrorKind::InvalidInput,
					"node.alias must be at most 32 bytes long.".to_string(),
				));
			}
			bytes[..alias_bytes.len()].copy_from_slice(alias_bytes);
			Some(NodeAlias(bytes))
		} else {
			None
		}
	};

	// Storage
	let storage = toml_config.as_ref().and_then(|t| t.storage.as_ref());
	let storage_dir_path = pick!(
		args_config.storage_dir_path.as_deref(),
		storage.and_then(|s| s.disk.dir_path.as_deref()),
		missing_field_msg("storage_dir_path")
	)?
	.to_string();

	// Bitcoind
	let bitcoind = toml_config.as_ref().and_then(|t| t.bitcoind.as_ref());
	let bitcoind_rpc_host = pick!(
		args_config.bitcoind_rpc_host.as_deref(),
		bitcoind.and_then(|b| b.rpc_host.as_deref()),
		missing_field_msg("bitcoind_rpc_host")
	)?
	.to_string();
	let bitcoind_rpc_port = pick!(
		args_config.bitcoind_rpc_port,
		bitcoind.and_then(|b| b.rpc_port),
		missing_field_msg("bitcoind_rpc_port")
	)?;
	let bitcoind_rpc_user = pick!(
		args_config.bitcoind_rpc_user.as_deref(),
		bitcoind.and_then(|b| b.rpc_user.as_deref()),
		missing_field_msg("bitcoind_rpc_user")
	)?
	.to_string();
	let bitcoind_rpc_password = pick!(
		args_config.bitcoind_rpc_password.as_deref(),
		bitcoind.and_then(|b| b.rpc_password.as_deref()),
		missing_field_msg("bitcoind_rpc_password")
	)?
	.to_string();

	// Load RabbitMQ and LSPS2 configurations
	let (mut rabbitmq_connection_string, mut rabbitmq_exchange_name, mut lsps2_service_config) =
		(String::new(), String::new(), None);
	if let Some(toml_config) = toml_config {
		let (rabbitmq_conn_str, rabbitmq_exch_name, lsps2_config) =
			load_config_feature(toml_config)?;

		rabbitmq_connection_string = rabbitmq_conn_str;
		rabbitmq_exchange_name = rabbitmq_exch_name;
		lsps2_service_config = lsps2_config;
	}

	Ok(Config {
		listening_addr,
		alias,
		network,
		rest_service_addr,
		storage_dir_path,
		bitcoind_rpc_host,
		bitcoind_rpc_port,
		bitcoind_rpc_user,
		bitcoind_rpc_password,
		rabbitmq_connection_string,
		rabbitmq_exchange_name,
		lsps2_service_config,
	})
}

fn load_config_feature(
	toml_config: TomlConfig,
) -> io::Result<(String, String, Option<LSPS2ServiceConfig>)> {
	let (rabbitmq_connection_string, rabbitmq_exchange_name) = {
		let rabbitmq = toml_config.rabbitmq.unwrap_or(RabbitmqConfig {
			connection_string: String::new(),
			exchange_name: String::new(),
		});
		#[cfg(feature = "events-rabbitmq")]
		if rabbitmq.connection_string.is_empty() || rabbitmq.exchange_name.is_empty() {
			return Err(io::Error::new(
					io::ErrorKind::InvalidInput,
					"Both `rabbitmq.connection_string` and `rabbitmq.exchange_name` must be configured if enabling `events-rabbitmq` feature.".to_string(),
				));
		}
		(rabbitmq.connection_string, rabbitmq.exchange_name)
	};

	#[cfg(not(feature = "experimental-lsps2-support"))]
	let lsps2_service_config: Option<LSPS2ServiceConfig> = None;
	#[cfg(feature = "experimental-lsps2-support")]
		let lsps2_service_config = Some(toml_config.liquidity
			.and_then(|l| l.lsps2_service)
			.ok_or_else(|| io::Error::new(
				io::ErrorKind::InvalidInput,
				"`liquidity.lsps2_service` must be defined in config if enabling `experimental-lsps2-support` feature."
			))?
			.into());

	Ok((rabbitmq_connection_string, rabbitmq_exchange_name, lsps2_service_config))
}

#[cfg(test)]
mod tests {
	use super::*;
	use ldk_node::{bitcoin::Network, lightning::ln::msgs::SocketAddress};

	use crate::util::config::{load_config, ArgsConfig};
	use std::str::FromStr;
	const DEFAULT_CONFIG: &str = r#"
				[node]
				network = "regtest"
				listening_address = "localhost:3001"
				rest_service_address = "127.0.0.1:3002"
				alias = "LDK Server"

				[storage.disk]
				dir_path = "/tmp"

				[bitcoind]
				rpc_host = "127.0.0.1"
				rpc_port = 8332
				rpc_user = "bitcoind-testuser"
				rpc_password = "bitcoind-testpassword"

				[rabbitmq]
				connection_string = "rabbitmq_connection_string"
				exchange_name = "rabbitmq_exchange_name"

				[liquidity.lsps2_service]
				advertise_service = false
				channel_opening_fee_ppm = 1000            # 0.1% fee
				channel_over_provisioning_ppm = 500000    # 50% extra capacity
				min_channel_opening_fee_msat = 10000000   # 10,000 satoshis
				min_channel_lifetime = 4320               # ~30 days
				max_client_to_self_delay = 1440           # ~10 days
				min_payment_size_msat = 10000000          # 10,000 satoshis
				max_payment_size_msat = 25000000000       # 0.25 BTC
				"#;

	fn default_args_config() -> ArgsConfig {
		ArgsConfig {
			config_file: None,
			node_network: Some(Network::Regtest),
			node_listening_address: Some(String::from("localhost:3008")),
			node_rest_service_address: Some(String::from("127.0.0.1:3009")),
			bitcoind_rpc_host: Some(String::from("127.0.1.9")),
			bitcoind_rpc_port: Some(18443),
			bitcoind_rpc_user: Some(String::from("bitcoind-testuser_cli")),
			bitcoind_rpc_password: Some(String::from("bitcoind-testpassword_cli")),
			storage_dir_path: Some(String::from("/tmp_cli")),
			node_alias: Some(String::from("LDK Server CLI")),
		}
	}

	fn missing_field_msg(field: &str) -> String {
		format!(
			"Missing `{}`. Please provide it via config file, CLI argument, or environment variable.",
			field
		)
	}

	fn parse_alias(alias_str: &str) -> NodeAlias {
		let mut bytes = [0u8; 32];
		let alias_bytes = alias_str.trim().as_bytes();
		bytes[..alias_bytes.len()].copy_from_slice(alias_bytes);
		NodeAlias(bytes)
	}

	#[test]
	fn test_config_from_file() {
		let storage_path = std::env::temp_dir();
		let config_file_name = "config.toml";

		fs::write(storage_path.join(config_file_name), DEFAULT_CONFIG).unwrap();
		let args_config = ArgsConfig {
			config_file: Some(storage_path.join(config_file_name).to_string_lossy().to_string()),
			node_network: None,
			node_listening_address: None,
			node_rest_service_address: None,
			bitcoind_rpc_host: None,
			bitcoind_rpc_port: None,
			bitcoind_rpc_user: None,
			bitcoind_rpc_password: None,
			storage_dir_path: None,
			node_alias: None,
		};

		let config = load_config(&args_config).unwrap();

		let alias = "LDK Server";
		let expected = Config {
			listening_addr: SocketAddress::from_str("localhost:3001").unwrap(),
			alias: Some(parse_alias(alias)),
			network: Network::Regtest,
			rest_service_addr: SocketAddr::from_str("127.0.0.1:3002").unwrap(),
			storage_dir_path: "/tmp".to_string(),
			bitcoind_rpc_host: "127.0.0.1".to_string(),
			bitcoind_rpc_port: 8332,
			bitcoind_rpc_user: "bitcoind-testuser".to_string(),
			bitcoind_rpc_password: "bitcoind-testpassword".to_string(),
			rabbitmq_connection_string: "rabbitmq_connection_string".to_string(),
			rabbitmq_exchange_name: "rabbitmq_exchange_name".to_string(),
			lsps2_service_config: Some(LSPS2ServiceConfig {
				require_token: None,
				advertise_service: false,
				channel_opening_fee_ppm: 1000,
				channel_over_provisioning_ppm: 500000,
				min_channel_opening_fee_msat: 10000000,
				min_channel_lifetime: 4320,
				max_client_to_self_delay: 1440,
				min_payment_size_msat: 10000000,
				max_payment_size_msat: 25000000000,
			}),
		};

		assert_eq!(config.listening_addr, expected.listening_addr);
		assert_eq!(config.network, expected.network);
		assert_eq!(config.rest_service_addr, expected.rest_service_addr);
		assert_eq!(config.storage_dir_path, expected.storage_dir_path);
		assert_eq!(config.bitcoind_rpc_host, expected.bitcoind_rpc_host);
		assert_eq!(config.bitcoind_rpc_port, expected.bitcoind_rpc_port);
		assert_eq!(config.bitcoind_rpc_user, expected.bitcoind_rpc_user);
		assert_eq!(config.bitcoind_rpc_password, expected.bitcoind_rpc_password);
		assert_eq!(config.rabbitmq_connection_string, expected.rabbitmq_connection_string);
		assert_eq!(config.rabbitmq_exchange_name, expected.rabbitmq_exchange_name);
		#[cfg(feature = "experimental-lsps2-support")]
		assert_eq!(config.lsps2_service_config.is_some(), expected.lsps2_service_config.is_some());
	}

	#[test]
	fn test_config_missing_fields_in_file() {
		let storage_path = std::env::temp_dir();
		let config_file_name = "config.toml";
		let mut toml_config = DEFAULT_CONFIG.to_string();
		let args_config = ArgsConfig {
			config_file: Some(storage_path.join(config_file_name).to_string_lossy().to_string()),
			node_network: None,
			node_listening_address: None,
			node_rest_service_address: None,
			bitcoind_rpc_host: None,
			bitcoind_rpc_port: None,
			bitcoind_rpc_user: None,
			bitcoind_rpc_password: None,
			storage_dir_path: None,
			node_alias: None,
		};

		macro_rules! validate_missing {
			($field:expr, $err_msg:expr) => {
				toml_config = remove_config_line(&toml_config, &format!("{} =", $field));
				fs::write(storage_path.join(config_file_name), &toml_config).unwrap();
				let result = load_config(&args_config);
				println!("Rsult: {:?}", result);
				assert!(result.is_err());
				let err = result.unwrap_err();
				assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
				assert_eq!(err.to_string(), $err_msg);
			};
		}

		#[cfg(feature = "experimental-lsps2-support")]
		{
			toml_config = remove_config_line(&toml_config, "[liquidity.lsps2_service]");
			validate_missing!(
				"lsps2_service",
				"`liquidity.lsps2_service` must be defined in config if enabling `experimental-lsps2-support` feature."
			);
		}

		#[cfg(feature = "events-rabbitmq")]
		{
			toml_config = remove_config_line(&toml_config, "[rabbitmq]");
			println!("TOML Config: {}", toml_config);
			validate_missing!(
				"rabbitmq",
				"Both `rabbitmq.connection_string` and `rabbitmq.exchange_name` must be configured if enabling `events-rabbitmq` feature."
			);
		}

		// The order here is important: it is the reverse of the validation order in `load_config`
		validate_missing!("rpc_password", missing_field_msg("bitcoind_rpc_password"));
		validate_missing!("rpc_user", missing_field_msg("bitcoind_rpc_user"));
		validate_missing!("rpc_port", missing_field_msg("bitcoind_rpc_port"));
		validate_missing!("rpc_host", missing_field_msg("bitcoind_rpc_host"));
		validate_missing!("dir_path", missing_field_msg("storage_dir_path"));
		validate_missing!("rest_service_address", missing_field_msg("rest_service_address"));
		validate_missing!("listening_address", missing_field_msg("node_listening_address"));
		validate_missing!("network", missing_field_msg("network"));
	}
	fn remove_config_line(config: &str, key: &str) -> String {
		config
			.lines()
			.filter(|line| !line.trim_start().starts_with(key))
			.collect::<Vec<_>>()
			.join("\n")
	}

	#[test]
	#[cfg(not(feature = "experimental-lsps2-support"))]
	#[cfg(not(feature = "events-rabbitmq"))]
	fn test_config_from_args_config() {
		let args_config = default_args_config();
		let config = load_config(&args_config).unwrap();

		let expected = Config {
			listening_addr: SocketAddress::from_str(
				args_config.node_listening_address.as_deref().unwrap(),
			)
			.unwrap(),
			network: Network::Regtest,
			rest_service_addr: SocketAddr::from_str(
				args_config.node_rest_service_address.as_deref().unwrap(),
			)
			.unwrap(),
			alias: Some(parse_alias(args_config.node_alias.as_deref().unwrap())),
			storage_dir_path: args_config.storage_dir_path.unwrap(),
			bitcoind_rpc_host: args_config.bitcoind_rpc_host.unwrap(),
			bitcoind_rpc_port: args_config.bitcoind_rpc_port.unwrap(),
			bitcoind_rpc_user: args_config.bitcoind_rpc_user.unwrap(),
			bitcoind_rpc_password: args_config.bitcoind_rpc_password.unwrap(),
			rabbitmq_connection_string: String::new(),
			rabbitmq_exchange_name: String::new(),
			lsps2_service_config: None,
		};

		assert_eq!(config.listening_addr, expected.listening_addr);
		assert_eq!(config.network, expected.network);
		assert_eq!(config.rest_service_addr, expected.rest_service_addr);
		assert_eq!(config.storage_dir_path, expected.storage_dir_path);
		assert_eq!(config.bitcoind_rpc_host, expected.bitcoind_rpc_host);
		assert_eq!(config.bitcoind_rpc_port, expected.bitcoind_rpc_port);
		assert_eq!(config.bitcoind_rpc_user, expected.bitcoind_rpc_user);
		assert_eq!(config.bitcoind_rpc_password, expected.bitcoind_rpc_password);
		assert_eq!(config.rabbitmq_connection_string, expected.rabbitmq_connection_string);
		assert_eq!(config.rabbitmq_exchange_name, expected.rabbitmq_exchange_name);
		assert!(config.lsps2_service_config.is_none());
	}

	#[test]
	#[cfg(not(feature = "experimental-lsps2-support"))]
	#[cfg(not(feature = "events-rabbitmq"))]
	fn test_config_missing_fields_in_args_config() {
		let mut args_config = default_args_config();

		macro_rules! validate_missing {
			($field:ident, $err_msg:expr) => {
				args_config.$field = None;
				let result = load_config(&args_config);
				assert!(result.is_err());
				let err = result.unwrap_err();
				assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
				assert_eq!(err.to_string(), $err_msg);
			};
		}
		// The order here is important: it is the reverse of the validation order in `load_config`
		validate_missing!(bitcoind_rpc_password, missing_field_msg("bitcoind_rpc_password"));
		validate_missing!(bitcoind_rpc_user, missing_field_msg("bitcoind_rpc_user"));
		validate_missing!(bitcoind_rpc_port, missing_field_msg("bitcoind_rpc_port"));
		validate_missing!(bitcoind_rpc_host, missing_field_msg("bitcoind_rpc_host"));
		validate_missing!(storage_dir_path, missing_field_msg("storage_dir_path"));
		validate_missing!(node_rest_service_address, missing_field_msg("rest_service_address"));
		validate_missing!(node_listening_address, missing_field_msg("node_listening_address"));
		validate_missing!(node_network, missing_field_msg("network"));
	}

	#[test]
	fn test_args_config_overrides_file() {
		let storage_path = std::env::temp_dir();
		let config_file_name = "config.toml";

		fs::write(storage_path.join(config_file_name), DEFAULT_CONFIG).unwrap();
		let mut args_config: ArgsConfig = default_args_config();
		args_config.config_file =
			Some(storage_path.join(config_file_name).to_string_lossy().to_string());

		let config = load_config(&args_config).unwrap();
		let expected = Config {
			listening_addr: SocketAddress::from_str(
				args_config.node_listening_address.as_deref().unwrap(),
			)
			.unwrap(),
			network: Network::Regtest,
			rest_service_addr: SocketAddr::from_str(
				args_config.node_rest_service_address.as_deref().unwrap(),
			)
			.unwrap(),
			alias: Some(parse_alias(args_config.node_alias.as_deref().unwrap())),
			storage_dir_path: args_config.storage_dir_path.unwrap(),
			bitcoind_rpc_host: args_config.bitcoind_rpc_host.unwrap(),
			bitcoind_rpc_port: args_config.bitcoind_rpc_port.unwrap(),
			bitcoind_rpc_user: args_config.bitcoind_rpc_user.unwrap(),
			bitcoind_rpc_password: args_config.bitcoind_rpc_password.unwrap(),
			rabbitmq_connection_string: "rabbitmq_connection_string".to_string(),
			rabbitmq_exchange_name: "rabbitmq_exchange_name".to_string(),
			lsps2_service_config: Some(LSPS2ServiceConfig {
				require_token: None,
				advertise_service: false,
				channel_opening_fee_ppm: 1000,
				channel_over_provisioning_ppm: 500000,
				min_channel_opening_fee_msat: 10000000,
				min_channel_lifetime: 4320,
				max_client_to_self_delay: 1440,
				min_payment_size_msat: 10000000,
				max_payment_size_msat: 25000000000,
			}),
		};

		assert_eq!(config.listening_addr, expected.listening_addr);
		assert_eq!(config.network, expected.network);
		assert_eq!(config.rest_service_addr, expected.rest_service_addr);
		assert_eq!(config.storage_dir_path, expected.storage_dir_path);
		assert_eq!(config.bitcoind_rpc_host, expected.bitcoind_rpc_host);
		assert_eq!(config.bitcoind_rpc_port, expected.bitcoind_rpc_port);
		assert_eq!(config.bitcoind_rpc_user, expected.bitcoind_rpc_user);
		assert_eq!(config.bitcoind_rpc_password, expected.bitcoind_rpc_password);
		assert_eq!(config.rabbitmq_connection_string, expected.rabbitmq_connection_string);
		assert_eq!(config.rabbitmq_exchange_name, expected.rabbitmq_exchange_name);
		#[cfg(feature = "experimental-lsps2-support")]
		assert_eq!(config.lsps2_service_config.is_some(), expected.lsps2_service_config.is_some());
	}

	#[test]
	#[cfg(feature = "events-rabbitmq")]
	fn test_error_if_rabbitmq_feature_without_config_file() {
		let args_config = ArgsConfig {
			config_file: None,
			node_network: None,
			node_listening_address: None,
			node_rest_service_address: None,
			node_alias: None,
			bitcoind_rpc_host: None,
			bitcoind_rpc_port: None,
			bitcoind_rpc_user: None,
			bitcoind_rpc_password: None,
			storage_dir_path: None,
		};
		let result = load_config(&args_config);
		assert!(result.is_err());
		let err = result.unwrap_err();
		assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
		assert_eq!(
			err.to_string(),
			"To use the `events-rabbitmq` feature, you must provide a configuration file."
		);
	}

	#[test]
	#[cfg(feature = "experimental-lsps2-support")]
	fn test_error_if_lsps2_feature_without_config_file() {
		let args_config = ArgsConfig {
			config_file: None,
			node_network: None,
			node_listening_address: None,
			node_rest_service_address: None,
			node_alias: None,
			bitcoind_rpc_host: None,
			bitcoind_rpc_port: None,
			bitcoind_rpc_user: None,
			bitcoind_rpc_password: None,
			storage_dir_path: None,
		};
		let result = load_config(&args_config);
		assert!(result.is_err());
		let err = result.unwrap_err();
		assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
		assert_eq!(err.to_string(), "To use the `experimental-lsps2-support` feature, you must provide a configuration file.");
	}
}
