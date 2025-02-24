use crate::core::{enclave::EnclaveBuilder, error::TEEResult};
use crate::sui::node::TEEValidator;
use crate::utils::config::ConfigurationManager;
use clap::{Arg, ArgAction, Command};
use std::path::PathBuf;
use tokio::fs;

pub struct CommandHandler;

impl CommandHandler {
    /// Build CLI command structure
    pub fn build_cli() -> Command {
        Command::new("suistack0x")
            .about("SuiStack0X TEE Framework CLI")
            .version(env!("CARGO_PKG_VERSION"))
            .subcommand_required(true)
            .arg_required_else_help(true)
            // Global flags
            .arg(
                Arg::new("verbose")
                    .short('v')
                    .long("verbose")
                    .action(ArgAction::Count)
                    .help("Increase logging verbosity")
            )
            // Help command
            .subcommand(
                Command::new("help")
                    .about("Show detailed help information")
                    .arg(
                        Arg::new("topic")
                            .help("Help topic (enclave, validator, config, etc.)")
                    )
            )
            // Version command
            .subcommand(
                Command::new("version")
                    .about("Show version information")
            )
            // Status command
            .subcommand(
                Command::new("status")
                    .about("Show current system status")
                    .arg(
                        Arg::new("json")
                            .long("json")
                            .help("Output in JSON format")
                    )
            )
            // Enclave management commands
            .subcommand(
                Command::new("enclave")
                    .about("Manage TEE enclaves")
                    .subcommand_required(true)
                    .subcommand(
                        Command::new("create")
                            .about("Create a new enclave")
                            .arg(
                                Arg::new("platform")
                                    .long("platform")
                                    .help("TEE platform (intel_sgx, amd_sev, arm_trustzone, aws_nitro)")
                                    .required(true)
                            )
                            .arg(
                                Arg::new("memory")
                                    .long("memory")
                                    .help("Memory size in MB")
                                    .required(true)
                            )
                            .arg(
                                Arg::new("cpus")
                                    .long("cpus")
                                    .help("Number of CPU cores")
                                    .required(true)
                            )
                            .arg(
                                Arg::new("config")
                                    .long("config")
                                    .help("Path to save enclave configuration")
                                    .required(false)
                            )
                    )
                    .subcommand(
                        Command::new("list")
                            .about("List available enclaves")
                    )
                    .subcommand(
                        Command::new("info")
                            .about("Show enclave information")
                            .arg(
                                Arg::new("config")
                                    .help("Path to enclave configuration")
                                    .required(true)
                            )
                    )
                    .subcommand(
                        Command::new("destroy")
                            .about("Destroy an enclave")
                            .arg(
                                Arg::new("config")
                                    .help("Path to enclave configuration")
                                    .required(true)
                            )
                            .arg(
                                Arg::new("force")
                                    .long("force")
                                    .help("Force destruction without confirmation")
                            )
                    )
            )
            // Validator management commands
            .subcommand(
                Command::new("validator")
                    .about("Manage validator node")
                    .subcommand_required(true)
                    .subcommand(
                        Command::new("start")
                            .about("Start validator node")
                            .arg(
                                Arg::new("endpoint")
                                    .long("endpoint")
                                    .help("Blockchain network endpoint")
                                    .required(true)
                            )
                            .arg(
                                Arg::new("config")
                                    .long("config")
                                    .help("Path to enclave configuration")
                                    .required(false)
                            )
                    )
                    .subcommand(
                        Command::new("stop")
                            .about("Stop validator node")
                    )
                    .subcommand(
                        Command::new("status")
                            .about("Show validator status")
                            .arg(
                                Arg::new("json")
                                    .long("json")
                                    .help("Output in JSON format")
                            )
                    )
                    .subcommand(
                        Command::new("metrics")
                            .about("Show validator metrics")
                            .arg(
                                Arg::new("json")
                                    .long("json")
                                    .help("Output in JSON format")
                            )
                    )
                    .subcommand(
                        Command::new("attestation")
                            .about("Manage validator attestation")
                            .subcommand(
                                Command::new("refresh")
                                    .about("Refresh attestation")
                            )
                            .subcommand(
                                Command::new("status")
                                    .about("Show attestation status")
                            )
                    )
            )
            // Configuration commands
            .subcommand(
                Command::new("config")
                    .about("Manage configuration")
                    .subcommand_required(true)
                    .subcommand(
                        Command::new("show")
                            .about("Show current configuration")
                            .arg(
                                Arg::new("json")
                                    .long("json")
                                    .help("Output in JSON format")
                            )
                    )
                    .subcommand(
                        Command::new("set")
                            .about("Set configuration value")
                            .arg(
                                Arg::new("key")
                                    .help("Configuration key")
                                    .required(true)
                            )
                            .arg(
                                Arg::new("value")
                                    .help("Configuration value")
                                    .required(true)
                            )
                    )
            )
    }

    /// Handle help command
    pub fn handle_help_command(topic: Option<&str>) -> TEEResult<String> {
        match topic {
            Some("enclave") => Ok(r#"Enclave Management Commands:

create  - Create a new TEE enclave
  Arguments:
    --platform  TEE platform type (required)
                Options: intel_sgx, amd_sev, arm_trustzone, aws_nitro
    --memory    Memory size in MB (required)
    --cpus      Number of CPU cores (required)
    --config    Path to save enclave configuration

list    - List all available enclaves
info    - Show detailed information about an enclave
destroy - Destroy an existing enclave

Examples:
  suistack0x enclave create --platform intel_sgx --memory 8192 --cpus 4
  suistack0x enclave list
  suistack0x enclave info my_enclave.json
"#
            .to_string()),

            Some("validator") => Ok(r#"Validator Management Commands:

start      - Start a validator node
  Arguments:
    --endpoint  Blockchain network endpoint (required)
    --config    Path to enclave configuration

stop       - Stop a running validator node
status     - Show validator status
metrics    - Show validator performance metrics
attestation - Manage validator attestation
  Commands:
    refresh - Refresh attestation
    status  - Show attestation status

Examples:
  suistack0x validator start --endpoint http://localhost:9000 --config my_enclave.json
  suistack0x validator status --json
  suistack0x validator attestation refresh
"#
            .to_string()),

            Some("config") => Ok(r#"Configuration Management Commands:

show    - Show current configuration
  Arguments:
    --json  Output in JSON format

set     - Set configuration value
  Arguments:
    <key>    Configuration key
    <value>  Configuration value

Examples:
  suistack0x config show --json
  suistack0x config set network.endpoint http://localhost:9000
"#
            .to_string()),

            None => Ok(r#"SuiStack0X TEE Framework CLI

Main Commands:
  enclave    - Manage TEE enclaves
  validator  - Manage validator node
  config     - Manage configuration
  status     - Show system status
  version    - Show version information
  help       - Show help information

Global Options:
  -v, --verbose  Increase logging verbosity

Use 'suistack0x help <topic>' for detailed help on a topic:
  - enclave
  - validator
  - config
"#
            .to_string()),

            _ => Ok(format!(
                "No help available for topic: {}",
                topic.unwrap_or("")
            )),
        }
    }

    /// Handle version command
    pub fn handle_version_command() -> TEEResult<String> {
        Ok(format!(
            "SuiStack0X TEE Framework v{}\n\
                   Build: {}\n\
                   Commit: {}\n\
                   Platform: {}",
            env!("CARGO_PKG_VERSION"),
            env!("BUILD_TIMESTAMP"),
            env!("GIT_HASH"),
            std::env::consts::OS
        ))
    }

    /// Handle status command
    pub async fn handle_status_command(json: bool) -> TEEResult<String> {
        // Get system status
        let status = ConfigurationManager::get_system_status().await?;

        if json {
            Ok(serde_json::to_string_pretty(&status)?)
        } else {
            Ok(format!(
                "System Status:\n\
                       Platform: {}\n\
                       Enclaves: {}\n\
                       Validators: {}\n\
                       Memory Usage: {}MB\n\
                       CPU Usage: {:.1}%",
                status.platform,
                status.active_enclaves,
                status.active_validators,
                status.memory_usage_mb,
                status.cpu_usage
            ))
        }
    }

    /// Handle enclave commands
    pub async fn handle_enclave_command(args: &clap::ArgMatches) -> TEEResult<String> {
        match args.subcommand() {
            Some(("create", create_args)) => {
                // Get enclave parameters
                let platform = create_args.get_one::<String>("platform").ok_or_else(|| {
                    crate::core::error::TEEError::ConfigurationError(
                        "Platform is required".to_string(),
                    )
                })?;

                let memory = create_args.get_one::<usize>("memory").ok_or_else(|| {
                    crate::core::error::TEEError::ConfigurationError(
                        "Memory size is required".to_string(),
                    )
                })?;

                let cpu_count = create_args.get_one::<u32>("cpus").ok_or_else(|| {
                    crate::core::error::TEEError::ConfigurationError(
                        "CPU count is required".to_string(),
                    )
                })?;

                // Create enclave using builder
                let enclave = EnclaveBuilder::new()
                    .platform(platform.clone())
                    .memory(*memory)
                    .cpu_count(*cpu_count)
                    .build()?;

                // Initialize enclave
                enclave.initialize()?;

                // Save enclave configuration
                let config_path = create_args
                    .get_one::<PathBuf>("config")
                    .cloned()
                    .unwrap_or_else(|| PathBuf::from("enclave_config.json"));

                ConfigurationManager::save_enclave_config(&config_path, enclave)?;

                Ok(format!(
                    "Enclave created successfully. Config saved to: {}",
                    config_path.display()
                ))
            }
            Some(("list", _)) => {
                let enclaves = ConfigurationManager::list_enclaves().await?;

                if enclaves.is_empty() {
                    Ok("No enclaves found.".to_string())
                } else {
                    let mut output = String::from("Available Enclaves:\n");
                    for enclave in enclaves {
                        output.push_str(&format!(
                            "- {} ({}, {} MB, {} CPUs)\n",
                            enclave.id, enclave.platform, enclave.memory_mb, enclave.cpu_count
                        ));
                    }
                    Ok(output)
                }
            }
            Some(("info", info_args)) => {
                let config_path = info_args.get_one::<PathBuf>("config").ok_or_else(|| {
                    crate::core::error::TEEError::ConfigurationError(
                        "Config path is required".to_string(),
                    )
                })?;

                let enclave = ConfigurationManager::load_enclave_config(config_path)?;
                let status = enclave.get_state();
                let metrics = enclave.get_metrics()?;

                Ok(format!(
                    "Enclave Information:\n\
                          ID: {}\n\
                          Platform: {}\n\
                          Status: {:?}\n\
                          Memory: {} MB\n\
                          CPUs: {}\n\
                          Memory Usage: {} MB\n\
                          CPU Usage: {:.1}%",
                    enclave.get_id(),
                    enclave.get_platform(),
                    status,
                    metrics.memory_total_mb,
                    metrics.cpu_count,
                    metrics.memory_used_mb,
                    metrics.cpu_usage
                ))
            }
            Some(("destroy", destroy_args)) => {
                let config_path = destroy_args.get_one::<PathBuf>("config").ok_or_else(|| {
                    crate::core::error::TEEError::ConfigurationError(
                        "Config path is required".to_string(),
                    )
                })?;

                let force = destroy_args.get_flag("force");

                if !force {
                    // TODO: Add interactive confirmation
                    println!(
                        "Warning: This will destroy the enclave. Use --force to skip confirmation."
                    );
                    return Ok("Operation cancelled".to_string());
                }

                let enclave = ConfigurationManager::load_enclave_config(config_path)?;
                enclave.terminate()?;
                fs::remove_file(config_path).await?;

                Ok("Enclave destroyed successfully".to_string())
            }
            _ => Err(crate::core::error::TEEError::ConfigurationError(
                "Invalid enclave command".to_string(),
            )),
        }
    }

    /// Handle validator commands
    pub async fn handle_validator_command(args: &clap::ArgMatches) -> TEEResult<String> {
        match args.subcommand() {
            Some(("start", start_args)) => {
                // Get node parameters
                let endpoint = start_args.get_one::<String>("endpoint").ok_or_else(|| {
                    crate::core::error::TEEError::ConfigurationError(
                        "Endpoint is required".to_string(),
                    )
                })?;

                let config_path = start_args
                    .get_one::<PathBuf>("config")
                    .cloned()
                    .unwrap_or_else(|| PathBuf::from("enclave_config.json"));

                // Load existing enclave
                let enclave = ConfigurationManager::load_enclave_config(&config_path)?;
                // Create and start validator
                let validator = TEEValidator::new(endpoint, enclave).await?;
                validator.start().await?;

                Ok("Validator node started successfully".to_string())
            }
            Some(("stop", _)) => {
                // Check if validator is running
                if let Some(validator) = ConfigurationManager::get_active_validator().await? {
                    validator.stop().await?;
                    Ok("Validator node stopped successfully".to_string())
                } else {
                    Ok("No active validator node found".to_string())
                }
            }
            Some(("status", status_args)) => {
                if let Some(validator) = ConfigurationManager::get_active_validator().await? {
                    let status = validator.status().await;
                    let metrics = validator.metrics().await;
                    let task_stats = validator.get_task_stats();
                    let error_stats = validator.get_error_stats();

                    if status_args.get_flag("json") {
                        Ok(serde_json::to_string_pretty(&json!({
                            "status": format!("{:?}", status),
                            "metrics": {
                                "commands_processed": metrics.commands_processed,
                                "commands_failed": metrics.commands_failed,
                                "avg_latency_ms": metrics.avg_latency_ms,
                                "memory_usage_mb": metrics.memory_usage_mb,
                                "cpu_usage": metrics.cpu_usage,
                                "uptime_secs": metrics.uptime_secs,
                                "blockchain_connected": metrics.blockchain_connected,
                                "attestation_age_secs": metrics.attestation_age_secs,
                            },
                            "tasks": {
                                "completed": task_stats.0,
                                "failed": task_stats.1,
                                "in_progress": task_stats.2
                            },
                            "errors": error_stats.iter()
                                .map(|(k, v)| (format!("{:?}", k), v))
                                .collect::<HashMap<String, u64>>()
                        }))?)
                    } else {
                        Ok(format!(
                            "Validator Status:\n\
                                Status: {:?}\n\
                                Commands Processed: {}\n\
                                Commands Failed: {}\n\
                                Average Latency: {:.2}ms\n\
                                Memory Usage: {}MB\n\
                                CPU Usage: {:.1}%\n\
                                Uptime: {}s\n\
                                Blockchain Connected: {}\n\
                                Attestation Age: {}s\n\
                                \n\
                                Tasks:\n\
                                - Completed: {}\n\
                                - Failed: {}\n\
                                - In Progress: {}\n\
                                \n\
                                Errors:\n{}",
                            status,
                            metrics.commands_processed,
                            metrics.commands_failed,
                            metrics.avg_latency_ms,
                            metrics.memory_usage_mb,
                            metrics.cpu_usage,
                            metrics.uptime_secs,
                            metrics.blockchain_connected,
                            metrics.attestation_age_secs,
                            task_stats.0,
                            task_stats.1,
                            task_stats.2,
                            error_stats
                                .iter()
                                .map(|(k, v)| format!("- {:?}: {}", k, v))
                                .collect::<Vec<_>>()
                                .join("\n")
                        ))
                    }
                } else {
                    Ok("No active validator node found".to_string())
                }
            }
            Some(("metrics", metrics_args)) => {
                if let Some(validator) = ConfigurationManager::get_active_validator().await? {
                    let metrics = validator.metrics().await;

                    if metrics_args.get_flag("json") {
                        Ok(serde_json::to_string_pretty(&metrics)?)
                    } else {
                        Ok(format!(
                            "Validator Metrics:\n\
                                Performance:\n\
                                - Commands Processed: {}\n\
                                - Average Latency: {:.2}ms\n\
                                - Command Queue Length: {}\n\
                                \n\
                                Resources:\n\
                                - Memory Usage: {}MB\n\
                                - CPU Usage: {:.1}%\n\
                                - Network Errors: {}\n\
                                \n\
                                Platform Metrics:\n{}",
                            metrics.commands_processed,
                            metrics.avg_latency_ms,
                            metrics.pending_commands,
                            metrics.memory_usage_mb,
                            metrics.cpu_usage,
                            metrics.network_errors,
                            metrics
                                .platform_metrics
                                .iter()
                                .map(|(k, v)| format!("- {}: {:.2}", k, v))
                                .collect::<Vec<_>>()
                                .join("\n")
                        ))
                    }
                } else {
                    Ok("No active validator node found".to_string())
                }
            }
            Some(("attestation", attestation_args)) => {
                match attestation_args.subcommand() {
                    Some(("refresh", _)) => {
                        if let Some(validator) =
                            ConfigurationManager::get_active_validator().await?
                        {
                            // Force attestation refresh
                            validator.refresh_attestation().await?;
                            Ok("Attestation refreshed successfully".to_string())
                        } else {
                            Ok("No active validator node found".to_string())
                        }
                    }
                    Some(("status", _)) => {
                        if let Some(validator) =
                            ConfigurationManager::get_active_validator().await?
                        {
                            let attestation = validator.get_attestation().await;
                            match attestation {
                                Some(att) => Ok(format!(
                                    "Attestation Status:\n\
                                        Age: {}s\n\
                                        Platform: {}\n\
                                        Valid: {}",
                                    SystemTime::now()
                                        .duration_since(UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs()
                                        - att.timestamp,
                                    att.platform_id,
                                    validator.verify_attestation(&att).await?
                                )),
                                None => Ok("No attestation found".to_string()),
                            }
                        } else {
                            Ok("No active validator node found".to_string())
                        }
                    }
                    _ => Err(crate::core::error::TEEError::ConfigurationError(
                        "Invalid attestation command".to_string(),
                    )),
                }
            }
            _ => Err(crate::core::error::TEEError::ConfigurationError(
                "Invalid validator command".to_string(),
            )),
        }
    }

    /// Handle configuration commands
    pub async fn handle_config_command(args: &clap::ArgMatches) -> TEEResult<String> {
        match args.subcommand() {
            Some(("show", show_args)) => {
                let config = ConfigurationManager::get_current_config()?;

                if show_args.get_flag("json") {
                    Ok(serde_json::to_string_pretty(&config)?)
                } else {
                    Ok(format!(
                        "Current Configuration:\n\
                            \n\
                            Platform:\n\
                            - Type: {}\n\
                            - Memory: {}MB\n\
                            - CPUs: {}\n\
                            \n\
                            Network:\n\
                            - Endpoint: {}\n\
                            - Timeout: {}s\n\
                            - Max Retries: {}\n\
                            \n\
                            Security:\n\
                            - Required Level: {:?}\n\
                            - Min Attestation Validity: {}s\n\
                            - Max Attestation Validity: {}s\n",
                        config.platform.platform_type,
                        config.platform.memory_size,
                        config.platform.cpu_cores,
                        config.network.endpoint,
                        config.network.timeout_secs,
                        config.network.max_retries,
                        config.security.required_security_level,
                        config.security.min_attestation_validity,
                        config.security.max_attestation_validity
                    ))
                }
            }
            Some(("set", set_args)) => {
                let key = set_args.get_one::<String>("key").ok_or_else(|| {
                    crate::core::error::TEEError::ConfigurationError(
                        "Configuration key is required".to_string(),
                    )
                })?;

                let value = set_args.get_one::<String>("value").ok_or_else(|| {
                    crate::core::error::TEEError::ConfigurationError(
                        "Configuration value is required".to_string(),
                    )
                })?;

                ConfigurationManager::set_config_value(key, value)?;
                Ok(format!("Configuration updated: {} = {}", key, value))
            }
            _ => Err(crate::core::error::TEEError::ConfigurationError(
                "Invalid config command".to_string(),
            )),
        }
    }
}

/// Helper function to format durations
fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m {}s", secs / 3600, (secs % 3600) / 60, secs % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;

    #[test]
    async fn test_help_command() {
        let result = CommandHandler::handle_help_command(None).unwrap();
        assert!(result.contains("Main Commands:"));
        assert!(result.contains("enclave"));
        assert!(result.contains("validator"));
    }

    #[test]
    async fn test_version_command() {
        let result = CommandHandler::handle_version_command().unwrap();
        assert!(result.contains("SuiStack0X TEE Framework"));
        assert!(result.contains("Build:"));
    }

    #[test]
    async fn test_status_command() {
        let result = CommandHandler::handle_status_command(false).await.unwrap();
        assert!(result.contains("System Status:"));
        assert!(result.contains("Platform:"));
    }

    #[test]
    async fn test_enclave_commands() {
        // Test create enclave
        let matches = CommandHandler::build_cli().get_matches_from(vec![
            "suistack0x",
            "enclave",
            "create",
            "--platform",
            "intel_sgx",
            "--memory",
            "8192",
            "--cpus",
            "4",
        ]);

        if let Some(("enclave", args)) = matches.subcommand() {
            let result = CommandHandler::handle_enclave_command(args).await.unwrap();
            assert!(result.contains("Enclave created successfully"));
        }
    }
}
