//! Command Line Interface for SuiStack0X TEE Framework

mod commands;

use crate::core::error::TEEResult;
pub use commands::CommandHandler;

/// Run the CLI with the given arguments
pub async fn run(args: &[String]) -> TEEResult<()> {
    let matches = CommandHandler::build_cli().get_matches_from(args);

    match matches.subcommand() {
        Some(("enclave", enclave_args)) => {
            let result = CommandHandler::handle_enclave_command(enclave_args).await?;
            println!("{}", result);
        }
        Some(("validator", validator_args)) => {
            let result = CommandHandler::handle_validator_command(validator_args).await?;
            println!("{}", result);
        }
        _ => {
            CommandHandler::build_cli().print_help()?;
        }
    }

    Ok(())
}
