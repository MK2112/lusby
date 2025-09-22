use clap::{CommandFactory, Parser};
use lusbyctl::{Cli, Commands};

#[test]
fn test_cli_parsing_list() {
    let cli = Cli::parse_from(["lusbyctl", "list"]);
    match cli.command {
        Commands::List => {}
        _ => panic!("List command not parsed correctly"),
    }
}

#[test]
fn test_cli_parsing_status() {
    let cli = Cli::parse_from(["lusbyctl", "status"]);
    match cli.command {
        Commands::Status => {}
        _ => panic!("Status command not parsed correctly"),
    }
}

#[test]
fn test_cli_command_help() {
    // CommandFactory erzeugt die Hilfe, sollte nicht paniken
    Cli::command().debug_assert();
}
