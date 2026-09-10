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

#[test]
fn test_cli_parsing_allow_ttl() {
    let cli = Cli::parse_from(["lusbyctl", "allow", "dev1", "--ttl", "60"]);
    match cli.command {
        Commands::Allow(args) => assert_eq!(args.ttl, 60),
        _ => panic!("Allow command not parsed correctly"),
    }
}

#[test]
fn test_cli_parsing_baseline_sign_secret_file() {
    let cli = Cli::parse_from([
        "lusbyctl",
        "baseline",
        "sign",
        "--secret-file",
        "/tmp/secret.b64",
        "--input",
        "in.json",
        "--output",
        "out.json",
    ]);
    match cli.command {
        Commands::Baseline { cmd } => match cmd {
            lusbyctl::BaselineCmd::Sign { secret_file, .. } => {
                assert!(secret_file.is_some())
            }
            _ => panic!("Sign subcommand not parsed"),
        },
        _ => panic!("Baseline command not parsed correctly"),
    }
}
