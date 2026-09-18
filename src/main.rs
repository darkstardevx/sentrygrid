mod audit;
mod docker;
mod format;
mod ss;
mod ufw;

use clap::Parser;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "sentrygrid",
    version = "0.1.0",
    about = "Network exposure auditor — is this port actually reachable?"
)]
struct Args {
    /// "report" (default, human-readable) | "json"
    #[arg(long, default_value = "report")]
    format: String,

    /// Pretty-print JSON output.
    #[arg(long)]
    pretty: bool,

    /// Disable cybercore color output.
    #[arg(long)]
    no_color: bool,

    /// Also list loopback-only (SAFE) sockets, not just the ones worth attention.
    #[arg(long)]
    show_safe: bool,

    /// Exit non-zero if any EXPOSED finding exists — for scripting/cron use.
    #[arg(long)]
    fail_on_exposed: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let sockets = match ss::list_sockets() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sentrygrid: failed to run `ss` (needs to be installed; run with sudo for full process visibility): {e}");
            return ExitCode::FAILURE;
        }
    };

    let ufw_state = ufw::status_verbose().unwrap_or_else(|e| {
        eprintln!("sentrygrid: warning: failed to run `ufw status` ({e}) — treating as if ufw is inactive, everything wide-bound will show as Blocked=false/exposed by default");
        ufw::UfwState::default()
    });

    let docker_ports = docker::list_published_ports();

    let findings = audit::correlate(sockets, &ufw_state, &docker_ports);

    if !ufw_state.active {
        eprintln!("sentrygrid: NOTE — ufw itself reports inactive. Every wide-bound, non-Docker port below is actually reachable regardless of its BLOCKED/EXPOSED label.");
    }

    match args.format.as_str() {
        "json" => println!("{}", format::render_json(&findings, args.pretty)),
        _ => print!(
            "{}",
            format::render_report(&findings, !args.no_color, args.show_safe)
        ),
    }

    let any_exposed = findings.iter().any(|f| {
        matches!(
            f.severity,
            audit::Severity::ExposedAllowed
                | audit::Severity::ExposedRestricted
                | audit::Severity::ExposedDocker
        )
    });
    if args.fail_on_exposed && any_exposed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
