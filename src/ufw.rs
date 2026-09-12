//! Parses `ufw status verbose` — just enough to answer "is this port
//! actually reachable from anywhere, or only from somewhere restricted".
//!
//! Doesn't model the full `ufw`/`iptables` rule grammar (rule ordering,
//! deny-overrides-allow precedence, interface-scoped rules) — just enough
//! structure (port, proto, an optional destination-address restriction on
//! the `To` side, and the `From` source) to distinguish a truly open rule
//! from a scoped one, which turned out to matter: an early version of this
//! parser treated ANY matching port/proto rule as "fully open," which
//! produced a false positive for `172.17.0.1 53/udp ALLOW IN 172.16.0.0/12`
//! (Docker's own DNS rule, scoped to Docker's subnet hitting the Docker
//! bridge IP specifically) — that rule doesn't mean port 53/udp is open to
//! the world, but the first version reported it as if it did.

use regex::Regex;
use std::process::Command;
use std::sync::OnceLock;

fn rule_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Captures an optional leading destination address, then port/proto,
    // e.g. "172.17.0.1 53/udp" or just "22/tcp".
    RE.get_or_init(|| Regex::new(r"^(?:([0-9a-fA-F:.]+)\s+)?(\d+)/(tcp|udp)").expect("hardcoded regex"))
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub port: u16,
    pub proto: &'static str,
    /// `Some(addr)` if the "To" column restricted this rule to one local
    /// destination address; `None` means it applies regardless of which
    /// local address the connection is destined for.
    pub dest: Option<String>,
    /// The raw "From" text: "Anywhere", "Anywhere (v6)", or a CIDR/IP.
    pub source: String,
}

impl Rule {
    fn is_source_anywhere(&self) -> bool {
        self.source.starts_with("Anywhere")
    }

    /// A rule is fully open only if it has no destination restriction AND
    /// its source is unrestricted. Anything else — a scoped destination,
    /// a scoped source, or both — only allows a narrower path in, not
    /// "reachable from anywhere."
    pub fn is_fully_open(&self) -> bool {
        self.dest.is_none() && self.is_source_anywhere()
    }
}

#[derive(Debug, Default)]
pub struct UfwState {
    pub active: bool,
    rules: Vec<Rule>,
}

impl UfwState {
    fn matching(&self, port: u16, proto: &str) -> Vec<&Rule> {
        let proto: &str = if proto == "udp" { "udp" } else { "tcp" };
        self.rules.iter().filter(|r| r.port == port && r.proto == proto).collect()
    }

    /// True only if some rule for this port/proto is unrestricted on both
    /// destination and source — genuinely reachable from anywhere.
    pub fn allows(&self, port: u16, proto: &str) -> bool {
        self.matching(port, proto).iter().any(|r| r.is_fully_open())
    }

    /// Rules that mention this port/proto but are scoped (a specific
    /// destination address and/or a restricted source) rather than fully
    /// open — worth surfacing as "reachable, but only from here."
    pub fn restricted(&self, port: u16, proto: &str) -> Vec<&Rule> {
        self.matching(port, proto).into_iter().filter(|r| !r.is_fully_open()).collect()
    }
}

pub fn parse(text: &str) -> UfwState {
    let mut state = UfwState::default();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Status:") {
            state.active = rest.trim() == "active";
            continue;
        }
        if !trimmed.contains("ALLOW") || trimmed.contains("OUT") {
            continue; // only inbound allow rules matter for "can something reach in"
        }

        let Some(caps) = rule_re().captures(trimmed) else { continue };
        let Ok(port) = caps[2].parse::<u16>() else { continue };
        let proto: &'static str = if &caps[3] == "udp" { "udp" } else { "tcp" };
        let dest = caps.get(1).map(|m| m.as_str().to_string());

        // The "From" column is whatever comes after "ALLOW IN" (or "ALLOW
        // OUT", already filtered above) up to an optional trailing "#
        // comment". Take the whole remainder and trim rather than
        // over-fitting a fragile column-width assumption.
        let source = trimmed
            .split("ALLOW IN")
            .nth(1)
            .map(|s| s.split('#').next().unwrap_or(s).trim().to_string())
            .unwrap_or_default();

        state.rules.push(Rule { port, proto, dest, source });
    }
    state
}

pub fn status_verbose() -> std::io::Result<UfwState> {
    let output = Command::new("ufw").arg("status").arg("verbose").output()?;
    Ok(parse(&String::from_utf8_lossy(&output.stdout)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real `ufw status verbose` output from this session, verbatim.
    const REAL_SAMPLE: &str = "Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), deny (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
53317/udp                  ALLOW IN    Anywhere
53317/tcp                  ALLOW IN    Anywhere
172.17.0.1 53/udp          ALLOW IN    172.16.0.0/12              # allow-docker-dns
172.17.0.1 53/udp          ALLOW IN    192.168.0.0/16             # allow-docker-dns
22/tcp                     ALLOW IN    Anywhere                   # ssh - key-only auth enforced
53317/udp (v6)              ALLOW IN    Anywhere (v6)
53317/tcp (v6)              ALLOW IN    Anywhere (v6)
22/tcp (v6)                ALLOW IN    Anywhere (v6)              # ssh - key-only auth enforced
";

    #[test]
    fn detects_active_status() {
        assert!(parse(REAL_SAMPLE).active);
    }

    #[test]
    fn detects_inactive_status() {
        assert!(!parse("Status: inactive\n").active);
    }

    #[test]
    fn ssh_port_is_fully_open() {
        let state = parse(REAL_SAMPLE);
        assert!(state.allows(22, "tcp"));
    }

    #[test]
    fn docker_dns_rule_is_restricted_not_fully_open() {
        // The regression case: this rule matches port 53/udp, but it's
        // scoped to a specific destination + specific sources — it must
        // NOT be reported as "port 53/udp is open to anywhere."
        let state = parse(REAL_SAMPLE);
        assert!(!state.allows(53, "udp"), "docker-dns rule is scoped, must not count as fully open");
        let restricted = state.restricted(53, "udp");
        assert_eq!(restricted.len(), 2, "both the /12 and /16 docker-dns rules should show up as restricted matches");
        assert!(restricted.iter().all(|r| r.dest.as_deref() == Some("172.17.0.1")));
    }

    #[test]
    fn unlisted_port_is_not_allowed() {
        let state = parse(REAL_SAMPLE);
        assert!(!state.allows(9999, "tcp"));
        assert!(state.restricted(9999, "tcp").is_empty());
    }
}
