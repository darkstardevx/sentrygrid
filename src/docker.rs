//! Parses `docker ps` port publications. The one thing this tells
//! SentryGrid that `ss`/`ufw` alone can't: whether a wide-bound port is
//! Docker-managed, which matters because Docker inserts its own `iptables`
//! rules ahead of `ufw`'s — a wide-bound Docker port is reachable
//! regardless of what `ufw` says, a lesson learned the hard way earlier
//! this session (the `vault`/`haproxy`/`sencho` exposure).

use regex::Regex;
use std::process::Command;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct DockerPort {
    pub container: String,
    pub host_bind: String,
    pub host_port: u16,
    pub proto: String,
}

fn mapping_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // e.g. "0.0.0.0:8200->8200/tcp" or "127.0.0.1:5433->5432/tcp" or "[::]:8404->8404/tcp"
    RE.get_or_init(|| Regex::new(r"(?:(\[[0-9a-fA-F:]+\]|[0-9.]+)):(\d+)->\d+/(tcp|udp)").expect("hardcoded regex"))
}

pub fn parse_ports_field(container: &str, ports_field: &str) -> Vec<DockerPort> {
    let mut out = Vec::new();
    for entry in ports_field.split(',') {
        let entry = entry.trim();
        if let Some(caps) = mapping_re().captures(entry) {
            out.push(DockerPort {
                container: container.to_string(),
                host_bind: caps[1].trim_matches(['[', ']']).to_string(),
                host_port: caps[2].parse().unwrap_or(0),
                proto: caps[3].to_string(),
            });
        }
        // Entries with no "->" (e.g. "443/tcp") are container-internal only
        // — not published to the host, so `ss` will never see them either.
        // Deliberately not surfaced as a finding.
    }
    out
}

/// Empty on any error (docker not installed, daemon not running, or the
/// user isn't in the `docker` group) — Docker context is an enrichment,
/// not a hard requirement for the rest of the audit to run.
pub fn list_published_ports() -> Vec<DockerPort> {
    let Ok(output) = Command::new("docker").args(["ps", "--format", "{{.Names}}\t{{.Ports}}"]).output() else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.splitn(2, '\t');
        let (Some(name), Some(ports)) = (parts.next(), parts.next()) else { continue };
        out.extend(parse_ports_field(name, ports));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_v4_and_v6_mapping() {
        let ports = parse_ports_field("vault", "0.0.0.0:8200->8200/tcp, [::]:8200->8200/tcp");
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].host_bind, "0.0.0.0");
        assert_eq!(ports[0].host_port, 8200);
        assert_eq!(ports[1].host_bind, "::");
    }

    #[test]
    fn parses_multiple_distinct_ports() {
        let ports = parse_ports_field("haproxy", "0.0.0.0:8081->8081/tcp, [::]:8081->8081/tcp, 0.0.0.0:8404->8404/tcp, [::]:8404->8404/tcp");
        let host_ports: Vec<u16> = ports.iter().map(|p| p.host_port).collect();
        assert!(host_ports.contains(&8081));
        assert!(host_ports.contains(&8404));
    }

    #[test]
    fn ignores_unpublished_internal_ports() {
        // real deploy-caddy-1 line: internal-only entries mixed with one real publish
        let ports = parse_ports_field("deploy-caddy-1", "443/tcp, 2019/tcp, 443/udp, 127.0.0.1:8880->80/tcp");
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].host_bind, "127.0.0.1");
        assert_eq!(ports[0].host_port, 8880);
    }

    #[test]
    fn loopback_bound_container_port_parses_correctly() {
        let ports = parse_ports_field("dev_postgres", "127.0.0.1:5433->5432/tcp");
        assert_eq!(ports[0].host_bind, "127.0.0.1");
        assert_eq!(ports[0].host_port, 5433);
    }
}
