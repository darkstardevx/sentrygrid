//! Correlates `ss` sockets, `ufw` rules, and `docker ps` port publications
//! into the one question none of those three tools answer alone: is this
//! port actually reachable, and if so, by what mechanism.

use crate::docker::DockerPort;
use crate::ss::{BindAddr, Socket};
use crate::ufw::UfwState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Loopback-only — not reachable from anywhere but this host.
    Safe,
    /// Bound wide, but `ufw`'s default-deny blocks it (no matching ALLOW
    /// IN rule) — currently unreachable, but worth knowing it's one `ufw`
    /// rule change away from being exposed.
    Blocked,
    /// Bound wide, `ufw` explicitly allows it from anywhere — reachable,
    /// presumably on purpose (e.g. sshd).
    ExposedAllowed,
    /// Bound wide, and `ufw` has a matching rule, but it's scoped to a
    /// specific destination address and/or a restricted source — reachable
    /// only from that scope, not "open to anywhere." Distinct from
    /// `ExposedAllowed` because conflating the two is a real false
    /// positive (Docker's own `172.17.0.1 53/udp` DNS rule is not the same
    /// thing as "port 53/udp is open to the world").
    ExposedRestricted,
    /// Bound wide AND Docker-managed — reachable regardless of what `ufw`
    /// says, since Docker's own `iptables` rules run ahead of `ufw`'s.
    /// Always worth a second look, `ufw` rules or not.
    ExposedDocker,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Safe => "SAFE",
            Severity::Blocked => "BLOCKED",
            Severity::ExposedAllowed => "EXPOSED (ufw-allowed)",
            Severity::ExposedRestricted => "EXPOSED (ufw-scoped)",
            Severity::ExposedDocker => "EXPOSED (docker bypasses ufw)",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub socket: Socket,
    pub severity: Severity,
    pub docker_container: Option<String>,
    /// Set only for `ExposedRestricted` — a human-readable description of
    /// the actual scope (e.g. "from 172.16.0.0/12, 192.168.0.0/16 -> 172.17.0.1 only").
    pub scope_note: Option<String>,
}

pub fn correlate(sockets: Vec<Socket>, ufw: &UfwState, docker_ports: &[DockerPort]) -> Vec<Finding> {
    sockets
        .into_iter()
        .map(|socket| {
            if socket.addr == BindAddr::Loopback {
                return Finding { socket, severity: Severity::Safe, docker_container: None, scope_note: None };
            }

            let docker_match = docker_ports.iter().find(|d| d.host_port == socket.port && d.proto == socket.proto);

            // Docker's own reported bind should agree with what `ss`
            // independently observed for the same port — a disagreement
            // would mean something unusual enough to be worth a human's
            // attention (e.g. two different processes racing for the
            // same port), so this cross-checks rather than just trusting
            // one source.
            if let Some(d) = docker_match {
                let ss_says_wide = socket.addr == BindAddr::Wildcard;
                let docker_says_wide = d.host_bind == "0.0.0.0" || d.host_bind == "::";
                if ss_says_wide != docker_says_wide {
                    eprintln!(
                        "sentrygrid: warning: port {} bind mismatch — ss reports {:?}, docker reports {}",
                        socket.port, socket.addr, d.host_bind
                    );
                }
            }

            let mut scope_note = None;
            let severity = if docker_match.is_some() {
                Severity::ExposedDocker
            } else if ufw.allows(socket.port, socket.proto) {
                Severity::ExposedAllowed
            } else {
                let restricted = ufw.restricted(socket.port, socket.proto);
                if restricted.is_empty() {
                    Severity::Blocked
                } else {
                    let sources: Vec<&str> = restricted.iter().map(|r| r.source.as_str()).collect();
                    let dest = restricted.iter().find_map(|r| r.dest.as_deref()).unwrap_or("this host");
                    scope_note = Some(format!("from {} -> {} only", sources.join(", "), dest));
                    Severity::ExposedRestricted
                }
            };

            Finding { socket, severity, docker_container: docker_match.map(|d| d.container.clone()), scope_note }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ss::BindAddr;

    fn socket(proto: &'static str, addr: BindAddr, port: u16, process: Option<&str>) -> Socket {
        Socket { proto, addr, port, process: process.map(String::from), pid: None }
    }

    #[test]
    fn loopback_is_always_safe_regardless_of_ufw_or_docker() {
        let sockets = vec![socket("tcp", BindAddr::Loopback, 8765, Some("cyberdesk"))];
        let ufw = UfwState::default(); // inactive, nothing allowed
        let findings = correlate(sockets, &ufw, &[]);
        assert_eq!(findings[0].severity, Severity::Safe);
    }

    #[test]
    fn wide_bound_with_no_ufw_rule_is_blocked() {
        let sockets = vec![socket("tcp", BindAddr::Wildcard, 9999, Some("something"))];
        let ufw = crate::ufw::parse("Status: active\n");
        let findings = correlate(sockets, &ufw, &[]);
        assert_eq!(findings[0].severity, Severity::Blocked);
    }

    #[test]
    fn wide_bound_with_ufw_allow_is_exposed_allowed() {
        let sockets = vec![socket("tcp", BindAddr::Wildcard, 22, Some("sshd"))];
        let ufw = crate::ufw::parse("Status: active\n22/tcp ALLOW IN Anywhere\n");
        let findings = correlate(sockets, &ufw, &[]);
        assert_eq!(findings[0].severity, Severity::ExposedAllowed);
    }

    #[test]
    fn scoped_ufw_rule_is_restricted_not_fully_exposed() {
        // The exact false positive this tool produced on its first real
        // run: systemd-resolved bound 53/udp to the wildcard address, and
        // the only matching ufw rule (Docker's own DNS rule) is scoped to
        // a specific destination + source, not "open to anywhere."
        let sockets = vec![socket("udp", BindAddr::Wildcard, 53, Some("systemd-resolve"))];
        let ufw = crate::ufw::parse(
            "Status: active\n172.17.0.1 53/udp ALLOW IN 172.16.0.0/12 # allow-docker-dns\n172.17.0.1 53/udp ALLOW IN 192.168.0.0/16 # allow-docker-dns\n",
        );
        let findings = correlate(sockets, &ufw, &[]);
        assert_eq!(findings[0].severity, Severity::ExposedRestricted);
        assert!(findings[0].scope_note.as_ref().unwrap().contains("172.17.0.1"));
    }

    #[test]
    fn docker_managed_port_is_exposed_regardless_of_ufw_state() {
        // This is *the* scenario from the actual vault/haproxy incident:
        // ufw fully inactive, and it wouldn't have mattered anyway.
        let sockets = vec![socket("tcp", BindAddr::Wildcard, 8200, None)];
        let ufw = UfwState::default(); // inactive
        let docker_ports =
            vec![DockerPort { container: "vault".to_string(), host_bind: "0.0.0.0".to_string(), host_port: 8200, proto: "tcp".to_string() }];
        let findings = correlate(sockets, &ufw, &docker_ports);
        assert_eq!(findings[0].severity, Severity::ExposedDocker);
        assert_eq!(findings[0].docker_container.as_deref(), Some("vault"));
    }

    #[test]
    fn specific_non_loopback_bind_is_treated_like_wildcard() {
        // Binding directly to a LAN interface IP is just as reachable from
        // that network as 0.0.0.0 — shouldn't be silently treated as safe.
        let lan_ip: std::net::IpAddr = "192.168.88.6".parse().unwrap();
        let sockets = vec![socket("tcp", BindAddr::Specific(lan_ip), 4444, None)];
        let ufw = UfwState::default();
        let findings = correlate(sockets, &ufw, &[]);
        assert_eq!(findings[0].severity, Severity::Blocked); // still correlated, not skipped
    }
}
