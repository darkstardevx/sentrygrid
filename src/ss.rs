//! Parses `ss -tlnp` / `ss -ulnp` output. Reuses `ss` itself for socket
//! enumeration (the kernel-correct way to do it) rather than re-deriving
//! it from `/proc/net/tcp` — the same "don't reinvent the capture, focus
//! on the analysis" choice AetherScope made with libpcap.

use regex::Regex;
use std::net::IpAddr;
use std::process::Command;
use std::sync::OnceLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindAddr {
    /// 0.0.0.0 or [::] or the `*` shorthand — every interface.
    Wildcard,
    /// 127.0.0.0/8 or ::1 — this host only.
    Loopback,
    /// A specific interface address (a LAN IP, a docker bridge IP, etc).
    Specific(IpAddr),
}

#[derive(Debug, Clone)]
pub struct Socket {
    pub proto: &'static str, // "tcp" | "udp"
    pub addr: BindAddr,
    pub port: u16,
    pub process: Option<String>,
    pub pid: Option<u32>,
}

fn process_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"users:\(\("([^"]+)",pid=(\d+)"#).expect("hardcoded regex"))
}

/// Splits `addr:port`, correctly handling bracketed IPv6 (`[::]:8404`) vs
/// plain IPv4/wildcard (`127.0.0.1:45636`, `*:80`) — a naive split on the
/// first or last `:` alone breaks on one of the two forms.
fn split_addr_port(s: &str) -> Option<(&str, &str)> {
    if let Some(rest) = s.strip_prefix('[') {
        let close = rest.find(']')?;
        let addr = &rest[..close];
        let port = rest[close + 1..].strip_prefix(':')?;
        Some((addr, port))
    } else {
        let idx = s.rfind(':')?;
        Some((&s[..idx], &s[idx + 1..]))
    }
}

fn classify(addr: &str) -> BindAddr {
    match addr {
        "*" | "0.0.0.0" | "::" => BindAddr::Wildcard,
        _ => match addr.parse::<IpAddr>() {
            Ok(IpAddr::V4(v4)) if v4.octets()[0] == 127 => BindAddr::Loopback,
            Ok(IpAddr::V6(v6)) if v6.is_loopback() => BindAddr::Loopback,
            Ok(ip) => BindAddr::Specific(ip),
            Err(_) => BindAddr::Wildcard, // unrecognized shorthand — treat as worth flagging, not silently ignoring
        },
    }
}

fn parse_lines(text: &str, proto: &'static str) -> Vec<Socket> {
    let mut out = Vec::new();
    for line in text.lines() {
        if !line.trim_start().starts_with("LISTEN") {
            continue; // header row, or (for udp) UNCONN — ss labels UDP listeners UNCONN
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        // State Recv-Q Send-Q Local:Port Peer:Port [Process...]
        let Some(local) = fields.get(3) else { continue };
        let Some((addr, port_str)) = split_addr_port(local) else { continue };
        let Ok(port) = port_str.parse::<u16>() else { continue };

        let (process, pid) = process_re()
            .captures(line)
            .map(|c| (Some(c[1].to_string()), c[2].parse().ok()))
            .unwrap_or((None, None));

        out.push(Socket { proto, addr: classify(addr), port, process, pid });
    }
    out
}

fn parse_udp_lines(text: &str) -> Vec<Socket> {
    // `ss -ulnp` labels UDP listeners UNCONN, not LISTEN.
    let mut out = Vec::new();
    for line in text.lines() {
        if !line.trim_start().starts_with("UNCONN") {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(local) = fields.get(3) else { continue };
        let Some((addr, port_str)) = split_addr_port(local) else { continue };
        let Ok(port) = port_str.parse::<u16>() else { continue };
        let (process, pid) = process_re()
            .captures(line)
            .map(|c| (Some(c[1].to_string()), c[2].parse().ok()))
            .unwrap_or((None, None));
        out.push(Socket { proto: "udp", addr: classify(addr), port, process, pid });
    }
    out
}

pub fn list_sockets() -> std::io::Result<Vec<Socket>> {
    let tcp_out = Command::new("ss").args(["-tlnp"]).output()?;
    let udp_out = Command::new("ss").args(["-ulnp"]).output()?;

    let mut sockets = parse_lines(&String::from_utf8_lossy(&tcp_out.stdout), "tcp");
    sockets.extend(parse_udp_lines(&String::from_utf8_lossy(&udp_out.stdout)));
    Ok(sockets)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real `ss -tlnp` output captured this session (redacted of nothing —
    // this is verbatim).
    const REAL_TCP_SAMPLE: &str = "State      Recv-Q Send-Q   Local Address:Port      Peer Address:Port  Process
LISTEN     0      128        127.0.0.1:45636      0.0.0.0:*    users:((\"wraithflow\",pid=405129,fd=12))
LISTEN     0      128          0.0.0.0:22         0.0.0.0:*
LISTEN     0      128                *:80               *:*    users:((\"caddy\",pid=860,fd=9))
LISTEN     0      4096      127.0.0.54:53         0.0.0.0:*
LISTEN     0      4096            [::]:8404          [::]:*    users:((\"docker-proxy\",pid=2612,fd=7))
LISTEN     0      128             [::]:22            [::]:*
";

    #[test]
    fn parses_loopback_bound_socket() {
        let sockets = parse_lines(REAL_TCP_SAMPLE, "tcp");
        let s = sockets.iter().find(|s| s.port == 45636).expect("port 45636 present");
        assert_eq!(s.addr, BindAddr::Loopback);
        assert_eq!(s.process.as_deref(), Some("wraithflow"));
        assert_eq!(s.pid, Some(405129));
    }

    #[test]
    fn parses_explicit_v4_wildcard() {
        let sockets = parse_lines(REAL_TCP_SAMPLE, "tcp");
        let s = sockets.iter().find(|s| s.port == 22 && s.addr == BindAddr::Wildcard);
        assert!(s.is_some(), "0.0.0.0:22 should classify as Wildcard");
    }

    #[test]
    fn parses_star_shorthand_wildcard() {
        let sockets = parse_lines(REAL_TCP_SAMPLE, "tcp");
        let s = sockets.iter().find(|s| s.port == 80).expect("port 80 present");
        assert_eq!(s.addr, BindAddr::Wildcard);
        assert_eq!(s.process.as_deref(), Some("caddy"));
    }

    #[test]
    fn classifies_127_range_not_just_exact_localhost() {
        let sockets = parse_lines(REAL_TCP_SAMPLE, "tcp");
        let s = sockets.iter().find(|s| s.port == 53).expect("port 53 present");
        assert_eq!(s.addr, BindAddr::Loopback, "127.0.0.54 is loopback range, not just 127.0.0.1");
    }

    #[test]
    fn parses_bracketed_ipv6_wildcard_with_process() {
        let sockets = parse_lines(REAL_TCP_SAMPLE, "tcp");
        let s = sockets.iter().find(|s| s.port == 8404).expect("port 8404 present");
        assert_eq!(s.addr, BindAddr::Wildcard);
        assert_eq!(s.process.as_deref(), Some("docker-proxy"));
    }

    #[test]
    fn ignores_header_row() {
        let sockets = parse_lines(REAL_TCP_SAMPLE, "tcp");
        // 6 LISTEN lines in the sample -> exactly 6 parsed, header not counted
        assert_eq!(sockets.len(), 6);
    }
}
