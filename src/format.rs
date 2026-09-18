use crate::audit::{Finding, Severity};

fn color(severity: Severity) -> String {
    match severity {
        Severity::Safe => cybercore::palette::acid_green(),
        Severity::Blocked => cybercore::palette::cyan(),
        Severity::ExposedRestricted => cybercore::palette::hot_pink(),
        Severity::ExposedAllowed => cybercore::palette::orange(),
        Severity::ExposedDocker => cybercore::palette::red(),
    }
}

fn reset() -> &'static str {
    cybercore::palette::RESET
}

pub fn render_report(findings: &[Finding], color_on: bool, show_safe: bool) -> String {
    let mut out = String::new();
    let mut counts = [0usize; 5];

    for f in findings {
        let idx = match f.severity {
            Severity::Safe => 0,
            Severity::Blocked => 1,
            Severity::ExposedRestricted => 2,
            Severity::ExposedAllowed => 3,
            Severity::ExposedDocker => 4,
        };
        counts[idx] += 1;

        if f.severity == Severity::Safe && !show_safe {
            continue;
        }

        let (c, r) = if color_on {
            (color(f.severity), reset().to_string())
        } else {
            (String::new(), String::new())
        };
        let process = f.socket.process.as_deref().unwrap_or("?");
        let container_note = f
            .docker_container
            .as_ref()
            .map(|c| format!(" (container: {c})"))
            .unwrap_or_default();
        let scope_suffix = f
            .scope_note
            .as_ref()
            .map(|n| format!(" [{n}]"))
            .unwrap_or_default();
        let addr_note = match &f.socket.addr {
            crate::ss::BindAddr::Wildcard => "0.0.0.0/[::]".to_string(),
            crate::ss::BindAddr::Loopback => "127.0.0.1".to_string(),
            crate::ss::BindAddr::Specific(ip) => ip.to_string(),
        };

        out.push_str(&format!(
            "{c}[{:<28}]{r} {}/{:<4} {:<14} process={}{}{}\n",
            f.severity.label(),
            f.socket.port,
            f.socket.proto,
            addr_note,
            process,
            container_note,
            scope_suffix
        ));
    }

    out.push_str(&format!(
        "\n{} sockets total — {} safe, {} blocked by ufw, {} exposed (ufw-scoped), {} exposed (ufw-allowed), {} exposed (docker bypasses ufw)\n",
        findings.len(),
        counts[0],
        counts[1],
        counts[2],
        counts[3],
        counts[4]
    ));
    out
}

pub fn render_json(findings: &[Finding], pretty: bool) -> String {
    let records: Vec<_> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "port": f.socket.port,
                "proto": f.socket.proto,
                "bind": match &f.socket.addr {
                    crate::ss::BindAddr::Wildcard => "wildcard".to_string(),
                    crate::ss::BindAddr::Loopback => "loopback".to_string(),
                    crate::ss::BindAddr::Specific(ip) => ip.to_string(),
                },
                "process": f.socket.process,
                "pid": f.socket.pid,
                "severity": f.severity.label(),
                "docker_container": f.docker_container,
                "scope_note": f.scope_note,
            })
        })
        .collect();

    if pretty {
        serde_json::to_string_pretty(&records).unwrap_or_default()
    } else {
        serde_json::to_string(&records).unwrap_or_default()
    }
}
