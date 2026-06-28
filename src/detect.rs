use crate::config::ServiceConfig;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct DetectedService {
    pub name: String,
    pub port: u16,
    pub role: String,
    pub framework: String,
    pub healthcheck_path: String,
    pub process_name: String,
    pub risky: bool,
    pub risk_reason: Option<String>,
    pub http_ready: bool,
    pub score: i32,
}

impl DetectedService {
    pub fn to_config(&self) -> ServiceConfig {
        ServiceConfig {
            name: self.name.clone(),
            port: self.port,
            role: self.role.clone(),
            framework: self.framework.clone(),
            healthcheck_path: self.healthcheck_path.clone(),
        }
    }
}

pub fn detect_services(project_root: &Path) -> Result<Vec<DetectedService>, String> {
    let output = Command::new("lsof")
        .args(["-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn"])
        .output()
        .map_err(|err| format!("failed to run lsof: {}", err))?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    let user = env::var("USER").unwrap_or_default().to_lowercase();
    let fingerprints = project_fingerprints(project_root);
    let mut services = Vec::new();
    let mut current_pid = String::new();
    let mut current_command = String::new();
    let mut seen_ports = HashSet::new();

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if line.is_empty() {
            continue;
        }
        match line.chars().next().unwrap_or_default() {
            'p' => current_pid = line[1..].to_string(),
            'c' => current_command = line[1..].to_string(),
            'n' => {
                if let Some(port) = parse_port(&line[1..]) {
                    if !seen_ports.insert(port) {
                        continue;
                    }
                    if should_skip_command(&current_command) {
                        continue;
                    }
                    let http_ready = probe_http(port);
                    let mut service = classify_service(
                        port,
                        &current_command,
                        &current_pid,
                        http_ready,
                        &fingerprints,
                    );
                    if !should_include_service(&service) {
                        continue;
                    }
                    if current_command.to_lowercase().contains(&user) {
                        service.score += 2;
                    }
                    services.push(service);
                }
            }
            _ => {}
        }
    }

    services.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then(left.risky.cmp(&right.risky))
            .then(left.port.cmp(&right.port))
    });
    Ok(services)
}

fn should_skip_command(command: &str) -> bool {
    matches!(
        command.to_lowercase().as_str(),
        "rapportd" | "controlcenter" | "sharingd" | "microsoft edge helper"
    )
}

fn should_include_service(service: &DetectedService) -> bool {
    service.http_ready && !service.risky
}

fn classify_service(
    port: u16,
    command: &str,
    pid: &str,
    http_ready: bool,
    fingerprints: &ProjectFingerprints,
) -> DetectedService {
    let command_lower = command.to_lowercase();
    let mut framework = "unknown".to_string();
    let mut role = "unknown".to_string();
    let mut score = 50;
    let mut risk_reason = None;

    if matches!(port, 5432 | 6379 | 27017 | 3306 | 9200 | 5672 | 9092) {
        risk_reason = Some("sensitive data or infrastructure port".to_string());
        score -= 40;
    }

    if !http_ready {
        risk_reason.get_or_insert_with(|| "service does not look like HTTP".to_string());
        score -= 25;
    }

    if command_lower.contains("story") || port == 6006 {
        framework = "storybook".to_string();
        role = "docs".to_string();
        score += 40;
    } else if command_lower.contains("next") || (port == 3000 && fingerprints.package_json) {
        framework = "nextjs".to_string();
        role = "frontend".to_string();
        score += 45;
    } else if command_lower.contains("vite") || port == 5173 || port == 4173 {
        framework = "vite".to_string();
        role = "frontend".to_string();
        score += 45;
    } else if command_lower.contains("nuxt") {
        framework = "nuxt".to_string();
        role = "frontend".to_string();
        score += 45;
    } else if command_lower.contains("uvicorn")
        || command_lower.contains("gunicorn")
        || command_lower.contains("flask")
    {
        framework = "python-web".to_string();
        role = "api".to_string();
        score += 35;
    } else if command_lower.contains("rails") || command_lower.contains("puma") {
        framework = "rails".to_string();
        role = "api".to_string();
        score += 30;
    } else if command_lower.contains("node") && http_ready && matches!(port, 3000 | 3001 | 5173) {
        framework = if fingerprints.package_json {
            "node-web".to_string()
        } else {
            "node".to_string()
        };
        role = "frontend".to_string();
        score += 30;
    } else if http_ready && matches!(port, 8000 | 8080 | 8787 | 9000) {
        framework = "http".to_string();
        role = "api".to_string();
        score += 20;
    } else if http_ready {
        framework = "http".to_string();
        role = "app".to_string();
        score += 10;
    }

    if command_lower.contains("postgres")
        || command_lower.contains("redis")
        || command_lower.contains("mysql")
        || command_lower.contains("mongo")
    {
        risk_reason = Some("database process".to_string());
        score -= 45;
    }

    let risky = risk_reason.is_some();
    let name = suggest_name(&role, &framework, port, pid);
    DetectedService {
        name,
        port,
        role,
        framework,
        healthcheck_path: "/".to_string(),
        process_name: command.to_string(),
        risky,
        risk_reason,
        http_ready,
        score,
    }
}

fn suggest_name(role: &str, framework: &str, port: u16, pid: &str) -> String {
    match role {
        "frontend" => "frontend".to_string(),
        "api" => "api".to_string(),
        "docs" => "docs".to_string(),
        "webhook" => "webhook".to_string(),
        "app" => format!("app-{}", port),
        _ => {
            if framework == "unknown" {
                format!("service-{}-{}", port, pid)
            } else {
                format!("{}-{}", framework, port)
            }
        }
    }
}

fn parse_port(binding: &str) -> Option<u16> {
    if binding.contains("->") {
        return None;
    }
    let candidate = binding
        .rsplit(':')
        .next()?
        .trim_matches(']')
        .trim_matches('[');
    candidate.parse::<u16>().ok()
}

fn probe_http(port: u16) -> bool {
    let mut stream = match connect_loopback(port) {
        Some(stream) => stream,
        None => return false,
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(600)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(600)));
    let request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let _ = stream.shutdown(Shutdown::Write);
    let mut buffer = [0u8; 16];
    match stream.read(&mut buffer) {
        Ok(size) if size > 0 => String::from_utf8_lossy(&buffer[..size]).starts_with("HTTP/"),
        _ => false,
    }
}

fn connect_loopback(port: u16) -> Option<TcpStream> {
    TcpStream::connect(("127.0.0.1", port))
        .or_else(|_| TcpStream::connect(("::1", port)))
        .ok()
}

struct ProjectFingerprints {
    package_json: bool,
}

fn project_fingerprints(project_root: &Path) -> ProjectFingerprints {
    ProjectFingerprints {
        package_json: fs::metadata(project_root.join("package.json")).is_ok(),
    }
}

pub fn print_services(services: &[DetectedService]) {
    if services.is_empty() {
        println!("No listening localhost services detected.");
        return;
    }

    println!(
        "{:<4} {:<12} {:<6} {:<10} {:<12} {:<7} {}",
        "#", "name", "port", "role", "framework", "score", "notes"
    );
    for (index, service) in services.iter().enumerate() {
        let note = match (&service.risk_reason, service.http_ready) {
            (Some(reason), _) => format!("warning: {}", reason),
            (None, false) => "warning: not http".to_string(),
            _ => format!("process: {}", service.process_name),
        };
        println!(
            "{:<4} {:<12} {:<6} {:<10} {:<12} {:<7} {}",
            index + 1,
            service.name,
            service.port,
            service.role,
            service.framework,
            service.score,
            note
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ports_from_lsof_bindings() {
        assert_eq!(parse_port("*:5173"), Some(5173));
        assert_eq!(parse_port("127.0.0.1:3000"), Some(3000));
        assert_eq!(parse_port("[::1]:8000"), Some(8000));
        assert_eq!(parse_port("127.0.0.1:3000->127.0.0.1:1234"), None);
    }
}
