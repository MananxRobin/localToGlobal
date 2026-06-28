use crate::config::{Config, Protection, RouteConfig, ServiceConfig};
use crate::detect::DetectedService;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct ShareOptions {
    pub selector: Option<String>,
    pub expires_in: Option<String>,
    pub access_mode: Option<String>,
    pub share_token: Option<String>,
    pub public: bool,
    pub detach: bool,
}

#[derive(Debug, Clone)]
pub struct ActiveShare {
    pub id: String,
    pub target_label: String,
    pub target_description: String,
    pub public_url: String,
    pub access_mode: String,
    pub share_token: Option<String>,
    pub started_at: u64,
    pub expires_at: Option<u64>,
    pub pid: u32,
    pub cloudflared_pid: Option<u32>,
    pub status: String,
    pub proxy_port: u16,
}

impl ActiveShare {
    pub fn launch_url(&self) -> String {
        if self.access_mode == "token" {
            if let Some(token) = &self.share_token {
                let separator = if self.public_url.contains('?') { '&' } else { '?' };
                return format!("{}{}ltg_token={}", self.public_url, separator, token);
            }
        }
        self.public_url.clone()
    }
}

#[derive(Debug, Clone)]
pub struct ShareTarget {
    pub label: String,
    pub description: String,
    pub routes: Vec<ShareRoute>,
    pub risky: bool,
    pub risk_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ShareRoute {
    pub path: String,
    pub upstream_port: u16,
}

pub fn state_dir(project_root: &Path) -> PathBuf {
    project_root.join(".localtoglobal").join("state")
}

pub fn logs_dir(project_root: &Path) -> PathBuf {
    project_root.join(".localtoglobal").join("logs")
}

pub fn ensure_runtime_dirs(project_root: &Path) -> Result<(), String> {
    fs::create_dir_all(state_dir(project_root))
        .map_err(|err| format!("failed to create state dir: {}", err))?;
    fs::create_dir_all(logs_dir(project_root))
        .map_err(|err| format!("failed to create log dir: {}", err))?;
    Ok(())
}

pub fn resolve_target(
    selector: Option<&str>,
    config: &Config,
    detected: &[DetectedService],
) -> Result<ShareTarget, String> {
    let selector = selector
        .map(|value| value.to_string())
        .or_else(|| {
            if config.default_share.target != "auto" {
                Some(config.default_share.target.clone())
            } else {
                None
            }
        });

    if let Some(selector) = selector {
        if let Ok(port) = selector.parse::<u16>() {
            return Ok(single_service_target_from_port(port, config, detected));
        }

        if let Some(service) = config.service_by_name(&selector) {
            return Ok(single_service_target(service, detected));
        }

        let routes = config.route_profile(&selector);
        if !routes.is_empty() {
            return build_profile_target(&selector, routes, config, detected);
        }

        return Err(format!(
            "could not find a service, port, or route profile named '{}'",
            selector
        ));
    }

    detected
        .first()
        .map(|service| ShareTarget {
            label: service.name.clone(),
            description: format!("{} on port {}", service.role, service.port),
            routes: vec![ShareRoute {
                path: "/".to_string(),
                upstream_port: service.port,
            }],
            risky: service.risky,
            risk_reason: service.risk_reason.clone(),
        })
        .ok_or_else(|| "no listening services available to share".to_string())
}

fn single_service_target_from_port(
    port: u16,
    config: &Config,
    detected: &[DetectedService],
) -> ShareTarget {
    if let Some(service) = config.services.iter().find(|service| service.port == port) {
        return single_service_target(service, detected);
    }
    let service = ServiceConfig {
        name: format!("service-{}", port),
        port,
        role: "app".to_string(),
        framework: "unknown".to_string(),
        healthcheck_path: "/".to_string(),
    };
    single_service_target(&service, detected)
}

fn single_service_target(service: &ServiceConfig, detected: &[DetectedService]) -> ShareTarget {
    let detected_match = detected.iter().find(|candidate| candidate.port == service.port);
    ShareTarget {
        label: service.name.clone(),
        description: format!("{} on port {}", service.role, service.port),
        routes: vec![ShareRoute {
            path: "/".to_string(),
            upstream_port: service.port,
        }],
        risky: detected_match.map(|service| service.risky).unwrap_or(false),
        risk_reason: detected_match.and_then(|service| service.risk_reason.clone()),
    }
}

fn build_profile_target(
    profile: &str,
    routes: Vec<&RouteConfig>,
    config: &Config,
    detected: &[DetectedService],
) -> Result<ShareTarget, String> {
    let mut share_routes = Vec::new();
    let mut risky = false;
    let mut risk_reasons = Vec::new();
    for route in routes {
        let service = config
            .service_by_name(&route.service)
            .ok_or_else(|| format!("route '{}' references missing service '{}'", route.path, route.service))?;
        if let Some(detected_service) = detected.iter().find(|candidate| candidate.port == service.port) {
            if detected_service.risky {
                risky = true;
                if let Some(reason) = &detected_service.risk_reason {
                    risk_reasons.push(format!("{} -> {}", route.path, reason));
                }
            }
        }
        share_routes.push(ShareRoute {
            path: route.path.clone(),
            upstream_port: service.port,
        });
    }
    share_routes.sort_by(|left, right| right.path.len().cmp(&left.path.len()));
    Ok(ShareTarget {
        label: profile.to_string(),
        description: format!("route profile with {} mappings", share_routes.len()),
        routes: share_routes,
        risky,
        risk_reason: if risk_reasons.is_empty() {
            None
        } else {
            Some(risk_reasons.join(", "))
        },
    })
}

pub fn effective_protection(config: &Config, options: &ShareOptions) -> Protection {
    let mut protection = config.protection.clone();
    if let Some(expires_in) = &options.expires_in {
        protection.expires_in = expires_in.clone();
    }
    if let Some(access_mode) = &options.access_mode {
        protection.access_mode = access_mode.clone();
    }
    if let Some(share_token) = &options.share_token {
        protection.share_token = share_token.clone();
    }
    if options.public {
        protection.access_mode = "public".to_string();
        protection.share_token = "".to_string();
    }
    if protection.share_token == "auto" && protection.access_mode == "token" {
        protection.share_token = generate_token();
    }
    protection
}

pub fn launch_share(
    project_root: &Path,
    target: &ShareTarget,
    protection: &Protection,
) -> Result<ActiveShare, String> {
    ensure_runtime_dirs(project_root)?;
    let share_id = format!("share-{}", unix_timestamp());
    let exe = std::env::current_exe().map_err(|err| format!("failed to resolve current binary: {}", err))?;
    let expires_at = if protection.expires_in.is_empty() {
        None
    } else {
        Some(unix_timestamp() + parse_duration_seconds(&protection.expires_in)?)
    };
    let routes_spec = target
        .routes
        .iter()
        .map(|route| format!("{}={}", route.path, route.upstream_port))
        .collect::<Vec<_>>()
        .join(",");

    let mut command = Command::new(exe);
    command
        .arg("__serve-share")
        .arg("--project-root")
        .arg(project_root.display().to_string())
        .arg("--share-id")
        .arg(&share_id)
        .arg("--label")
        .arg(&target.label)
        .arg("--description")
        .arg(&target.description)
        .arg("--routes")
        .arg(routes_spec)
        .arg("--access-mode")
        .arg(&protection.access_mode);

    if let Some(expires_at) = expires_at {
        command.arg("--expires-at").arg(expires_at.to_string());
    }
    if protection.access_mode == "token" && !protection.share_token.is_empty() {
        command.arg("--share-token").arg(&protection.share_token);
    }

    command.stdin(Stdio::null());
    let runner_log_path = logs_dir(project_root).join(format!("{}.runner.log", share_id));
    let share_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&runner_log_path)
        .map_err(|err| format!("failed to create share log: {}", err))?;
    let share_log_clone = share_log
        .try_clone()
        .map_err(|err| format!("failed to clone share log handle: {}", err))?;
    command.stdout(Stdio::from(share_log));
    command.stderr(Stdio::from(share_log_clone));
    let child = command.spawn().map_err(|err| format!("failed to launch share worker: {}", err))?;

    wait_for_state(project_root, &share_id, child.id(), &runner_log_path)
}

pub fn wait_for_state(
    project_root: &Path,
    share_id: &str,
    pid: u32,
    runner_log_path: &Path,
) -> Result<ActiveShare, String> {
    let state_path = state_dir(project_root).join(format!("{}.state", share_id));
    for _ in 0..60 {
        if let Ok(active) = load_active_share_from_path(&state_path) {
            if !active.public_url.is_empty() {
                return Ok(active);
            }
        }
        if let Ok(log_contents) = fs::read_to_string(runner_log_path) {
            if log_contents.contains("error:") {
                return Err(log_contents.lines().last().unwrap_or("share worker failed").to_string());
            }
        }
        thread::sleep(Duration::from_millis(500));
    }
    Err(format!(
        "share worker {} started but did not publish a URL in time. Check logs in {}",
        pid,
        logs_dir(project_root).display()
    ))
}

pub fn list_active_shares(project_root: &Path) -> Result<Vec<ActiveShare>, String> {
    ensure_runtime_dirs(project_root)?;
    let mut shares = Vec::new();
    for entry in fs::read_dir(state_dir(project_root)).map_err(|err| format!("failed to read state dir: {}", err))? {
        let entry = entry.map_err(|err| format!("failed to read state entry: {}", err))?;
        if entry.path().extension().and_then(|extension| extension.to_str()) != Some("state") {
            continue;
        }
        if let Ok(mut share) = load_active_share_from_path(&entry.path()) {
            refresh_share_status(&mut share);
            shares.push(share);
        }
    }
    shares.sort_by(|left, right| right.started_at.cmp(&left.started_at));
    Ok(shares)
}

fn refresh_share_status(share: &mut ActiveShare) {
    if share
        .expires_at
        .map(|expires_at| unix_timestamp() >= expires_at)
        .unwrap_or(false)
    {
        share.status = "expired".to_string();
        return;
    }
    if let Some(alive) = process_alive(share.pid) {
        if !alive {
            share.status = "stopped".to_string();
            return;
        }
    }
    if let Some(cloudflared_pid) = share.cloudflared_pid {
        if let Some(alive) = process_alive(cloudflared_pid) {
            if !alive {
                share.status = "cloudflared-stopped".to_string();
            }
        }
    }
}

pub fn run_share_worker(args: &[String]) -> Result<(), String> {
    let parsed = InternalArgs::parse(args)?;
    ensure_runtime_dirs(&parsed.project_root)?;
    let proxy_port = bind_free_port()?;
    let state_path = state_dir(&parsed.project_root).join(format!("{}.state", parsed.share_id));
    let access_log_path = logs_dir(&parsed.project_root).join(format!("{}.access.log", parsed.share_id));
    let route_map = parse_routes(&parsed.routes)?;
    let request_count = Arc::new(Mutex::new(0u64));
    let shutdown = Arc::new(AtomicBool::new(false));
    let proxy_shutdown = shutdown.clone();
    let proxy_token = parsed.share_token.clone();
    let proxy_access_mode = parsed.access_mode.clone();
    let expires_at = parsed.expires_at;
    let access_log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&access_log_path)
        .map_err(|err| format!("failed to open access log: {}", err))?;
    let access_log = Arc::new(Mutex::new(access_log));
    let request_count_for_thread = request_count.clone();
    let access_log_for_thread = access_log.clone();
    let route_map_for_thread = route_map.clone();

    thread::spawn(move || {
        if let Err(err) = run_proxy(
            proxy_port,
            route_map_for_thread,
            proxy_access_mode,
            proxy_token,
            expires_at,
            proxy_shutdown,
            request_count_for_thread,
            access_log_for_thread,
        ) {
            eprintln!("proxy exited with error: {}", err);
        }
    });

    let cloudflared_log_path = logs_dir(&parsed.project_root).join(format!("{}.cloudflared.log", parsed.share_id));
    let (mut cloudflared, public_url) = start_cloudflared(proxy_port, &cloudflared_log_path)?;
    let cloudflared_pid = cloudflared.id();

    let mut active = ActiveShare {
        id: parsed.share_id.clone(),
        target_label: parsed.label.clone(),
        target_description: parsed.description.clone(),
        public_url,
        access_mode: parsed.access_mode.clone(),
        share_token: parsed.share_token.clone(),
        started_at: unix_timestamp(),
        expires_at,
        pid: std::process::id(),
        cloudflared_pid: Some(cloudflared_pid),
        status: "active".to_string(),
        proxy_port,
    };
    save_active_share(&state_path, &active)?;

    loop {
        if let Some(expires_at) = expires_at {
            if unix_timestamp() >= expires_at {
                active.status = "expired".to_string();
                shutdown.store(true, Ordering::Relaxed);
                let _ = cloudflared.kill();
                break;
            }
        }
        if let Some(status) = cloudflared.try_wait().map_err(|err| format!("failed to check cloudflared: {}", err))? {
            active.status = format!("stopped({})", status);
            shutdown.store(true, Ordering::Relaxed);
            break;
        }
        save_active_share(&state_path, &active)?;
        thread::sleep(Duration::from_secs(2));
    }

    save_active_share(&state_path, &active)?;
    Ok(())
}

fn run_proxy(
    proxy_port: u16,
    routes: Vec<ShareRoute>,
    access_mode: String,
    share_token: Option<String>,
    expires_at: Option<u64>,
    shutdown: Arc<AtomicBool>,
    request_count: Arc<Mutex<u64>>,
    access_log: Arc<Mutex<File>>,
) -> Result<(), String> {
    let listener = TcpListener::bind(("127.0.0.1", proxy_port))
        .map_err(|err| format!("failed to bind proxy port {}: {}", proxy_port, err))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("failed to mark proxy listener nonblocking: {}", err))?;
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer_addr)) => {
                let routes = routes.clone();
                let share_token = share_token.clone();
                let access_mode = access_mode.clone();
                let shutdown = shutdown.clone();
                let request_count = request_count.clone();
                let access_log = access_log.clone();
                thread::spawn(move || {
                    let result = handle_client(
                        stream,
                        routes,
                        &access_mode,
                        share_token.as_deref(),
                        expires_at,
                    );
                    let (status_code, path, method, user_agent) = match result {
                        Ok(summary) => summary,
                        Err((stream, status_code, path, method, message, user_agent)) => {
                            let _ = write_error_response(stream, status_code, &message);
                            (status_code, path, method, user_agent)
                        }
                    };
                    if let Ok(mut count) = request_count.lock() {
                        *count += 1;
                    }
                    if let Ok(mut log_file) = access_log.lock() {
                        let _ = writeln!(
                            log_file,
                            "{}\t{}\t{}\t{}\t{}\t{}",
                            unix_timestamp(),
                            peer_addr.ip(),
                            method,
                            path,
                            status_code,
                            user_agent.unwrap_or_else(|| "-".to_string())
                        );
                    }
                    shutdown.load(Ordering::Relaxed);
                });
            }
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) => return Err(format!("proxy accept failed: {}", err)),
        }
    }
    Ok(())
}

fn handle_client(
    mut client: TcpStream,
    routes: Vec<ShareRoute>,
    access_mode: &str,
    share_token: Option<&str>,
    expires_at: Option<u64>,
) -> Result<(u16, String, String, Option<String>), (TcpStream, u16, String, String, String, Option<String>)> {
    let mut buffer = Vec::new();
    let mut temp = [0u8; 2048];
    let mut header_end = None;
    loop {
        match client.read(&mut temp) {
            Ok(0) => break,
            Ok(size) => {
                buffer.extend_from_slice(&temp[..size]);
                if let Some(position) = find_header_end(&buffer) {
                    header_end = Some(position);
                    break;
                }
            }
            Err(err) => {
                return Err((
                    client,
                    400,
                    "/".to_string(),
                    "GET".to_string(),
                    format!("failed to read request: {}", err),
                    None,
                ))
            }
        }
    }

    let header_end = match header_end {
        Some(position) => position,
        None => {
            return Err((
                client,
                400,
                "/".to_string(),
                "GET".to_string(),
                "malformed request".to_string(),
                None,
            ))
        }
    };

    let head = &buffer[..header_end];
    let mut body = buffer[header_end..].to_vec();
    let header_text = String::from_utf8_lossy(head);
    let mut lines = header_text.split("\r\n").filter(|line| !line.is_empty());
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let uri = parts.next().unwrap_or("/").to_string();
    let _version = parts.next().unwrap_or("HTTP/1.1").to_string();

    if let Some(expires_at) = expires_at {
        if unix_timestamp() >= expires_at {
            return Err((
                client,
                410,
                uri,
                method,
                "this share has expired".to_string(),
                None,
            ));
        }
    }

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    let mut user_agent = None;
    let mut header_token = None;
    let mut cookie_token = None;
    let mut referer_token = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let lower = name.trim().to_lowercase();
            let value = value.trim().to_string();
            if lower == "content-length" {
                content_length = value.parse::<usize>().unwrap_or(0);
            } else if lower == "user-agent" {
                user_agent = Some(value.clone());
            } else if lower == "x-ltg-token" {
                header_token = Some(value.clone());
                continue;
            } else if lower == "cookie" {
                cookie_token = cookie_value(&value, "ltg_auth");
            } else if lower == "referer" {
                referer_token = token_from_referer(&value);
            }
            headers.push((name.trim().to_string(), value));
        }
    }

    while body.len() < content_length {
        match client.read(&mut temp) {
            Ok(0) => break,
            Ok(size) => body.extend_from_slice(&temp[..size]),
            Err(err) => {
                return Err((
                    client,
                    400,
                    uri,
                    method,
                    format!("failed to read request body: {}", err),
                    user_agent,
                ))
            }
        }
    }

    let (path_only, query) = split_uri(&uri);
    let upstream = match select_route(path_only, &routes) {
        Some(route) => route,
        None => {
            return Err((
                client,
                404,
                uri,
                method,
                "no route matched this request".to_string(),
                user_agent,
            ))
        }
    };
    let (query_without_token, query_token) = strip_token_from_query(query);

    let mut should_set_auth_cookie = false;
    if access_mode == "token" {
        let expected = share_token.unwrap_or_default();
        let provided = header_token
            .clone()
            .or(query_token.clone())
            .or(cookie_token.clone())
            .or(referer_token.clone());
        if provided.as_deref() != Some(expected) {
            return Err((
                client,
                401,
                uri,
                method,
                "missing or invalid share token. Pass ?ltg_token=... or X-LTG-Token.".to_string(),
                user_agent,
            ));
        }
        should_set_auth_cookie = query_token.as_deref() == Some(expected)
            || header_token.as_deref() == Some(expected)
            || referer_token.as_deref() == Some(expected);
    }

    let upstream_uri = if query_without_token.is_empty() {
        path_only.to_string()
    } else {
        format!("{}?{}", path_only, query_without_token)
    };
    let mut forward_request = format!("{} {} {}\r\n", method, upstream_uri, _version);
    let mut saw_host = false;
    let mut saw_connection = false;
    for (name, value) in headers {
        let lower = name.to_lowercase();
        if lower == "host" {
            saw_host = true;
            forward_request.push_str(&format!("Host: localhost:{}\r\n", upstream.upstream_port));
        } else if lower == "connection" {
            saw_connection = true;
            forward_request.push_str("Connection: close\r\n");
        } else {
            forward_request.push_str(&format!("{}: {}\r\n", name, value));
        }
    }
    if !saw_host {
        forward_request.push_str(&format!("Host: localhost:{}\r\n", upstream.upstream_port));
    }
    if !saw_connection {
        forward_request.push_str("Connection: close\r\n");
    }
    forward_request.push_str("\r\n");

    let mut upstream_stream = match connect_loopback(upstream.upstream_port) {
        Ok(stream) => stream,
        Err(err) => {
            return Err((
                client,
                502,
                uri,
                method,
                format!("failed to connect to upstream {}: {}", upstream.upstream_port, err),
                user_agent,
            ))
        }
    };

    let _ = upstream_stream.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = upstream_stream.set_write_timeout(Some(Duration::from_secs(30)));
    if upstream_stream.write_all(forward_request.as_bytes()).is_err()
        || upstream_stream.write_all(&body).is_err()
    {
        return Err((
            client,
            502,
            uri,
            method,
            "failed to forward request to upstream".to_string(),
            user_agent,
        ));
    }
    let mut pending_header = Vec::new();
    let mut sent_response_head = false;
    let mut response_buffer = [0u8; 8192];
    loop {
        let size = match upstream_stream.read(&mut response_buffer) {
            Ok(0) => break,
            Ok(size) => size,
            Err(_) => {
                return Err((
                    client,
                    502,
                    uri,
                    method,
                    "failed to read upstream response".to_string(),
                    user_agent,
                ))
            }
        };
        if !sent_response_head {
            pending_header.extend_from_slice(&response_buffer[..size]);
            if let Some(response_header_end) = find_header_end(&pending_header) {
                let header_bytes = &pending_header[..response_header_end];
                let body_bytes = &pending_header[response_header_end..];
                let (status_code, content_length, chunked) = parse_response_metadata(header_bytes);
                let response_head = if should_set_auth_cookie {
                    inject_auth_cookie(header_bytes, share_token.unwrap_or_default())
                } else {
                    header_bytes.to_vec()
                };
                if client.write_all(&response_head).is_err() {
                    return Err((
                        client,
                        502,
                        uri,
                        method,
                        "failed to stream upstream response".to_string(),
                        user_agent,
                    ));
                }
                if chunked {
                    if relay_chunked_body(&mut client, &mut upstream_stream, body_bytes.to_vec()).is_err() {
                        return Err((
                            client,
                            502,
                            uri,
                            method,
                            "failed to stream chunked upstream response".to_string(),
                            user_agent,
                        ));
                    }
                    return Ok((status_code, path_only.to_string(), method, user_agent));
                }
                if let Some(content_length) = content_length {
                    if relay_sized_body(&mut client, &mut upstream_stream, body_bytes.to_vec(), content_length)
                        .is_err()
                    {
                        return Err((
                            client,
                            502,
                            uri,
                            method,
                            "failed to stream upstream response body".to_string(),
                            user_agent,
                        ));
                    }
                    return Ok((status_code, path_only.to_string(), method, user_agent));
                }
                if client.write_all(body_bytes).is_err() {
                    return Err((
                        client,
                        502,
                        uri,
                        method,
                        "failed to stream upstream response".to_string(),
                        user_agent,
                    ));
                }
                sent_response_head = true;
            }
        } else if client.write_all(&response_buffer[..size]).is_err() {
            return Err((
                client,
                502,
                uri,
                method,
                "failed to stream upstream response".to_string(),
                user_agent,
            ));
        }
    }

    if !sent_response_head {
        if client.write_all(&pending_header).is_err() {
            return Err((
                client,
                502,
                uri,
                method,
                "failed to stream upstream response".to_string(),
                user_agent,
            ));
        }
    }

    let status_code = parse_status_code(&pending_header).unwrap_or(200);
    Ok((status_code, path_only.to_string(), method, user_agent))
}

fn write_error_response(mut stream: TcpStream, status_code: u16, message: &str) -> io::Result<()> {
    let body = format!("{}\n", message);
    let response = format!(
        "HTTP/1.1 {} ERROR\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status_code,
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())
}

fn start_cloudflared(proxy_port: u16, log_path: &Path) -> Result<(Child, String), String> {
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|err| format!("failed to open cloudflared log: {}", err))?;
    let log_file_clone = log_file
        .try_clone()
        .map_err(|err| format!("failed to clone cloudflared log: {}", err))?;
    let mut child = Command::new("cloudflared")
        .args([
            "tunnel",
            "--no-autoupdate",
            "--url",
            &format!("http://127.0.0.1:{}", proxy_port),
        ])
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_clone))
        .spawn()
        .map_err(|err| format!("failed to start cloudflared: {}", err))?;

    for _ in 0..60 {
        if let Ok(contents) = fs::read_to_string(log_path) {
            if let Some(url) = extract_public_url(&contents) {
                return Ok((child, url));
            }
        }
        if let Some(status) = child.try_wait().map_err(|err| format!("failed to poll cloudflared: {}", err))? {
            return Err(format!(
                "cloudflared exited before creating a tunnel: {}. Check {}",
                status,
                log_path.display()
            ));
        }
        thread::sleep(Duration::from_millis(500));
    }

    Err(format!(
        "timed out waiting for cloudflared to publish a URL. Check {}",
        log_path.display()
    ))
}

fn extract_public_url(log: &str) -> Option<String> {
    for token in log.split_whitespace() {
        let trimmed = token.trim_matches(|ch: char| matches!(ch, '"' | '\'' | ',' | ')'));
        if trimmed.starts_with("https://") && trimmed.contains("trycloudflare.com") {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn parse_routes(spec: &str) -> Result<Vec<ShareRoute>, String> {
    let mut routes = Vec::new();
    for route in spec.split(',') {
        if route.trim().is_empty() {
            continue;
        }
        let (path, port) = route
            .split_once('=')
            .ok_or_else(|| format!("invalid route '{}'", route))?;
        routes.push(ShareRoute {
            path: path.to_string(),
            upstream_port: port
                .parse::<u16>()
                .map_err(|err| format!("invalid route port '{}': {}", port, err))?,
        });
    }
    routes.sort_by(|left, right| right.path.len().cmp(&left.path.len()));
    Ok(routes)
}

fn select_route<'a>(path: &str, routes: &'a [ShareRoute]) -> Option<&'a ShareRoute> {
    let mut best: Option<&ShareRoute> = None;
    for route in routes {
        let matches = if route.path == "/" {
            true
        } else {
            path == route.path || path.starts_with(&format!("{}/", route.path.trim_end_matches('/')))
        };
        if !matches {
            continue;
        }
        let should_replace = match best {
            Some(existing) => route.path.len() > existing.path.len(),
            None => true,
        };
        if should_replace {
            best = Some(route);
        }
    }
    best
}

fn split_uri(uri: &str) -> (&str, &str) {
    uri.split_once('?').unwrap_or((uri, ""))
}

fn cookie_value(header: &str, name: &str) -> Option<String> {
    for cookie in header.split(';') {
        let cookie = cookie.trim();
        let (cookie_name, cookie_value) = cookie.split_once('=')?;
        if cookie_name.trim() == name {
            return Some(cookie_value.trim().to_string());
        }
    }
    None
}

fn strip_token_from_query(query: &str) -> (String, Option<String>) {
    let mut kept = Vec::new();
    let mut token = None;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if name == "ltg_token" {
            token = Some(value.to_string());
        } else {
            kept.push(pair.to_string());
        }
    }
    (kept.join("&"), token)
}

fn token_from_referer(referer: &str) -> Option<String> {
    let query = referer.split_once('?')?.1.split('#').next().unwrap_or("");
    strip_token_from_query(query).1
}

fn parse_status_code(response: &[u8]) -> Option<u16> {
    let text = String::from_utf8_lossy(response);
    let mut parts = text.lines().next()?.split_whitespace();
    let _ = parts.next()?;
    parts.next()?.parse::<u16>().ok()
}

fn parse_response_metadata(response_head: &[u8]) -> (u16, Option<usize>, bool) {
    let text = String::from_utf8_lossy(response_head);
    let mut status_code = 200u16;
    let mut content_length = None;
    let mut chunked = false;

    for (index, line) in text.split("\r\n").enumerate() {
        if index == 0 {
            let mut parts = line.split_whitespace();
            let _ = parts.next();
            status_code = parts
                .next()
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(200);
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let lower = name.trim().to_lowercase();
            let value = value.trim();
            if lower == "content-length" {
                content_length = value.parse::<usize>().ok();
            } else if lower == "transfer-encoding" && value.to_lowercase().contains("chunked") {
                chunked = true;
            }
        }
    }

    (status_code, content_length, chunked)
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

fn relay_sized_body(
    client: &mut TcpStream,
    upstream_stream: &mut TcpStream,
    mut initial_body: Vec<u8>,
    content_length: usize,
) -> io::Result<()> {
    if initial_body.len() > content_length {
        initial_body.truncate(content_length);
    }
    client.write_all(&initial_body)?;
    let mut remaining = content_length.saturating_sub(initial_body.len());
    let mut buffer = [0u8; 8192];
    while remaining > 0 {
        let size = upstream_stream.read(&mut buffer)?;
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "upstream closed before content-length bytes were read",
            ));
        }
        let to_write = size.min(remaining);
        client.write_all(&buffer[..to_write])?;
        remaining -= to_write;
    }
    Ok(())
}

fn relay_chunked_body(
    client: &mut TcpStream,
    upstream_stream: &mut TcpStream,
    mut buffer: Vec<u8>,
) -> io::Result<()> {
    let mut offset = 0usize;
    loop {
        while find_crlf(&buffer[offset..]).is_none() {
            read_more(upstream_stream, &mut buffer)?;
        }
        let line_end = offset + find_crlf(&buffer[offset..]).unwrap();
        let size_line = &buffer[offset..line_end];
        let chunk_size = parse_chunk_size(size_line)?;
        let chunk_header_end = line_end + 2;
        let total_needed = if chunk_size == 0 {
            chunk_header_end + 2
        } else {
            chunk_header_end + chunk_size + 2
        };
        while buffer.len() < total_needed {
            read_more(upstream_stream, &mut buffer)?;
        }
        client.write_all(&buffer[offset..total_needed])?;
        offset = total_needed;
        if chunk_size == 0 {
            return Ok(());
        }
        if offset == buffer.len() {
            buffer.clear();
            offset = 0;
        }
    }
}

fn read_more(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> io::Result<()> {
    let mut chunk = [0u8; 8192];
    let size = stream.read(&mut chunk)?;
    if size == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "upstream closed while proxy was reading response",
        ));
    }
    buffer.extend_from_slice(&chunk[..size]);
    Ok(())
}

fn find_crlf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|window| window == b"\r\n")
}

fn parse_chunk_size(size_line: &[u8]) -> io::Result<usize> {
    let text = String::from_utf8_lossy(size_line);
    let hex = text.split(';').next().unwrap_or("").trim();
    usize::from_str_radix(hex, 16).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn inject_auth_cookie(response_head: &[u8], token: &str) -> Vec<u8> {
    let mut text = String::from_utf8_lossy(response_head).to_string();
    if let Some(position) = text.rfind("\r\n\r\n") {
        let cookie = format!(
            "\r\nSet-Cookie: ltg_auth={}; Path=/; HttpOnly; SameSite=Lax",
            token
        );
        text.insert_str(position, &cookie);
        text.into_bytes()
    } else {
        response_head.to_vec()
    }
}

fn bind_free_port() -> Result<u16, String> {
    for port in 43120..43220 {
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    let listener =
        TcpListener::bind(("127.0.0.1", 0)).map_err(|err| format!("failed to reserve port: {}", err))?;
    let port = listener
        .local_addr()
        .map_err(|err| format!("failed to inspect reserved port: {}", err))?
        .port();
    drop(listener);
    Ok(port)
}

fn connect_loopback(port: u16) -> io::Result<TcpStream> {
    TcpStream::connect(("127.0.0.1", port))
        .or_else(|_| TcpStream::connect(("::1", port)))
}

fn generate_token() -> String {
    format!("ltg-{:x}", unix_timestamp() ^ (std::process::id() as u64))
}

fn parse_duration_seconds(value: &str) -> Result<u64, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("expires_in cannot be empty".to_string());
    }
    if let Some(hours) = trimmed.strip_suffix('h') {
        return Ok(hours
            .parse::<u64>()
            .map_err(|err| format!("invalid hour duration '{}': {}", value, err))?
            * 3600);
    }
    if let Some(minutes) = trimmed.strip_suffix('m') {
        return Ok(minutes
            .parse::<u64>()
            .map_err(|err| format!("invalid minute duration '{}': {}", value, err))?
            * 60);
    }
    if let Some(seconds) = trimmed.strip_suffix('s') {
        return seconds
            .parse::<u64>()
            .map_err(|err| format!("invalid second duration '{}': {}", value, err));
    }
    trimmed
        .parse::<u64>()
        .map_err(|err| format!("invalid duration '{}': {}", value, err))
}

fn save_active_share(path: &Path, share: &ActiveShare) -> Result<(), String> {
    let mut data = String::new();
    data.push_str(&format!("id={}\n", share.id));
    data.push_str(&format!("target_label={}\n", escape_state(&share.target_label)));
    data.push_str(&format!(
        "target_description={}\n",
        escape_state(&share.target_description)
    ));
    data.push_str(&format!("public_url={}\n", share.public_url));
    data.push_str(&format!("access_mode={}\n", share.access_mode));
    data.push_str(&format!(
        "share_token={}\n",
        share.share_token.as_deref().unwrap_or("")
    ));
    data.push_str(&format!("started_at={}\n", share.started_at));
    data.push_str(&format!(
        "expires_at={}\n",
        share.expires_at.map(|value| value.to_string()).unwrap_or_default()
    ));
    data.push_str(&format!("pid={}\n", share.pid));
    data.push_str(&format!(
        "cloudflared_pid={}\n",
        share.cloudflared_pid
            .map(|value| value.to_string())
            .unwrap_or_default()
    ));
    data.push_str(&format!("status={}\n", escape_state(&share.status)));
    data.push_str(&format!("proxy_port={}\n", share.proxy_port));
    fs::write(path, data).map_err(|err| format!("failed to persist share state: {}", err))
}

fn load_active_share_from_path(path: &Path) -> Result<ActiveShare, String> {
    let contents = fs::read_to_string(path)
        .map_err(|err| format!("failed to read share state {}: {}", path.display(), err))?;
    let mut map = HashMap::new();
    for line in contents.lines() {
        if let Some((key, value)) = line.split_once('=') {
            map.insert(key.to_string(), unescape_state(value));
        }
    }
    Ok(ActiveShare {
        id: required(&map, "id")?,
        target_label: required(&map, "target_label")?,
        target_description: required(&map, "target_description")?,
        public_url: map.get("public_url").cloned().unwrap_or_default(),
        access_mode: map.get("access_mode").cloned().unwrap_or_else(|| "token".to_string()),
        share_token: map.get("share_token").filter(|value| !value.is_empty()).cloned(),
        started_at: map
            .get("started_at")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or_default(),
        expires_at: map
            .get("expires_at")
            .filter(|value| !value.is_empty())
            .and_then(|value| value.parse::<u64>().ok()),
        pid: map
            .get("pid")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or_default(),
        cloudflared_pid: map
            .get("cloudflared_pid")
            .filter(|value| !value.is_empty())
            .and_then(|value| value.parse::<u32>().ok()),
        status: map
            .get("status")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string()),
        proxy_port: map
            .get("proxy_port")
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or_default(),
    })
}

pub fn summarize_access(project_root: &Path, share_id: &str) -> Result<(u64, Vec<String>), String> {
    let path = logs_dir(project_root).join(format!("{}.access.log", share_id));
    if !path.exists() {
        return Ok((0, Vec::new()));
    }
    let file = File::open(&path).map_err(|err| format!("failed to read access log: {}", err))?;
    let reader = BufReader::new(file);
    let mut count = 0u64;
    let mut visitors = Vec::new();
    let mut seen = HashMap::new();
    for line in reader.lines() {
        let line = line.map_err(|err| format!("failed to read access log line: {}", err))?;
        count += 1;
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() > 1 && !seen.contains_key(parts[1]) {
            seen.insert(parts[1].to_string(), true);
            visitors.push(parts[1].to_string());
        }
    }
    Ok((count, visitors))
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

fn process_alive(pid: u32) -> Option<bool> {
    if pid == 0 {
        return None;
    }
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "pid="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(!String::from_utf8_lossy(&output.stdout).trim().is_empty())
}

fn required(map: &HashMap<String, String>, key: &str) -> Result<String, String> {
    map.get(key)
        .cloned()
        .ok_or_else(|| format!("share state missing key '{}'", key))
}

fn escape_state(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\n', "\\n")
}

fn unescape_state(value: &str) -> String {
    value.replace("\\n", "\n").replace("\\\\", "\\")
}

struct InternalArgs {
    project_root: PathBuf,
    share_id: String,
    label: String,
    description: String,
    routes: String,
    access_mode: String,
    share_token: Option<String>,
    expires_at: Option<u64>,
}

impl InternalArgs {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut map = HashMap::new();
        let mut index = 0usize;
        while index < args.len() {
            let key = &args[index];
            if !key.starts_with("--") {
                index += 1;
                continue;
            }
            let key = key.trim_start_matches("--").to_string();
            let value = args
                .get(index + 1)
                .cloned()
                .ok_or_else(|| format!("missing value for --{}", key))?;
            map.insert(key, value);
            index += 2;
        }
        Ok(Self {
            project_root: PathBuf::from(required(&map, "project-root")?),
            share_id: required(&map, "share-id")?,
            label: required(&map, "label")?,
            description: required(&map, "description")?,
            routes: required(&map, "routes")?,
            access_mode: required(&map, "access-mode")?,
            share_token: map.get("share-token").cloned(),
            expires_at: map
                .get("expires-at")
                .and_then(|value| value.parse::<u64>().ok()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_token_from_query() {
        let (query, token) = strip_token_from_query("foo=bar&ltg_token=abc&x=1");
        assert_eq!(query, "foo=bar&x=1");
        assert_eq!(token.as_deref(), Some("abc"));
    }

    #[test]
    fn chooses_longest_matching_route() {
        let routes = vec![
            ShareRoute {
                path: "/".to_string(),
                upstream_port: 3000,
            },
            ShareRoute {
                path: "/api".to_string(),
                upstream_port: 8000,
            },
        ];
        let route = select_route("/api/users", &routes).unwrap();
        assert_eq!(route.upstream_port, 8000);
    }

    #[test]
    fn extracts_quick_tunnel_url() {
        let log = "INF Requesting new quick Tunnel on trycloudflare.com https://soft-meadow.trycloudflare.com";
        assert_eq!(
            extract_public_url(log).as_deref(),
            Some("https://soft-meadow.trycloudflare.com")
        );
    }

    #[test]
    fn parses_cookie_value() {
        assert_eq!(
            cookie_value("foo=bar; ltg_auth=secret-token; theme=dark", "ltg_auth").as_deref(),
            Some("secret-token")
        );
    }

    #[test]
    fn extracts_token_from_referer_query() {
        assert_eq!(
            token_from_referer("https://example.com/app?foo=bar&ltg_token=secret&x=1").as_deref(),
            Some("secret")
        );
        assert_eq!(token_from_referer("https://example.com/app").as_deref(), None);
    }

    #[test]
    fn injects_auth_cookie_into_response_headers() {
        let original = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        let injected = String::from_utf8(inject_auth_cookie(original, "abc123")).unwrap();
        assert!(injected.contains("Set-Cookie: ltg_auth=abc123; Path=/; HttpOnly; SameSite=Lax"));
        assert!(injected.starts_with("HTTP/1.1 200 OK\r\n"));
    }
}
