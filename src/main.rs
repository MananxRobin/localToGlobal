mod config;
mod detect;
mod share;

use config::{generate_default_routes, load_config, merge_detected_services, save_config, Config, Protection};
use detect::{detect_services, print_services};
use share::{effective_protection, launch_share, list_active_shares, resolve_target, run_share_worker, summarize_access, ShareOptions};
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {}", err);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if let Some(command) = args.first() {
        if command == "__serve-share" {
            return run_share_worker(&args[1..]);
        }
    }

    let project_root = env::current_dir().map_err(|err| format!("failed to resolve current dir: {}", err))?;
    let command = args.first().map(|value| value.as_str()).unwrap_or("help");
    match command {
        "run" => cmd_run(&project_root),
        "share" => cmd_share(&project_root, &args[1..]),
        "routes" => cmd_routes(&project_root, &args[1..]),
        "protect" => cmd_protect(&project_root, &args[1..]),
        "status" => cmd_status(&project_root),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        unknown => Err(format!("unknown command '{}'. Run `ltg help` for usage.", unknown)),
    }
}

fn cmd_run(project_root: &PathBuf) -> Result<(), String> {
    let detected = detect_services(project_root)?;
    print_services(&detected);

    let mut config = load_or_default_config(project_root)?;
    let detected_config = detected.iter().map(|service| service.to_config()).collect::<Vec<_>>();
    merge_detected_services(&mut config, &detected_config);
    if config.routes.is_empty() {
        generate_default_routes(&mut config);
    }
    save_config(project_root, &config)?;

    if let Some(best) = detected.first() {
        println!();
        println!(
            "Recommended share target: {} (port {}, role {}, framework {})",
            best.name, best.port, best.role, best.framework
        );
        if best.risky {
            println!(
                "Warning: {}",
                best.risk_reason
                    .clone()
                    .unwrap_or_else(|| "this service looks risky to expose".to_string())
            );
        }
    } else {
        println!();
        println!("No shareable HTTP services detected. Start your local app, then re-run `ltg run`.");
    }
    println!(
        "Project config synced to {}",
        config::config_path(project_root).display()
    );
    Ok(())
}

fn cmd_share(project_root: &PathBuf, args: &[String]) -> Result<(), String> {
    let detected = detect_services(project_root)?;
    let mut config = load_or_default_config(project_root)?;
    let detected_config = detected.iter().map(|service| service.to_config()).collect::<Vec<_>>();
    merge_detected_services(&mut config, &detected_config);
    if config.routes.is_empty() {
        generate_default_routes(&mut config);
    }
    save_config(project_root, &config)?;

    let options = parse_share_options(args)?;
    let selector = if let Some(selector) = options.selector.as_deref() {
        Some(selector.to_string())
    } else if detected.len() > 1 {
        Some(prompt_for_service(&detected)?)
    } else if let Some(service) = detected.first() {
        Some(service.name.clone())
    } else {
        None
    };

    let target = resolve_target(selector.as_deref(), &config, &detected)?;
    if target.routes.is_empty() {
        return Err("the selected share target has no active routes".to_string());
    }
    if config.protection.warn_on_sensitive_ports && target.risky {
        println!(
            "Warning: {}",
            target
                .risk_reason
                .clone()
                .unwrap_or_else(|| "this target looks risky to expose".to_string())
        );
        if !confirm("Continue sharing this target? [y/N]: ")? {
            return Err("share cancelled".to_string());
        }
    }

    let protection = effective_protection(&config, &options);
    let active = launch_share(project_root, &target, &protection)?;
    println!("Share ready: {}", active.launch_url());
    println!("Target: {} ({})", active.target_label, active.target_description);
    println!("Access mode: {}", active.access_mode);
    if let Some(token) = &active.share_token {
        println!("Share token: {}", token);
        println!("Raw URL: {}", active.public_url);
        println!("Tip: send header `X-LTG-Token: {}` if you cannot use query params.", token);
    }
    if let Some(expires_at) = active.expires_at {
        println!("Expires at: {}", expires_at);
    }
    println!("Share id: {}", active.id);
    if !options.detach {
        println!("Tunnel is running in the foreground. Keep this command open; press Ctrl+C to stop.");
        loop {
            if active
                .expires_at
                .map(|expires_at| unix_timestamp() >= expires_at)
                .unwrap_or(false)
            {
                println!("Share expired.");
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
    }
    Ok(())
}

fn cmd_routes(project_root: &PathBuf, args: &[String]) -> Result<(), String> {
    let detected = detect_services(project_root)?;
    let mut config = load_or_default_config(project_root)?;
    let detected_config = detected.iter().map(|service| service.to_config()).collect::<Vec<_>>();
    merge_detected_services(&mut config, &detected_config);
    let action = args.first().map(|value| value.as_str()).unwrap_or("show");
    match action {
        "init" => {
            generate_default_routes(&mut config);
            save_config(project_root, &config)?;
            println!("Route profiles written to {}", config::config_path(project_root).display());
        }
        "show" => {
            if config.routes.is_empty() {
                println!("No route profiles configured. Run `ltg routes init` to scaffold a default profile.");
            } else {
                println!("Route profiles:");
                for route in &config.routes {
                    println!(
                        "  profile={} path={} service={}",
                        route.profile, route.path, route.service
                    );
                }
            }
        }
        other => return Err(format!("unsupported routes action '{}'. Use `show` or `init`.", other)),
    }
    Ok(())
}

fn cmd_protect(project_root: &PathBuf, args: &[String]) -> Result<(), String> {
    let mut config = load_or_default_config(project_root)?;
    let mut protection = config.protection.clone();
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--expires-in" => {
                protection.expires_in = required_arg(args, index + 1, "--expires-in")?.to_string();
                index += 2;
            }
            "--access-mode" => {
                protection.access_mode = required_arg(args, index + 1, "--access-mode")?.to_string();
                index += 2;
            }
            "--share-token" => {
                protection.share_token = required_arg(args, index + 1, "--share-token")?.to_string();
                index += 2;
            }
            "--warn-sensitive" => {
                protection.warn_on_sensitive_ports = true;
                index += 1;
            }
            "--no-warn-sensitive" => {
                protection.warn_on_sensitive_ports = false;
                index += 1;
            }
            flag => return Err(format!("unsupported protect flag '{}'", flag)),
        }
    }
    config.protection = protection.clone();
    save_config(project_root, &config)?;
    println!("Updated protection defaults:");
    print_protection(&protection);
    Ok(())
}

fn cmd_status(project_root: &PathBuf) -> Result<(), String> {
    let shares = list_active_shares(project_root)?;
    if shares.is_empty() {
        println!("No share state found for this project.");
        return Ok(());
    }

    println!(
        "{:<18} {:<14} {:<10} {:<8} {:<8} {}",
        "share_id", "target", "status", "access", "hits", "launch_url"
    );
    for share in shares {
        let (hits, visitors) = summarize_access(project_root, &share.id)?;
        println!(
            "{:<18} {:<14} {:<10} {:<8} {:<8} {}",
            share.id, share.target_label, share.status, share.access_mode, hits, share.launch_url()
        );
        if let Some(expires_at) = share.expires_at {
            println!("  expires_at={}", expires_at);
        }
        if share.access_mode == "token" {
            println!("  raw_url={}", share.public_url);
        }
        if !visitors.is_empty() {
            println!("  visitors={}", visitors.join(", "));
        }
        println!("  proxy_port={} pid={} cloudflared_pid={:?}", share.proxy_port, share.pid, share.cloudflared_pid);
    }
    Ok(())
}

fn load_or_default_config(project_root: &PathBuf) -> Result<Config, String> {
    let project_name = project_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("localtoglobal")
        .to_string();
    Ok(load_config(project_root)?.unwrap_or_else(|| Config::default_for_project(project_name)))
}

fn parse_share_options(args: &[String]) -> Result<ShareOptions, String> {
    let mut selector = None;
    let mut expires_in = None;
    let mut access_mode = None;
    let mut share_token = None;
    let mut public = false;
    let mut detach = false;
    let mut index = 0usize;
    while index < args.len() {
        match args[index].as_str() {
            "--expires-in" => {
                expires_in = Some(required_arg(args, index + 1, "--expires-in")?.to_string());
                index += 2;
            }
            "--access-mode" => {
                access_mode = Some(required_arg(args, index + 1, "--access-mode")?.to_string());
                index += 2;
            }
            "--share-token" => {
                share_token = Some(required_arg(args, index + 1, "--share-token")?.to_string());
                index += 2;
            }
            "--public" => {
                public = true;
                index += 1;
            }
            "--detach" => {
                detach = true;
                index += 1;
            }
            value if value.starts_with("--") => return Err(format!("unsupported share flag '{}'", value)),
            value => {
                if selector.is_none() {
                    selector = Some(value.to_string());
                    index += 1;
                } else {
                    return Err(format!("unexpected extra argument '{}'", value));
                }
            }
        }
    }
    Ok(ShareOptions {
        selector,
        expires_in,
        access_mode,
        share_token,
        public,
        detach,
    })
}

fn prompt_for_service(services: &[detect::DetectedService]) -> Result<String, String> {
    println!("Multiple services detected. Pick one to share:");
    print_services(services);
    print!("Selection [1-{}]: ", services.len());
    io::stdout()
        .flush()
        .map_err(|err| format!("failed to flush prompt: {}", err))?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|err| format!("failed to read selection: {}", err))?;
    let selection = input
        .trim()
        .parse::<usize>()
        .map_err(|err| format!("invalid selection: {}", err))?;
    let service = services
        .get(selection.saturating_sub(1))
        .ok_or_else(|| "selection out of range".to_string())?;
    Ok(service.name.clone())
}

fn confirm(prompt: &str) -> Result<bool, String> {
    print!("{}", prompt);
    io::stdout()
        .flush()
        .map_err(|err| format!("failed to flush prompt: {}", err))?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|err| format!("failed to read confirmation: {}", err))?;
    Ok(matches!(input.trim().to_lowercase().as_str(), "y" | "yes"))
}

fn required_arg<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, String> {
    args.get(index)
        .map(|value| value.as_str())
        .ok_or_else(|| format!("missing value for {}", flag))
}

fn print_protection(protection: &Protection) {
    println!("  expires_in={}", protection.expires_in);
    println!("  access_mode={}", protection.access_mode);
    println!("  share_token={}", protection.share_token);
    println!(
        "  warn_on_sensitive_ports={}",
        protection.warn_on_sensitive_ports
    );
}

fn print_help() {
    println!("LocalToGlobal (ltg)");
    println!();
    println!("Commands:");
    println!("  run                 Detect local services, recommend what to share, and sync config");
    println!("  share [target]      Share a detected service, port, or route profile");
    println!("  routes [show|init]  Inspect or scaffold route profiles");
    println!("  protect [flags]     Update protection defaults in .localtoglobal.yml");
    println!("  status              Show active shares, health, and access summary");
    println!();
    println!("Share flags:");
    println!("  --expires-in <1h|30m|120>");
    println!("  --access-mode <token|public>");
    println!("  --share-token <value>");
    println!("  --public");
    println!("  --detach");
    println!();
    println!("Protect flags:");
    println!("  --expires-in <value>");
    println!("  --access-mode <token|public>");
    println!("  --share-token <value>");
    println!("  --warn-sensitive | --no-warn-sensitive");
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}
