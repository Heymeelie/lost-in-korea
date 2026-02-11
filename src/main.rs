//! lost-in-korea: Spin up a spot VM in GCP Korea, run a WireGuard server,
//! connect this machine via the generated config, and tear down the VM when the CLI exits.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::Parser;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::thread;
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(windows)]
const GCLOUD_EXE: &str = "gcloud.cmd";
#[cfg(not(windows))]
const GCLOUD_EXE: &str = "gcloud";

const VM_NAME: &str = "lost-in-korea-wg";
const KOREA_ZONE: &str = "asia-northeast3-a";
const WIREGUARD_PORT: u16 = 51820;
const WG_SERVER_IP: &str = "10.66.66.1/24";
const WG_CLIENT_IP: &str = "10.66.66.2/24";

#[derive(Parser)]
#[command(name = "lost-in-korea")]
#[command(about = "Start a spot VM in GCP Korea with WireGuard; tear down on exit")]
struct Cli {
    /// GCP project ID (default: from gcloud config)
    #[arg(long, short = 'p')]
    project: Option<String>,
}

fn find_gcloud() -> Option<PathBuf> {
    if let Ok(path) = which::which(GCLOUD_EXE) {
        return Some(path);
    }
    #[cfg(windows)]
    {
        let sub = PathBuf::from("Google").join("Cloud SDK").join("google-cloud-sdk").join("bin").join(GCLOUD_EXE);
        for base in [
            std::env::var("LOCALAPPDATA").ok().map(PathBuf::from),
            std::env::var("ProgramFiles").ok().map(PathBuf::from),
            std::env::var("ProgramFiles(x86)").ok().map(PathBuf::from),
        ]
        .into_iter()
        .flatten()
        {
            let p = base.join(&sub);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

fn run_gcloud(args: &[&str]) -> Result<String, String> {
    let gcloud = find_gcloud().ok_or_else(|| {
        "gcloud not found. Install the Google Cloud SDK and add it to PATH:\n  \
         https://cloud.google.com/sdk/docs/install\n  \
         On Windows, common locations are:\n  \
         - %LOCALAPPDATA%\\Google\\Cloud SDK\\google-cloud-sdk\\bin\n  \
         - %ProgramFiles%\\Google\\Cloud SDK\\google-cloud-sdk\\bin"
            .to_string()
    })?;
    let out = Command::new(&gcloud)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run gcloud: {}", e))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        return Err(format!("gcloud failed: {}", stderr.trim().lines().next().unwrap_or(&stderr)));
    }
    Ok(stdout.trim().to_string())
}

fn get_project() -> Result<String, String> {
    let s = run_gcloud(&["config", "get-value", "project", "--format=value(core.project)"])
        .map(|s| s.trim().to_string())?;
    if s.is_empty() || s.contains('(') {
        Err(
            "No default GCP project is set.\n\n\
             Either pass it explicitly:\n  \
             lost-in-korea --project YOUR_PROJECT_ID\n\n\
             Or set the default and try again:\n  \
             gcloud config set project YOUR_PROJECT_ID\n  \
             gcloud projects list   # to see your project IDs"
                .to_string(),
        )
    } else {
        Ok(s)
    }
}

fn ensure_firewall(project: &str) -> Result<(), String> {
    let rule_name = "allow-wireguard-lost-in-korea";
    let _ = run_gcloud(&[
        "compute",
        "firewall-rules",
        "create",
        rule_name,
        "--project",
        project,
        "--allow=udp:51820",
        "--direction=INGRESS",
        "--source-ranges=0.0.0.0/0",
        "--description=WireGuard for lost-in-korea",
    ]);
    // Ignore error if rule already exists
    Ok(())
}

fn create_vm(project: &str, zone: &str) -> Result<(), String> {
    println!("Creating spot VM in {} (Korea/Seoul)...", zone);
    run_gcloud(&[
        "compute",
        "instances",
        "create",
        VM_NAME,
        "--project",
        project,
        "--zone",
        zone,
        "--machine-type=e2-micro",
        "--image-family=debian-12",
        "--image-project=debian-cloud",
        "--provisioning-model=SPOT",
        "--instance-termination-action=DELETE",
        "--metadata=enable-oslogin=TRUE",
        "--scopes=default",
    ])?;
    println!("VM created.");
    Ok(())
}

fn get_instance_external_ip(project: &str, zone: &str) -> Result<String, String> {
    run_gcloud(&[
        "compute",
        "instances",
        "describe",
        VM_NAME,
        "--project",
        project,
        "--zone",
        zone,
        "--format=get(networkInterfaces[0].accessConfigs[0].natIP)",
    ])
}

fn wait_for_ssh(project: &str, zone: &str, max_attempts: u32) -> Result<(), String> {
    println!("Waiting for SSH to be ready...");
    for i in 0..max_attempts {
        let result = run_gcloud(&[
            "compute",
            "ssh",
            VM_NAME,
            "--project",
            project,
            "--zone",
            zone,
            "--command=echo ok",
            "--strict-host-key-checking=no",
        ]);
        if result.as_deref() == Ok("ok") {
            println!("SSH ready.");
            return Ok(());
        }
        if i < max_attempts - 1 {
            thread::sleep(Duration::from_secs(5));
        }
    }
    Err("SSH did not become ready in time".to_string())
}

fn ssh_command(project: &str, zone: &str, command: &str) -> Result<String, String> {
    run_gcloud(&[
        "compute",
        "ssh",
        VM_NAME,
        "--project",
        project,
        "--zone",
        zone,
        "--command",
        command,
        "--strict-host-key-checking=no",
    ])
}

fn delete_vm(project: &str, zone: &str) -> Result<(), String> {
    println!("Deleting VM...");
    let _ = run_gcloud(&[
        "compute",
        "instances",
        "delete",
        VM_NAME,
        "--project",
        project,
        "--zone",
        zone,
        "--quiet",
    ]);
    println!("VM deleted.");
    Ok(())
}

fn generate_wireguard_keypair() -> (String, String) {
    let mut rng = rand_core::OsRng;
    let secret = StaticSecret::random_from_rng(&mut rng);
    let public = PublicKey::from(&secret);
    let priv_b64 = BASE64.encode(secret.to_bytes());
    let pub_b64 = BASE64.encode(public.to_bytes());
    (priv_b64, pub_b64)
}

fn build_client_config(client_private_key: &str, server_public_key: &str, endpoint: &str) -> String {
    format!(
        "[Interface]\n\
         PrivateKey = {}\n\
         Address = {}\n\
         DNS = 8.8.8.8\n\
         \n\
         [Peer]\n\
         PublicKey = {}\n\
         Endpoint = {}:{}\n\
         AllowedIPs = 0.0.0.0/0\n\
         PersistentKeepalive = 25\n",
        client_private_key,
        WG_CLIENT_IP,
        server_public_key,
        endpoint,
        WIREGUARD_PORT
    )
}

fn setup_wireguard_on_vm(
    project: &str,
    zone: &str,
    client_public_key: &str,
) -> Result<String, String> {
    // Install WireGuard
    ssh_command(
        project,
        zone,
        "sudo apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard",
    )?;

    // Generate server keys on VM and get server public key
    let script = format!(
        "sudo bash -c 'mkdir -p /etc/wireguard && \
         wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key && \
         chmod 600 /etc/wireguard/server_private.key && \
         cat /etc/wireguard/server_public.key'"
    );
    let server_pub = ssh_command(project, zone, &script)?
        .trim()
        .to_string();

    // Default egress interface on GCP is often ens4, not eth0; detect it for NAT
    let iface = ssh_command(project, zone, "ip -o route get 8.8.8.8 2>/dev/null | awk '{print $5}' | head -1")
        .unwrap_or_else(|_| String::new())
        .trim()
        .to_string();
    let egress = if iface.is_empty() { "ens4" } else { iface.as_str() };

    // Write server config: NAT (MASQUERADE) on the real egress interface so traffic goes through
    let write_cmd = format!(
        "sudo bash -c 'SK=$(cat /etc/wireguard/server_private.key); \
         echo -e \"[Interface]\\nAddress = {}\\nListenPort = {}\\nPrivateKey = $SK\\nPostUp = iptables -t nat -A POSTROUTING -o {} -j MASQUERADE; sysctl -w net.ipv4.ip_forward=1\\nPostDown = iptables -t nat -D POSTROUTING -o {} -j MASQUERADE\\n\\n[Peer]\\nPublicKey = {}\\nAllowedIPs = 10.66.66.2/32\" > /etc/wireguard/wg0.conf'",
        WG_SERVER_IP,
        WIREGUARD_PORT,
        egress,
        egress,
        client_public_key
    );
    ssh_command(project, zone, &write_cmd)?;

    ssh_command(project, zone, "sudo wg-quick up wg0")?;

    Ok(server_pub)
}

/// On Windows, copy the config into WireGuard's Data\Configurations so it shows up in the app.
#[cfg(windows)]
fn install_wireguard_config_windows(config_content: &str, fallback_path: &str) {
    let program_files = match std::env::var("ProgramFiles") {
        Ok(p) => PathBuf::from(p),
        Err(_) => return,
    };
    let wg_config_dir = program_files.join("WireGuard").join("Data").join("Configurations");
    if !wg_config_dir.is_dir() {
        println!("WireGuard config directory not found: {}", wg_config_dir.display());
        println!(
            "\nWireGuard config saved to {}. Import it in WireGuard: File → Import tunnel(s) from file.",
            fallback_path
        );
        return;
    }
    let wg_config_path = wg_config_dir.join("lost-in-korea.conf");
    match std::fs::write(&wg_config_path, config_content) {
        Ok(()) => {
            println!(
                "\nConfig added to WireGuard. Open the WireGuard app and activate \"lost-in-korea\"."
            );
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                println!(
                    "\nConfig saved to {}. To add it to WireGuard automatically, run this program as Administrator.",
                    fallback_path
                );
                println!("Or import manually: WireGuard → File → Import tunnel(s) from file → choose {}.", fallback_path);
            } else {
                println!("\nConfig saved to {}. Import in WireGuard: File → Import tunnel(s) from file.", fallback_path);
            }
        }
    }
}

fn main() -> Result<(), String> {
    let cli = Cli::parse();

    let project = match cli.project.filter(|s| !s.is_empty()) {
        Some(p) => p,
        None => get_project()?,
    };
    println!("Using project: {}", project);
    let zone = KOREA_ZONE.to_string();

    ensure_firewall(&project)?;
    create_vm(&project, &zone)?;
    wait_for_ssh(&project, &zone, 24)?; // ~2 min max

    let (client_private, client_public) = generate_wireguard_keypair();
    let server_public = setup_wireguard_on_vm(&project, &zone, &client_public)?;
    let external_ip = get_instance_external_ip(&project, &zone)?;
    let client_config = build_client_config(&client_private, &server_public, &external_ip);

    static CLEANUP_DONE: AtomicBool = AtomicBool::new(false);
    let project_cleanup = project.clone();
    let zone_cleanup = zone.clone();
    ctrlc::set_handler(move || {
        if !CLEANUP_DONE.swap(true, Ordering::SeqCst) {
            let _ = delete_vm(&project_cleanup, &zone_cleanup);
        }
        std::process::exit(0);
    })
    .map_err(|e| format!("Failed to set Ctrl+C handler: {}", e))?;

    let config_path = "lost-in-korea.conf";
    let _ = std::fs::write(config_path, &client_config);

    #[cfg(windows)]
    install_wireguard_config_windows(&client_config, config_path);

    println!("--- WireGuard client config ---\n");
    println!("{}", client_config);
    println!("--- VM is running. Press Ctrl+C to shut down and delete the VM. ---\n");

    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
