# lost-in-korea

CLI tool that starts a **spot VM on GCP in the Korea (Seoul) region**, brings up a **WireGuard** server on it, and gives you a client config so this machine can connect. When you stop the CLI (e.g. Ctrl+C), it **shuts down and deletes the VM**.

## Prerequisites

- **Rust** (e.g. `rustup default stable`)
- **Google Cloud SDK** (`gcloud`) installed and logged in:
  - [Install gcloud](https://cloud.google.com/sdk/docs/install)
  - `gcloud auth login`
- **Billing** enabled on the project (spot VMs are cheap but not free).
- **WireGuard** on your machine (to use the generated config):
  - Windows: [WireGuard for Windows](https://www.wireguard.com/install/)
  - macOS: `brew install wireguard-tools` or WireGuard app
  - Linux: `wg-quick` / `wireguard-tools`

## Build and run

```bash
cargo build --release
./target/release/lost-in-korea -p {project-id}
```

## What it does

1. Ensures a firewall rule allows UDP 51820 (WireGuard) for your project.
2. Creates a **spot** (preemptible) VM in `asia-northeast3-a` (Seoul) with Debian 12.
3. Waits for SSH, installs WireGuard on the VM, and configures a server with one client peer (this machine).
4. Prints the **WireGuard client config** and writes it to `lost-in-korea.conf`.
5. Keeps running until you press **Ctrl+C**, then deletes the VM.

## Notes

- The VM name is fixed: `lost-in-korea-wg`. Only one such instance is expected per project/zone.
- Spot VMs can be preempted by GCP; if the VPN drops, stop the CLI and run it again to get a new VM and config.
- The client config uses `AllowedIPs = 0.0.0.0/0` (all traffic via VPN). Change it in the generated config if you want split tunneling.
