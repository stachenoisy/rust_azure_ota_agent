<h1 align="center">Azure RAUC OTA Agent</h1>

<p align="center">
  <a href="https://github.com/stachenoisy/rust_azure_ota_agent">
    <img src="https://img.shields.io/github/stars/stachenoisy/rust_azure_ota_agent" alt="GitHub Repo stars">
  </a>
  <a href="https://github.com/stachenoisy/rust_azure_ota_agent/commits/main">
    <img src="https://img.shields.io/github/last-commit/stachenoisy/rust_azure_ota_agent" alt="GitHub Last Commit">
  </a>
  <a href="https://github.com/stachenoisy/rust_azure_ota_agent/commits/main">
    <img src="https://img.shields.io/github/commit-activity/t/stachenoisy/rust_azure_ota_agent" alt="GitHub Total Commit">
  </a>
  <a href="https://opensource.org/license/apache-2.0">
    <img src="https://img.shields.io/github/license/stachenoisy/rust_azure_ota_agent" alt="License: Apache License 2.0">
  </a>
</p>

A lightweight, asynchronous OTA (Over-The-Air) update daemon written in Rust for embedded Linux targets (eMMC/NAND). It coordinates updates between **Azure IoT Hub** (via Device Twin) and **RAUC** (Robust Auto-Update Controller), supporting encrypted bundles and automatic rollback-safe reboots.

## Features

- **Compile-Time Config Ingestion**: File paths and system targets are baked directly into the binary at build time from a `.env` file.
- **Azure IoT Hub Device Twin Sync**: Listens for desired property changes over native TLS/MQTT (`rumqttc`).
- **Encrypted Bundle Support**: Automatically decrypts OpenSSL AES-256-CBC wrapped bundles before handoff.
- **Atomic RAUC Triggering**: Invokes the `rauc` daemon safely and tracks full status lifecycle back to reported twin properties.
- **Hardware ID Discovery**: Extracts persistent serial identifiers from `/proc/cpuinfo` or `/sys/block/mmcblk0`.
- **Low Footprint**: Asynchronous runtime (`tokio`) optimized for embedded ARM targets.

---

## Architecture Flow

```text
  Azure IoT Hub
   (Device Twin)
        │  1. Desired property update (url, version)
        ▼
┌──────────────────┐
│ azure-ota-agent  │ ──► 2. Stream chunked bundle to /userdata
└─────────┬────────┘
          │  3. OpenSSL Decrypt (AES-256-CBC)
          ▼
┌──────────────────┐
│  RAUC Installer  │ ──► 4. Apply bundle to inactive A/B slot
└─────────┬────────┘
          │  5. Report success to IoT Hub Twin
          ▼
   Reboot Device
```

## Environment Setup (Build-Time)

The agent bakes target paths directly into the binary using `dotenvy_macro`. Copy `.env.example` to `.env` before compiling:

```bash
cp .env.example .env
```

| Variable          | Description                                     | Default Target Path                |
| ----------------- | ----------------------------------------------- | ---------------------------------- |
| `CONF_FILE`       | Azure IoT Hub connection string file            | `/etc/rauc/azure.conf`             |
| `DOWNLOAD_PATH`   | Staging location for downloaded bundles         | `/userdata/update.encrypted.raucb` |
| `DECRYPTED_PATH`  | Target output for decrypted bundle              | `/userdata/update.raucb`           |
| `CRYPT_KEY_FILE`  | Key file used for AES-256-CBC bundle decryption | `/etc/rauc/encryption.key`         |
| `FW_VERSION_FILE` | System version definition file                  | `/etc/firmware-version`            |

> Note: The .env file is only needed during compilation. It is not required on the target device filesystem.

## Device Twin Payload Format

Trigger an update by pushing the following structure to desired properties:

```json
{
  "properties": {
    "desired": {
      "ota_update": {
        "url": "https://storage.example.com/bundles/update-v1.2.0.encrypted.raucb",
        "version": "1.2.0"
      }
    }
  }
}
```

Reported properties sent back to IoT Hub:

```json
{
  "hardware_id": "00000000a1b2c3d4",
  "installed_version": "1.0.0",
  "ota_status": "downloading_v1.2.0",
  "last_boot": "2026-08-15 10:45:00"
}
```

## Building & Cross-Compilation
### Prerequisites

#### Ensure you have Rust and `cross` installed:

```bash
cargo install cross --git https://github.com/cross-rs/cross
```

### Build for Target (aarch64 / ARMv7)
For `aarch64-unknown-linux-musl`:

```bash
cross build --target aarch64-unknown-linux-musl --release
```

For `armv7-unknown-linux-musleabihf`:

```bash
cross build --target armv7-unknown-linux-musleabihf --release
```

The resulting binary will be located at `target/<target-triple>/release/azure-ota-agent`.

## Systemd Service Setup

### Create `/etc/systemd/system/azure-ota-agent.service`:

```ini
[Unit]
Description=Azure RAUC OTA Update Daemon
After=network-online.target rauc.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/azure-ota-agent
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

#### Enable and start the service:

```bash
systemctl daemon-reload
systemctl enable --now azure-ota-agent
```