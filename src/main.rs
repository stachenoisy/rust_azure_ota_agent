use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::Utc;
use dotenvy_macro::dotenv;
use futures_util::StreamExt;
use hmac::{Hmac, KeyInit, Mac};
use rumqttc::{AsyncClient, MqttOptions, QoS, Transport};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;

// Resolved and embedded into the binary at compile time via .env
const CONF_FILE: &str = dotenv!("CONF_FILE");
const DOWNLOAD_PATH: &str = dotenv!("DOWNLOAD_PATH");
const DECRYPTED_PATH: &str = dotenv!("DECRYPTED_PATH");
const CRYPT_KEY_FILE: &str = dotenv!("CRYPT_KEY_FILE");
const FW_VERSION_FILE: &str = dotenv!("FW_VERSION_FILE");

static RID_COUNTER: AtomicU32 = AtomicU32::new(1);

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
struct IotHubConfig {
    host_name: String,
    device_id: String,
    shared_access_key: String,
}

#[derive(Deserialize, Debug)]
struct OtaUpdatePayload {
    url: Option<String>,
    version: Option<String>,
}

fn get_cpu_serial() -> String {
    if let Ok(file) = File::open("/proc/cpuinfo") {
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            let line_trimmed = line.trim();
            if line_trimmed.starts_with("Serial") {
                if let Some(val) = line_trimmed.split(':').nth(1) {
                    let serial = val.trim();
                    if !serial.is_empty() && serial != "0000000000000000" {
                        return serial.to_string();
                    }
                }
            }
        }
    }

    // Fallback to eMMC serial if cpuinfo doesn't expose a valid serial
    if let Ok(content) = fs::read_to_string("/sys/block/mmcblk0/device/serial") {
        let serial = content.trim();
        if !serial.is_empty() {
            return serial.to_string();
        }
    }

    "UNKNOWN_DEVICE_ID".to_string()
}

fn get_firmware_version() -> String {
    if let Ok(file) = File::open(FW_VERSION_FILE) {
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            if line.starts_with("VERSION=") {
                if let Some(val) = line.split('=').nth(1) {
                    return val.trim().replace('"', "");
                }
            }
        }
    }
    "1.0.0-base".to_string()
}

fn parse_connection_string() -> Result<IotHubConfig> {
    let raw = fs::read_to_string(CONF_FILE)
        .with_context(|| format!("Failed to read Azure config at {}", CONF_FILE))?;
    let conn_str = raw.trim();
    if conn_str.is_empty() {
        bail!("Connection string is empty");
    }

    let mut map = HashMap::new();
    for part in conn_str.split(';') {
        let mut kv = part.splitn(2, '=');
        if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
            map.insert(k.trim(), v.trim());
        }
    }

    Ok(IotHubConfig {
        host_name: map
            .get("HostName")
            .ok_or_else(|| anyhow!("Missing HostName in connection string"))?
            .to_string(),
        device_id: map
            .get("DeviceId")
            .ok_or_else(|| anyhow!("Missing DeviceId in connection string"))?
            .to_string(),
        shared_access_key: map
            .get("SharedAccessKey")
            .ok_or_else(|| anyhow!("Missing SharedAccessKey in connection string"))?
            .to_string(),
    })
}

fn generate_sas_token(config: &IotHubConfig, ttl_secs: i64) -> Result<String> {
    let expiry = Utc::now().timestamp() + ttl_secs;
    let resource_uri = format!("{}/devices/{}", config.host_name, config.device_id);
    let encoded_uri = urlencoding::encode(&resource_uri);
    let to_sign = format!("{}\n{}", encoded_uri, expiry);

    let key_bytes = BASE64
        .decode(&config.shared_access_key)
        .context("Failed to base64-decode SharedAccessKey")?;
    let mut mac = HmacSha256::new_from_slice(&key_bytes)
        .map_err(|e| anyhow!("Failed to initialize HMAC: {}", e))?;
    mac.update(to_sign.as_bytes());
    let sig = BASE64.encode(mac.finalize().into_bytes());
    let encoded_sig = urlencoding::encode(&sig);

    Ok(format!(
        "SharedAccessSignature sr={}&sig={}&se={}",
        encoded_uri, encoded_sig, expiry
    ))
}

fn run_cmd(cmd: &str) -> (bool, String, String) {
    match Command::new("sh").arg("-c").arg(cmd).output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            (out.status.success(), stdout, stderr)
        }
        Err(e) => (false, String::new(), e.to_string()),
    }
}

fn cleanup_temp_files() {
    for path in &[DOWNLOAD_PATH, DECRYPTED_PATH] {
        if Path::new(path).exists() {
            match fs::remove_file(path) {
                Ok(_) => println!("[clean] Removed temporary file: {}", path),
                Err(e) => eprintln!("[warn] Failed to delete temporary file {}: {}", path, e),
            }
        }
    }
}

async fn download_file(url: &str, target_path: &str) -> Result<()> {
    println!("[download] Fetching update bundle -> {}", target_path);
    if Path::new(target_path).exists() {
        let _ = fs::remove_file(target_path);
    }

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .build()?;

    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        bail!("Download request failed: HTTP {}", response.status());
    }

    let mut file = File::create(target_path)?;
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let data = chunk?;
        file.write_all(&data)?;
    }

    let metadata = fs::metadata(target_path)?;
    if metadata.len() == 0 {
        bail!("Downloaded file is empty (0 bytes)");
    }

    let size_mb = metadata.len() as f64 / (1024.0 * 1024.0);
    println!("[download] Completed successfully ({:.2} MB)", size_mb);
    Ok(())
}

fn decrypt_bundle_if_needed(src: &str, dst: &str) -> Result<String> {
    if src.ends_with(".enc") || src.contains("encrypted") {
        println!("[crypto] Encrypted bundle detected, decrypting via OpenSSL...");
        if !Path::new(CRYPT_KEY_FILE).exists() {
            bail!("Decryption key file not found: {}", CRYPT_KEY_FILE);
        }

        let cmd = format!(
            "openssl enc -d -aes-256-cbc -salt -in '{}' -out '{}' -pass file:'{}'",
            src, dst, CRYPT_KEY_FILE
        );
        let (ok, _, err) = run_cmd(&cmd);
        if ok {
            println!("[crypto] Bundle decrypted successfully");
            return Ok(dst.to_string());
        } else {
            bail!("OpenSSL bundle decryption failed: {}", err);
        }
    }
    Ok(src.to_string())
}

fn apply_rauc_update(file_path: &str) -> bool {
    println!("[rauc] Triggering bundle installation: {}", file_path);
    let (ok, _, err) = run_cmd(&format!("rauc install {}", file_path));
    if ok {
        println!("[rauc] Update installed successfully");
        true
    } else {
        eprintln!("[rauc] Installation failed: {}", err);
        false
    }
}

async fn update_reported_status(client: &AsyncClient, patch: Value) {
    let rid = RID_COUNTER.fetch_add(1, Ordering::SeqCst);
    let topic = format!("$iothub/twin/PATCH/properties/reported/?$rid={}", rid);
    let payload = patch.to_string();

    if let Err(e) = client
        .publish(topic, QoS::AtLeastOnce, false, payload)
        .await
    {
        eprintln!("[warn] Failed to report twin status: {}", e);
    }
}

async fn handle_twin_patch(patch_str: &str, client: &AsyncClient) {
    let Ok(patch) = serde_json::from_str::<Value>(patch_str) else {
        return;
    };

    println!("[twin] Received desired property update: {}", patch);

    if let Some(ota_info) = patch.get("ota_update") {
        let payload: OtaUpdatePayload = match serde_json::from_value(ota_info.clone()) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[error] Failed to parse ota_update payload: {}", e);
                return;
            }
        };

        if let Some(url) = payload.url {
            let version = payload.version.unwrap_or_else(|| "unknown".to_string());
            println!("[ota] Update trigger received (target: {})", version);

            update_reported_status(
                client,
                json!({ "ota_status": format!("downloading_v{}", version) }),
            )
            .await;

            if let Err(e) = download_file(&url, DOWNLOAD_PATH).await {
                eprintln!("[error] Download failed: {}", e);
                update_reported_status(client, json!({ "ota_status": format!("error: {}", e) }))
                    .await;
                cleanup_temp_files();
                return;
            }

            let target_raucb = match decrypt_bundle_if_needed(DOWNLOAD_PATH, DECRYPTED_PATH) {
                Ok(path) => path,
                Err(e) => {
                    eprintln!("[error] Decryption failed: {}", e);
                    update_reported_status(
                        client,
                        json!({ "ota_status": format!("error: {}", e) }),
                    )
                    .await;
                    cleanup_temp_files();
                    return;
                }
            };

            update_reported_status(
                client,
                json!({ "ota_status": format!("installing_v{}", version) }),
            )
            .await;

            if apply_rauc_update(&target_raucb) {
                update_reported_status(
                    client,
                    json!({
                        "ota_status": format!("installed_v{}_rebooting", version),
                        "pending_version": version
                    }),
                )
                .await;

                cleanup_temp_files();
                println!("[ota] Installation completed. Rebooting device in 5 seconds...");
                tokio::time::sleep(Duration::from_secs(5)).await;
                let _ = Command::new("reboot").spawn();
            } else {
                update_reported_status(
                    client,
                    json!({ "ota_status": format!("failed_v{}", version) }),
                )
                .await;
                cleanup_temp_files();
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install ring-backed rustls crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("Failed to install crypto provider"))?;

    println!("[init] Starting Azure RAUC OTA Agent...");

    let device_id = get_cpu_serial();
    let fw_version = get_firmware_version();

    println!("[init] Hardware ID: {}", device_id);
    println!("[init] Active Firmware: {}", fw_version);

    let config = parse_connection_string()?;
    println!("[init] Configured Device ID: {}", config.device_id);

    // Generate SAS token valid for 1 year
    let sas_token = generate_sas_token(&config, 3600 * 24 * 365)?;

    let mut mqttoptions = MqttOptions::new(&config.device_id, &config.host_name, 8883);
    mqttoptions.set_keep_alive(Duration::from_secs(30));
    mqttoptions.set_clean_session(false);
    mqttoptions.set_transport(Transport::tls_with_default_config());

    let username = format!(
        "{}/{}/?api-version=2021-04-12",
        config.host_name, config.device_id
    );
    mqttoptions.set_credentials(username, sas_token);

    let (client, mut eventloop) = AsyncClient::new(mqttoptions, 50);
    let client = Arc::new(client);

    let init_status = json!({
        "hardware_id": device_id,
        "installed_version": fw_version,
        "agent_status": "idle",
        "last_boot": Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
    });

    let is_busy = Arc::new(Mutex::new(false));

    loop {
        match eventloop.poll().await {
            Ok(event) => match event {
                rumqttc::Event::Incoming(rumqttc::Packet::ConnAck(_)) => {
                    println!("[mqtt] Connected to Azure IoT Hub (TLS session established)");

                    let client_sub = Arc::clone(&client);
                    tokio::spawn(async move {
                        let _ = client_sub
                            .subscribe("$iothub/twin/PATCH/properties/desired/#", QoS::AtLeastOnce)
                            .await;
                        let _ = client_sub
                            .subscribe("$iothub/twin/res/#", QoS::AtLeastOnce)
                            .await;
                    });

                    update_reported_status(&client, init_status.clone()).await;
                }
                rumqttc::Event::Incoming(rumqttc::Packet::Publish(p)) => {
                    if p.topic.starts_with("$iothub/twin/PATCH/properties/desired") {
                        if let Ok(payload_str) = String::from_utf8(p.payload.to_vec()) {
                            let busy_lock = Arc::clone(&is_busy);
                            let client_ref = Arc::clone(&client);

                            tokio::spawn(async move {
                                let mut busy = busy_lock.lock().await;
                                if *busy {
                                    eprintln!(
                                        "[warn] Another OTA task is already in progress, skipping"
                                    );
                                    return;
                                }
                                *busy = true;
                                handle_twin_patch(&payload_str, &client_ref).await;
                                *busy = false;
                            });
                        }
                    }
                }
                _ => {}
            },
            Err(e) => {
                eprintln!("[mqtt] Connection error: {}. Retrying in 3 seconds...", e);
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }
    }
}
