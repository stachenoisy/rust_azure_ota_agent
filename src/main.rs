use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{Timelike, Utc};
use dotenvy_macro::dotenv;
use futures_util::StreamExt;
use hmac::{Hmac, KeyInit, Mac};
use rumqttc::{AsyncClient, MqttOptions, QoS, Transport};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

// Resolved and embedded into the binary at compile time via .env
const CONF_FILE: &str = dotenv!("CONF_FILE");
const DOWNLOAD_PATH: &str = dotenv!("DOWNLOAD_PATH");
const DECRYPTED_PATH: &str = dotenv!("DECRYPTED_PATH");
const CRYPT_KEY_FILE: &str = dotenv!("CRYPT_KEY_FILE");
const FW_VERSION_FILE: &str = dotenv!("FW_VERSION_FILE");

const PENDING_UPDATE_PATH: &str = "/run/nvr/pending_ota_update.json";
const OTA_CHECK_NOW_PATH: &str = "/run/nvr/ota_check_now";
const OTA_DOWNLOAD_NOW_PATH: &str = "/run/nvr/ota_download_now";
const OTA_CANCEL_DOWNLOAD_PATH: &str = "/run/nvr/ota_cancel_download";
const STNVR_REBOOT_NOW_PATH: &str = "/run/stnvr_reboot_now";

#[derive(Debug, Clone)]
struct AgentOtaConfig {
    pub auto_ota_enabled: bool,
    pub download_start_hour: u32,
    pub download_end_hour: u32,
    pub reboot_start_hour: u32,
    pub reboot_end_hour: u32,
}

fn load_agent_ota_config() -> AgentOtaConfig {
    let paths = ["/run/nvr/ota_config.json", "/userdata/config/ota_config.json"];
    for path in &paths {
        if let Ok(raw) = std::fs::read_to_string(path) {
            if let Ok(v) = serde_json::from_str::<Value>(&raw) {
                return AgentOtaConfig {
                    auto_ota_enabled: v.get("autoOtaEnabled").and_then(|b| b.as_bool()).unwrap_or(true),
                    download_start_hour: v.get("downloadStartHour").and_then(|h| h.as_u64()).unwrap_or(2) as u32,
                    download_end_hour: v.get("downloadEndHour").and_then(|h| h.as_u64()).unwrap_or(3) as u32,
                    reboot_start_hour: v.get("rebootStartHour").and_then(|h| h.as_u64()).unwrap_or(3) as u32,
                    reboot_end_hour: v.get("rebootEndHour").and_then(|h| h.as_u64()).unwrap_or(5) as u32,
                };
            }
        }
    }
    AgentOtaConfig {
        auto_ota_enabled: true,
        download_start_hour: 2,
        download_end_hour: 3,
        reboot_start_hour: 3,
        reboot_end_hour: 5,
    }
}

static RID_COUNTER: AtomicU32 = AtomicU32::new(1);

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
struct IotHubConfig {
    host_name: String,
    device_id: String,
    shared_access_key: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct OtaUpdatePayload {
    url: Option<String>,
    version: Option<String>,
    immediate: Option<bool>,
    maintenance_start_hour: Option<u32>,
    maintenance_end_hour: Option<u32>,
    description: Option<String>,
    highlights: Option<Vec<String>>,
    release_notes: Option<Vec<String>>,
    changelog: Option<Vec<String>>,
}

fn is_in_maintenance_window(start_hour: u32, end_hour: u32) -> bool {
    let now_utc = Utc::now().time();
    let current_hour = now_utc.hour();
    if start_hour <= end_hour {
        current_hour >= start_hour && current_hour < end_hour
    } else {
        current_hour >= start_hour || current_hour < end_hour
    }
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
    if let Ok(content) = std::fs::read_to_string("/sys/block/mmcblk0/device/serial") {
        let serial = content.trim();
        if !serial.is_empty() {
            return serial.to_string();
        }
    }

    "UNKNOWN_DEVICE_ID".to_string()
}

fn get_firmware_version() -> String {
    // 1. RAUC CLI (`rauc status --output-format=json`) üzerinden aktif slotun sürümünü al
    if let Ok(output) = Command::new("rauc").args(&["status", "--output-format=json"]).output() {
        if output.status.success() {
            if let Ok(val) = serde_json::from_slice::<Value>(&output.stdout) {
                if let Some(ver) = val.get("version").and_then(|v| v.as_str()) {
                    let trimmed = ver.trim();
                    if !trimmed.is_empty() && trimmed != "null" {
                        return trimmed.to_string();
                    }
                }
                if let Some(slots) = val.get("slots").and_then(|s| s.as_array()) {
                    for slot_wrapper in slots {
                        if let Some(slot_obj) = slot_wrapper.as_object() {
                            for (_slot_name, slot_info) in slot_obj {
                                let is_booted = slot_info.get("booted").and_then(|b| b.as_bool()).unwrap_or(false);
                                if is_booted {
                                    if let Some(ver) = slot_info
                                        .get("bundle")
                                        .and_then(|b| b.get("version"))
                                        .and_then(|v| v.as_str())
                                    {
                                        let trimmed = ver.trim();
                                        if !trimmed.is_empty() {
                                            return trimmed.to_string();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. /userdata/rauc.status dosyasından aktif slotun bundle.version'ını oku
    if let Ok(content) = std::fs::read_to_string("/userdata/rauc.status") {
        let is_system1 = std::fs::read_to_string("/proc/cmdline")
            .map(|c| c.contains("system1") || c.contains("mmcblk0p7"))
            .unwrap_or(false);
        let target_section = if is_system1 { "[rootfs.1]" } else { "[rootfs.0]" };
        let mut in_section = false;
        for line in content.lines() {
            let l = line.trim();
            if l.starts_with('[') && l.ends_with(']') {
                in_section = l == target_section;
                continue;
            }
            if in_section && l.starts_with("bundle.version=") {
                if let Some(ver) = l.split('=').nth(1) {
                    let trimmed = ver.trim().trim_matches('"');
                    if !trimmed.is_empty() {
                        return trimmed.to_string();
                    }
                }
            }
        }
    }

    // 3. /etc/firmware-version (varsa)
    if let Ok(file) = File::open(FW_VERSION_FILE) {
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            if line.starts_with("VERSION=") {
                if let Some(val) = line.split('=').nth(1) {
                    let trimmed = val.trim().replace('"', "");
                    if !trimmed.is_empty() {
                        return trimmed;
                    }
                }
            }
        }
    }

    // 4. /etc/os-release içindeki STNVR_VERSION
    if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            let line_trimmed = line.trim();
            if line_trimmed.starts_with("STNVR_VERSION=") || line_trimmed.starts_with("VERSION_ID=") {
                let parts: Vec<&str> = line_trimmed.split('=').collect();
                if parts.len() > 1 {
                    let ver = parts[1].trim_matches('"').trim();
                    if !ver.is_empty() {
                        return ver.to_string();
                    }
                }
            }
        }
    }

    "1.0.4".to_string()
}

fn parse_connection_string() -> Result<IotHubConfig> {
    let raw = std::fs::read_to_string(CONF_FILE)
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

async fn cleanup_temp_files() {
    for path in &[DOWNLOAD_PATH, DECRYPTED_PATH] {
        if Path::new(path).exists() {
            match fs::remove_file(path).await {
                Ok(_) => println!("[clean] Removed temporary file: {}", path),
                Err(e) => eprintln!("[warn] Failed to delete temporary file {}: {}", path, e),
            }
        }
    }
}

async fn download_file(
    url: &str,
    target_path: &str,
    target_version: &str,
    highlights: &Option<Vec<String>>,
    description: &Option<String>,
) -> Result<()> {
    println!("[download] Fetching update bundle -> {}", target_path);
    if Path::new(target_path).exists() {
        let _ = fs::remove_file(target_path).await;
    }

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .build()?;

    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        bail!("Download request failed: HTTP {}", response.status());
    }

    let total_size = response.content_length();
    let mut file = fs::File::create(target_path).await?;
    let mut stream = response.bytes_stream();
    let mut downloaded: u64 = 0;
    let mut last_progress_write = std::time::Instant::now();

    while let Some(chunk) = stream.next().await {
        // İndirme iptal bayrağı kontrolü
        if Path::new(OTA_CANCEL_DOWNLOAD_PATH).exists() {
            let _ = fs::remove_file(OTA_CANCEL_DOWNLOAD_PATH).await;
            let _ = fs::remove_file(target_path).await;
            bail!("Download cancelled by user");
        }

        let data = chunk?;
        downloaded += data.len() as u64;
        file.write_all(&data).await?;

        // 350ms'de bir Web Dashboard'un canlı görmesi için durumu güncelle
        if last_progress_write.elapsed().as_millis() >= 350 {
            let pct = total_size
                .map(|t| if t > 0 { ((downloaded as f64 / t as f64) * 100.0) as u32 } else { 0 })
                .unwrap_or(0);

            let mut status_json = json!({
                "ota_status": format!("downloading_v{}", target_version),
                "download_progress_percent": pct,
                "downloaded_bytes": downloaded,
                "total_bytes": total_size,
                "available_version": target_version,
                "download_url": url,
                "updated_at": Utc::now().to_rfc3339()
            });
            if let Some(desc) = description {
                status_json["description"] = json!(desc);
            }
            if let Some(hl) = highlights {
                status_json["highlights"] = json!(hl);
            }
            let _ = fs::write("/run/nvr/ota_status.json", status_json.to_string()).await;
            last_progress_write = std::time::Instant::now();
        }
    }
    file.flush().await?;

    let metadata = fs::metadata(target_path).await?;
    if metadata.len() == 0 {
        bail!("Downloaded file is empty (0 bytes)");
    }

    let size_mb = metadata.len() as f64 / (1024.0 * 1024.0);
    println!("[download] Completed successfully ({:.2} MB)", size_mb);
    Ok(())
}

fn decrypt_bundle_if_needed(url: &str, src: &str, dst: &str) -> Result<String> {
    let is_encrypted =
        url.ends_with(".enc") || url.contains(".encrypted.") || url.ends_with(".encrypted");

    if is_encrypted {
        println!("[crypto] Encrypted bundle detected, decrypting via OpenSSL...");
        let key_file = if Path::new(CRYPT_KEY_FILE).exists() {
            CRYPT_KEY_FILE
        } else if Path::new("/etc/rauc/encryption.key").exists() {
            "/etc/rauc/encryption.key"
        } else {
            bail!("Decryption key file not found: {} (or /etc/rauc/encryption.key)", CRYPT_KEY_FILE);
        };

        let pass_arg = format!("file:{}", key_file);
        let args = [
            "enc",
            "-d",
            "-aes-256-cbc",
            "-salt",
            "-pbkdf2",
            "-iter",
            "100000",
            "-in",
            src,
            "-out",
            dst,
            "-pass",
            &pass_arg,
        ];

        let (ok, _, err) = run_command_direct("openssl", &args);
        if ok {
            println!("[crypto] Bundle decrypted successfully");
            return Ok(dst.to_string());
        } else {
            bail!("OpenSSL bundle decryption failed: {}", err);
        }
    }
    Ok(src.to_string())
}

fn run_command_direct(program: &str, args: &[&str]) -> (bool, String, String) {
    match Command::new(program).args(args).output() {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout).to_string();
            let stderr = String::from_utf8_lossy(&out.stderr).to_string();
            (out.status.success(), stdout, stderr)
        }
        Err(e) => (false, String::new(), e.to_string()),
    }
}

fn apply_rauc_update(file_path: &str) -> bool {
    println!("[rauc] Triggering bundle installation: {}", file_path);
    let (ok, _, err) = run_command_direct("rauc", &["install", file_path]);
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

    // Yerel IPC köprüsü: `/run/nvr/ota_status.json` dosyasına yazarak nvr-webd'yi ve Web arayüzünü anlık bilgilendir
    let state_dir = Path::new("/run/nvr");
    if !state_dir.exists() {
        let _ = fs::create_dir_all(state_dir).await;
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("chown").args(&["root:nvr", "/run/nvr"]).status();
        let _ = std::process::Command::new("chmod").args(&["775", "/run/nvr"]).status();
    }

    // Mevcut /run/nvr/ota_status.json ile yeni bilgileri harmanla (mevcut alanların ezilmesini önler)
    let mut merged = if let Ok(existing_str) = fs::read_to_string("/run/nvr/ota_status.json").await {
        serde_json::from_str::<Value>(&existing_str).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };

    if let Some(patch_obj) = patch.as_object() {
        if let Some(merged_obj) = merged.as_object_mut() {
            for (k, v) in patch_obj {
                merged_obj.insert(k.clone(), v.clone());
            }
        }
    }
    merged["updated_at"] = json!(Utc::now().to_rfc3339());
    let _ = fs::write("/run/nvr/ota_status.json", merged.to_string()).await;

    if let Err(e) = client
        .publish(topic, QoS::AtLeastOnce, false, payload)
        .await
    {
        eprintln!("[warn] Failed to report twin status: {}", e);
    }
}

async fn handle_twin_patch(patch_str: &str, client: Arc<AsyncClient>) {
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

        if let Some(ref url) = payload.url {
            let target_version = payload.version.clone().unwrap_or_else(|| "unknown".to_string());
            let current_version = get_firmware_version();

            if target_version != "unknown" && !is_version_newer(&target_version, &current_version) {
                println!(
                    "[ota] Device already at or newer than desired version (current: v{}, target: v{}). Skipping update.",
                    current_version, target_version
                );
                update_reported_status(
                    &client,
                    json!({
                        "ota_status": "idle",
                        "installed_version": current_version
                    }),
                )
                .await;
                return;
            }

            let effective_highlights = payload
                .highlights
                .clone()
                .or(payload.release_notes.clone())
                .or(payload.changelog.clone());

            let cfg = load_agent_ota_config();
            let manual_download = Path::new(OTA_DOWNLOAD_NOW_PATH).exists();
            let immediate = payload.immediate.unwrap_or(false) || manual_download;
            let in_download_window = is_in_maintenance_window(cfg.download_start_hour, cfg.download_end_hour);

            // Eğer otomatik indirme saati değilse ve acil/manuel talep yoksa, durumu 'available' olarak bildir
            if !immediate && !in_download_window {
                println!(
                    "[ota] New version v{} detected, but outside download window ({:02}:00-{:02}:00 UTC). Setting status to 'available'.",
                    target_version, cfg.download_start_hour, cfg.download_end_hour
                );
                let _ = fs::write(PENDING_UPDATE_PATH, serde_json::to_string(&payload).unwrap_or_default()).await;
                let mut avail_val = json!({
                    "ota_status": "available",
                    "available_version": target_version,
                    "download_url": url,
                    "maintenance_window": format!("{:02}:00-{:02}:00 UTC", cfg.download_start_hour, cfg.download_end_hour)
                });
                if let Some(ref desc) = payload.description {
                    avail_val["description"] = json!(desc);
                }
                if let Some(ref hl) = effective_highlights {
                    avail_val["highlights"] = json!(hl);
                }
                update_reported_status(&client, avail_val).await;
                return;
            }

            let _ = fs::remove_file(OTA_DOWNLOAD_NOW_PATH).await;

            println!(
                "[ota] Update trigger received (current: {}, target: {}). Starting download...",
                current_version, target_version
            );

            let mut dl_status = json!({
                "ota_status": format!("downloading_v{}", target_version),
                "available_version": target_version,
                "download_url": url,
                "download_progress_percent": 0
            });
            if let Some(ref desc) = payload.description {
                dl_status["description"] = json!(desc);
            }
            if let Some(ref hl) = effective_highlights {
                dl_status["highlights"] = json!(hl);
            }
            update_reported_status(&client, dl_status).await;

            if let Err(e) = download_file(&url, DOWNLOAD_PATH, &target_version, &effective_highlights, &payload.description).await {
                eprintln!("[error] Download interrupted: {}", e);
                if e.to_string().contains("cancelled") || e.to_string().contains("İptal") {
                    println!("[ota] Download was cancelled by user. Resetting status to 'available'.");
                    let mut avail_val = json!({
                        "ota_status": "available",
                        "available_version": target_version,
                        "download_url": url,
                        "maintenance_window": format!("{:02}:00-{:02}:00 UTC", cfg.download_start_hour, cfg.download_end_hour)
                    });
                    if let Some(ref desc) = payload.description {
                        avail_val["description"] = json!(desc);
                    }
                    if let Some(ref hl) = effective_highlights {
                        avail_val["highlights"] = json!(hl);
                    }
                    update_reported_status(&client, avail_val).await;
                } else {
                    update_reported_status(&client, json!({ "ota_status": format!("error: {}", e) })).await;
                }
                cleanup_temp_files().await;
                return;
            }

            let target_raucb = match decrypt_bundle_if_needed(&url, DOWNLOAD_PATH, DECRYPTED_PATH) {
                Ok(path) => path,
                Err(e) => {
                    eprintln!("[error] Decryption failed: {}", e);
                    update_reported_status(
                        &client,
                        json!({ "ota_status": format!("error: {}", e) }),
                    )
                    .await;
                    cleanup_temp_files().await;
                    return;
                }
            };

            let mut inst_status = json!({
                "ota_status": format!("installing_v{}", target_version),
                "available_version": target_version,
                "download_url": url
            });
            if let Some(ref desc) = payload.description {
                inst_status["description"] = json!(desc);
            }
            if let Some(ref hl) = effective_highlights {
                inst_status["highlights"] = json!(hl);
            }
            update_reported_status(&client, inst_status).await;

            if apply_rauc_update(&target_raucb) {
                cleanup_temp_files().await;
                let _ = fs::remove_file(PENDING_UPDATE_PATH).await;

                let start_hour = cfg.reboot_start_hour;
                let end_hour = cfg.reboot_end_hour;
                let manual_reboot = Path::new(STNVR_REBOOT_NOW_PATH).exists();
                let twin_immediate = payload.immediate.unwrap_or(false);

                if twin_immediate || manual_reboot || is_in_maintenance_window(start_hour, end_hour) {
                    println!("[ota] Immediate reboot permitted or inside maintenance window. Rebooting now...");
                    update_reported_status(
                        &client,
                        json!({
                            "ota_status": format!("installed_v{}_rebooting", target_version),
                            "pending_version": target_version
                        }),
                    )
                    .await;
                    tokio::time::sleep(Duration::from_secs(4)).await;
                    let _ = Command::new("sudo").args(&["/bin/systemctl", "reboot"]).status();
                    let _ = Command::new("reboot").spawn();
                } else {
                    println!(
                        "[ota] Update installed! Deferring reboot until maintenance window ({:02}:00-{:02}:00 UTC) or manual trigger...",
                        start_hour, end_hour
                    );
                    let mut pend_status = json!({
                        "ota_status": format!("installed_v{}_pending_window", target_version),
                        "pending_version": target_version,
                        "available_version": target_version,
                        "maintenance_window": format!("{:02}:00-{:02}:00 UTC", start_hour, end_hour)
                    });
                    if let Some(ref desc) = payload.description {
                        pend_status["description"] = json!(desc);
                    }
                    if let Some(ref hl) = effective_highlights {
                        pend_status["highlights"] = json!(hl);
                    }
                    update_reported_status(&client, pend_status).await;
                }
            } else {
                update_reported_status(
                    &client,
                    json!({ "ota_status": format!("failed_v{}", target_version) }),
                )
                .await;
                cleanup_temp_files().await;
            }
        }
    }
}

fn is_version_newer(candidate: &str, current: &str) -> bool {
    let parse_parts = |s: &str| -> Vec<u64> {
        s.trim()
            .trim_start_matches('v')
            .trim_start_matches('V')
            .split(|c: char| c == '.' || c == '-' || c == '_')
            .filter_map(|part| part.parse::<u64>().ok())
            .collect()
    };

    let cand_parts = parse_parts(candidate);
    let curr_parts = parse_parts(current);

    if cand_parts.is_empty() || curr_parts.is_empty() {
        return false;
    }

    let max_len = cand_parts.len().max(curr_parts.len());
    for i in 0..max_len {
        let c = cand_parts.get(i).copied().unwrap_or(0);
        let cur = curr_parts.get(i).copied().unwrap_or(0);
        if c > cur {
            return true;
        } else if c < cur {
            return false;
        }
    }
    false
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("Failed to install crypto provider"))?;

    println!("[init] Starting Azure RAUC OTA Agent...");

    // Shared runtime IPC directory (/run/nvr) setup with group nvr write permissions
    let state_dir = Path::new("/run/nvr");
    if !state_dir.exists() {
        let _ = fs::create_dir_all(state_dir).await;
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("chown").args(&["root:nvr", "/run/nvr"]).status();
        let _ = std::process::Command::new("chmod").args(&["775", "/run/nvr"]).status();
    }

    let device_id = get_cpu_serial();
    let fw_version = get_firmware_version();

    println!("[init] Hardware ID: {}", device_id);
    println!("[init] Active Firmware: {}", fw_version);

    let config = parse_connection_string()?;
    println!("[init] Configured Device ID: {}", config.device_id);

    let init_status = json!({
        "hardware_id": device_id,
        "installed_version": fw_version,
        "agent_status": "idle",
        "last_boot": Utc::now().format("%Y-%m-%d %H:%M:%S").to_string()
    });

    let is_busy = Arc::new(Mutex::new(false));

    // Standard short-lived SAS token TTL (1 hour)
    const SAS_TOKEN_TTL_SECS: i64 = 3600;

    'reconnect: loop {
        let sas_token = match generate_sas_token(&config, SAS_TOKEN_TTL_SECS) {
            Ok(token) => token,
            Err(e) => {
                eprintln!("[auth] Failed to generate SAS token: {}. Retrying...", e);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue 'reconnect;
            }
        };

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

        loop {
            match eventloop.poll().await {
                Ok(event) => match event {
                    rumqttc::Event::Incoming(rumqttc::Packet::ConnAck(_)) => {
                        println!("[mqtt] Connected to Azure IoT Hub (TLS session established)");

                        let client_sub = Arc::clone(&client);
                        tokio::spawn(async move {
                            let _ = client_sub
                                .subscribe(
                                    "$iothub/twin/PATCH/properties/desired/#",
                                    QoS::AtLeastOnce,
                                )
                                .await;
                            let _ = client_sub
                                .subscribe(
                                    "$iothub/twin/res/#",
                                    QoS::AtLeastOnce,
                                )
                                .await;

                            // Açılışta Device Twin durumunu sorgula
                            let rid = RID_COUNTER.fetch_add(1, Ordering::SeqCst);
                            let _ = client_sub
                                .publish(
                                    format!("$iothub/twin/GET/?$rid={}", rid),
                                    QoS::AtLeastOnce,
                                    false,
                                    "",
                                )
                                .await;
                        });

                        // Arka plan IPC dosya denetleyicisi (Web Dashboard butonları ve zamanlayıcı)
                        let client_ipc = Arc::clone(&client);
                        let busy_ipc = Arc::clone(&is_busy);
                        tokio::spawn(async move {
                            loop {
                                tokio::time::sleep(Duration::from_secs(1)).await;

                                // 1. Manuel OTA Denetimi Tetikleyicisi
                                if Path::new(OTA_CHECK_NOW_PATH).exists() {
                                    let _ = fs::remove_file(OTA_CHECK_NOW_PATH).await;
                                    println!("[ota-ipc] Manual OTA check trigger detected! Querying Device Twin...");
                                    let rid = RID_COUNTER.fetch_add(1, Ordering::SeqCst);
                                    let _ = client_ipc
                                        .publish(
                                            format!("$iothub/twin/GET/?$rid={}", rid),
                                            QoS::AtLeastOnce,
                                            false,
                                            "",
                                        )
                                        .await;
                                }

                                // 2. Manuel veya Zamanlanmış İndirme Tetikleyicisi
                                let cfg = load_agent_ota_config();
                                let manual_download = Path::new(OTA_DOWNLOAD_NOW_PATH).exists();
                                let in_download_window = is_in_maintenance_window(cfg.download_start_hour, cfg.download_end_hour);

                                if manual_download || (Path::new(PENDING_UPDATE_PATH).exists() && in_download_window) {
                                    let raw_payload = if Path::new(PENDING_UPDATE_PATH).exists() {
                                        fs::read_to_string(PENDING_UPDATE_PATH).await.ok()
                                    } else if let Ok(status_str) = fs::read_to_string("/run/nvr/ota_status.json").await {
                                        if let Ok(st) = serde_json::from_str::<Value>(&status_str) {
                                            if let Some(url) = st.get("download_url").and_then(|u| u.as_str()) {
                                                let ver = st.get("available_version").and_then(|v| v.as_str()).unwrap_or("unknown");
                                                Some(json!({
                                                    "url": url,
                                                    "version": ver,
                                                    "immediate": true,
                                                    "description": st.get("description"),
                                                    "highlights": st.get("highlights")
                                                }).to_string())
                                            } else {
                                                None
                                            }
                                        } else {
                                            None
                                        }
                                    } else {
                                        None
                                    };

                                    if let Some(raw) = raw_payload {
                                        let mut busy = busy_ipc.lock().await;
                                        if !*busy {
                                            *busy = true;
                                            let client_ref = Arc::clone(&client_ipc);
                                            let mut update_obj = serde_json::from_str::<Value>(&raw).unwrap_or_default();
                                            if manual_download {
                                                println!("[ota-ipc] Manual download trigger detected from Web UI. Forcing immediate=true.");
                                                update_obj["immediate"] = json!(true);
                                                let _ = fs::remove_file(OTA_DOWNLOAD_NOW_PATH).await;
                                            }
                                            let mock_patch = json!({ "ota_update": update_obj }).to_string();
                                            let busy_task = Arc::clone(&busy_ipc);
                                            tokio::spawn(async move {
                                                handle_twin_patch(&mock_patch, client_ref).await;
                                                let mut b = busy_task.lock().await;
                                                *b = false;
                                            });
                                        }
                                    } else if manual_download {
                                        println!("[ota-ipc] Manual download trigger detected but no pending payload found. Querying Device Twin...");
                                        let _ = fs::remove_file(OTA_DOWNLOAD_NOW_PATH).await;
                                        let rid = RID_COUNTER.fetch_add(1, Ordering::SeqCst);
                                        let _ = client_ipc
                                            .publish(
                                                format!("$iothub/twin/GET/?$rid={}", rid),
                                                QoS::AtLeastOnce,
                                                false,
                                                "",
                                            )
                                            .await;
                                    }
                                }

                                // 3. Manuel veya Zamanlanmış Yeniden Başlatma Tetikleyicisi
                                let manual_reboot = Path::new(STNVR_REBOOT_NOW_PATH).exists();
                                let in_reboot_window = is_in_maintenance_window(cfg.reboot_start_hour, cfg.reboot_end_hour);

                                if manual_reboot || in_reboot_window {
                                    if let Ok(raw) = fs::read_to_string("/run/nvr/ota_status.json").await {
                                        if raw.contains("pending_window") {
                                            let _ = fs::remove_file(STNVR_REBOOT_NOW_PATH).await;
                                            println!("[ota-ipc] Reboot trigger reached. Rebooting into new slot...");
                                            update_reported_status(&client_ipc, json!({ "ota_status": "rebooting" })).await;
                                            tokio::time::sleep(Duration::from_secs(3)).await;
                                            let _ = Command::new("sudo").args(&["/bin/systemctl", "reboot"]).status();
                                            let _ = Command::new("reboot").spawn();
                                            break;
                                        }
                                    }
                                }
                            }
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
                                    handle_twin_patch(&payload_str, client_ref).await;
                                    *busy = false;
                                });
                            }
                        } else if p.topic.starts_with("$iothub/twin/res/200") {
                            if let Ok(payload_str) = String::from_utf8(p.payload.to_vec()) {
                                if let Ok(twin_json) = serde_json::from_str::<Value>(&payload_str) {
                                    if let Some(desired) = twin_json.get("desired") {
                                        println!("[twin] Received full twin state from IoT Hub.");
                                        let busy_lock = Arc::clone(&is_busy);
                                        let client_ref = Arc::clone(&client);
                                        let desired_str = desired.to_string();

                                        tokio::spawn(async move {
                                            let mut busy = busy_lock.lock().await;
                                            if !*busy {
                                                *busy = true;
                                                handle_twin_patch(&desired_str, client_ref).await;
                                                *busy = false;
                                            }
                                        });
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                },
                Err(e) => {
                    eprintln!(
                        "[mqtt] Connection dropped: {}. Reconnecting with refreshed SAS token...",
                        e
                    );
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    break;
                }
            }
        }
    }
}
