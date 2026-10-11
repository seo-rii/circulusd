// SPDX-License-Identifier: Apache-2.0
//! Native celld boot measurement and one-shot independent proof publication.
//!
//! This module deliberately has no Worker API, mutable descriptor setter, or
//! caller-provided eligibility flag. It is also a small standalone crate so the
//! exact wire/signature vectors can be checked without compiling V8.
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub const CELLD_COMMIT: &str = "89e4ffc53a14ecb496d2ca5014ff9d19b0061ad9";
pub const STATE_PATH: &str = "/circulusd/state/v1/production:probe";
pub const STORAGE_PATH: &str = "/circulusd/native-storage/v1/production:probe";
pub const STATE_TYPE: &str = "application/vnd.circulusd.state-production-probe+cbor";
pub const STORAGE_TYPE: &str = "application/vnd.circulusd.native-storage-probe+cbor";
const STATE_PROTOCOL: &str = "circulus.state-production-probe.v1alpha1";
const STORAGE_PROTOCOL: &str = "circulus.native-storage-probe.v1alpha1";
const STATE_SCHEMA: &str =
    "sha256:33c8297cba9d6460e219e31e8c080927ed6275407c6eb159ea1f4d06fc87910f";
const STORAGE_SCHEMA_TEXT: &str = "circulus.native-storage-probe.v1alpha1|major=1|minor=0|native-ed25519|nonce=32|capability=native-storage,command-receipt|descriptor=production-dependency-v1|maxBytes=32768";
const MAX_INTEGER: u64 = (1 << 53) - 1;
static BOOT: OnceLock<Boot> = OnceLock::new();
static PUBLISHED: OnceLock<Snapshot> = OnceLock::new();

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    schema_version: u32,
    mode: String,
    measurement_output: String,
    runtime_key_file: String,
    runtime_key_id: String,
    instance_id: String,
    transaction_domain_id: String,
    probe_epoch: u64,
    epoch_guard_file: String,
    evidence_file: Option<String>,
    conformance_roots_file: Option<String>,
    conformance_report_file: Option<String>,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Measurement {
    pub schema_version: u32,
    pub celld_commit: String,
    pub build_digest: String,
    pub application_digest: String,
    pub effective_configuration_digest: String,
    pub instance_id: String,
    pub transaction_domain_id: String,
    pub runtime_key_id: String,
    pub runtime_public_key: String,
    pub probe_epoch: u64,
    pub process_id: u32,
    pub process_start_time_ticks: u64,
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Descriptor {
    schema_version: u32,
    backend_kind: String,
    build_digest: String,
    application_digest: String,
    instance_id: String,
    transaction_domain_id: String,
    durability_class: String,
    conformance_run_id: String,
    conformance_digest: String,
    runtime_key_id: String,
    probe_epoch: u64,
    production_eligible: bool,
    atomic_groups: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Evidence {
    schema_version: u32,
    descriptor: Descriptor,
    issued_at_unix: i64,
    expires_at_unix: i64,
    key_id: String,
    algorithm: String,
    signature: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Roots {
    schema_version: u32,
    trust_domain: String,
    roots: Vec<Root>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Root {
    key_id: String,
    algorithm: String,
    public_key: String,
}

struct Boot {
    config: Config,
    measurement: Measurement,
    signing_key: SigningKey,
    roots: Option<Vec<(String, VerifyingKey)>>,
    host_boot_id: String,
    // The epoch reservation lock survives for the complete native process.
    _epoch_guard: File,
}
struct Snapshot {
    descriptor: Descriptor,
    issued_at_unix: i64,
    expires_at_unix: i64,
    deadline: std::time::Instant,
}

pub fn digest_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
pub fn graph_digest(value: &serde_json::Value) -> Result<String> {
    // Sort recursively even if a transitive crate enables preserve_order.
    fn ordered(value: &serde_json::Value, depth: usize) -> Result<serde_json::Value> {
        ensure!(depth <= 64, "effective graph exceeds depth bound");
        Ok(match value {
            serde_json::Value::Object(fields) => {
                let mut entries = fields.iter().collect::<Vec<_>>();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                let mut out = serde_json::Map::new();
                for (key, value) in entries {
                    out.insert(key.clone(), ordered(value, depth + 1)?);
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(items) => serde_json::Value::Array(
                items
                    .iter()
                    .map(|v| ordered(v, depth + 1))
                    .collect::<Result<_>>()?,
            ),
            value => value.clone(),
        })
    }
    let encoded = serde_json::to_vec(&ordered(value, 0)?)?;
    ensure!(
        encoded.len() <= 8 << 20,
        "effective graph exceeds byte bound"
    );
    Ok(digest_bytes(&encoded))
}
fn now() -> Result<i64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}
fn identifier(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 256
        && text.as_bytes()[0].is_ascii_alphanumeric()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b))
}
fn digest(text: &str) -> bool {
    text.len() == 71
        && text.starts_with("sha256:")
        && text[7..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn decode_base64<const N: usize>(encoded: &str) -> Result<[u8; N]> {
    let bytes = STANDARD.decode(encoded).context("invalid base64")?;
    ensure!(STANDARD.encode(&bytes) == encoded, "noncanonical base64");
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid base64 length"))
}
fn validate_descriptor(d: &Descriptor) -> Result<()> {
    ensure!(
        d.schema_version == 1
            && d.backend_kind == "celld"
            && d.durability_class == "crash-durable-rpo0"
            && d.production_eligible
            && digest(&d.build_digest)
            && digest(&d.application_digest)
            && digest(&d.conformance_digest)
            && identifier(&d.instance_id)
            && identifier(&d.transaction_domain_id)
            && identifier(&d.conformance_run_id)
            && identifier(&d.runtime_key_id)
            && d.probe_epoch > 0
            && d.probe_epoch <= MAX_INTEGER
            && !d.atomic_groups.is_empty()
            && d.atomic_groups.len() <= 64
            && d.atomic_groups.iter().all(|g| identifier(g))
            && d.atomic_groups.windows(2).all(|w| w[0] < w[1]),
        "invalid descriptor"
    );
    Ok(())
}

// All input files are opened through held descriptors from /, never through a
// symlink/magic-link path. Parent ownership/mode checks happen on pinned inodes.
fn private_parent(path: &Path) -> Result<(File, CString)> {
    ensure!(path.is_absolute(), "absolute path required");
    let parts = path.components().collect::<Vec<_>>();
    ensure!(
        parts.len() > 1
            && matches!(parts[0], Component::RootDir)
            && parts[1..].iter().all(|c| matches!(c, Component::Normal(_))),
        "invalid path"
    );
    let canonical: std::path::PathBuf = parts.iter().map(|c| c.as_os_str()).collect();
    ensure!(
        canonical.as_os_str() == path.as_os_str(),
        "noncanonical path"
    );
    let initial = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    ensure!(initial >= 0, "cannot open root directory");
    let mut held = unsafe { File::from_raw_fd(initial) };
    let uid = unsafe { libc::geteuid() };
    let metadata = held.metadata()?;
    ensure!(
        metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
        "unsafe root directory"
    );
    for part in &parts[1..parts.len() - 1] {
        let name = CString::new(part.as_os_str().as_encoded_bytes())?;
        let fd = unsafe {
            libc::openat(
                held.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        ensure!(fd >= 0, "cannot open private directory");
        held = unsafe { File::from_raw_fd(fd) };
        let metadata = held.metadata()?;
        ensure!(
            (metadata.uid() == 0 || metadata.uid() == uid) && metadata.mode() & 0o022 == 0,
            "unsafe parent directory"
        );
    }
    let name = CString::new(parts.last().unwrap().as_os_str().as_encoded_bytes())?;
    Ok((held, name))
}
fn open_private(path: &str, flags: i32) -> Result<File> {
    let (parent, name) = private_parent(Path::new(path))?;
    open_private_at(&parent, &name, flags)
}
fn open_private_at(parent: &File, name: &CString, flags: i32) -> Result<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    ensure!(fd >= 0, "cannot open private file");
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.nlink() == 1
            && matches!(metadata.mode() & 0o7777, 0o400 | 0o600),
        "unsafe private file"
    );
    Ok(file)
}
fn metadata_identity(
    m: &std::fs::Metadata,
) -> (u64, u64, u32, u64, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.mode(),
        m.nlink(),
        m.uid(),
        m.gid(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn read_private(path: &str, limit: usize) -> Result<Vec<u8>> {
    let mut file = open_private(path, libc::O_RDONLY)?;
    let before = file.metadata()?;
    ensure!(before.len() <= limit as u64, "private file exceeds bound");
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() == before.len() as usize
            && metadata_identity(&before) == metadata_identity(&file.metadata()?),
        "private file changed"
    );
    Ok(bytes)
}
fn reserve_epoch(config: &Config) -> Result<File> {
    let (parent, name) = private_parent(Path::new(&config.epoch_guard_file))?;
    let mut file = open_private_at(&parent, &name, libc::O_RDWR | libc::O_CREAT)?;
    ensure!(
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
        "epoch reservation is busy"
    );
    let mut old = String::new();
    (&mut file).take(32).read_to_string(&mut old)?;
    let previous = if old.is_empty() {
        0
    } else {
        let parsed: u64 = old.parse().context("invalid epoch reservation")?;
        ensure!(parsed.to_string() == old, "invalid epoch reservation");
        parsed
    };
    ensure!(
        config.probe_epoch > previous && config.probe_epoch <= MAX_INTEGER,
        "probe epoch did not advance"
    );
    file.seek(SeekFrom::Start(0))?;
    file.set_len(0)?;
    file.write_all(config.probe_epoch.to_string().as_bytes())?;
    file.sync_all()?;
    parent.sync_all()?;
    Ok(file)
}
fn executable_digest() -> Result<String> {
    // /proc/self/exe is a kernel identity handle, not a user-controlled path.
    let mut file = File::open("/proc/self/exe")?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.len() <= 512 * 1024 * 1024,
        "invalid executable identity"
    );
    let mut hash = Sha256::new();
    let mut block = [0_u8; 65536];
    let mut total = 0;
    loop {
        let n = file.read(&mut block)?;
        if n == 0 {
            break;
        }
        total += n;
        ensure!(total <= 512 * 1024 * 1024, "executable exceeds bound");
        hash.update(&block[..n]);
    }
    ensure!(
        total as u64 == before.len()
            && metadata_identity(&before) == metadata_identity(&file.metadata()?),
        "executable changed"
    );
    Ok(format!("sha256:{}", hex::encode(hash.finalize())))
}
fn process_start_time_ticks() -> Result<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat")?;
    let end = stat.rfind(')').context("invalid process identity")?;
    // The first field after ')' is field 3; starttime is field 22.
    stat[end + 1..]
        .split_whitespace()
        .nth(19)
        .context("missing process starttime")?
        .parse()
        .context("invalid process starttime")
}

fn host_boot_id() -> Result<String> {
    let value = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let id = value.trim_end_matches('\n').replace('-', "");
    ensure!(
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid kernel boot identity"
    );
    Ok(id)
}

/// Install once, only for the real bucket+replication startup branch. Caller
/// passes loaded-byte measurements; no filename/version-string heuristic.
pub fn install(application_digest: String, effective_graph: serde_json::Value) -> Result<()> {
    let Some(path) = std::env::var_os("CELLD_CIRCULUSD_NATIVE_CONFIG") else {
        return Ok(());
    };
    let path = path.to_str().context("invalid native configuration path")?;
    let config: Config = serde_json::from_slice(&read_private(path, 64 << 10)?)
        .context("invalid native configuration")?;
    ensure!(
        config.schema_version == 1
            && matches!(config.mode.as_str(), "measure" | "attest")
            && identifier(&config.runtime_key_id)
            && identifier(&config.instance_id)
            && identifier(&config.transaction_domain_id)
            && config.probe_epoch > 0
            && digest(&application_digest),
        "invalid native configuration"
    );
    let proof_paths = [
        &config.evidence_file,
        &config.conformance_roots_file,
        &config.conformance_report_file,
    ];
    ensure!(
        proof_paths.iter().all(|p| p.is_some()) == (config.mode == "attest")
            && (config.mode != "measure" || proof_paths.iter().all(|p| p.is_none())),
        "invalid proof handoff configuration"
    );
    let mut paths = vec![
        path.to_owned(),
        config.measurement_output.clone(),
        config.runtime_key_file.clone(),
        config.epoch_guard_file.clone(),
    ];
    paths.extend(proof_paths.iter().filter_map(|p| p.as_ref().cloned()));
    ensure!(
        paths.iter().collect::<BTreeSet<_>>().len() == paths.len(),
        "native paths overlap"
    );
    for path in &paths {
        private_parent(Path::new(path))?;
    }
    let epoch_guard = reserve_epoch(&config)?;
    let mut encoded = read_private(&config.runtime_key_file, 64)?;
    ensure!(
        encoded.len() == 64
            && encoded
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)),
        "invalid runtime key"
    );
    let mut secret = [0_u8; 32];
    hex::decode_to_slice(&encoded, &mut secret).context("invalid runtime key")?;
    let key = SigningKey::from_bytes(&secret);
    secret.fill(0);
    encoded.fill(0);
    let roots = if let Some(path) = &config.conformance_roots_file {
        Some(decode_roots(
            &read_private(path, 1 << 20)?,
            &config.runtime_key_id,
            &key.verifying_key(),
        )?)
    } else {
        None
    };
    let measurement = Measurement {
        schema_version: 1,
        celld_commit: CELLD_COMMIT.into(),
        build_digest: executable_digest()?,
        application_digest,
        effective_configuration_digest: graph_digest(&effective_graph)?,
        instance_id: config.instance_id.clone(),
        transaction_domain_id: config.transaction_domain_id.clone(),
        runtime_key_id: config.runtime_key_id.clone(),
        runtime_public_key: STANDARD.encode(key.verifying_key().as_bytes()),
        probe_epoch: config.probe_epoch,
        process_id: std::process::id(),
        process_start_time_ticks: process_start_time_ticks()?,
    };
    let mut output = open_private(
        &config.measurement_output,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
    )?;
    serde_json::to_writer(&mut output, &measurement)?;
    output.write_all(b"\n")?;
    output.sync_all()?;
    BOOT.set(Boot {
        config,
        measurement,
        signing_key: key,
        roots,
        host_boot_id: host_boot_id()?,
        _epoch_guard: epoch_guard,
    })
    .map_err(|_| anyhow::anyhow!("native snapshot already installed"))?;
    Ok(())
}
pub fn configured() -> bool {
    std::env::var_os("CELLD_CIRCULUSD_NATIVE_CONFIG").is_some()
}
pub fn attestation_pending() -> bool {
    BOOT.get().is_some_and(|boot| boot.config.mode == "attest") && PUBLISHED.get().is_none()
}

fn decode_roots(
    bytes: &[u8],
    runtime_id: &str,
    runtime_key: &VerifyingKey,
) -> Result<Vec<(String, VerifyingKey)>> {
    let document: Roots = serde_json::from_slice(bytes).context("invalid roots")?;
    ensure!(
        document.schema_version == 1
            && document.trust_domain == "conformance-evidence"
            && (1..=64).contains(&document.roots.len()),
        "invalid roots"
    );
    let mut ids = BTreeSet::new();
    let mut materials = BTreeSet::new();
    let mut roots = Vec::new();
    for root in document.roots {
        ensure!(
            root.algorithm == "ed25519"
                && identifier(&root.key_id)
                && root.key_id != runtime_id
                && ids.insert(root.key_id.clone()),
            "invalid root role"
        );
        let encoded: [u8; 32] = decode_base64(&root.public_key)?;
        let point = CompressedEdwardsY(encoded)
            .decompress()
            .context("invalid root point")?;
        ensure!(
            point.compress().to_bytes() == encoded
                && point.is_torsion_free()
                && !point.is_small_order()
                && encoded != runtime_key.to_bytes()
                && materials.insert(encoded),
            "invalid root material"
        );
        roots.push((root.key_id, VerifyingKey::from_bytes(&encoded)?));
    }
    Ok(roots)
}

/// Called only by the native startup task. Missing files keep probes unsigned;
/// a malformed/stale handoff must never be retried as a different authority.
pub fn publish_once() -> Result<bool> {
    let Some(boot) = BOOT.get() else {
        return Ok(false);
    };
    if boot.config.mode != "attest" || PUBLISHED.get().is_some() {
        return Ok(false);
    }
    let evidence_path = boot.config.evidence_file.as_ref().unwrap();
    let report_path = boot.config.conformance_report_file.as_ref().unwrap();
    // Existence is a scheduling hint. Security comes from the held-file read,
    // never from this pathname observation.
    if !Path::new(evidence_path).exists() || !Path::new(report_path).exists() {
        return Ok(false);
    }
    let evidence_bytes = read_private(evidence_path, 64 << 10)?;
    let report_bytes = read_private(report_path, 1 << 20)?;
    let evidence: Evidence = serde_json::from_slice(&evidence_bytes).context("invalid evidence")?;
    validate_descriptor(&evidence.descriptor)?;
    let observed_now = now()?;
    ensure!(
        evidence.schema_version == 1
            && evidence.algorithm == "ed25519"
            && identifier(&evidence.key_id)
            && evidence.issued_at_unix > 0
            && evidence.expires_at_unix > evidence.issued_at_unix
            && evidence.expires_at_unix - evidence.issued_at_unix <= 24 * 60 * 60
            && observed_now >= evidence.issued_at_unix
            && observed_now < evidence.expires_at_unix,
        "invalid evidence lifetime"
    );
    let root = &boot
        .roots
        .as_ref()
        .unwrap()
        .iter()
        .find(|(id, _)| id == &evidence.key_id)
        .context("untrusted evidence root")?
        .1;
    let signature = Signature::from_bytes(&decode_base64::<64>(&evidence.signature)?);
    let value = map(vec![
        ("descriptor", descriptor_value(&evidence.descriptor)),
        ("issuedAtUnix", uint(evidence.issued_at_unix as u64)),
        ("expiresAtUnix", uint(evidence.expires_at_unix as u64)),
        ("keyId", text(&evidence.key_id)),
    ]);
    root.verify_strict(
        structured_digest("circulusd.production-dependency-evidence", value).as_bytes(),
        &signature,
    )
    .context("invalid evidence signature")?;
    let d = &evidence.descriptor;
    let m = &boot.measurement;
    ensure!(
        d.build_digest == m.build_digest
            && d.application_digest == m.application_digest
            && d.instance_id == m.instance_id
            && d.transaction_domain_id == m.transaction_domain_id
            && d.runtime_key_id == m.runtime_key_id
            && d.probe_epoch == m.probe_epoch
            && d.conformance_digest == digest_bytes(&report_bytes)
            && executable_digest()? == m.build_digest,
        "measurement mismatch"
    );
    // The report is signed indirectly by the exact conformance digest. Decode
    // only the observer's exact measurement (reject duplicate measurement keys).
    #[derive(Deserialize)]
    struct ReportBinding {
        measurement: Measurement,
        #[serde(rename = "runId")]
        run_id: String,
        #[serde(rename = "hostBootId")]
        host_boot_id: String,
    }
    let report: ReportBinding =
        serde_json::from_slice(&report_bytes).context("invalid report binding")?;
    ensure!(
        report.measurement == *m
            && report.run_id == d.conformance_run_id
            && report.host_boot_id == boot.host_boot_id
            && host_boot_id()? == boot.host_boot_id,
        "report measurement mismatch"
    );
    PUBLISHED
        .set(Snapshot {
            descriptor: evidence.descriptor,
            issued_at_unix: evidence.issued_at_unix,
            expires_at_unix: evidence.expires_at_unix,
            deadline: std::time::Instant::now()
                + std::time::Duration::from_secs((evidence.expires_at_unix - observed_now) as u64),
        })
        .map_err(|_| anyhow::anyhow!("native proof already published"))?;
    Ok(true)
}

pub fn reserved(path: &str) -> bool {
    matches!(path, STATE_PATH | STORAGE_PATH)
}
pub fn content_type(path: &str) -> Option<&'static str> {
    match path {
        STATE_PATH => Some(STATE_TYPE),
        STORAGE_PATH => Some(STORAGE_TYPE),
        _ => None,
    }
}
fn profile(path: &str) -> Result<(&'static str, String)> {
    match path {
        STATE_PATH => Ok((STATE_PROTOCOL, STATE_SCHEMA.into())),
        STORAGE_PATH => Ok((
            STORAGE_PROTOCOL,
            digest_bytes(STORAGE_SCHEMA_TEXT.as_bytes()),
        )),
        _ => bail!("invalid probe path"),
    }
}
/// Finite exact-request decoder: canonical request bytes are reconstructed and
/// compared, excluding every duplicate/unknown member or alternate encoding.
pub fn decode_challenge(path: &str, body: &[u8]) -> Result<[u8; 32]> {
    ensure!(body.len() <= 256, "probe request exceeds bound");
    let (protocol, schema) = profile(path)?;
    let prefix = [
        0xa5, 0x65, b'm', b'a', b'j', b'o', b'r', 0x01, 0x65, b'm', b'i', b'n', b'o', b'r', 0x00,
        0x65, b'n', b'o', b'n', b'c', b'e', 0x58, 0x20,
    ];
    ensure!(
        body.starts_with(&prefix) && body.len() >= prefix.len() + 32,
        "invalid challenge"
    );
    let nonce: [u8; 32] = body[prefix.len()..prefix.len() + 32].try_into().unwrap();
    let expected = map(vec![
        ("protocol", text(protocol)),
        ("major", uint(1)),
        ("minor", uint(0)),
        ("schemaDigest", text(&schema)),
        ("nonce", bytes(&nonce)),
    ]);
    ensure!(body == expected, "noncanonical challenge");
    Ok(nonce)
}
pub fn response(path: &str, nonce: &[u8; 32]) -> Result<Option<Vec<u8>>> {
    let Some(snapshot) = PUBLISHED.get() else {
        return Ok(None);
    };
    let current = now()?;
    if current < snapshot.issued_at_unix
        || current >= snapshot.expires_at_unix
        || std::time::Instant::now() >= snapshot.deadline
    {
        return Ok(None);
    }
    let boot = BOOT.get().context("missing native boot")?;
    if path == STORAGE_PATH
        && (!snapshot
            .descriptor
            .atomic_groups
            .iter()
            .any(|g| g == "native-storage")
            || !snapshot
                .descriptor
                .atomic_groups
                .iter()
                .any(|g| g == "command-receipt"))
    {
        return Ok(None);
    }
    Ok(Some(encode_response(
        path,
        &snapshot.descriptor,
        nonce,
        &boot.signing_key,
    )?))
}
fn encode_response(
    path: &str,
    d: &Descriptor,
    nonce: &[u8; 32],
    key: &SigningKey,
) -> Result<Vec<u8>> {
    let (protocol, schema) = profile(path)?;
    let signing_digest = structured_digest(
        "circulusd.production-dependency-probe",
        map(vec![
            ("descriptor", descriptor_value(d)),
            ("nonce", bytes(nonce)),
        ]),
    );
    let signature = key.sign(signing_digest.as_bytes()).to_bytes();
    let mut fields = vec![
        ("protocol", text(protocol)),
        ("major", uint(1)),
        ("minor", uint(0)),
        ("schemaDigest", text(&schema)),
        ("descriptor", descriptor_value(d)),
        ("keyId", text(&d.runtime_key_id)),
        ("signature", bytes(&signature)),
    ];
    if path == STATE_PATH {
        fields.push(("algorithm", text("ed25519")));
    } else {
        fields.push(("nonce", bytes(nonce)));
    }
    Ok(map(fields))
}
fn head(major: u8, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    if value < 24 {
        out.push((major << 5) | value as u8);
    } else if value <= 255 {
        out.extend([(major << 5) | 24, value as u8]);
    } else if value <= 65535 {
        out.push((major << 5) | 25);
        out.extend((value as u16).to_be_bytes());
    } else if value <= u32::MAX as u64 {
        out.push((major << 5) | 26);
        out.extend((value as u32).to_be_bytes());
    } else {
        out.push((major << 5) | 27);
        out.extend(value.to_be_bytes());
    }
    out
}
fn uint(value: u64) -> Vec<u8> {
    head(0, value)
}
fn text(value: &str) -> Vec<u8> {
    let mut v = head(3, value.len() as u64);
    v.extend(value.as_bytes());
    v
}
fn bytes(value: &[u8]) -> Vec<u8> {
    let mut v = head(2, value.len() as u64);
    v.extend(value);
    v
}
fn array(values: Vec<Vec<u8>>) -> Vec<u8> {
    let mut v = head(4, values.len() as u64);
    for value in values {
        v.extend(value);
    }
    v
}
fn map(fields: Vec<(&str, Vec<u8>)>) -> Vec<u8> {
    let mut fields = fields
        .into_iter()
        .map(|(k, v)| (text(k), v))
        .collect::<Vec<_>>();
    fields.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then(a.0.cmp(&b.0)));
    let mut v = head(5, fields.len() as u64);
    for (key, value) in fields {
        v.extend(key);
        v.extend(value);
    }
    v
}
fn structured_digest(domain: &str, payload: Vec<u8>) -> String {
    digest_bytes(&array(vec![
        text("circulusd.hash"),
        uint(1),
        text(domain),
        uint(1),
        payload,
    ]))
}
fn descriptor_value(d: &Descriptor) -> Vec<u8> {
    map(vec![
        ("schemaVersion", uint(d.schema_version as u64)),
        ("backendKind", text(&d.backend_kind)),
        ("buildDigest", text(&d.build_digest)),
        ("applicationDigest", text(&d.application_digest)),
        ("instanceId", text(&d.instance_id)),
        ("transactionDomainId", text(&d.transaction_domain_id)),
        ("durabilityClass", text(&d.durability_class)),
        ("conformanceRunId", text(&d.conformance_run_id)),
        ("conformanceDigest", text(&d.conformance_digest)),
        ("runtimeKeyId", text(&d.runtime_key_id)),
        ("probeEpoch", uint(d.probe_epoch)),
        (
            "productionEligible",
            vec![if d.production_eligible { 0xf5 } else { 0xf4 }],
        ),
        (
            "atomicGroups",
            array(d.atomic_groups.iter().map(|g| text(g)).collect()),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../fixtures/state-production-probe-v1alpha1.json"
        ))
        .unwrap()
    }
    #[test]
    fn frozen_request_and_signed_response() {
        let f = fixture();
        let request = hex::decode(f["requestCborHex"].as_str().unwrap()).unwrap();
        let nonce = decode_challenge(STATE_PATH, &request).unwrap();
        let descriptor: Descriptor = serde_json::from_value(f["descriptor"].clone()).unwrap();
        validate_descriptor(&descriptor).unwrap();
        let signature = hex::decode(f["signatureHex"].as_str().unwrap()).unwrap();
        let public = hex::decode(f["runtimePublicKeyHex"].as_str().unwrap()).unwrap();
        let signing_digest = structured_digest(
            "circulusd.production-dependency-probe",
            map(vec![
                ("descriptor", descriptor_value(&descriptor)),
                ("nonce", bytes(&nonce)),
            ]),
        );
        assert_eq!(signing_digest, f["signingDigest"]);
        VerifyingKey::from_bytes(&public.try_into().unwrap())
            .unwrap()
            .verify_strict(
                signing_digest.as_bytes(),
                &Signature::from_slice(&signature).unwrap(),
            )
            .unwrap();
        let response = map(vec![
            ("protocol", text(STATE_PROTOCOL)),
            ("major", uint(1)),
            ("minor", uint(0)),
            ("schemaDigest", text(STATE_SCHEMA)),
            ("descriptor", descriptor_value(&descriptor)),
            ("keyId", text(&descriptor.runtime_key_id)),
            ("algorithm", text("ed25519")),
            ("signature", bytes(&signature)),
        ]);
        assert_eq!(
            hex::encode(response),
            f["responseCborHex"].as_str().unwrap()
        );
    }
    #[test]
    fn alternate_request_encodings_and_members_are_rejected() {
        let f = fixture();
        let original = hex::decode(f["requestCborHex"].as_str().unwrap()).unwrap();
        for offset in 0..original.len() {
            let mut changed = original.clone();
            if (23..55).contains(&offset) {
                continue;
            }
            changed[offset] ^= 1;
            assert!(
                decode_challenge(STATE_PATH, &changed).is_err(),
                "offset {offset}"
            );
        }
        let mut trailing = original.clone();
        trailing.push(0);
        assert!(decode_challenge(STATE_PATH, &trailing).is_err());
        assert!(decode_challenge(STORAGE_PATH, &original).is_err());
        assert!(decode_challenge(STATE_PATH, &original[..original.len() - 1]).is_err());
        assert!(decode_challenge(STATE_PATH, &[0; 257]).is_err());
    }
    #[test]
    fn independent_roles_and_prime_order_points() {
        let runtime = SigningKey::from_bytes(&[7; 32]).verifying_key();
        let root = SigningKey::from_bytes(&[8; 32]).verifying_key();
        let make = |id: &str, key: &[u8]| {
            serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"trustDomain":"conformance-evidence","roots":[{"keyId":id,"algorithm":"ed25519","publicKey":STANDARD.encode(key)}]})).unwrap()
        };
        assert!(decode_roots(&make("observer", root.as_bytes()), "runtime", &runtime).is_ok());
        assert!(decode_roots(&make("runtime", root.as_bytes()), "runtime", &runtime).is_err());
        assert!(decode_roots(&make("observer", runtime.as_bytes()), "runtime", &runtime).is_err());
        assert!(decode_roots(&make("observer", &[0; 32]), "runtime", &runtime).is_err());
    }
    #[test]
    fn descriptor_order_and_numeric_bounds() {
        let mut d: Descriptor = serde_json::from_value(fixture()["descriptor"].clone()).unwrap();
        d.atomic_groups.reverse();
        assert!(validate_descriptor(&d).is_err());
        d.atomic_groups.reverse();
        d.probe_epoch = MAX_INTEGER + 1;
        assert!(validate_descriptor(&d).is_err());
        d.probe_epoch = 1;
        d.production_eligible = false;
        assert!(validate_descriptor(&d).is_err());
    }
    #[test]
    fn graph_covers_changes_without_exposing_values() {
        let a = serde_json::json!({"worker":{"applicationDigest":"a","vars":[["SECRET","hidden"]]},"bucket":"qualification","outputGate":true});
        let mut b = a.clone();
        b["outputGate"] = serde_json::Value::Bool(false);
        assert_ne!(graph_digest(&a).unwrap(), graph_digest(&b).unwrap());
        let digest = graph_digest(&a).unwrap();
        assert!(!digest.contains("hidden"));
        assert!(super::digest(&digest));
    }

    fn private_test_dir(label: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(format!(".test-{label}-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }
    fn private_write(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }
    #[test]
    fn held_file_paths_reject_symlinks_permissions_and_hardlinks() {
        use std::os::unix::fs::PermissionsExt;
        let dir = private_test_dir("held");
        let file = dir.join("safe");
        private_write(&file, b"snapshot");
        assert_eq!(
            read_private(file.to_str().unwrap(), 8).unwrap(),
            b"snapshot"
        );
        assert!(read_private(file.to_str().unwrap(), 7).is_err());
        let link = dir.join("alias");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(read_private(link.to_str().unwrap(), 8).is_err());
        let hard = dir.join("hard");
        std::fs::hard_link(&file, &hard).unwrap();
        assert!(read_private(file.to_str().unwrap(), 8).is_err());
        std::fs::remove_file(hard).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private(file.to_str().unwrap(), 8).is_err());
        let parent = dir.join("parent");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        let child = parent.join("child");
        private_write(&child, b"x");
        assert!(read_private(child.to_str().unwrap(), 1).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn independent_signed_handoff_publishes_only_exact_current_process() {
        let dir = private_test_dir("publication");
        let runtime = SigningKey::from_bytes(&[19; 32]);
        let observer = SigningKey::from_bytes(&[20; 32]);
        let keyfile = dir.join("runtime-key");
        private_write(&keyfile, hex::encode(runtime.to_bytes()).as_bytes());
        let rootsfile = dir.join("roots");
        private_write(&rootsfile,&serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"trustDomain":"conformance-evidence","roots":[{"keyId":"independent-observer","algorithm":"ed25519","publicKey":STANDARD.encode(observer.verifying_key().as_bytes())}]})).unwrap());
        let evidencefile = dir.join("evidence");
        let reportfile = dir.join("report");
        let measurementfile = dir.join("measurement");
        let configfile = dir.join("config");
        private_write(&configfile,&serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"mode":"attest","measurementOutput":measurementfile,"runtimeKeyFile":keyfile,"runtimeKeyId":"native-runtime","instanceId":"native-instance","transactionDomainId":"native-domain","probeEpoch":1,"epochGuardFile":dir.join("epoch"),"evidenceFile":evidencefile,"conformanceRootsFile":rootsfile,"conformanceReportFile":reportfile})).unwrap());
        std::env::set_var("CELLD_CIRCULUSD_NATIVE_CONFIG", &configfile);
        install(
            digest_bytes(b"actual loaded app"),
            serde_json::json!({"workers":["actual app"],"outputGate":true}),
        )
        .unwrap();
        assert!(!publish_once().unwrap());
        assert!(response(STATE_PATH, &[0; 32]).unwrap().is_none());
        let actual = BOOT.get().unwrap().measurement.clone();
        let produce = |measurement: &Measurement| {
            let report=serde_json::to_vec(&serde_json::json!({"measurement":measurement,"runId":"independent-run","hostBootId":host_boot_id().unwrap(),"rawFaultObservations":["recorded separately"]})).unwrap();
            private_write(&reportfile, &report);
            let d = Descriptor {
                schema_version: 1,
                backend_kind: "celld".into(),
                build_digest: actual.build_digest.clone(),
                application_digest: actual.application_digest.clone(),
                instance_id: actual.instance_id.clone(),
                transaction_domain_id: actual.transaction_domain_id.clone(),
                durability_class: "crash-durable-rpo0".into(),
                conformance_run_id: "independent-run".into(),
                conformance_digest: digest_bytes(&report),
                runtime_key_id: actual.runtime_key_id.clone(),
                probe_epoch: actual.probe_epoch,
                production_eligible: true,
                atomic_groups: vec!["command-receipt".into(), "native-storage".into()],
            };
            let issued = now().unwrap();
            let expires = issued + 60;
            let signing = structured_digest(
                "circulusd.production-dependency-evidence",
                map(vec![
                    ("descriptor", descriptor_value(&d)),
                    ("issuedAtUnix", uint(issued as u64)),
                    ("expiresAtUnix", uint(expires as u64)),
                    ("keyId", text("independent-observer")),
                ]),
            );
            private_write(&evidencefile,&serde_json::to_vec(&serde_json::json!({"schemaVersion":1,"descriptor":d,"issuedAtUnix":issued,"expiresAtUnix":expires,"keyId":"independent-observer","algorithm":"ed25519","signature":STANDARD.encode(observer.sign(signing.as_bytes()).to_bytes())})).unwrap());
        };
        let mut earlier = actual.clone();
        earlier.process_start_time_ticks -= 1;
        produce(&earlier);
        assert!(publish_once().is_err());
        assert!(response(STATE_PATH, &[0; 32]).unwrap().is_none());
        produce(&actual);
        assert!(publish_once().unwrap());
        let before = response(STATE_PATH, &[1; 32]).unwrap().unwrap();
        private_write(&evidencefile, b"{}\n");
        assert!(!publish_once().unwrap());
        assert_eq!(response(STATE_PATH, &[1; 32]).unwrap().unwrap(), before);
        assert!(response(STORAGE_PATH, &[1; 32]).unwrap().is_some());
        assert!(install(digest_bytes(b"different app"), serde_json::json!({})).is_err());
        std::env::remove_var("CELLD_CIRCULUSD_NATIVE_CONFIG");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
