// Copyright 2024 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::{
    DiagnosticJobEnvelope, DiagnosticJobExecution, DiagnosticJobTarget, ProfileProvenance, TrustedDiagnosticJobSigner,
    execute_diagnostic_job,
};
use crate::connect::config::HeartbeatConfig;
use crate::connect::report_upload::ReportUploadClient;
use crate::connect::telemetry::{TelemetryDelivery, TelemetryTransport};

const PROTOCOL_VERSION: &str = "v1";
const MAX_EXECUTABLE_BYTES: u64 = 2_147_483_648;
const INITIAL_DELIVERY_BACKOFF: Duration = Duration::from_secs(1);
const MAX_DELIVERY_BACKOFF: Duration = Duration::from_secs(30);
const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: usize = 524_288;
const MAX_STATE_FILES: usize = 65_536;
const DELIVERED_STATE_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

// The executable identity is stable for this process; avoid hashing the full binary for every profile request.
static EXECUTABLE_PROVENANCE: tokio::sync::OnceCell<ProfileProvenance> = tokio::sync::OnceCell::const_new();

#[derive(Clone)]
pub(crate) struct DiagnosticJobRuntime {
    config: HeartbeatConfig,
    signer: TrustedDiagnosticJobSigner,
    states: Arc<Mutex<BTreeMap<String, JobState>>>,
    deliveries: DeliveryRegistry,
    store: JobStateStore,
}

#[derive(Clone, Default)]
struct DeliveryRegistry(Arc<Mutex<HashSet<String>>>);

struct DeliveryLease {
    job_id: String,
    registry: DeliveryRegistry,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "state", content = "result", rename_all = "SCREAMING_SNAKE_CASE")]
enum JobState {
    Active,
    Completed(DiagnosticJobExecution),
    Uploaded(UploadedDiagnosticJobResult),
    Delivered,
}

#[derive(Clone)]
struct JobStateStore {
    directory: PathBuf,
    // Serialize state-file operations so the file-count check, pruning and atomic
    // replacement form one process-local critical section.
    operation_lock: Arc<Mutex<()>>,
    // Count .json records once per process, then maintain it with successful
    // creates/removals. This avoids a directory scan on every offered job.
    state_file_count_cache: Arc<Mutex<Option<usize>>>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct UploadedDiagnosticJobResult {
    job_id: String,
    // Persist the idempotency key before the first network request. Option keeps
    // compatibility with Uploaded state files written by older Agent v1 builds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    outcome: String,
    reason: String,
    artifact_name: Option<String>,
    artifact_sha256: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticJobResultRequest<'a> {
    protocol_version: &'static str,
    request_id: &'a str,
    job_id: &'a str,
    outcome: &'a str,
    reason: &'a str,
    artifact_name: Option<&'a str>,
    artifact_sha256: Option<&'a str>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DeliveryAttempt {
    Accepted,
    Retry,
    Stop,
}

impl DiagnosticJobRuntime {
    pub(crate) fn from_config(config: &HeartbeatConfig) -> Option<Self> {
        let state_root = config.state_root()?.to_path_buf();
        Some(Self {
            config: config.clone(),
            signer: config.diagnostic_job_signer.clone()?,
            states: Arc::new(Mutex::new(BTreeMap::new())),
            deliveries: DeliveryRegistry::default(),
            store: JobStateStore {
                directory: state_root.join("diagnostic-jobs"),
                operation_lock: Arc::new(Mutex::new(())),
                state_file_count_cache: Arc::new(Mutex::new(None)),
            },
        })
    }

    pub(crate) fn offer(&self, envelope: DiagnosticJobEnvelope, shutdown: &CancellationToken) {
        let Ok((target, identity)) = target_and_identity(&self.config) else {
            return;
        };
        let Ok(job) = self.signer.verify(&envelope, &target, Utc::now()) else {
            return;
        };
        let job_id = job.job_id().to_owned();
        let cached = {
            let Ok(mut states) = self.states.lock() else {
                return;
            };
            match states.get(&job_id) {
                Some(JobState::Active) => return,
                Some(JobState::Completed(result)) => Some(result.clone()),
                Some(JobState::Uploaded(result)) => {
                    let result = result.clone();
                    let expire_time = job.expire_time().to_owned();
                    drop(states);
                    let runtime = self.clone();
                    let cancel = shutdown.child_token();
                    tokio::spawn(async move {
                        runtime.deliver_uploaded(result, &expire_time, &cancel).await;
                    });
                    return;
                }
                Some(JobState::Delivered) => return,
                None => match self.store.load(&job_id) {
                    Ok(Some(JobState::Completed(result))) => {
                        if !valid_execution(&result, &job_id) {
                            return;
                        }
                        states.insert(job_id.clone(), JobState::Completed(result.clone()));
                        Some(result)
                    }
                    Ok(Some(JobState::Delivered)) => return,
                    Ok(Some(JobState::Uploaded(result))) => {
                        if !valid_uploaded_result(&result, &job_id) {
                            return;
                        }
                        states.insert(job_id.clone(), JobState::Uploaded(result.clone()));
                        let expire_time = job.expire_time().to_owned();
                        drop(states);
                        let runtime = self.clone();
                        let cancel = shutdown.child_token();
                        tokio::spawn(async move {
                            runtime.deliver_uploaded(result, &expire_time, &cancel).await;
                        });
                        return;
                    }
                    Ok(Some(JobState::Active)) => {
                        let result = failed_execution(&job_id, "INTERRUPTED");
                        if self.store.save(&job_id, &JobState::Completed(result.clone())).is_err() {
                            return;
                        }
                        states.insert(job_id.clone(), JobState::Completed(result.clone()));
                        Some(result)
                    }
                    Ok(None) => {
                        let evicted = match self.store.save_new(&job_id, &JobState::Active) {
                            Ok(evicted) => evicted,
                            Err(()) => {
                                tracing::error!(job_id = %job_id, "failed to persist initial diagnostic job state; job was not executed");
                                return;
                            }
                        };
                        // Keep the in-memory replay cache consistent with Delivered
                        // records reclaimed from the persistent store at capacity.
                        for evicted_job_id in evicted {
                            states.remove(&evicted_job_id);
                        }
                        states.insert(job_id.clone(), JobState::Active);
                        None
                    }
                    Err(()) => return,
                },
            }
        };
        let runtime = self.clone();
        let cancel = shutdown.child_token();
        let expire_time = job.expire_time().to_owned();
        tokio::spawn(async move {
            let result = match cached {
                Some(result) => result,
                None => {
                    let result = match executable_provenance().await {
                        Ok(provenance) => execute_diagnostic_job(job, &identity, provenance, &cancel)
                            .await
                            .unwrap_or_else(|error| failed_execution(&job_id, error.reason())),
                        Err(reason) => failed_execution(&job_id, reason),
                    };
                    let terminal = JobState::Completed(result.clone());
                    if runtime.store.save(&job_id, &terminal).is_ok() {
                        if let Ok(mut states) = runtime.states.lock() {
                            states.insert(job_id.clone(), terminal);
                        }
                    } else {
                        tracing::error!(job_id = %job_id, "failed to persist completed diagnostic job state");
                    }
                    result
                }
            };
            if let Some(uploaded) = prepare_result(&runtime, result, &cancel).await {
                runtime.deliver_uploaded(uploaded, &expire_time, &cancel).await;
            }
        });
    }

    async fn deliver_uploaded(&self, mut result: UploadedDiagnosticJobResult, expire_time: &str, cancel: &CancellationToken) {
        let job_id = result.job_id.clone();
        let Some(_lease) = self.deliveries.acquire(&job_id) else {
            return;
        };
        // Older persisted Uploaded records do not contain requestId. Migrate them
        // atomically before sending so a crash after server acceptance cannot cause
        // a retry with a new idempotency key.
        if self.store.ensure_delivery_request_id(&mut result).is_err() {
            tracing::warn!(job_id = %job_id, "failed to persist diagnostic result request id");
            return;
        }
        if let Ok(mut states) = self.states.lock() {
            states.insert(job_id.clone(), JobState::Uploaded(result.clone()));
        }
        if deliver_result(&self.config, &result, expire_time, cancel).await {
            if self.store.save(&job_id, &JobState::Delivered).is_ok() {
                // Persisted Delivered records are the replay barrier. Do not keep
                // them in the in-memory map: that map should remain bounded as old
                // Delivered records are eventually pruned from disk.
                if let Ok(mut states) = self.states.lock() {
                    states.remove(&job_id);
                }
            } else {
                // Keep the Uploaded state (and its persisted requestId) so a restart
                // retries with the same idempotency key instead of executing again.
                tracing::error!(job_id = %job_id, "result accepted but Delivered state could not be persisted; preserving Uploaded state for safe retry");
            }
        }
    }
}

impl DeliveryRegistry {
    fn acquire(&self, job_id: &str) -> Option<DeliveryLease> {
        let mut active = self.0.lock().ok()?;
        if !active.insert(job_id.to_owned()) {
            return None;
        }
        Some(DeliveryLease {
            job_id: job_id.to_owned(),
            registry: self.clone(),
        })
    }
}

impl Drop for DeliveryLease {
    fn drop(&mut self) {
        if let Ok(mut active) = self.registry.0.lock() {
            active.remove(&self.job_id);
        }
    }
}

impl JobStateStore {
    fn path(&self, job_id: &str) -> PathBuf {
        self.directory.join(format!("{job_id}.json"))
    }

    fn load(&self, job_id: &str) -> Result<Option<JobState>, ()> {
        let _guard = self.operation_lock.lock().map_err(|_| ())?;
        self.load_unlocked(job_id)
    }

    fn load_unlocked(&self, job_id: &str) -> Result<Option<JobState>, ()> {
        let path = self.path(job_id);
        let initial = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(()),
        };
        if !initial.file_type().is_file() || initial.len() == 0 || initial.len() > MAX_STATE_BYTES {
            return Err(());
        }
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options.open(path).map_err(|_| ())?;
        let opened = file.metadata().map_err(|_| ())?;
        if !secure_state_file(&initial, &opened) {
            return Err(());
        }
        let mut bytes = Vec::with_capacity(usize::try_from(initial.len()).map_err(|_| ())?);
        file.take(MAX_STATE_BYTES + 1).read_to_end(&mut bytes).map_err(|_| ())?;
        if u64::try_from(bytes.len()).map_err(|_| ())? > MAX_STATE_BYTES {
            return Err(());
        }
        serde_json::from_slice(&bytes).map(Some).map_err(|_| ())
    }

    fn save(&self, job_id: &str, state: &JobState) -> Result<(), ()> {
        let _guard = self.operation_lock.lock().map_err(|_| ())?;
        self.ensure_directory()?;
        let destination = self.path(job_id);
        match fs::symlink_metadata(&destination) {
            Ok(metadata) if metadata.file_type().is_file() => self.write_state_unlocked(job_id, state),
            // State transitions must update an existing record. A missing state is
            // not silently recreated because doing so could bypass replay control.
            Ok(_) => Err(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(()),
            Err(_) => Err(()),
        }
    }

    fn save_new(&self, job_id: &str, state: &JobState) -> Result<Vec<String>, ()> {
        let _guard = self.operation_lock.lock().map_err(|_| ())?;
        self.save_new_unlocked(job_id, state, MAX_STATE_FILES)
    }

    #[cfg(test)]
    fn save_new_with_limit(&self, job_id: &str, state: &JobState, max_state_files: usize) -> Result<Vec<String>, ()> {
        let _guard = self.operation_lock.lock().map_err(|_| ())?;
        self.save_new_unlocked(job_id, state, max_state_files)
    }

    fn save_new_unlocked(&self, job_id: &str, state: &JobState, max_state_files: usize) -> Result<Vec<String>, ()> {
        if max_state_files == 0 {
            return Err(());
        }
        self.ensure_directory()?;
        let destination = self.path(job_id);
        match fs::symlink_metadata(&destination) {
            Ok(_) => return Err(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(()),
        }

        let mut evicted = Vec::new();
        if self.cached_state_file_count_unlocked()? >= max_state_files {
            let cutoff = SystemTime::now()
                .checked_sub(DELIVERED_STATE_RETENTION)
                .unwrap_or(SystemTime::UNIX_EPOCH);
            evicted = self.prune_delivered_before_unlocked(cutoff)?;
            if self.cached_state_file_count_unlocked()? >= max_state_files {
                return Err(());
            }
        }

        self.write_state_unlocked(job_id, state)?;
        self.adjust_cached_state_file_count_unlocked(1)?;
        Ok(evicted)
    }

    fn write_state_unlocked(&self, job_id: &str, state: &JobState) -> Result<(), ()> {
        let bytes = serde_json::to_vec(state).map_err(|_| ())?;
        if bytes.is_empty() || u64::try_from(bytes.len()).map_err(|_| ())? > MAX_STATE_BYTES {
            return Err(());
        }
        let temporary = self.directory.join(format!(".{job_id}.{}.tmp", Uuid::new_v4()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary).map_err(|_| ())?;
        let result = file
            .write_all(&bytes)
            .and_then(|()| file.sync_all())
            .and_then(|()| fs::rename(&temporary, self.path(job_id)))
            .and_then(|()| sync_directory(&self.directory));
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result.map_err(|_| ())
    }

    fn ensure_delivery_request_id(&self, result: &mut UploadedDiagnosticJobResult) -> Result<(), ()> {
        match result.request_id.as_deref() {
            Some(request_id) if valid_delivery_request_id(request_id) => Ok(()),
            Some(_) => Err(()),
            None => {
                result.request_id = Some(Uuid::new_v4().to_string());
                self.save(&result.job_id, &JobState::Uploaded(result.clone()))
            }
        }
    }

    // Delivered records are replay barriers only while a signed job could still
    // be valid. Prune them only when the state-file cap is reached, not on every
    // incoming job, and never prune pending or unreadable states.
    #[cfg(test)]
    fn prune_delivered_before(&self, cutoff: SystemTime) -> Result<Vec<String>, ()> {
        let _guard = self.operation_lock.lock().map_err(|_| ())?;
        self.ensure_directory()?;
        self.prune_delivered_before_unlocked(cutoff)
    }

    fn prune_delivered_before_unlocked(&self, cutoff: SystemTime) -> Result<Vec<String>, ()> {
        let mut removed = Vec::new();
        for entry in fs::read_dir(&self.directory).map_err(|_| ())? {
            let entry = entry.map_err(|_| ())?;
            let name = entry.file_name();
            let Some(filename) = name.to_str() else {
                continue;
            };
            let Some(job_id) = filename.strip_suffix(".json") else {
                continue;
            };
            // State files are keyed by canonical UUIDv7 job IDs. Ignore any
            // unrelated or malformed files in this private directory.
            let Ok(parsed_id) = Uuid::parse_str(job_id) else {
                continue;
            };
            if parsed_id.get_version_num() != 7 || parsed_id.to_string() != job_id {
                continue;
            }
            let path = entry.path();
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_file() => metadata,
                _ => continue,
            };
            match metadata.modified() {
                Ok(modified) if modified <= cutoff => {}
                _ => continue,
            }
            // Corrupt, unreadable, or untrusted files are deliberately retained.
            // Cleanup must never turn an uncertain state into permission to rerun.
            if !matches!(self.load_unlocked(job_id), Ok(Some(JobState::Delivered))) {
                continue;
            }
            fs::remove_file(path).map_err(|_| ())?;
            self.adjust_cached_state_file_count_unlocked(-1)?;
            removed.push(job_id.to_owned());
        }
        if !removed.is_empty() {
            sync_directory(&self.directory).map_err(|_| ())?;
        }
        Ok(removed)
    }

    // The operation lock must be held by the caller. The first call scans the
    // directory; subsequent calls are O(1) until this process creates/removes a
    // state file. Only this process may write to the private state directory.
    fn cached_state_file_count_unlocked(&self) -> Result<usize, ()> {
        let mut cached = self.state_file_count_cache.lock().map_err(|_| ())?;
        if cached.is_none() {
            *cached = Some(self.state_file_count()?);
        }
        cached.as_ref().copied().ok_or(())
    }

    // Positive values count successful creates; negative values count removals.
    fn adjust_cached_state_file_count_unlocked(&self, delta: isize) -> Result<(), ()> {
        let mut cached = self.state_file_count_cache.lock().map_err(|_| ())?;
        if let Some(count) = cached.as_mut() {
            let updated = if delta >= 0 {
                count.checked_add(usize::try_from(delta).map_err(|_| ())?).ok_or(())?
            } else {
                count.checked_sub(delta.unsigned_abs()).ok_or(())?
            };
            *count = updated;
        }
        Ok(())
    }

    fn ensure_directory(&self) -> Result<(), ()> {
        fs::create_dir_all(&self.directory).map_err(|_| ())?;
        #[cfg(unix)]
        {
            let metadata = fs::symlink_metadata(&self.directory).map_err(|_| ())?;
            if !metadata.file_type().is_dir() || metadata.uid() != rustix::process::geteuid().as_raw() {
                return Err(());
            }
            fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700)).map_err(|_| ())?;
        }
        Ok(())
    }

    fn state_file_count(&self) -> Result<usize, ()> {
        let mut count = 0_usize;
        for entry in fs::read_dir(&self.directory).map_err(|_| ())? {
            let entry = entry.map_err(|_| ())?;
            if entry.file_name().to_string_lossy().ends_with(".json") {
                count = count.checked_add(1).ok_or(())?;
            }
        }
        Ok(count)
    }
}

#[cfg(unix)]
fn secure_state_file(initial: &fs::Metadata, opened: &fs::Metadata) -> bool {
    opened.is_file()
        && opened.uid() == rustix::process::geteuid().as_raw()
        && opened.permissions().mode() & 0o077 == 0
        && opened.dev() == initial.dev()
        && opened.ino() == initial.ino()
}

#[cfg(not(unix))]
fn secure_state_file(_initial: &fs::Metadata, _opened: &fs::Metadata) -> bool {
    false
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

fn target_and_identity(config: &HeartbeatConfig) -> Result<(DiagnosticJobTarget, crate::connect::DeviceIdentity), ()> {
    let credential = config.credential_store.load().map_err(|_| ())?.ok_or(())?;
    let parts: Vec<_> = credential.name.split('/').collect();
    if parts.len() != 6
        || parts[0] != "organizations"
        || parts[1].is_empty()
        || parts[2] != "clusters"
        || parts[3].is_empty()
        || parts[4] != "clusterDevices"
        || parts[5] != credential.uid
    {
        return Err(());
    }
    let identity = config.identity_store.load().map_err(|_| ())?.ok_or(())?;
    Ok((
        DiagnosticJobTarget {
            organization_name: format!("organizations/{}", parts[1]),
            cluster_name: format!("organizations/{}/clusters/{}", parts[1], parts[3]),
            device_name: credential.name,
        },
        identity,
    ))
}

pub(super) async fn executable_provenance() -> Result<ProfileProvenance, &'static str> {
    let provenance = EXECUTABLE_PROVENANCE
        .get_or_try_init(|| async {
            let digest = tokio::task::spawn_blocking(hash_current_executable)
                .await
                .map_err(|_| "PROVENANCE_FAILED")?
                .map_err(|_| "PROVENANCE_FAILED")?;
            Ok::<_, &'static str>(ProfileProvenance::new(
                crate::version::build::COMMIT_HASH,
                digest,
                env!("CARGO_PKG_VERSION"),
                enabled_build_features(),
            ))
        })
        .await?;
    Ok(provenance.clone())
}

fn hash_current_executable() -> Result<String, ()> {
    let path = std::env::current_exe().map_err(|_| ())?;
    let mut file = File::open(path).map_err(|_| ())?;
    let metadata = file.metadata().map_err(|_| ())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_EXECUTABLE_BYTES {
        return Err(());
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer).map_err(|_| ())?;
        if read == 0 {
            break;
        }
        total = total.checked_add(u64::try_from(read).map_err(|_| ())?).ok_or(())?;
        if total > MAX_EXECUTABLE_BYTES {
            return Err(());
        }
        hasher.update(&buffer[..read]);
    }
    if total != metadata.len() {
        return Err(());
    }
    Ok(hex_simd::encode_to_string(hasher.finalize(), hex_simd::AsciiCase::Lower))
}

fn enabled_build_features() -> Vec<String> {
    let mut features = Vec::new();
    for (enabled, name) in [
        (cfg!(feature = "connect-e2e-short-credentials"), "connect-e2e-short-credentials"),
        (cfg!(feature = "dial9"), "dial9"),
        (cfg!(feature = "e2e-test-hooks"), "e2e-test-hooks"),
        (cfg!(feature = "ftps"), "ftps"),
        (cfg!(feature = "full"), "full"),
        (cfg!(feature = "gcs"), "gcs"),
        (cfg!(feature = "hotpath"), "hotpath"),
        (cfg!(feature = "hotpath-alloc"), "hotpath-alloc"),
        (cfg!(feature = "hotpath-cpu"), "hotpath-cpu"),
        (cfg!(feature = "io-scheduler-debug"), "io-scheduler-debug"),
        (cfg!(feature = "license"), "license"),
        (cfg!(feature = "metrics-gpu"), "metrics-gpu"),
        (cfg!(feature = "offline-enrollment-e2e-root"), "offline-enrollment-e2e-root"),
        (cfg!(feature = "pyroscope"), "pyroscope"),
        (cfg!(feature = "rio-v2"), "rio-v2"),
        (cfg!(feature = "sftp"), "sftp"),
        (cfg!(feature = "swift"), "swift"),
        (cfg!(feature = "tracing-chunk-debug"), "tracing-chunk-debug"),
        (cfg!(feature = "webdav"), "webdav"),
    ] {
        if enabled {
            features.push(name.to_owned());
        }
    }
    features
}

fn failed_execution(job_id: &str, reason: &'static str) -> DiagnosticJobExecution {
    let reason = if reason == "CANCELLED" {
        "CANCELLED"
    } else if reason == "LIMIT_EXCEEDED" {
        "LIMIT_EXCEEDED"
    } else {
        "COLLECTION_FAILED"
    };
    DiagnosticJobExecution {
        job_id: job_id.to_owned(),
        outcome: if reason == "CANCELLED" { "CANCELLED" } else { "FAILED" }.to_owned(),
        reason: reason.to_owned(),
        artifact_uid: None,
        artifact_sha256: None,
        artifact_bytes: None,
    }
}

async fn prepare_result(
    runtime: &DiagnosticJobRuntime,
    result: DiagnosticJobExecution,
    cancel: &CancellationToken,
) -> Option<UploadedDiagnosticJobResult> {
    let uploaded = if let (Some(bytes), true) =
        (result.artifact_bytes.as_ref(), matches!(result.outcome.as_str(), "SUCCEEDED" | "PARTIAL"))
    {
        if runtime.store.ensure_directory().is_err() {
            return None;
        }
        let path = runtime
            .store
            .directory
            .join(format!(".{}.{}.artifact", result.job_id, Uuid::new_v4()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&path).ok()?;
        if file.write_all(bytes).and_then(|()| file.sync_all()).is_err() {
            let _ = fs::remove_file(&path);
            return None;
        }
        drop(file);
        let receipt = match ReportUploadClient::new(runtime.config.clone(), Duration::from_secs(15 * 60)) {
            Ok(client) => client.upload(&path, cancel).await.ok(),
            Err(_) => None,
        };
        let _ = fs::remove_file(path);
        let receipt = receipt?;
        UploadedDiagnosticJobResult {
            job_id: result.job_id,
            request_id: Some(Uuid::new_v4().to_string()),
            outcome: result.outcome,
            reason: result.reason,
            artifact_name: Some(receipt.name),
            artifact_sha256: Some(receipt.declared_sha256),
        }
    } else {
        UploadedDiagnosticJobResult {
            job_id: result.job_id,
            request_id: Some(Uuid::new_v4().to_string()),
            outcome: result.outcome,
            reason: result.reason,
            artifact_name: None,
            artifact_sha256: None,
        }
    };
    let state = JobState::Uploaded(uploaded.clone());
    if runtime.store.save(&uploaded.job_id, &state).is_err() {
        tracing::error!(job_id = %uploaded.job_id, "failed to persist uploaded diagnostic result; result delivery was not started");
        return None;
    }
    if let Ok(mut states) = runtime.states.lock() {
        states.insert(uploaded.job_id.clone(), state);
    }
    Some(uploaded)
}

async fn deliver_result(
    config: &HeartbeatConfig,
    result: &UploadedDiagnosticJobResult,
    expire_time: &str,
    cancel: &CancellationToken,
) -> bool {
    let Ok(transport) = TelemetryTransport::new(config.clone()) else {
        return false;
    };
    let Some(request_id) = result.request_id.as_deref() else {
        return false;
    };
    let request = DiagnosticJobResultRequest {
        protocol_version: PROTOCOL_VERSION,
        request_id,
        job_id: &result.job_id,
        outcome: &result.outcome,
        reason: &result.reason,
        artifact_name: result.artifact_name.as_deref(),
        artifact_sha256: result.artifact_sha256.as_deref(),
    };
    let Some(deadline) = delivery_deadline(expire_time) else {
        return false;
    };
    retry_delivery(deadline, cancel, || async {
        match transport.post("diagnosticJobResults", &request).await {
            Ok(delivery) => classify_delivery_attempt(delivery),
            Err(_) => DeliveryAttempt::Retry,
        }
    })
    .await
}

fn classify_delivery_attempt(delivery: TelemetryDelivery) -> DeliveryAttempt {
    match delivery {
        TelemetryDelivery::Accepted { .. } => DeliveryAttempt::Accepted,
        TelemetryDelivery::Rejected { status: 409, .. } | TelemetryDelivery::Retry { .. } => DeliveryAttempt::Retry,
        TelemetryDelivery::AuthenticationStopped { .. } | TelemetryDelivery::Rejected { .. } => DeliveryAttempt::Stop,
    }
}

fn delivery_deadline(expire_time: &str) -> Option<tokio::time::Instant> {
    let expire = chrono::DateTime::parse_from_rfc3339(expire_time).ok()?.with_timezone(&Utc);
    let remaining = (expire - Utc::now()).to_std().ok()?;
    Some(tokio::time::Instant::now() + remaining)
}

async fn retry_delivery<F, Fut>(deadline: tokio::time::Instant, cancel: &CancellationToken, mut deliver: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = DeliveryAttempt>,
{
    let mut backoff = INITIAL_DELIVERY_BACKOFF;
    loop {
        if cancel.is_cancelled() || tokio::time::Instant::now() >= deadline {
            return false;
        }
        match deliver().await {
            DeliveryAttempt::Accepted => return true,
            DeliveryAttempt::Stop => return false,
            DeliveryAttempt::Retry => {}
        }
        tokio::select! {
            () = cancel.cancelled() => return false,
            () = tokio::time::sleep_until(deadline.min(tokio::time::Instant::now() + backoff)) => {}
        }
        backoff = (backoff * 2).min(MAX_DELIVERY_BACKOFF);
    }
}

fn valid_uploaded_result(result: &UploadedDiagnosticJobResult, job_id: &str) -> bool {
    result.job_id == job_id
        && result.request_id.as_deref().map_or(true, valid_delivery_request_id)
        && valid_terminal_fields(&result.outcome, &result.reason)
        && match (&result.artifact_name, &result.artifact_sha256) {
            (Some(name), Some(digest)) => {
                matches!(result.outcome.as_str(), "SUCCEEDED" | "PARTIAL")
                    && name.len() <= 512
                    && name.starts_with("organizations/")
                    && lower_hex(digest, 64)
            }
            (None, None) => matches!(result.outcome.as_str(), "FAILED" | "UNSUPPORTED" | "CANCELLED"),
            _ => false,
        }
}

fn valid_delivery_request_id(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uuid| uuid.get_version_num() == 4 && uuid.to_string() == value)
}

fn valid_terminal_fields(outcome: &str, reason: &str) -> bool {
    matches!(outcome, "SUCCEEDED" | "PARTIAL" | "FAILED" | "UNSUPPORTED" | "CANCELLED")
        && !reason.is_empty()
        && reason.len() <= 64
        && reason
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_execution(result: &DiagnosticJobExecution, job_id: &str) -> bool {
    let valid_artifact = match (&result.artifact_uid, &result.artifact_sha256, &result.artifact_bytes) {
        (Some(uid), Some(digest), Some(bytes)) => {
            Uuid::parse_str(uid).is_ok_and(|value| value.get_version_num() == 7 && value.to_string() == *uid)
                && !bytes.is_empty()
                && bytes.len() <= MAX_ARTIFACT_BYTES
                && hex_simd::encode_to_string(Sha256::digest(bytes), hex_simd::AsciiCase::Lower) == *digest
        }
        (None, None, None) => matches!(result.outcome.as_str(), "FAILED" | "CANCELLED") && result.reason != "COMPLETE",
        _ => false,
    };
    result.job_id == job_id && valid_terminal_fields(&result.outcome, &result.reason) && valid_artifact
}

#[cfg(test)]
mod tests {
    use super::*;

    fn execution(job_id: &str, artifact: &[u8]) -> DiagnosticJobExecution {
        DiagnosticJobExecution {
            job_id: job_id.to_owned(),
            outcome: "SUCCEEDED".to_owned(),
            reason: "COMPLETE".to_owned(),
            artifact_uid: Some(Uuid::now_v7().to_string()),
            artifact_sha256: Some(hex_simd::encode_to_string(Sha256::digest(artifact), hex_simd::AsciiCase::Lower)),
            artifact_bytes: Some(artifact.to_vec()),
        }
    }

    #[test]
    fn result_request_has_no_generic_execution_fields() {
        let request = DiagnosticJobResultRequest {
            protocol_version: "v1",
            request_id: "123e4567-e89b-42d3-a456-426614174001",
            job_id: "018cc251-f400-7abc-8def-0123456789ab",
            outcome: "FAILED",
            reason: "CANCELLED",
            artifact_name: None,
            artifact_sha256: None,
        };
        let value = serde_json::to_value(request).expect("result request");
        assert_eq!(value["jobId"], "018cc251-f400-7abc-8def-0123456789ab");
        for forbidden in [
            "command",
            "script",
            "path",
            "sql",
            "arguments",
            "artifact",
            "artifactUid",
            "artifactEncoding",
        ] {
            assert!(value.get(forbidden).is_none());
        }
    }

    #[test]
    fn result_redelivery_has_only_one_in_flight_attempt_loop() {
        let registry = DeliveryRegistry::default();
        let job_id = Uuid::now_v7().to_string();
        let first = registry.acquire(&job_id).expect("first delivery");
        assert!(registry.acquire(&job_id).is_none());
        drop(first);
        assert!(registry.acquire(&job_id).is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn result_delivery_retries_a_conflict_until_accepted() {
        let cancel = CancellationToken::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut attempts = 0;
        let delivered = retry_delivery(deadline, &cancel, || {
            attempts += 1;
            std::future::ready(if attempts == 1 {
                classify_delivery_attempt(TelemetryDelivery::Rejected {
                    status: 409,
                    reason: Some("BUNDLE_NOT_READY".to_owned()),
                })
            } else {
                DeliveryAttempt::Accepted
            })
        })
        .await;
        assert!(delivered);
        assert_eq!(attempts, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn result_delivery_stops_at_job_expiry() {
        let cancel = CancellationToken::new();
        let mut attempts = 0;
        let delivered = retry_delivery(tokio::time::Instant::now() + Duration::from_secs(2), &cancel, || {
            attempts += 1;
            std::future::ready(DeliveryAttempt::Retry)
        })
        .await;
        assert!(!delivered);
        assert_eq!(attempts, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn result_delivery_stops_on_shutdown() {
        let cancel = CancellationToken::new();
        let attempts = std::cell::Cell::new(0);
        let delivery = retry_delivery(tokio::time::Instant::now() + Duration::from_secs(30), &cancel, || {
            attempts.set(attempts.get() + 1);
            std::future::ready(DeliveryAttempt::Retry)
        });
        tokio::pin!(delivery);
        tokio::select! {
            delivered = &mut delivery => panic!("delivery stopped before shutdown: {delivered}"),
            () = tokio::task::yield_now() => {}
        }
        assert_eq!(attempts.get(), 1);
        cancel.cancel();
        let delivered = delivery.await;
        assert!(!delivered);
        assert_eq!(attempts.get(), 1);
    }

    #[test]
    fn durable_state_preserves_single_execution_terminal_result() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let store = JobStateStore {
            directory: temporary.path().join("diagnostic-jobs"),
            operation_lock: Arc::new(Mutex::new(())),
            state_file_count_cache: Arc::new(Mutex::new(None)),
        };
        let job_id = Uuid::now_v7().to_string();
        store.save_new(&job_id, &JobState::Active).expect("active state");
        assert!(matches!(store.load(&job_id), Ok(Some(JobState::Active))));

        let expected = execution(&job_id, b"bounded artifact");
        store
            .save(&job_id, &JobState::Completed(expected.clone()))
            .expect("completed state");
        let loaded = match store.load(&job_id).expect("load state") {
            Some(JobState::Completed(result)) => result,
            _ => panic!("completed state expected"),
        };
        assert_eq!(loaded, expected);
        assert!(valid_execution(&loaded, &job_id));

        let uploaded = UploadedDiagnosticJobResult {
            job_id: job_id.clone(),
            request_id: Some(Uuid::new_v4().to_string()),
            outcome: "SUCCEEDED".to_owned(),
            reason: "COMPLETE".to_owned(),
            artifact_name: Some(format!(
                "organizations/{}/clusters/{}/supportBundles/{}",
                Uuid::now_v7(),
                Uuid::now_v7(),
                Uuid::now_v7()
            )),
            artifact_sha256: Some("a".repeat(64)),
        };
        store.save(&job_id, &JobState::Uploaded(uploaded)).expect("uploaded state");
        let loaded = match store.load(&job_id).expect("load state") {
            Some(JobState::Uploaded(result)) => result,
            _ => panic!("uploaded state expected"),
        };
        assert!(valid_uploaded_result(&loaded, &job_id));

        store.save(&job_id, &JobState::Delivered).expect("delivered state");
        assert!(matches!(store.load(&job_id), Ok(Some(JobState::Delivered))));
    }

    #[test]
    fn state_store_does_not_recreate_or_overwrite_initial_records() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let store = JobStateStore {
            directory: temporary.path().join("diagnostic-jobs"),
            operation_lock: Arc::new(Mutex::new(())),
            state_file_count_cache: Arc::new(Mutex::new(None)),
        };
        let job_id = Uuid::now_v7().to_string();

        assert!(store.save(&job_id, &JobState::Delivered).is_err());
        assert!(matches!(store.load(&job_id), Ok(None)));

        store.save_new(&job_id, &JobState::Active).expect("initial state");
        assert!(store.save_new(&job_id, &JobState::Delivered).is_err());
        assert!(matches!(store.load(&job_id), Ok(Some(JobState::Active))));
    }

    #[test]
    fn delivered_state_pruning_preserves_pending_states() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let store = JobStateStore {
            directory: temporary.path().join("diagnostic-jobs"),
            operation_lock: Arc::new(Mutex::new(())),
            state_file_count_cache: Arc::new(Mutex::new(None)),
        };
        let delivered_id = Uuid::now_v7().to_string();
        let active_id = Uuid::now_v7().to_string();
        let uploaded_id = Uuid::now_v7().to_string();

        store.save_new(&delivered_id, &JobState::Delivered).expect("delivered state");
        store.save_new(&active_id, &JobState::Active).expect("active state");
        let uploaded = UploadedDiagnosticJobResult {
            job_id: uploaded_id.clone(),
            request_id: Some(Uuid::new_v4().to_string()),
            outcome: "FAILED".to_owned(),
            reason: "COLLECTION_FAILED".to_owned(),
            artifact_name: None,
            artifact_sha256: None,
        };
        store
            .save_new(&uploaded_id, &JobState::Uploaded(uploaded))
            .expect("uploaded state");

        let cutoff = SystemTime::now() + Duration::from_secs(1);
        assert_eq!(store.prune_delivered_before(cutoff).expect("prune"), vec![delivered_id.clone()]);
        assert!(matches!(store.load(&delivered_id), Ok(None)));
        assert!(matches!(store.load(&active_id), Ok(Some(JobState::Active))));
        assert!(matches!(store.load(&uploaded_id), Ok(Some(JobState::Uploaded(_)))));
    }

    #[test]
    fn delivered_state_pruning_keeps_corrupt_and_non_job_files() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let store = JobStateStore {
            directory: temporary.path().join("diagnostic-jobs"),
            operation_lock: Arc::new(Mutex::new(())),
            state_file_count_cache: Arc::new(Mutex::new(None)),
        };
        let corrupt_id = Uuid::now_v7().to_string();
        store
            .save_new(&corrupt_id, &JobState::Delivered)
            .expect("initial delivered state");
        fs::write(store.path(&corrupt_id), b"not-json").expect("corrupt state file");
        store.save_new("legacy", &JobState::Delivered).expect("non-UUID file name");

        let old_time = std::fs::FileTimes::new().set_modified(SystemTime::UNIX_EPOCH);
        for path in [store.path(&corrupt_id), store.path("legacy")] {
            File::options()
                .write(true)
                .open(path)
                .expect("open state file")
                .set_times(old_time)
                .expect("age state file");
        }

        assert!(
            store
                .prune_delivered_before(SystemTime::now() + Duration::from_secs(1))
                .expect("prune")
                .is_empty()
        );
        assert!(store.path(&corrupt_id).is_file());
        assert!(store.path("legacy").is_file());
    }

    #[test]
    fn capacity_pruning_is_triggered_only_at_the_limit_and_returns_evicted_ids() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let store = JobStateStore {
            directory: temporary.path().join("diagnostic-jobs"),
            operation_lock: Arc::new(Mutex::new(())),
            state_file_count_cache: Arc::new(Mutex::new(None)),
        };
        let expired_delivered_id = Uuid::now_v7().to_string();
        let active_id = Uuid::now_v7().to_string();
        let below_capacity_id = Uuid::now_v7().to_string();
        let at_capacity_id = Uuid::now_v7().to_string();
        store
            .save_new_with_limit(&expired_delivered_id, &JobState::Delivered, 4)
            .expect("delivered state");
        store
            .save_new_with_limit(&active_id, &JobState::Active, 4)
            .expect("active state");

        let old_time = std::fs::FileTimes::new().set_modified(SystemTime::UNIX_EPOCH);
        File::options()
            .write(true)
            .open(store.path(&expired_delivered_id))
            .expect("open delivered state")
            .set_times(old_time)
            .expect("age delivered state");

        // With two files and a limit of three, the old Delivered record remains.
        assert!(
            store
                .save_new_with_limit(&below_capacity_id, &JobState::Active, 3)
                .expect("capacity available")
                .is_empty()
        );
        assert!(matches!(store.load(&expired_delivered_id), Ok(Some(JobState::Delivered))));

        // At the limit, only the expired Delivered replay barrier is reclaimed.
        let evicted = store
            .save_new_with_limit(&at_capacity_id, &JobState::Active, 3)
            .expect("expired Delivered record reclaimed");
        assert_eq!(evicted, vec![expired_delivered_id.clone()]);
        assert!(matches!(store.load(&expired_delivered_id), Ok(None)));
        assert!(matches!(store.load(&active_id), Ok(Some(JobState::Active))));
        assert!(matches!(store.load(&below_capacity_id), Ok(Some(JobState::Active))));
        assert!(matches!(store.load(&at_capacity_id), Ok(Some(JobState::Active))));
    }

    #[test]
    fn state_capacity_fails_closed_when_only_pending_state_exists() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let store = JobStateStore {
            directory: temporary.path().join("diagnostic-jobs"),
            operation_lock: Arc::new(Mutex::new(())),
            state_file_count_cache: Arc::new(Mutex::new(None)),
        };
        let active_id = Uuid::now_v7().to_string();
        let new_id = Uuid::now_v7().to_string();
        store
            .save_new_with_limit(&active_id, &JobState::Active, 1)
            .expect("active state");

        assert!(store.save_new_with_limit(&new_id, &JobState::Active, 1).is_err());
        assert!(matches!(store.load(&active_id), Ok(Some(JobState::Active))));
        assert!(matches!(store.load(&new_id), Ok(None)));
    }

    #[test]
    fn delivery_request_id_requires_canonical_uuid_v4() {
        let valid = Uuid::new_v4().to_string();
        assert!(valid_delivery_request_id(&valid));
        assert!(!valid_delivery_request_id(&valid.to_uppercase()));
        assert!(!valid_delivery_request_id(&Uuid::now_v7().to_string()));
        assert!(!valid_delivery_request_id("not-a-uuid"));
    }

    #[test]
    fn legacy_uploaded_state_migrates_and_persists_stable_request_id() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let store = JobStateStore {
            directory: temporary.path().join("diagnostic-jobs"),
            operation_lock: Arc::new(Mutex::new(())),
            state_file_count_cache: Arc::new(Mutex::new(None)),
        };
        let job_id = Uuid::now_v7().to_string();
        let uploaded = UploadedDiagnosticJobResult {
            job_id: job_id.clone(),
            request_id: None,
            outcome: "FAILED".to_owned(),
            reason: "COLLECTION_FAILED".to_owned(),
            artifact_name: None,
            artifact_sha256: None,
        };
        store
            .save_new(&job_id, &JobState::Uploaded(uploaded))
            .expect("legacy uploaded state");

        // Simulate a state file written by an older release, before requestId
        // existed in UploadedDiagnosticJobResult.
        let path = store.path(&job_id);
        let mut legacy: serde_json::Value = serde_json::from_slice(&fs::read(&path).expect("read state")).expect("decode state");
        legacy["result"].as_object_mut().expect("result object").remove("requestId");
        fs::write(&path, serde_json::to_vec(&legacy).expect("encode legacy state")).expect("write legacy state");

        let mut loaded = match store.load(&job_id).expect("load legacy state") {
            Some(JobState::Uploaded(result)) => result,
            _ => panic!("uploaded state expected"),
        };
        assert!(loaded.request_id.is_none());
        store.ensure_delivery_request_id(&mut loaded).expect("migrate request id");
        let request_id = loaded.request_id.clone().expect("request id");
        assert!(valid_delivery_request_id(&request_id));

        let reloaded = match store.load(&job_id).expect("reload migrated state") {
            Some(JobState::Uploaded(result)) => result,
            _ => panic!("uploaded state expected"),
        };
        assert_eq!(reloaded.request_id.as_deref(), Some(request_id.as_str()));
        store.ensure_delivery_request_id(&mut loaded).expect("idempotent ensure");
        assert_eq!(loaded.request_id.as_deref(), Some(request_id.as_str()));
    }

    #[test]
    fn persisted_result_must_match_job_and_artifact_digest() {
        let job_id = Uuid::now_v7().to_string();
        let mut result = execution(&job_id, b"artifact");
        assert!(valid_execution(&result, &job_id));
        assert!(!valid_execution(&result, &Uuid::now_v7().to_string()));

        result.artifact_sha256 = Some("0".repeat(64));
        assert!(!valid_execution(&result, &job_id));
        result.artifact_bytes = Some(vec![0; MAX_ARTIFACT_BYTES + 1]);
        assert!(!valid_execution(&result, &job_id));
    }

    #[cfg(unix)]
    #[test]
    fn state_loader_rejects_group_readable_files() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let store = JobStateStore {
            directory: temporary.path().join("diagnostic-jobs"),
            operation_lock: Arc::new(Mutex::new(())),
            state_file_count_cache: Arc::new(Mutex::new(None)),
        };
        let job_id = Uuid::now_v7().to_string();
        store.save_new(&job_id, &JobState::Active).expect("active state");
        fs::set_permissions(store.path(&job_id), fs::Permissions::from_mode(0o640)).expect("permissions");
        assert!(store.load(&job_id).is_err());
    }
}
