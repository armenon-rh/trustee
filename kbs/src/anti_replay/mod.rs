// Copyright (c) 2026 by Red Hat, Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::HttpResponse;
use key_value_storage::{KeyValueStorage, SetParameters, StorageProvider};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

pub mod config;
pub mod error;
pub use config::AntiReplayConfig;
pub use error::AntiReplayError;

pub const ANTI_REPLAY_STORAGE_NAMESPACE: &str = "svsm-anti-replay";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AntiReplayRecord {
    pub version: u8,
    pub boot_counter: u64,
    pub nonce: String, // 32-character hex string representing 16 raw bytes
    /// CocoonFS's internal filesystem update counter, as last synced by SVSM -- a 32-character
    /// hex string representing a 16-byte little-endian u128. `None` until the first
    /// register-nonce or sync-fs-counter call reports one (including for records persisted
    /// before this field existed, via `#[serde(default)]`).
    #[serde(default)]
    pub fs_update_counter: Option<String>,
    #[serde(default)]
    pub active_lease: Option<String>, // Active Session ID holding the lease
    #[serde(default)]
    pub lease_expiry: Option<u64>, // Unix timestamp in seconds when the lease expires
}

#[derive(Clone)]
pub struct AntiReplayManager {
    config: AntiReplayConfig,
    storage: Arc<dyn KeyValueStorage>,
}

impl AntiReplayManager {
    pub async fn new(
        storage_provider: Arc<dyn StorageProvider>,
        config: AntiReplayConfig,
    ) -> Result<Self, AntiReplayError> {
        let storage = storage_provider
            .get_or_register(ANTI_REPLAY_STORAGE_NAMESPACE)
            .await
            .map_err(|e| AntiReplayError::StorageInit(e.to_string()))?;

        Ok(Self { config, storage })
    }

    /// Checks if a resource_id requires anti-replay validation based on configured prefixes
    pub fn is_protected(&self, resource_id: &str) -> bool {
        if !self.config.enabled {
            return false;
        }
        self.config
            .enforce_prefixes
            .iter()
            .any(|prefix| resource_id.starts_with(prefix))
    }

    /// Extracts the presented disk nonce, boot counter, and version from token claims.
    /// Strictly extracts from Structured Runtime Data claims (CoCo-AS standard).
    pub fn extract_disk_state(
        &self,
        claims: &serde_json::Value,
    ) -> Result<(u8, u64, [u8; 16]), AntiReplayError> {
        let runtime_claims = claims
            .pointer("/submods/cpu0/ear.veraison.annotated-evidence/runtime_data_claims")
            .or_else(|| claims.pointer("/customized_claims/runtime_data"))
            .or_else(|| claims.pointer("/runtime_data"))
            .ok_or(AntiReplayError::MissingReportData)?;

        let nonce_val = runtime_claims
            .get("disk_nonce")
            .and_then(|v| v.as_str())
            .ok_or(AntiReplayError::MissingReportData)?;

        let nonce_bytes = hex::decode(nonce_val)
            .map_err(|e| AntiReplayError::InvalidReportDataHex(e.to_string()))?;

        if nonce_bytes.len() != 16 {
            return Err(AntiReplayError::InvalidReportDataHex(
                "disk_nonce must be 16 bytes (32 hex characters)".into(),
            ));
        }

        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&nonce_bytes);

        let version = runtime_claims
            .get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u8;

        let counter = runtime_claims
            .get("boot_counter")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                AntiReplayError::BadRequest("Missing boot_counter in runtime_data".into())
            })?;

        Ok((version, counter, nonce))
    }

    /// Validates both the nonce, monotonic boot counter, and active session lease
    pub async fn validate_resource_request(
        &self,
        resource_id: &str,
        claims: &serde_json::Value,
    ) -> Result<Option<String>, AntiReplayError> {
        if !self.is_protected(resource_id) {
            return Ok(None);
        }

        let raw_record = match self
            .storage
            .get(resource_id)
            .await
            .map_err(|e| AntiReplayError::Storage(e.to_string()))?
        {
            Some(bytes) if !bytes.is_empty() => bytes,
            _ => {
                warn!(
                    resource_id = %resource_id,
                    "No anti-replay record registered for protected resource"
                );
                return Err(AntiReplayError::NonceNotRegistered(resource_id.to_string()));
            }
        };

        let mut record: AntiReplayRecord = serde_json::from_slice(&raw_record)
            .map_err(|e| AntiReplayError::Storage(format!("Corrupt record: {e}")))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // 1. Mutual Exclusion Check: Verify no active unexpired lease is currently held
        if let Some(ref lease_id) = record.active_lease {
            if let Some(expiry) = record.lease_expiry {
                if now < expiry {
                    warn!(
                        resource_id = %resource_id,
                        lease_id = %lease_id,
                        expiry = expiry,
                        "Anti-replay rejected: Resource is currently in use by an active VM lease"
                    );
                    return Err(AntiReplayError::LeaseActive { expiry });
                }
            }
        }

        let (_version, presented_counter, presented_nonce) = self.extract_disk_state(claims)?;
        let expected_nonce_bytes =
            hex::decode(&record.nonce).map_err(|e| AntiReplayError::Storage(e.to_string()))?;

        // 2. Verify Nonce Parity
        if presented_nonce.as_slice() != expected_nonce_bytes.as_slice() {
            warn!(
                resource_id = %resource_id,
                expected = %record.nonce,
                presented = %hex::encode(presented_nonce),
                "Anti-replay mismatch: Disk nonce mismatch (State replay detected)"
            );
            return Err(AntiReplayError::NonceMismatch);
        }

        // 3. Verify Monotonic Counter Parity
        if presented_counter != record.boot_counter {
            warn!(
                resource_id = %resource_id,
                expected = record.boot_counter,
                presented = presented_counter,
                "Anti-replay mismatch: Boot counter mismatch (Split-brain fork detected)"
            );
            return Err(AntiReplayError::CounterMismatch {
                expected: record.boot_counter,
                presented: presented_counter,
            });
        }

        // 4. Grant Lease: Mark resource as active for this session
        // Generate pseudo-random session ID from counter and timestamp
        let session_id = format!(
            "{}-{}-{}",
            record.boot_counter,
            now,
            hex::encode(&presented_nonce[..8])
        );
        record.active_lease = Some(session_id.clone());
        record.lease_expiry = Some(now + self.config.lease_duration_secs);

        let record_bytes =
            serde_json::to_vec(&record).map_err(|e| AntiReplayError::Storage(e.to_string()))?;
        self.storage
            .set(
                resource_id,
                &record_bytes,
                SetParameters { overwrite: true, ttl: None },
            )
            .await
            .map_err(|e| AntiReplayError::Storage(e.to_string()))?;

        info!(
            resource_id = %resource_id,
            boot_counter = record.boot_counter,
            session_id = %session_id,
            "Anti-replay validation successful; lease granted"
        );
        Ok(Some(session_id))
    }

    /// Handles periodic heartbeat to refresh lease: POST /kbs/v0/svsm/heartbeat
    pub async fn handle_heartbeat(
        &self,
        body: &[u8],
    ) -> Result<HttpResponse, AntiReplayError> {
        #[derive(Deserialize)]
        struct HeartbeatPayload {
            resource_id: String,
            session_id: String,
        }

        let payload: HeartbeatPayload =
            serde_json::from_slice(body).map_err(|e| AntiReplayError::BadRequest(e.to_string()))?;

        let raw_record = match self
            .storage
            .get(&payload.resource_id)
            .await
            .map_err(|e| AntiReplayError::Storage(e.to_string()))?
        {
            Some(bytes) if !bytes.is_empty() => bytes,
            _ => return Err(AntiReplayError::NonceNotRegistered(payload.resource_id)),
        };

        let mut record: AntiReplayRecord = serde_json::from_slice(&raw_record)
            .map_err(|e| AntiReplayError::Storage(format!("Corrupt record: {e}")))?;

        if record.active_lease.as_deref() != Some(payload.session_id.as_str()) {
            return Err(AntiReplayError::Unauthorized(
                "Invalid session lease ID for heartbeat".into(),
            ));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let new_expiry = now + self.config.lease_duration_secs;
        record.lease_expiry = Some(new_expiry);

        let record_bytes =
            serde_json::to_vec(&record).map_err(|e| AntiReplayError::Storage(e.to_string()))?;
        self.storage
            .set(
                &payload.resource_id,
                &record_bytes,
                SetParameters { overwrite: true, ttl: None },
            )
            .await
            .map_err(|e| AntiReplayError::Storage(e.to_string()))?;

        Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "refreshed",
            "lease_expiry": new_expiry,
        })))
    }

    /// Handles stateful fs_update_counter sync: POST /kbs/v0/svsm/sync-fs-counter
    ///
    /// Authenticated the same way as heartbeat/release-lease (resource_id + session_id matched
    /// against the stored active_lease), not a Bearer token -- this fires on every committed
    /// write (not just once per boot or every 25s), so requiring full JWT verification here
    /// would reintroduce the token-expiry failure already hit and fixed for
    /// heartbeat/release-lease, except on the hottest path in the whole design.
    ///
    /// `fs_update_counter` is a monotonic 128-bit counter (little-endian -- see
    /// `cocoon-tpm-storage`'s `transaction::write_journal`), expected to climb across commits
    /// rather than stay fixed like `nonce`/`boot_counter`, so the check is `presented >=
    /// recorded`, not equality: a confirmed drop below the recorded value is evidence of a
    /// spliced/rolled-back payload (an old encrypted image paired with a current plaintext
    /// header). On rejection, `active_lease`/`lease_expiry` are cleared (the lease granted
    /// moments earlier, based on the plaintext header alone, was bogus) without touching the
    /// stored `fs_update_counter`, so the real, current disk still validates fine on its own
    /// next sync.
    pub async fn handle_sync_fs_counter(&self, body: &[u8]) -> Result<HttpResponse, AntiReplayError> {
        #[derive(Deserialize)]
        struct SyncFsCounterPayload {
            resource_id: String,
            session_id: String,
            fs_update_counter: String,
        }

        let payload: SyncFsCounterPayload =
            serde_json::from_slice(body).map_err(|e| AntiReplayError::BadRequest(e.to_string()))?;

        let presented_bytes = hex::decode(&payload.fs_update_counter).map_err(|e| {
            AntiReplayError::BadRequest(format!("Invalid hex fs_update_counter: {e}"))
        })?;
        let presented_bytes: [u8; 16] = presented_bytes.try_into().map_err(|v: Vec<u8>| {
            AntiReplayError::BadRequest(format!(
                "fs_update_counter must be 16 bytes, got {}",
                v.len()
            ))
        })?;
        let presented = u128::from_le_bytes(presented_bytes);

        let raw_record = match self
            .storage
            .get(&payload.resource_id)
            .await
            .map_err(|e| AntiReplayError::Storage(e.to_string()))?
        {
            Some(bytes) if !bytes.is_empty() => bytes,
            _ => return Err(AntiReplayError::NonceNotRegistered(payload.resource_id)),
        };

        let mut record: AntiReplayRecord = serde_json::from_slice(&raw_record)
            .map_err(|e| AntiReplayError::Storage(format!("Corrupt record: {e}")))?;

        if record.active_lease.as_deref() != Some(payload.session_id.as_str()) {
            return Err(AntiReplayError::Unauthorized(
                "Invalid session lease ID for sync_fs_counter".into(),
            ));
        }

        if let Some(ref recorded_hex) = record.fs_update_counter {
            let recorded_bytes = hex::decode(recorded_hex)
                .map_err(|e| AntiReplayError::Storage(format!("Corrupt fs_update_counter: {e}")))?;
            let recorded_bytes: [u8; 16] = recorded_bytes.try_into().map_err(|v: Vec<u8>| {
                AntiReplayError::Storage(format!(
                    "Corrupt fs_update_counter: expected 16 bytes, got {}",
                    v.len()
                ))
            })?;
            let recorded = u128::from_le_bytes(recorded_bytes);

            if presented < recorded {
                warn!(
                    resource_id = %payload.resource_id,
                    expected = %recorded_hex,
                    presented = %payload.fs_update_counter,
                    "Anti-replay mismatch: fs_update_counter went backward (possible header/payload splicing)"
                );

                record.active_lease = None;
                record.lease_expiry = None;
                let record_bytes = serde_json::to_vec(&record)
                    .map_err(|e| AntiReplayError::Storage(e.to_string()))?;
                self.storage
                    .set(
                        &payload.resource_id,
                        &record_bytes,
                        SetParameters {
                            overwrite: true,
                            ttl: None,
                        },
                    )
                    .await
                    .map_err(|e| AntiReplayError::Storage(e.to_string()))?;

                return Err(AntiReplayError::FsCounterMismatch {
                    expected: recorded_hex.clone(),
                    presented: payload.fs_update_counter,
                });
            }
        }

        record.fs_update_counter = Some(payload.fs_update_counter);
        let record_bytes =
            serde_json::to_vec(&record).map_err(|e| AntiReplayError::Storage(e.to_string()))?;
        self.storage
            .set(
                &payload.resource_id,
                &record_bytes,
                SetParameters {
                    overwrite: true,
                    ttl: None,
                },
            )
            .await
            .map_err(|e| AntiReplayError::Storage(e.to_string()))?;

        Ok(HttpResponse::Ok().json(serde_json::json!({ "status": "synced" })))
    }

    /// Handles clean shutdown lease release: POST /kbs/v0/svsm/release-lease
    pub async fn handle_release_lease(
        &self,
        body: &[u8],
    ) -> Result<HttpResponse, AntiReplayError> {
        #[derive(Deserialize)]
        struct ReleasePayload {
            resource_id: String,
            session_id: String,
        }

        let payload: ReleasePayload =
            serde_json::from_slice(body).map_err(|e| AntiReplayError::BadRequest(e.to_string()))?;

        let raw_record = match self
            .storage
            .get(&payload.resource_id)
            .await
            .map_err(|e| AntiReplayError::Storage(e.to_string()))?
        {
            Some(bytes) if !bytes.is_empty() => bytes,
            _ => return Err(AntiReplayError::NonceNotRegistered(payload.resource_id)),
        };

        let mut record: AntiReplayRecord = serde_json::from_slice(&raw_record)
            .map_err(|e| AntiReplayError::Storage(format!("Corrupt record: {e}")))?;

        if record.active_lease.as_deref() == Some(payload.session_id.as_str()) {
            record.active_lease = None;
            record.lease_expiry = None;
            let record_bytes =
                serde_json::to_vec(&record).map_err(|e| AntiReplayError::Storage(e.to_string()))?;
            self.storage
                .set(
                    &payload.resource_id,
                    &record_bytes,
                    SetParameters { overwrite: true, ttl: None },
                )
                .await
                .map_err(|e| AntiReplayError::Storage(e.to_string()))?;
            info!(
                resource_id = %payload.resource_id,
                "Session lease cleanly released on shutdown"
            );
        }

        Ok(HttpResponse::Ok().json(serde_json::json!({ "status": "released" })))
    }

    /// Handles authenticated POST /kbs/v0/svsm/roll-nonce
    pub async fn handle_roll_nonce(
        &self,
        _token_claims: &serde_json::Value,
        body: &[u8],
    ) -> Result<HttpResponse, AntiReplayError> {
        #[derive(Deserialize)]
        struct RollNoncePayload {
            version: Option<u8>,
            resource_id: String,
            new_boot_counter: u64,
            new_nonce: String,
        }

        let payload: RollNoncePayload =
            serde_json::from_slice(body).map_err(|e| AntiReplayError::BadRequest(e.to_string()))?;

        let new_nonce_bytes = hex::decode(&payload.new_nonce)
            .map_err(|e| AntiReplayError::BadRequest(format!("Invalid hex nonce: {e}")))?;

        if new_nonce_bytes.len() != 16 {
            return Err(AntiReplayError::BadRequest(
                "new_nonce must be 16 bytes (32 hex characters)".into(),
            ));
        }

        // Fetch existing record to preserve active lease if any
        let existing: Option<AntiReplayRecord> = match self.storage.get(&payload.resource_id).await
        {
            Ok(Some(bytes)) => serde_json::from_slice(&bytes).ok(),
            _ => None,
        };

        let updated_record = AntiReplayRecord {
            version: payload.version.unwrap_or(1),
            boot_counter: payload.new_boot_counter,
            nonce: payload.new_nonce,
            // Rolling the plaintext header nonce/boot_counter is independent of
            // fs_update_counter tracking; preserve whatever was last synced.
            fs_update_counter: existing.as_ref().and_then(|r| r.fs_update_counter.clone()),
            active_lease: existing.as_ref().and_then(|r| r.active_lease.clone()),
            lease_expiry: existing.as_ref().and_then(|r| r.lease_expiry),
        };

        let record_bytes = serde_json::to_vec(&updated_record)
            .map_err(|e| AntiReplayError::Storage(e.to_string()))?;

        self.storage
            .set(
                &payload.resource_id,
                &record_bytes,
                SetParameters { overwrite: true, ttl: None },
            )
            .await
            .map_err(|e| AntiReplayError::Storage(e.to_string()))?;

        info!(
            resource_id = %payload.resource_id,
            boot_counter = payload.new_boot_counter,
            "Successfully rolled anti-replay nonce & monotonic counter in KBS"
        );
        Ok(HttpResponse::Ok().json(serde_json::json!({
            "status": "success",
            "resource_id": payload.resource_id,
            "boot_counter": payload.new_boot_counter,
        })))
    }

    /// Handles admin POST /kbs/v0/svsm/register-nonce
    pub async fn handle_register_nonce(
        &self,
        body: &[u8],
    ) -> Result<HttpResponse, AntiReplayError> {
        #[derive(Deserialize)]
        struct RegisterPayload {
            version: Option<u8>,
            resource_id: String,
            boot_counter: Option<u64>,
            nonce: String,
            #[serde(default)]
            fs_update_counter: Option<String>,
        }

        let payload: RegisterPayload =
            serde_json::from_slice(body).map_err(|e| AntiReplayError::BadRequest(e.to_string()))?;

        let nonce_bytes = hex::decode(&payload.nonce)
            .map_err(|e| AntiReplayError::BadRequest(format!("Invalid hex nonce: {e}")))?;

        if nonce_bytes.len() != 16 {
            return Err(AntiReplayError::BadRequest("nonce must be 16 bytes".into()));
        }

        if let Some(ref fs_update_counter) = payload.fs_update_counter {
            let counter_bytes = hex::decode(fs_update_counter).map_err(|e| {
                AntiReplayError::BadRequest(format!("Invalid hex fs_update_counter: {e}"))
            })?;
            if counter_bytes.len() != 16 {
                return Err(AntiReplayError::BadRequest(
                    "fs_update_counter must be 16 bytes".into(),
                ));
            }
        }

        let record = AntiReplayRecord {
            version: payload.version.unwrap_or(1),
            boot_counter: payload.boot_counter.unwrap_or(1),
            nonce: payload.nonce,
            fs_update_counter: payload.fs_update_counter,
            active_lease: None,
            lease_expiry: None,
        };

        let record_bytes =
            serde_json::to_vec(&record).map_err(|e| AntiReplayError::Storage(e.to_string()))?;

        self.storage
            .set(
                &payload.resource_id,
                &record_bytes,
                SetParameters { overwrite: true, ttl: None },
            )
            .await
            .map_err(|e| AntiReplayError::Storage(e.to_string()))?;

        info!(
            resource_id = %payload.resource_id,
            "Admin registered initial anti-replay record"
        );
        Ok(HttpResponse::Ok().json(serde_json::json!({ "status": "registered" })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use key_value_storage::memory::MemoryKeyValueStorage;

    #[tokio::test]
    async fn test_extract_disk_state() {
        let storage = Arc::new(MemoryKeyValueStorage::default());
        let mgr = AntiReplayManager {
            config: AntiReplayConfig {
                enabled: true,
                enforce_prefixes: vec!["default/vtpm/".to_string()],
                lease_duration_secs: 60,
            },
            storage,
        };

        let claims = serde_json::json!({
            "submods": {
                "cpu0": {
                    "ear.veraison.annotated-evidence": {
                        "runtime_data_claims": {
                            "version": 1,
                            "boot_counter": 5,
                            "disk_nonce": "aabbccdd11223344556677889900aabb"
                        }
                    }
                }
            }
        });

        let (ver, counter, nonce) = mgr
            .extract_disk_state(&claims)
            .expect("should extract state");
        assert_eq!(ver, 1);
        assert_eq!(counter, 5);
        assert_eq!(hex::encode(nonce), "aabbccdd11223344556677889900aabb");
    }

    #[tokio::test]
    async fn test_validate_and_roll() {
        let storage = Arc::new(MemoryKeyValueStorage::default());
        let mgr = AntiReplayManager {
            config: AntiReplayConfig {
                enabled: true,
                enforce_prefixes: vec!["default/vtpm/".to_string()],
                lease_duration_secs: 60,
            },
            storage,
        };

        let reg_body = serde_json::json!({
            "version": 1,
            "resource_id": "default/vtpm/vm1",
            "boot_counter": 1,
            "nonce": "11111111111111111111111111111111"
        });
        mgr.handle_register_nonce(&serde_json::to_vec(&reg_body).unwrap())
            .await
            .unwrap();

        let valid_claims = serde_json::json!({
            "submods": {
                "cpu0": {
                    "ear.veraison.annotated-evidence": {
                        "runtime_data_claims": {
                            "version": 1,
                            "boot_counter": 1,
                            "disk_nonce": "11111111111111111111111111111111"
                        }
                    }
                }
            }
        });
        let session_id = mgr
            .validate_resource_request("default/vtpm/vm1", &valid_claims)
            .await
            .unwrap()
            .expect("should return session lease ID");
        assert!(!session_id.is_empty());

        // A second request while the lease is active should fail with LeaseActive
        let second_attempt = mgr
            .validate_resource_request("default/vtpm/vm1", &valid_claims)
            .await
            .unwrap_err();
        assert!(matches!(
            second_attempt,
            AntiReplayError::LeaseActive { .. }
        ));

        // Heartbeat should succeed with correct session_id
        let heartbeat_body = serde_json::json!({
            "resource_id": "default/vtpm/vm1",
            "session_id": session_id,
        });
        mgr.handle_heartbeat(
            &serde_json::to_vec(&heartbeat_body).unwrap(),
        )
        .await
        .unwrap();

        // Release lease should succeed
        let release_body = serde_json::json!({
            "resource_id": "default/vtpm/vm1",
            "session_id": session_id,
        });
        mgr.handle_release_lease(
            &serde_json::to_vec(&release_body).unwrap(),
        )
        .await
        .unwrap();

        // Roll nonce to counter 2
        let roll_body = serde_json::json!({
            "version": 1,
            "resource_id": "default/vtpm/vm1",
            "new_boot_counter": 2,
            "new_nonce": "22222222222222222222222222222222"
        });
        mgr.handle_roll_nonce(
            &serde_json::Value::Null,
            &serde_json::to_vec(&roll_body).unwrap(),
        )
        .await
        .unwrap();

        // Old claims should now fail with NonceMismatch
        let err = mgr
            .validate_resource_request("default/vtpm/vm1", &valid_claims)
            .await
            .unwrap_err();
        assert!(matches!(err, AntiReplayError::NonceMismatch));
    }

    #[tokio::test]
    async fn test_sync_fs_counter_mismatch_clears_lease() {
        let storage = Arc::new(MemoryKeyValueStorage::default());
        let mgr = AntiReplayManager {
            config: AntiReplayConfig {
                enabled: true,
                enforce_prefixes: vec!["default/vtpm/".to_string()],
                lease_duration_secs: 60,
            },
            storage,
        };

        let initial_counter = hex::encode(1u128.to_le_bytes());
        let reg_body = serde_json::json!({
            "version": 1,
            "resource_id": "default/vtpm/vm1",
            "boot_counter": 1,
            "nonce": "11111111111111111111111111111111",
            "fs_update_counter": initial_counter,
        });
        mgr.handle_register_nonce(&serde_json::to_vec(&reg_body).unwrap())
            .await
            .unwrap();

        let valid_claims = serde_json::json!({
            "submods": {
                "cpu0": {
                    "ear.veraison.annotated-evidence": {
                        "runtime_data_claims": {
                            "version": 1,
                            "boot_counter": 1,
                            "disk_nonce": "11111111111111111111111111111111"
                        }
                    }
                }
            }
        });
        let session_id = mgr
            .validate_resource_request("default/vtpm/vm1", &valid_claims)
            .await
            .unwrap()
            .expect("should return session lease ID");

        // A legitimate forward sync (counter bumped to 2) succeeds.
        let higher_counter = hex::encode(2u128.to_le_bytes());
        let sync_body = serde_json::json!({
            "resource_id": "default/vtpm/vm1",
            "session_id": session_id,
            "fs_update_counter": higher_counter,
        });
        mgr.handle_sync_fs_counter(&serde_json::to_vec(&sync_body).unwrap())
            .await
            .unwrap();

        // Presenting a counter behind the recorded value (1 < 2) is a splice/rollback.
        let stale_counter = hex::encode(1u128.to_le_bytes());
        let stale_sync_body = serde_json::json!({
            "resource_id": "default/vtpm/vm1",
            "session_id": session_id,
            "fs_update_counter": stale_counter,
        });
        let err = mgr
            .handle_sync_fs_counter(&serde_json::to_vec(&stale_sync_body).unwrap())
            .await
            .unwrap_err();
        assert!(matches!(err, AntiReplayError::FsCounterMismatch { .. }));

        // The rejected sync must have cleared the lease: a heartbeat with the same
        // (now stale) session_id should be rejected as unauthorized.
        let heartbeat_body = serde_json::json!({
            "resource_id": "default/vtpm/vm1",
            "session_id": session_id,
        });
        let heartbeat_err = mgr
            .handle_heartbeat(&serde_json::to_vec(&heartbeat_body).unwrap())
            .await
            .unwrap_err();
        assert!(matches!(heartbeat_err, AntiReplayError::Unauthorized(_)));
    }
}
