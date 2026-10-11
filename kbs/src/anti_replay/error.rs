// Copyright (c) 2026 by Red Hat, Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AntiReplayError {
    #[error("Storage initialization failed: {0}")]
    StorageInit(String),

    #[error("Storage backend error: {0}")]
    Storage(String),

    #[error("Missing report_data or runtime_data_claims in attestation token")]
    MissingReportData,

    #[error("Invalid hex in report_data: {0}")]
    InvalidReportDataHex(String),

    #[error("No anti-replay record registered for protected resource: {0}")]
    NonceNotRegistered(String),

    #[error(
        "State replay / rollback detected: presented disk nonce does not match expected nonce"
    )]
    NonceMismatch,

    #[error("Split-brain fork detected: presented boot counter ({presented}) does not match expected counter ({expected})")]
    CounterMismatch { expected: u64, presented: u64 },

    #[error("Resource is currently in use by an active VM session (lease expires at {expiry})")]
    LeaseActive { expiry: u64 },

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}
