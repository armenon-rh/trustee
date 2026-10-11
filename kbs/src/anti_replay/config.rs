// Copyright (c) 2026 by Red Hat, Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct AntiReplayConfig {
    /// Enable anti-replay validation for incoming requests
    #[serde(default)]
    pub enabled: bool,

    /// Only enforce anti-replay checks for resource paths starting with these prefixes
    /// Default: ["default/vtpm/"]
    #[serde(default = "default_enforce_prefixes")]
    pub enforce_prefixes: Vec<String>,

    /// Duration of an active session lease in seconds (default: 60)
    #[serde(default = "default_lease_duration_secs")]
    pub lease_duration_secs: u64,
}

impl Default for AntiReplayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            enforce_prefixes: default_enforce_prefixes(),
            lease_duration_secs: default_lease_duration_secs(),
        }
    }
}

fn default_enforce_prefixes() -> Vec<String> {
    vec!["default/vtpm/".to_string()]
}

fn default_lease_duration_secs() -> u64 {
    60
}
