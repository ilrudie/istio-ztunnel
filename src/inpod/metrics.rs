// Copyright Istio Authors
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

use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;

#[derive(Default)]
pub struct Metrics {
    pub(super) active_proxy_count: Gauge,
    pub(super) pending_proxy_count: Gauge,
    pub(super) proxies_started: Counter,
    pub(super) proxies_stopped: Counter,
    pub(super) workload_drains: Family<WorkloadDrainLabels, Counter>,
}

/// Whether a DrainWorkload found a running proxy for its workload.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum WorkloadDrainResult {
    found,
    /// No proxy is running for the workload (not started yet, or already gone): nothing to drain.
    not_found,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct WorkloadDrainLabels {
    pub result: WorkloadDrainResult,
}

impl Metrics {
    pub fn new(registry: &mut Registry) -> Self {
        let m = Self::default();
        registry.register(
            "active_proxy_count",
            "The total number current workloads with active proxies (unstable)",
            m.active_proxy_count.clone(),
        );
        registry.register(
            "pending_proxy_count",
            "The total number current workloads with pending proxies (unstable)",
            m.pending_proxy_count.clone(),
        );
        registry.register(
            "proxies_started",
            "The total number of proxies that were started (unstable)",
            m.proxies_started.clone(),
        );
        registry.register(
            "proxies_stopped",
            "The total number of proxies that were stopped (unstable)",
            m.proxies_stopped.clone(),
        );
        registry.register(
            "workload_drains",
            "The total number of DrainWorkload requests received, by whether a proxy was running for the workload (unstable)",
            m.workload_drains.clone(),
        );
        m
    }

    pub(super) fn record_workload_drain(&self, result: WorkloadDrainResult) {
        self.workload_drains
            .get_or_create(&WorkloadDrainLabels { result })
            .inc();
    }
}
