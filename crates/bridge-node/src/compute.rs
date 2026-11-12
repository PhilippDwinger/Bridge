//! Compute at a node (docs/09 §11, ADR 0020): pure WebAssembly functions in the sandbox (`bridge-wasm`, deterministic:
//! no floating point, no imports). A node computes only with an active seal of the service `compute`.
//!
//! - `POST /v4/compute/run` (session, member) `{"module","input","fuel"?}` → `{"output","fuel","result"}`; `result`
//!   is a `compute` statement signed by this node over the SHA-256 of module, input and output and the fuel used - the
//!   caller can prove what the node answered (spot checks, docs/09 §11).
//! - `POST /v4/compute/probe`: the same as a request signed by a watcher of the network (op `compute`, body
//!   `{"module","input"}`, at most 64 KiB) - the watcher's probe (docs/09 §6).
//! - At most [`MAX_AT_ONCE`] jobs at once (more: `429`), each in a blocking thread; fuel at most [`MAX_JOB_FUEL`].

use std::sync::Arc;

use bridge_core::crypto::sha256;
use bridge_core::encoding::{b64, b64_var};
use bridge_core::{Draft, SignedRequest, Statement};
use bridge_net::Service;
use bridge_wasm::{Grants, Limits, NoHost};
use serde_json::{Map, Value, json};

use crate::{Node, NodeError, NodeResult, body_object};

/// Jobs at once per node.
pub const MAX_AT_ONCE: usize = 2;
/// Most fuel of one job.
pub const MAX_JOB_FUEL: u64 = 1_000_000_000;
/// Default fuel.
pub const DEFAULT_JOB_FUEL: u64 = 100_000_000;
/// Largest module (as Base64url it must fit into the 1 MiB body).
pub const MAX_JOB_MODULE: usize = 700 * 1024;
/// Largest input and output.
pub const MAX_JOB_IO: usize = 128 * 1024;
/// Largest request body.
const MAX_JOB_BODY: usize = 1024 * 1024;
/// The watcher's compute probe (docs/09 §6): FNV-1a over the input, 4,096 rounds (about 10^5 steps for 32 bytes),
/// 8 bytes out. Source: `(module (memory (export "memory") 1 1) (func (export "alloc") …) (func (export "run") …))`
/// in `crates/bridge-node/src/network/watcher.rs` history; checked by the test `compute_probe_module_runs`.
pub(crate) const COMPUTE_PROBE: &[u8] = &[
    0, 97, 115, 109, 1, 0, 0, 0, 1, 12, 2, 96, 1, 127, 1, 127, 96, 2, 127, 127, 1, 126, 3, 3, 2, 0, 1, 5, 4, 1, 1, 1,
    1, 7, 24, 3, 6, 109, 101, 109, 111, 114, 121, 2, 0, 5, 97, 108, 108, 111, 99, 0, 0, 3, 114, 117, 110, 0, 1, 10,
    121, 2, 5, 0, 65, 128, 8, 11, 113, 2, 1, 126, 2, 127, 66, 165, 198, 136, 161, 200, 156, 167, 249, 75, 33, 2, 2, 64,
    3, 64, 32, 3, 65, 128, 32, 79, 13, 1, 65, 0, 33, 4, 2, 64, 3, 64, 32, 4, 32, 1, 79, 13, 1, 32, 2, 32, 0, 32, 4,
    106, 45, 0, 0, 173, 133, 66, 179, 131, 128, 128, 128, 32, 126, 33, 2, 32, 4, 65, 1, 106, 33, 4, 12, 0, 11, 11, 32,
    2, 32, 3, 173, 133, 33, 2, 32, 3, 65, 1, 106, 33, 3, 12, 0, 11, 11, 65, 128, 4, 32, 2, 55, 3, 0, 66, 136, 128, 128,
    128, 128, 192, 0, 11, 0, 54, 4, 110, 97, 109, 101, 2, 18, 1, 1, 5, 0, 1, 112, 1, 1, 108, 2, 1, 104, 3, 1, 114, 4,
    1, 105, 3, 27, 1, 1, 4, 0, 4, 100, 111, 110, 101, 1, 5, 114, 111, 117, 110, 100, 2, 3, 101, 110, 100, 3, 4, 98,
    121, 116, 101,
];

/// A result statement holds this long.
const RESULT_LIFETIME_MS: i64 = 30 * 24 * 3600 * 1000;

impl Node {
    /// Routes `/v4/compute/...`.
    pub(crate) async fn route_compute(&self, request: &bridge_transport::Request, now: i64) -> NodeResult<Vec<u8>> {
        self.inner.guard.admit_read(request.peer, now)?;
        match request.path.as_str() {
            "/v4/compute/run" => {
                self.session(request, now)?;
                let body = body_object(&request.body, MAX_JOB_BODY)?;
                self.compute_job(&body, now, false).await
            }
            "/v4/compute/probe" => {
                let me = self.inner.identity.id().clone();
                let signed = SignedRequest::parse(&request.body)?;
                signed.check(&me, now)?;
                if signed.op() != "compute" {
                    return Err(NodeError::bad_format("op: expected compute"));
                }
                let watcher = signed.iss().clone();
                let card = self.with_core(|core| {
                    if !core.state.is_watcher(&watcher, now) {
                        return Err(NodeError::forbidden("only watchers of the network send probes"));
                    }
                    core.state.card_of(&watcher).cloned().ok_or_else(|| NodeError::forbidden("unknown watcher"))
                })??;
                signed.verify(&card)?;
                self.inner.guard.remember_nonce(
                    signed.iss(),
                    signed.nonce(),
                    signed.iat().saturating_add(bridge_core::CLOCK_SKEW_MS),
                    now,
                )?;
                let body = signed.body().as_object().cloned().ok_or_else(|| NodeError::bad_format("body"))?;
                // A probe runs before the node has its seal: the watcher decides with it whether it gets one.
                self.compute_job(&body, now, true).await
            }
            _ => Err(NodeError::not_found()),
        }
    }

    /// Whether this node computes (an active seal with `compute`).
    fn computes(&self, now: i64) -> bool {
        let me = self.inner.identity.id().clone();
        self.with_core(|core| core.state.services(&me, now).has(Service::Compute)).unwrap_or(false)
    }

    async fn compute_job(&self, body: &Map<String, Value>, now: i64, probe: bool) -> NodeResult<Vec<u8>> {
        if !probe && !self.computes(now) {
            return Err(NodeError::forbidden("this node has no seal with the service compute"));
        }
        if body.keys().any(|key| !["module", "input", "fuel"].contains(&key.as_str())) {
            return Err(NodeError::bad_format("fields: module, input, fuel"));
        }
        let text = |name: &str| body.get(name).and_then(Value::as_str).unwrap_or_default();
        let module = b64_var(text("module"), "module", MAX_JOB_MODULE)?;
        let input = b64_var(text("input"), "input", MAX_JOB_IO)?;
        let fuel = crate::optional_u64(body, "fuel", DEFAULT_JOB_FUEL, MAX_JOB_FUEL)?.max(1);
        let slot = Arc::clone(&self.inner.computes).try_acquire_owned().map_err(|_| NodeError {
            retry_after: Some(1),
            ..NodeError::new(429, "RATE_LIMITED", "too many compute jobs at once")
        })?;
        let (module_hash, input_hash) = (sha256(&module), sha256(&input));
        let limits = Limits { fuel, io_bytes: MAX_JOB_IO, ..Limits::default() };
        let ran = tokio::task::spawn_blocking(move || {
            let result = bridge_wasm::run(&module, "run", &input, limits, Grants::default(), NoHost);
            drop(slot);
            result
        })
        .await
        .map_err(|_| NodeError::unavailable())?;
        let (outcome, _) = ran.map_err(|error| NodeError::new(422, "COMPUTE", error.to_string()))?;
        let body = json!({
            "module": b64(&module_hash),
            "input": b64(&input_hash),
            "output": b64(&sha256(&outcome.output)),
            "fuel": outcome.fuel_used,
        });
        let draft = Draft { kind: "compute", net: &self.inner.net, iat: now, exp: now + RESULT_LIFETIME_MS, body };
        let statement = Statement::sign(&draft, &self.inner.identity)?;
        Ok(json!({"output": b64(&outcome.output), "fuel": outcome.fuel_used, "result": statement.to_value()})
            .to_string()
            .into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_probe_module_runs() -> Result<(), bridge_wasm::WasmError> {
        let limits = Limits::default();
        let (a, _) = bridge_wasm::run(COMPUTE_PROBE, "run", b"abc", limits, Grants::default(), NoHost)?;
        let (b, _) = bridge_wasm::run(COMPUTE_PROBE, "run", b"abd", limits, Grants::default(), NoHost)?;
        assert_eq!(a.output.len(), 8);
        assert_ne!(a.output, b.output, "the input decides the output");
        assert!(a.fuel_used > 10_000, "real work: {}", a.fuel_used);
        Ok(())
    }
}
