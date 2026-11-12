//! Compute (docs/09 §11): a pure WebAssembly function at a compute node, its answer signed by the node, and spot checks
//! - another node computes the same job; different answers are proof that one of them lies.

use bridge_core::crypto::sha256;
use bridge_core::encoding::{b64, b64_fixed, b64_var};
use bridge_core::{KeyCard, Statement};
use rand_core::{OsRng, RngCore};
use serde_json::{Value, json};

use crate::{Client, SdkError, SdkResult};

/// Largest output taken from a node.
const MAX_OUTPUT: usize = 128 * 1024;

fn untrusted(what: impl Into<String>) -> SdkError {
    SdkError::Untrusted(what.into())
}

/// A node's verified answer.
#[derive(Debug, Clone)]
pub struct Computed {
    /// The output.
    pub output: Vec<u8>,
    /// Fuel the node says it used (part of the signed result).
    pub fuel: u64,
    /// The node's signed `compute` statement (module, input and output as SHA-256, fuel).
    pub result: Statement,
}

impl Client {
    /// Runs `module` (`run` entry, no imports, no floating point) with `input` at the connected compute node.
    /// The answer is checked: the signed result is the node's (its card from the login), of this network, and names
    /// exactly this module, this input and this output.
    pub async fn compute(&self, module: &[u8], input: &[u8], fuel: Option<u64>) -> SdkResult<Computed> {
        let mut body = json!({"module": b64(module), "input": b64(input)});
        if let Some(fuel) = fuel {
            body["fuel"] = json!(fuel);
        }
        let answer = Self::check(
            self.http.post("/v4/compute/run", self.session.as_deref(), body.to_string().into_bytes()).await?,
        )?;
        let node = self.node.as_ref().ok_or_else(|| untrusted("not connected"))?;
        let net = self.net.as_ref().ok_or_else(|| untrusted("no network"))?;
        verified(&answer, node, net, module, input)
    }
}

fn verified(
    answer: &serde_json::Map<String, Value>,
    node: &KeyCard,
    net: &bridge_core::Id,
    module: &[u8],
    input: &[u8],
) -> SdkResult<Computed> {
    let output = b64_var(answer.get("output").and_then(Value::as_str).unwrap_or_default(), "output", MAX_OUTPUT)?;
    let result = Statement::from_value(answer.get("result").cloned().unwrap_or(Value::Null))?;
    if result.kind() != "compute" || result.net() != net || result.claimed_signers() != [node.id()] {
        return Err(untrusted("compute: the result is not this node's"));
    }
    result.verify(&[node], 1)?;
    let body = result.body();
    let hash = |name: &str| b64_fixed::<32>(body.get(name).and_then(Value::as_str).unwrap_or_default(), name);
    if hash("module")? != sha256(module) || hash("input")? != sha256(input) || hash("output")? != sha256(&output) {
        return Err(untrusted("compute: the signed result names another job or output"));
    }
    let fuel = body.get("fuel").and_then(Value::as_u64).ok_or_else(|| untrusted("compute: fuel"))?;
    Ok(Computed { output, fuel, result })
}

/// What a spot check found.
#[derive(Debug, Clone)]
pub enum Checked {
    /// The answer of the first node (checked by the second one if `confirmed`).
    Agreed {
        /// The answer.
        computed: Computed,
        /// A second node computed the same.
        confirmed: bool,
    },
    /// The two nodes answered differently - both signed results are the proof.
    Mismatch {
        /// The first node's answer.
        first: Computed,
        /// The second node's answer.
        second: Computed,
    },
}

/// Runs the job at `first`; with probability `rate` (0.0-1.0; 1.0 = always) also at `second` and compares.
pub async fn run_checked(
    first: &Client,
    second: &Client,
    module: &[u8],
    input: &[u8],
    fuel: Option<u64>,
    rate: f64,
) -> SdkResult<Checked> {
    let computed = first.compute(module, input, fuel).await?;
    let draw = f64::from(OsRng.next_u32()) / f64::from(u32::MAX);
    if draw >= rate.clamp(0.0, 1.0) && rate < 1.0 {
        return Ok(Checked::Agreed { computed, confirmed: false });
    }
    let other = second.compute(module, input, fuel).await?;
    if other.output == computed.output {
        Ok(Checked::Agreed { computed, confirmed: true })
    } else {
        Ok(Checked::Mismatch { first: computed, second: other })
    }
}

impl Client {
    /// Calls an installed plugin of the connected node (docs/09 §12): its `handle` gets `input`, the answer is its
    /// output (the plugin's own data - not signed by the node).
    pub async fn plugin_call(&self, plugin: &bridge_core::Id, input: &[u8]) -> SdkResult<Vec<u8>> {
        let body = json!({"input": b64(input)});
        let path = format!("/v4/plugin/{plugin}/call");
        let answer = Self::check(self.http.post(&path, self.session.as_deref(), body.to_string().into_bytes()).await?)?;
        Ok(b64_var(answer.get("output").and_then(Value::as_str).unwrap_or_default(), "output", MAX_OUTPUT)?)
    }
}
