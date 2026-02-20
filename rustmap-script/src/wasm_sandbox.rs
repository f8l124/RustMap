// ---------------------------------------------------------------------------
// WebAssembly scripting sandbox using wasmtime
// ---------------------------------------------------------------------------
//
// WASM scripts communicate with the host through JSON-encoded buffers
// passed through linear memory. The ABI:
// 1. Host calls guest `alloc(len)` → returns pointer
// 2. Host writes JSON input at that pointer
// 3. Host calls guest `action(ptr, len)` → returns packed u64 (ptr << 32 | len)
// 4. Host reads JSON output from returned pointer

use crate::error::ScriptError;
use rustmap_types::ScriptResult;
use wasmtime::*;

/// Maximum guest memory: 50 MB.
const WASM_MEMORY_LIMIT: usize = 50 * 1024 * 1024;

/// Instruction fuel limit (prevents infinite loops).
const WASM_FUEL_LIMIT: u64 = 10_000_000;

/// Internal state for the wasmtime Store.
struct WasmState {
    limits: StoreLimits,
}

/// A sandboxed WASM execution environment with resource limits.
pub struct WasmSandbox {
    module: Module,
    store: Store<WasmState>,
}

impl WasmSandbox {
    /// Create a new WASM sandbox from raw module bytes (binary or WAT text).
    pub fn new(wasm_bytes: &[u8]) -> Result<Self, ScriptError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config)
            .map_err(|e| ScriptError::Wasm(format!("failed to create WASM engine: {e}")))?;
        let module = Module::new(&engine, wasm_bytes)
            .map_err(|e| ScriptError::Wasm(format!("failed to compile WASM module: {e}")))?;

        let mut store = Store::new(
            &engine,
            WasmState {
                limits: StoreLimitsBuilder::new()
                    .memory_size(WASM_MEMORY_LIMIT)
                    .build(),
            },
        );
        store
            .set_fuel(WASM_FUEL_LIMIT)
            .map_err(|e| ScriptError::Wasm(format!("failed to set fuel: {e}")))?;
        store.limiter(|state| &mut state.limits);

        Ok(Self { module, store })
    }

    /// Execute the WASM module's `action` function with JSON input.
    ///
    /// Returns the raw output bytes (expected to be JSON).
    pub fn execute(&mut self, input_json: &[u8]) -> Result<Vec<u8>, ScriptError> {
        let instance = Instance::new(&mut self.store, &self.module, &[])
            .map_err(|e| ScriptError::Wasm(format!("failed to instantiate module: {e}")))?;

        let memory = instance
            .get_memory(&mut self.store, "memory")
            .ok_or_else(|| ScriptError::Wasm("module does not export 'memory'".into()))?;

        let alloc = instance
            .get_typed_func::<u32, u32>(&mut self.store, "alloc")
            .map_err(|e| ScriptError::Wasm(format!("module missing 'alloc' export: {e}")))?;
        let action = instance
            .get_typed_func::<(u32, u32), u64>(&mut self.store, "action")
            .map_err(|e| ScriptError::Wasm(format!("module missing 'action' export: {e}")))?;

        // Allocate space for input in guest memory
        let ptr = alloc
            .call(&mut self.store, input_json.len() as u32)
            .map_err(|e| ScriptError::Wasm(format!("alloc failed: {e}")))?;

        // Write input JSON to guest memory
        memory
            .write(&mut self.store, ptr as usize, input_json)
            .map_err(|e| ScriptError::Wasm(format!("failed to write input to memory: {e}")))?;

        // Call the action function
        let result = action
            .call(&mut self.store, (ptr, input_json.len() as u32))
            .map_err(|e| ScriptError::Wasm(format!("action failed: {e}")))?;

        // Decode packed result: high 32 bits = output pointer, low 32 bits = output length
        let out_ptr = (result >> 32) as u32;
        let out_len = (result & 0xFFFF_FFFF) as u32;

        if out_len == 0 {
            return Ok(Vec::new());
        }

        if out_len as usize > WASM_MEMORY_LIMIT {
            return Err(ScriptError::Wasm(format!(
                "output length {} exceeds memory limit {}",
                out_len, WASM_MEMORY_LIMIT
            )));
        }

        // Read output from guest memory
        let mut output = vec![0u8; out_len as usize];
        memory
            .read(&self.store, out_ptr as usize, &mut output)
            .map_err(|e| ScriptError::Wasm(format!("failed to read output from memory: {e}")))?;

        Ok(output)
    }
}

/// Parse WASM script output bytes into a ScriptResult.
pub fn parse_wasm_output(
    script_id: &str,
    output_bytes: &[u8],
) -> Result<Option<ScriptResult>, ScriptError> {
    if output_bytes.is_empty() || output_bytes == b"null" {
        return Ok(None);
    }

    let output: serde_json::Value = serde_json::from_slice(output_bytes)
        .map_err(|e| ScriptError::Execution(format!("WASM output is not valid JSON: {e}")))?;

    if output.is_null() {
        return Ok(None);
    }

    let output_str = output
        .get("output")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if output_str.is_empty() {
        return Ok(None);
    }

    Ok(Some(ScriptResult {
        id: script_id.to_string(),
        output: output_str,
        elements: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_sandbox_basic_execution() {
        let wat = br#"
        (module
            (memory (export "memory") 1)
            (func (export "alloc") (param $len i32) (result i32)
                i32.const 1024
            )
            (func (export "action") (param $ptr i32) (param $len i32) (result i64)
                ;; Write "{}" at offset 2048
                (i32.store8 (i32.const 2048) (i32.const 123))
                (i32.store8 (i32.const 2049) (i32.const 125))
                ;; Return packed: (2048 << 32) | 2
                (i64.or
                    (i64.shl (i64.extend_i32_u (i32.const 2048)) (i64.const 32))
                    (i64.const 2)
                )
            )
        )
        "#;
        let mut sandbox = WasmSandbox::new(wat).unwrap();
        let output = sandbox.execute(b"{}").unwrap();
        assert_eq!(output, b"{}");
    }

    #[test]
    fn wasm_sandbox_fuel_exhaustion() {
        let wat = br#"
        (module
            (memory (export "memory") 1)
            (func (export "alloc") (param $len i32) (result i32)
                i32.const 1024
            )
            (func (export "action") (param $ptr i32) (param $len i32) (result i64)
                (local $i i32)
                (loop $loop
                    (local.set $i (i32.add (local.get $i) (i32.const 1)))
                    (br $loop)
                )
                i64.const 0
            )
        )
        "#;
        let mut sandbox = WasmSandbox::new(wat).unwrap();
        let result = sandbox.execute(b"{}");
        assert!(result.is_err(), "infinite loop should exhaust fuel");
    }

    #[test]
    fn wasm_sandbox_missing_memory() {
        let wat = br#"
        (module
            (func (export "alloc") (param $len i32) (result i32) i32.const 0)
            (func (export "action") (param $ptr i32) (param $len i32) (result i64) i64.const 0)
        )
        "#;
        let mut sandbox = WasmSandbox::new(wat).unwrap();
        let result = sandbox.execute(b"{}");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("memory"));
    }

    #[test]
    fn wasm_sandbox_missing_alloc() {
        let wat = br#"
        (module
            (memory (export "memory") 1)
            (func (export "action") (param $ptr i32) (param $len i32) (result i64) i64.const 0)
        )
        "#;
        let mut sandbox = WasmSandbox::new(wat).unwrap();
        let result = sandbox.execute(b"{}");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("alloc"));
    }

    #[test]
    fn parse_wasm_output_empty() {
        assert!(parse_wasm_output("test", b"").unwrap().is_none());
    }

    #[test]
    fn parse_wasm_output_null() {
        assert!(parse_wasm_output("test", b"null").unwrap().is_none());
    }

    #[test]
    fn parse_wasm_output_valid() {
        let json = br#"{"output": "hello world"}"#;
        let result = parse_wasm_output("test-script", json).unwrap().unwrap();
        assert_eq!(result.id, "test-script");
        assert_eq!(result.output, "hello world");
    }

    #[test]
    fn parse_wasm_output_empty_output_field() {
        let json = br#"{"output": ""}"#;
        assert!(parse_wasm_output("test", json).unwrap().is_none());
    }
}
