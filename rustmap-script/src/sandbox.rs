use mlua::{Lua, Result as LuaResult, StdLib, Value};

use crate::error::ScriptError;

/// Maximum memory a script can allocate (50 MB).
const MEMORY_LIMIT: usize = 50 * 1024 * 1024;

/// Maximum number of Lua VM instructions before a script is killed.
const INSTRUCTION_LIMIT: u32 = 10_000_000;

/// A sandboxed Lua environment that restricts dangerous operations.
pub struct LuaSandbox {
    lua: Lua,
}

impl LuaSandbox {
    /// Create a new sandboxed Lua environment.
    pub fn new() -> Result<Self, ScriptError> {
        // Load only safe standard libraries
        let libs = StdLib::STRING
            | StdLib::TABLE
            | StdLib::MATH
            | StdLib::COROUTINE
            | StdLib::OS
            | StdLib::UTF8;

        let lua = Lua::new_with(libs, mlua::LuaOptions::default())
            .map_err(|e| ScriptError::Lua(format!("failed to create Lua state: {e}")))?;

        // Set memory limit
        let _ = lua.set_memory_limit(MEMORY_LIMIT);

        // Remove dangerous functions from the os table
        remove_dangerous_functions(&lua)?;

        Ok(Self { lua })
    }

    /// Get a reference to the inner Lua state.
    pub fn lua(&self) -> &Lua {
        &self.lua
    }

    /// Execute a Lua chunk from a string and return the result.
    pub fn execute(&self, code: &str) -> Result<Value, ScriptError> {
        // Set instruction limit hook to prevent infinite loops
        let hook_count = INSTRUCTION_LIMIT;
        self.lua
            .set_hook(
                mlua::HookTriggers::new().every_nth_instruction(hook_count),
                |_lua, _debug| {
                    Err(mlua::Error::RuntimeError(
                        "script exceeded instruction limit".into(),
                    ))
                },
            );

        let result = self
            .lua
            .load(code)
            .eval::<Value>()
            .map_err(|e| ScriptError::Lua(e.to_string()))?;

        // Remove hook after execution
        self.lua.remove_hook();

        Ok(result)
    }

    /// Load and execute a Lua file.
    pub fn execute_file(&self, path: &std::path::Path) -> Result<(), ScriptError> {
        let code = std::fs::read_to_string(path)?;

        // Set instruction limit hook to prevent infinite loops
        let hook_count = INSTRUCTION_LIMIT;
        self.lua
            .set_hook(
                mlua::HookTriggers::new().every_nth_instruction(hook_count),
                |_lua, _debug| {
                    Err(mlua::Error::RuntimeError(
                        "script exceeded instruction limit".into(),
                    ))
                },
            );

        let result = self.lua
            .load(&code)
            .set_name(path.to_string_lossy())
            .exec()
            .map_err(|e| ScriptError::Lua(e.to_string()));

        // Remove hook after execution
        self.lua.remove_hook();

        result
    }

    /// Call a global Lua function with arguments and return its result.
    pub fn call_function(
        &self,
        name: &str,
        args: impl mlua::IntoLuaMulti,
    ) -> Result<Value, ScriptError> {
        let func: mlua::Function = self
            .lua
            .globals()
            .get(name)
            .map_err(|e| ScriptError::Lua(format!("function '{name}' not found: {e}")))?;

        // Set instruction limit hook to prevent infinite loops
        let hook_count = INSTRUCTION_LIMIT;
        self.lua
            .set_hook(
                mlua::HookTriggers::new().every_nth_instruction(hook_count),
                |_lua, _debug| {
                    Err(mlua::Error::RuntimeError(
                        "script exceeded instruction limit".into(),
                    ))
                },
            );

        let result = func.call(args)
            .map_err(|e| ScriptError::Lua(e.to_string()));

        // Remove hook after execution
        self.lua.remove_hook();

        result
    }
}

/// Remove dangerous functions from the Lua environment.
fn remove_dangerous_functions(lua: &Lua) -> Result<(), ScriptError> {
    let globals = lua.globals();

    // Remove top-level dangerous functions.
    // - loadfile/dofile: load and execute arbitrary files
    // - load: execute arbitrary Lua from strings (bypasses file restrictions)
    // - require: module loading (package lib not loaded, but prevent attempts)
    // - rawget/rawset: bypass __index/__newindex metamethods
    // - getmetatable/setmetatable: metatable manipulation can escape sandbox
    let dangerous_globals = [
        "loadfile",
        "dofile",
        "load",
        "require",
        "rawget",
        "rawset",
        "getmetatable",
        "setmetatable",
    ];
    for name in &dangerous_globals {
        globals
            .set(*name, Value::Nil)
            .map_err(|e| ScriptError::Sandbox(format!("failed to remove {name}: {e}")))?;
    }

    // Remove dangerous os functions, keep safe ones (os.time, os.clock, os.date, os.difftime)
    let os_table: mlua::Table = globals
        .get("os")
        .map_err(|e| ScriptError::Sandbox(format!("os table not found: {e}")))?;

    let dangerous_os = ["execute", "remove", "rename", "exit", "tmpname", "getenv", "setlocale"];
    for name in &dangerous_os {
        os_table
            .set(*name, Value::Nil)
            .map_err(|e| ScriptError::Sandbox(format!("failed to remove os.{name}: {e}")))?;
    }

    Ok(())
}

/// Convert a Lua Value to a ScriptValue for storage.
pub fn lua_value_to_script_value(value: &Value) -> Option<rustmap_types::ScriptValue> {
    match value {
        Value::String(s) => Some(rustmap_types::ScriptValue::String(
            s.to_string_lossy().to_string(),
        )),
        Value::Integer(n) => Some(rustmap_types::ScriptValue::Number(*n as f64)),
        Value::Number(n) => Some(rustmap_types::ScriptValue::Number(*n)),
        Value::Boolean(b) => Some(rustmap_types::ScriptValue::Bool(*b)),
        Value::Table(t) => {
            // Check if it's a sequence (array) or a map
            let len = t.raw_len();
            if len > 0 {
                // Try as array first
                let mut is_array = true;
                let mut items = Vec::new();
                for i in 1..=len {
                    match t.raw_get::<Value>(i) {
                        Ok(v) => {
                            if let Some(sv) = lua_value_to_script_value(&v) {
                                items.push(sv);
                            } else {
                                is_array = false;
                                break;
                            }
                        }
                        Err(_) => {
                            is_array = false;
                            break;
                        }
                    }
                }
                if is_array {
                    return Some(rustmap_types::ScriptValue::List(items));
                }
            }

            // Treat as map
            let mut map = Vec::new();
            if let Ok(pairs) = t.pairs::<Value, Value>().collect::<LuaResult<Vec<_>>>() {
                for (k, v) in pairs {
                    let key = match &k {
                        Value::String(s) => s.to_string_lossy().to_string(),
                        Value::Integer(n) => n.to_string(),
                        _ => continue,
                    };
                    if let Some(sv) = lua_value_to_script_value(&v) {
                        map.push((key, sv));
                    }
                }
            }
            if map.is_empty() {
                None
            } else {
                Some(rustmap_types::ScriptValue::Map(map))
            }
        }
        Value::Nil | Value::LightUserData(_) | Value::Function(_) | Value::Thread(_)
        | Value::UserData(_) | Value::Error(_) | Value::Other(..) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_creates_successfully() {
        let sandbox = LuaSandbox::new().unwrap();
        let result = sandbox.execute("return 1 + 2").unwrap();
        assert_eq!(result.as_integer(), Some(3));
    }

    #[test]
    fn sandbox_allows_string_library() {
        let sandbox = LuaSandbox::new().unwrap();
        let result = sandbox.execute(r#"return string.upper("hello")"#).unwrap();
        assert_eq!(
            result.as_str().map(|s| s.to_string()),
            Some("HELLO".to_string())
        );
    }

    #[test]
    fn sandbox_allows_table_library() {
        let sandbox = LuaSandbox::new().unwrap();
        let result = sandbox
            .execute(
                r#"
                local t = {3, 1, 2}
                table.sort(t)
                return t[1]
            "#,
            )
            .unwrap();
        assert_eq!(result.as_integer(), Some(1));
    }

    #[test]
    fn sandbox_allows_math_library() {
        let sandbox = LuaSandbox::new().unwrap();
        let result = sandbox.execute("return math.floor(3.7)").unwrap();
        assert_eq!(result.as_integer(), Some(3));
    }

    #[test]
    fn sandbox_allows_os_time() {
        let sandbox = LuaSandbox::new().unwrap();
        let result = sandbox.execute("return os.time()").unwrap();
        assert!(result.as_integer().is_some());
    }

    #[test]
    fn sandbox_blocks_os_execute() {
        let sandbox = LuaSandbox::new().unwrap();
        let result = sandbox.execute(r#"return os.execute("echo hello")"#);
        assert!(result.is_err());
    }

    #[test]
    fn sandbox_blocks_os_remove() {
        let sandbox = LuaSandbox::new().unwrap();
        let result = sandbox.execute(r#"os.remove("/tmp/test")"#);
        assert!(result.is_err());
    }

    #[test]
    fn sandbox_blocks_loadfile() {
        let sandbox = LuaSandbox::new().unwrap();
        let result = sandbox.execute(r#"return loadfile("/etc/passwd")"#);
        // loadfile is nil, so calling it fails
        assert!(result.is_err() || matches!(result.unwrap(), Value::Nil));
    }

    #[test]
    fn sandbox_blocks_dofile() {
        let sandbox = LuaSandbox::new().unwrap();
        let result = sandbox.execute(r#"dofile("/etc/passwd")"#);
        assert!(result.is_err());
    }

    #[test]
    fn sandbox_blocks_load() {
        let sandbox = LuaSandbox::new().unwrap();
        let result = sandbox.execute(r#"return load("return 1")()"#);
        assert!(result.is_err());
    }

    #[test]
    fn sandbox_blocks_require() {
        let sandbox = LuaSandbox::new().unwrap();
        let result = sandbox.execute(r#"require("os")"#);
        assert!(result.is_err());
    }

    #[test]
    fn sandbox_blocks_getmetatable() {
        let sandbox = LuaSandbox::new().unwrap();
        let result = sandbox.execute(r#"return getmetatable("")"#);
        assert!(result.is_err());
    }

    #[test]
    fn sandbox_blocks_setmetatable() {
        let sandbox = LuaSandbox::new().unwrap();
        let result = sandbox.execute(r#"setmetatable({}, {})"#);
        assert!(result.is_err());
    }

    #[test]
    fn sandbox_memory_limit() {
        let sandbox = LuaSandbox::new().unwrap();
        // Try to allocate a very large string
        let result = sandbox.execute(
            r#"
            local s = "x"
            for i = 1, 30 do
                s = s .. s
            end
            return #s
        "#,
        );
        // Should fail due to memory limit
        assert!(result.is_err());
    }

    #[test]
    fn lua_value_to_script_value_string() {
        let sandbox = LuaSandbox::new().unwrap();
        let val = sandbox.execute(r#"return "hello""#).unwrap();
        let sv = lua_value_to_script_value(&val).unwrap();
        assert!(matches!(sv, rustmap_types::ScriptValue::String(s) if s == "hello"));
    }

    #[test]
    fn lua_value_to_script_value_number() {
        let sandbox = LuaSandbox::new().unwrap();
        let val = sandbox.execute("return 42").unwrap();
        let sv = lua_value_to_script_value(&val).unwrap();
        assert!(matches!(sv, rustmap_types::ScriptValue::Number(n) if (n - 42.0).abs() < f64::EPSILON));
    }

    #[test]
    fn lua_value_to_script_value_table_as_list() {
        let sandbox = LuaSandbox::new().unwrap();
        let val = sandbox.execute("return {1, 2, 3}").unwrap();
        let sv = lua_value_to_script_value(&val).unwrap();
        assert!(matches!(sv, rustmap_types::ScriptValue::List(ref items) if items.len() == 3));
    }

    #[test]
    fn lua_value_to_script_value_table_as_map() {
        let sandbox = LuaSandbox::new().unwrap();
        let val = sandbox
            .execute(r#"return {name = "test", value = 42}"#)
            .unwrap();
        let sv = lua_value_to_script_value(&val).unwrap();
        assert!(matches!(sv, rustmap_types::ScriptValue::Map(_)));
    }

    #[test]
    fn lua_value_to_script_value_nil() {
        let sandbox = LuaSandbox::new().unwrap();
        let val = sandbox.execute("return nil").unwrap();
        let sv = lua_value_to_script_value(&val);
        assert!(sv.is_none());
    }

    #[test]
    fn lua_value_to_script_value_bool() {
        let sandbox = LuaSandbox::new().unwrap();
        let val = sandbox.execute("return true").unwrap();
        let sv = lua_value_to_script_value(&val).unwrap();
        assert!(matches!(sv, rustmap_types::ScriptValue::Bool(true)));
    }
}
