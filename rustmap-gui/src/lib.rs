#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod config;
mod state;

use std::sync::Arc;

pub fn run() {
    let scan_state = state::ScanState::new()
        .expect("failed to open scan database — check filesystem permissions");

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(Arc::new(scan_state))
        .invoke_handler(tauri::generate_handler![
            commands::start_scan,
            commands::stop_scan,
            commands::get_scan_history,
            commands::delete_scan_history,
            commands::clear_scan_history,
            commands::export_results,
            commands::export_to_file,
            commands::check_privileges_cmd,
            commands::list_scripts,
            commands::get_scripts_dir,
            commands::parse_custom_scripts,
            commands::list_presets,
            commands::save_preset,
            commands::load_preset,
            commands::delete_preset,
            commands::import_scan_from_file,
            commands::get_app_version,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
