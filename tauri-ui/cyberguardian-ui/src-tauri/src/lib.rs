use tauri::{
    Manager,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{TrayIconBuilder, TrayIconEvent, MouseButton, MouseButtonState},
};

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_http::init())
        .setup(|app| {
            println!("🔧 Setup starting...");

            // -----------------------------
            // TRAY MENU (right-click on tray icon)
            // -----------------------------
            let dashboard_item =
                MenuItem::with_id(app, "dashboard", "Open Dashboard", true, None::<&str>)?;
            let protection_item =
                MenuItem::with_id(app, "protection", "Protection: ON", true, None::<&str>)?;
            let settings_item =
                MenuItem::with_id(app, "settings", "Settings", true, None::<&str>)?;
            let devtools_item =
                MenuItem::with_id(app, "toggle_devtools", "Toggle DevTools", true, None::<&str>)?;
            let quit_item =
                MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;

            let tray_menu = Menu::with_items(app, &[
                &dashboard_item,
                &protection_item,
                &settings_item,
                &PredefinedMenuItem::separator(app)?,
                &devtools_item,
                &PredefinedMenuItem::separator(app)?,
                &quit_item,
            ])?;

            println!("✅ Tray menu created");

            // -----------------------------
            // APP MENU BAR (top menu in window)
            // -----------------------------
            let app_devtools_item =
                MenuItem::with_id(app, "toggle_devtools", "Toggle DevTools", true, None::<&str>)?;
            let app_menu = Menu::with_items(app, &[
                &PredefinedMenuItem::separator(app)?,
                &app_devtools_item,
            ])?;
            app.set_menu(app_menu)?;

            println!("✅ App menu set");

            // -----------------------------
            // TRAY ICON
            // -----------------------------
            let _tray = TrayIconBuilder::new()
                .menu(&tray_menu)
                .tooltip("CyberGuardian XDR")
                .on_tray_icon_event(|tray, event| {
                    println!("🖱️ Tray icon event: {:?}", event);

                    match event {
                        TrayIconEvent::Click { button, button_state, .. } => {
                            println!(
                                "🖱️ Click detected - Button: {:?}, State: {:?}",
                                button, button_state
                            );

                            if button == MouseButton::Right
                                && button_state == MouseButtonState::Down
                            {
                                println!("🖱️ Right click detected - menu should show");
                            }

                            if button == MouseButton::Left
                                && button_state == MouseButtonState::Down
                            {
                                println!("🖱️ Left click detected");
                                if let Some(window) = tray.app_handle().get_webview_window("main") {
                                    let _ = window.show();
                                    let _ = window.set_focus();
                                }
                            }
                        }
                        _ => {}
                    }
                })
                .on_menu_event(|app, event| {
                    println!("🖱️ Menu event: {}", event.id.as_ref());
                    match event.id.as_ref() {
                        "dashboard" => {
                            println!("📊 Opening dashboard...");
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                        "settings" => {
                            println!("⚙️ Opening settings...");
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                    "toggle_devtools" => {
    println!("🛠️ Toggling DevTools...");
    if let Some(window) = app.get_webview_window("main") {
    window.open_devtools();
}

}

                        "quit" => {
                            println!("🛑 Quitting...");
                            std::process::exit(0);
                        }
                        _ => {
                            println!("❓ Unknown menu item: {}", event.id.as_ref());
                        }
                    }
                })
                .build(app)?;

            println!("✅ Tray icon created");
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                println!("🔒 Window close requested - hiding instead");
                window.hide().unwrap();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![greet])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
