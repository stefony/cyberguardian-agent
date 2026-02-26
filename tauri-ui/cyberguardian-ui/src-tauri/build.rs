fn main() {
    #[cfg(target_os = "windows")]
    embed_manifest::embed_manifest(embed_manifest::new_manifest("app.manifest")).unwrap();
    tauri_build::build()
}
