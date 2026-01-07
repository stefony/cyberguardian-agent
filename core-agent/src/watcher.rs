use notify::{Watcher, RecursiveMode, Event};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};
use std::path::Path;
use std::thread;
use crate::ml_integration;

pub struct FileWatcher {
    paths: Vec<String>,
    events: Arc<Mutex<Vec<FileEvent>>>,
    monitoring: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct FileEvent {
    pub event_type: String,
    pub path: String,
    pub timestamp: String,
    pub file_size: Option<u64>,
    pub threat_score: Option<u8>,
    pub threat_category: Option<String>,
}

impl FileWatcher {
    pub fn new() -> Self {
        Self {
            paths: Vec::new(),
            events: Arc::new(Mutex::new(Vec::new())),
            monitoring: false,
        }
    }

    pub fn start(&mut self, paths: Vec<String>) -> notify::Result<()> {
        println!("👀 Starting file watcher for {} paths", paths.len());
        self.paths = paths.clone();
        self.monitoring = true;

        let (tx, rx) = channel();
        let mut watcher = notify::recommended_watcher(tx)?;

        for path in &paths {
            println!("📂 Watching: {}", path);
            watcher.watch(Path::new(path), RecursiveMode::Recursive)?;
        }

        let events = self.events.clone();
        thread::spawn(move || {
            Self::process_events(rx, watcher, events);
        });
        
        Ok(())
    }

    pub fn stop(&mut self) {
        println!("🛑 Stopping file watcher");
        self.monitoring = false;
        self.paths.clear();
    }

    fn process_events(
        _rx: Receiver<notify::Result<Event>>,
        _watcher: impl Watcher,
        events: Arc<Mutex<Vec<FileEvent>>>
    ) {
        loop {
            match _rx.recv() {
                Ok(Ok(event)) => {
                    let event_type = format!("{:?}", event.kind);
                    for path in event.paths {
                        println!("📁 File event: {} - {:?}", event_type, path);
                        
                        let file_size = if path.exists() {
                            std::fs::metadata(&path).ok().map(|m| m.len())
                        } else {
                            None
                        };
                        
                        // Scan file for threats (skip if file doesn't exist)
let (threat_score, threat_category) = if path.exists() {
    match ml_integration::scan_file(&path.display().to_string()) {
        Ok((score, category)) => {
            println!("🔍 Threat scan: {} - Score: {}, Category: {}", path.display(), score, category);
            (Some(score), Some(category))
        },
        Err(e) => {
            println!("⚠️ ML scan failed: {}", e);
            (None, None)
        }
    }
} else {
    // File doesn't exist (removed), skip scan
    (None, None)
};

                        let file_event = FileEvent {
                            event_type: event_type.clone(),
                            path: path.display().to_string(),
                            timestamp: chrono::Utc::now().to_rfc3339(),
                            file_size,
                            threat_score,
                            threat_category,
                        };
                        
                        if let Ok(mut events_list) = events.lock() {
                            events_list.push(file_event);
                            if events_list.len() > 100 {
                                events_list.remove(0);
                            }
                        }
                    }
                },
                Ok(Err(e)) => println!("❌ Watch error: {:?}", e),
                Err(e) => {
                    println!("❌ Channel error: {:?}", e);
                    break;
                }
            }
        }
    }

    pub fn get_paths(&self) -> Vec<String> {
        self.paths.clone()
    }

    pub fn is_monitoring(&self) -> bool {
        self.monitoring
    }

    pub fn get_events(&self) -> Vec<FileEvent> {
        if let Ok(events) = self.events.lock() {
            events.clone()
        } else {
            Vec::new()
        }
    }
}