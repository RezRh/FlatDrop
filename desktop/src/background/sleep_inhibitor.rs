//! Desktop Background Transfer Support
//!
//! Prevents OS sleep during transfers using platform-specific inhibitors
//! Works on Windows, Linux, and macOS

use crate::types::{transfer_state_changed, TransferStateChanged};
use std::{
    collections::HashSet,
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use keepawake::{Builder, Inhibitor};

pub struct DesktopSleepInhibitor {
    inner: Arc<Mutex<InhibitorState>>,
}

struct InhibitorState {
    active: HashSet<String>,
    handle: Option<PlatformHandle>,
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
struct PlatformHandle {
    _inhibitor: Inhibitor,
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
struct PlatformHandle;

impl DesktopSleepInhibitor {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InhibitorState {
                active: HashSet::new(),
                handle: None,
            })),
        }
    }

    pub fn handle_transfer_state_change(&self, state: &TransferStateChanged) {
        match state.state() {
            transfer_state_changed::State::Preparing | transfer_state_changed::State::InProgress => {
                self.start_inhibiting(&state.transfer_id);
            }
            transfer_state_changed::State::Finished
            | transfer_state_changed::State::Failed
            | transfer_state_changed::State::Cancelled => {
                self.stop_inhibiting(&state.transfer_id);
            }
            _ => {}
        }
    }

    fn start_inhibiting(&self, transfer_id: &str) {
        let mut guard = self.lock_state();
        let inserted = guard.active.insert(transfer_id.to_string());
        if !inserted {
            return;
        }
        if guard.active.len() == 1 && guard.handle.is_none() {
            match Self::platform_inhibit() {
                Ok(h) => {
                    guard.handle = Some(h);
                    tracing::info!("Sleep inhibition enabled");
                }
                Err(e) => {
                    tracing::error!("Failed to enable sleep inhibition: {}", e);
                }
            }
        }
    }

    fn stop_inhibiting(&self, transfer_id: &str) {
        let mut guard = self.lock_state();
        let removed = guard.active.remove(transfer_id);
        if !removed {
            return;
        }
        if guard.active.is_empty() {
            guard.handle = None;
            tracing::info!("Sleep inhibition disabled");
        }
    }

    pub fn active_transfer_count(&self) -> usize {
        self.lock_state().active.len()
    }

    pub fn is_inhibiting(&self) -> bool {
        let guard = self.lock_state();
        !guard.active.is_empty() && guard.handle.is_some()
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, InhibitorState> {
        match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    fn platform_inhibit() -> Result<PlatformHandle, String> {
        let inhibitor = Builder::default()
            .idle(true)
            .display(false)
            .create()
            .map_err(|e| format!("{e:?}"))?;
        Ok(PlatformHandle { _inhibitor: inhibitor })
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    fn platform_inhibit() -> Result<PlatformHandle, String> {
        Ok(PlatformHandle)
    }
}

impl Default for DesktopSleepInhibitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for DesktopSleepInhibitor {
    fn drop(&mut self) {
        let mut guard = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.active.clear();
        guard.handle = None;
    }
}

pub struct DesktopConfig {
    pub inhibit_sleep: bool,
    pub show_notifications: bool,
    pub download_dir: PathBuf,
    pub show_progress_in_title: bool,
}

impl Default for DesktopConfig {
    fn default() -> Self {
        let download_dir = dirs::download_dir()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."));
        Self {
            inhibit_sleep: true,
            show_notifications: true,
            download_dir,
            show_progress_in_title: true,
        }
    }
}

pub struct DesktopBackgroundManager {
    inhibitor: DesktopSleepInhibitor,
    config: DesktopConfig,
}

impl DesktopBackgroundManager {
    pub fn new() -> Self {
        Self {
            inhibitor: DesktopSleepInhibitor::new(),
            config: DesktopConfig::default(),
        }
    }

    pub fn with_config(config: DesktopConfig) -> Self {
        Self {
            inhibitor: DesktopSleepInhibitor::new(),
            config,
        }
    }

    pub fn handle_transfer_state_change(&self, state: &TransferStateChanged) {
        if self.config.inhibit_sleep {
            self.inhibitor.handle_transfer_state_change(state);
        }

        match state.state() {
            transfer_state_changed::State::Preparing => {
                tracing::info!(transfer_id=%state.transfer_id, file=%state.file_name, "transfer preparing");
                self.update_title_bar("Preparing...", state.progress);
            }
            transfer_state_changed::State::InProgress => {
                let pct = (state.progress.clamp(0.0, 1.0) * 100.0).round() as i32;
                tracing::info!(transfer_id=%state.transfer_id, file=%state.file_name, pct, "transfer progress");
                self.update_title_bar(&format!("{pct}%"), state.progress);
            }
            transfer_state_changed::State::Finished => {
                tracing::info!(transfer_id=%state.transfer_id, file=%state.file_name, "transfer complete");
                self.update_title_bar("Complete", 1.0);
            }
            transfer_state_changed::State::Failed => {
                tracing::error!(
                    transfer_id=%state.transfer_id,
                    file=%state.file_name,
                    error=%state.error_message,
                    "transfer failed"
                );
                self.update_title_bar("Failed", 0.0);
            }
            transfer_state_changed::State::Cancelled => {
                tracing::info!(transfer_id=%state.transfer_id, file=%state.file_name, "transfer cancelled");
                self.update_title_bar("Cancelled", 0.0);
            }
            _ => {}
        }
    }

    fn update_title_bar(&self, status: &str, _progress: f64) {
        if self.config.show_progress_in_title {
            tracing::debug!("Window title: FlatDrop - {}", status);
        }
    }

    pub fn active_transfer_count(&self) -> usize {
        self.inhibitor.active_transfer_count()
    }

    pub fn is_inhibiting_sleep(&self) -> bool {
        self.inhibitor.is_inhibiting()
    }
}

impl Default for DesktopBackgroundManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sleep_inhibitor_tracks_transfers() {
        let inhibitor = DesktopSleepInhibitor::new();

        inhibitor.start_inhibiting("t1");
        inhibitor.start_inhibiting("t2");

        assert_eq!(inhibitor.active_transfer_count(), 2);

        inhibitor.stop_inhibiting("t1");
        assert_eq!(inhibitor.active_transfer_count(), 1);

        inhibitor.stop_inhibiting("t2");
        assert_eq!(inhibitor.active_transfer_count(), 0);
    }
}