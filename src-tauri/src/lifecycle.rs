use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Default)]
pub struct LifecycleState {
    exit_requested: AtomicBool,
}

impl LifecycleState {
    pub fn begin_exit(&self) {
        self.exit_requested.store(true, Ordering::SeqCst);
    }

    pub fn should_hide_window_on_close(&self) -> bool {
        !self.exit_requested.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::LifecycleState;

    #[test]
    fn ordinary_close_hides_to_tray() {
        let state = LifecycleState::default();

        assert!(state.should_hide_window_on_close());
    }

    #[test]
    fn explicit_exit_stops_close_to_tray_behavior() {
        let state = LifecycleState::default();

        state.begin_exit();

        assert!(!state.should_hide_window_on_close());
    }
}
