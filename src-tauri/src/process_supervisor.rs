use std::{
    collections::HashMap,
    process::Child,
    sync::{Mutex, MutexGuard},
};

#[derive(Default)]
pub struct ProcessSupervisor {
    children: Mutex<HashMap<String, Child>>,
}

impl ProcessSupervisor {
    fn children(&self) -> MutexGuard<'_, HashMap<String, Child>> {
        self.children
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn register(&self, id: impl Into<String>, mut child: Child) -> Result<(), &'static str> {
        let id = id.into();
        let mut children = self.children();

        if children.contains_key(&id) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("a managed process already uses this id");
        }

        children.insert(id, child);
        Ok(())
    }

    pub fn running_count(&self) -> usize {
        let mut children = self.children();
        children.retain(|_, child| match child.try_wait() {
            Ok(Some(_)) => false,
            Ok(None) => true,
            Err(_) => true,
        });
        children.len()
    }

    pub fn stop_all(&self) -> usize {
        let mut children = self.children();
        let tracked = children.len();

        for child in children.values_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }

        children.clear();
        tracked
    }
}

impl Drop for ProcessSupervisor {
    fn drop(&mut self) {
        let children = self
            .children
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        for child in children.values_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }

        children.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::ProcessSupervisor;
    use std::process::Command;

    fn spawn_long_running_child() -> std::process::Child {
        #[cfg(windows)]
        {
            Command::new("ping")
                .args(["127.0.0.1", "-n", "30"])
                .spawn()
                .expect("Windows ping should be available in the test runner")
        }

        #[cfg(not(windows))]
        {
            Command::new("sleep")
                .arg("30")
                .spawn()
                .expect("sleep should be available in the test runner")
        }
    }

    #[test]
    fn empty_supervisor_has_no_running_processes() {
        let supervisor = ProcessSupervisor::default();

        assert_eq!(supervisor.running_count(), 0);
        assert_eq!(supervisor.stop_all(), 0);
    }

    #[test]
    fn stop_all_terminates_and_forgets_managed_children() {
        let supervisor = ProcessSupervisor::default();
        let child = spawn_long_running_child();

        supervisor
            .register("test-child", child)
            .expect("child should register");

        assert_eq!(supervisor.running_count(), 1);
        assert_eq!(supervisor.stop_all(), 1);
        assert_eq!(supervisor.running_count(), 0);
    }
}
