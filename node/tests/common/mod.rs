//! Helpers shared by the node's integration tests.

use blacksilk_node::Shared;
use std::sync::mpsc;
use std::sync::PoisonError;
use std::thread::JoinHandle;

/// Holds the chain lock of a [`Shared`] manager on a thread of its own
/// until dropped, so that the chain actor started on it waits.
///
/// A test must not hold the `MutexGuard` itself while it asserts (INV-70):
/// a failing assertion unwinds through the guard and poisons the lock, the
/// actor waiting on it then stops the whole test process with
/// `POISONED_EXIT_CODE` (70, fail-stop), and the failure's own message,
/// captured by the test harness, is never printed. Held here, the guard is
/// released normally when the test unwinds: the actor goes on and the test
/// fails with its message.
pub struct HeldChain {
    release: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl HeldChain {
    /// Takes the lock (waiting for it) and returns once it is held.
    pub fn hold(shared: &Shared) -> Self {
        let (held_tx, held_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel::<()>();
        let chain = shared.clone();
        let thread = std::thread::spawn(move || {
            let _guard = chain.lock().unwrap_or_else(PoisonError::into_inner);
            let _ = held_tx.send(());
            // Released by `drop`: a message or the sender's drop.
            let _ = release_rx.recv();
        });
        held_rx
            .recv()
            .expect("the holder thread holds the chain lock");
        Self {
            release: Some(release),
            thread: Some(thread),
        }
    }
}

impl Drop for HeldChain {
    fn drop(&mut self) {
        drop(self.release.take());
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}
