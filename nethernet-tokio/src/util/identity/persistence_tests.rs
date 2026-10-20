use super::*;
use std::{
    future::{Future, poll_fn},
    path::PathBuf,
    sync::{Arc, Mutex, mpsc},
    task::{Context, Poll, Wake, Waker},
};
use tokio::{runtime::Handle, task::JoinHandle};

/// Releases its one owned blocking task even when fixture setup unwinds.
struct BlockedWrite {
    release: Option<mpsc::Sender<()>>,
    task: Option<JoinHandle<()>>,
    file_created: bool,
}

impl BlockedWrite {
    /// Queues before the identity future's next filesystem operation on its sole blocking worker.
    fn new(runtime: &Handle, file_created: bool) -> Self {
        let (release, wait) = mpsc::channel();
        let task = runtime.spawn_blocking(move || {
            let _ = wait.recv();
        });
        Self {
            release: Some(release),
            task: Some(task),
            file_created,
        }
    }

    /// Releases and joins this exact task before any persistence assertion.
    async fn finish(mut self) {
        let _ = self.release.take().unwrap().send(());
        self.task.take().unwrap().await.unwrap();
    }
}

impl Drop for BlockedWrite {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

struct CreationWake {
    path: PathBuf,
    runtime: Handle,
    state: Mutex<CreationState>,
}

struct CreationState {
    outer: Waker,
    blocked: Option<BlockedWrite>,
    created: bool,
}

impl Wake for CreationWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    /// Holds each real filesystem completion until the next original operation registers its wait.
    fn wake_by_ref(self: &Arc<Self>) {
        let outer = {
            let mut state = self.state.lock().unwrap();
            if !state.created && state.blocked.is_none() {
                state.created = self.path.is_file();
                state.blocked = Some(BlockedWrite::new(&self.runtime, state.created));
            }
            state.outer.clone()
        };
        outer.wake();
    }
}

/// The actual identity writer must finish its queued file write before publishing the saved identity.
#[test]
fn a_created_identity_waits_for_its_original_file_write_before_returning() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let directory = std::env::temp_dir().join(format!(
            "nethernet-persist-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&directory).unwrap();
        let pem = directory.join("identity.pem");
        let gate = Arc::new(CreationWake {
            path: pem.clone(),
            runtime: Handle::current(),
            state: Mutex::new(CreationState {
                outer: Waker::noop().clone(),
                blocked: Some(BlockedWrite::new(&Handle::current(), false)),
                created: false,
            }),
        });
        let waker = Waker::from(Arc::clone(&gate));
        let mut saving = Box::pin(from_pem_or_create(&pem, "example.com"));
        let (waited_for_write, completed) = loop {
            let (result, blocked) = poll_fn(|cx| {
                let outer = cx.waker().clone();
                let previous = {
                    let mut state = gate.state.lock().unwrap();
                    std::mem::replace(&mut state.outer, outer)
                };
                drop(previous);
                let result = saving.as_mut().poll(&mut Context::from_waker(&waker));
                let blocked = gate.state.lock().unwrap().blocked.take();
                if blocked.is_some() || result.is_ready() {
                    Poll::Ready((result, blocked))
                } else {
                    Poll::Pending
                }
            })
            .await;
            let file_created = blocked.as_ref().is_some_and(|blocked| blocked.file_created);
            if let Some(blocked) = blocked {
                blocked.finish().await;
            }
            if file_created || result.is_ready() {
                break (file_created && result.is_pending(), result);
            }
        };
        let created = match completed {
            Poll::Ready(result) => result.unwrap(),
            Poll::Pending => saving.await.unwrap(),
        };
        let loaded = from_pem(&pem, "example.com").await.unwrap();
        let same_key = created.verifying_key() == loaded.verifying_key();
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::metadata(&pem)
                .await
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        };
        tokio::fs::remove_dir_all(&directory).await.unwrap();
        drop(gate);

        assert!(same_key, "original persisted identity did not reload");
        #[cfg(unix)]
        assert_eq!(mode, 0o600);
        assert!(
            waited_for_write,
            "identity creation returned while its original file write was still queued"
        );
    });
}
