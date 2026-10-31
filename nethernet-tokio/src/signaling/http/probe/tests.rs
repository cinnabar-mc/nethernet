use super::*;
use futures::{future::BoxFuture, poll};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::oneshot;

type Reply = oneshot::Sender<Result<(), ProbeError>>;
struct Requests {
    answers: HashMap<String, oneshot::Receiver<Result<(), ProbeError>>>,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Requests {
    /// Reports actual polling and retains each response behind an explicit test barrier.
    fn request(&mut self, endpoint: String) -> BoxFuture<'static, Result<(), ProbeError>> {
        let answer = self
            .answers
            .remove(&endpoint)
            .expect("candidate started once");
        let seen = self.seen.clone();
        Box::pin(async move {
            seen.lock().unwrap().push(endpoint);
            answer.await.expect("fixture retains its response sender")
        })
    }
}

/// Builds controlled completions for all candidates without network timing or sleeps.
fn requests(
    pairs: &[(String, String)],
) -> (Requests, HashMap<String, Reply>, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut answers = HashMap::new();
    let mut replies = HashMap::new();
    for (secure, plain) in pairs {
        for endpoint in [secure, plain] {
            let (reply, answer) = oneshot::channel();
            answers.insert(endpoint.clone(), answer);
            replies.insert(endpoint.clone(), reply);
        }
    }
    (
        Requests {
            answers,
            seen: seen.clone(),
        },
        replies,
        seen,
    )
}

/// Candidate generation treats omitted and explicit game ports identically, including IPv6.
#[test]
fn candidate_batches_cover_default_custom_and_ipv6_ports() {
    for host in ["example.test", "::1", "[::1]"] {
        let formatted = if host.contains(':') { "[::1]" } else { host };
        for port in [0, 19132, 19133] {
            let pairs = candidates(host, port);
            let game = if port == 0 { 19132 } else { port };
            assert_eq!(
                pairs[0],
                (
                    format!("https://{formatted}:{game}"),
                    format!("http://{formatted}:{game}")
                )
            );
            assert_eq!(pairs.len(), if port == 19133 { 1 } else { 2 });
            if pairs.len() == 2 {
                assert_eq!(
                    pairs[1],
                    (
                        format!("https://{formatted}"),
                        format!("http://{formatted}")
                    )
                );
            }
        }
    }
}

/// Refusing 443 cannot release the default HTTP website ahead of a pending secure game port.
#[tokio::test(start_paused = true)]
async fn game_http_starts_early_but_port_80_waits_for_the_head_start() {
    let pairs = candidates("example.test", 19132);
    let (mut requests, mut replies, seen) = requests(&pairs);
    let now = Instant::now();
    let mut probe = Box::pin(run(pairs.clone(), now + Duration::from_secs(20), |url| {
        requests.request(url)
    }));
    assert!(poll!(&mut probe).is_pending());
    assert_eq!(seen.lock().unwrap().len(), 2);
    replies
        .remove(&pairs[1].0)
        .unwrap()
        .send(Err(ProbeError::Status(503)))
        .unwrap();
    assert!(poll!(&mut probe).is_pending());
    assert_eq!(seen.lock().unwrap().len(), 2);
    tokio::time::advance(Duration::from_millis(999)).await;
    assert!(poll!(&mut probe).is_pending());
    assert_eq!(seen.lock().unwrap().len(), 2);
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(poll!(&mut probe).is_pending());
    assert_eq!(seen.lock().unwrap().len(), 4);
    replies.remove(&pairs[0].1).unwrap().send(Ok(())).unwrap();
    assert_eq!(probe.await.unwrap(), pairs[0].1);
}

/// A failed secure game port releases only its matching HTTP candidate immediately.
#[tokio::test(start_paused = true)]
async fn failed_game_https_releases_game_http_and_first_success_cancels_peers() {
    let pairs = candidates("example.test", 0);
    let (mut requests, mut replies, seen) = requests(&pairs);
    let mut probe = Box::pin(run(
        pairs.clone(),
        Instant::now() + Duration::from_secs(20),
        |url| requests.request(url),
    ));
    assert!(poll!(&mut probe).is_pending());
    replies
        .remove(&pairs[0].0)
        .unwrap()
        .send(Err(ProbeError::Status(426)))
        .unwrap();
    assert!(poll!(&mut probe).is_pending());
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        &[pairs[0].0.clone(), pairs[1].0.clone(), pairs[0].1.clone()]
    );
    replies.remove(&pairs[0].1).unwrap().send(Ok(())).unwrap();
    assert_eq!(probe.await.unwrap(), pairs[0].1);
    assert!(replies[&pairs[1].0].is_closed());
    assert_eq!(seen.lock().unwrap().len(), 3);
}

/// A secure answer can still win after HTTP starts, and a secure win starts no more requests.
#[tokio::test(start_paused = true)]
async fn secure_success_before_or_after_the_head_start_wins_without_waiting() {
    for advance in [false, true] {
        let pairs = candidates("example.test", 0);
        let (mut requests, mut replies, seen) = requests(&pairs);
        let mut probe = Box::pin(run(
            pairs.clone(),
            Instant::now() + Duration::from_secs(20),
            |url| requests.request(url),
        ));
        assert!(poll!(&mut probe).is_pending());
        if advance {
            tokio::time::advance(HTTPS_HEAD_START).await;
            assert!(poll!(&mut probe).is_pending());
            for (_, plain) in &pairs {
                replies
                    .remove(plain)
                    .unwrap()
                    .send(Err(ProbeError::Status(404)))
                    .unwrap();
            }
            assert!(poll!(&mut probe).is_pending());
        }
        replies.remove(&pairs[0].0).unwrap().send(Ok(())).unwrap();
        assert_eq!(probe.await.unwrap(), pairs[0].0);
        assert_eq!(seen.lock().unwrap().len(), if advance { 4 } else { 2 });
        assert!(replies[&pairs[1].0].is_closed());
    }
}

/// Full-body completion is bounded by the original deadline and a six-second overall cap.
#[tokio::test(start_paused = true)]
async fn stalled_candidates_obey_the_original_cutoff_and_cancellation() {
    for budget in [Duration::from_secs(2), Duration::from_secs(20)] {
        let pairs = candidates("example.test", 19133);
        let (mut requests, replies, seen) = requests(&pairs);
        let mut probe = Box::pin(run(pairs, Instant::now() + budget, |url| {
            requests.request(url)
        }));
        assert!(poll!(&mut probe).is_pending());
        tokio::time::advance(budget.min(PROBE_TIMEOUT)).await;
        assert!(matches!(probe.await, Err(ProbeError::TimedOut)));
        assert!(
            seen.lock()
                .unwrap()
                .iter()
                .all(|endpoint| replies[endpoint].is_closed())
        );
    }
    let pairs = candidates("example.test", 19132);
    let (mut requests, replies, seen) = requests(&pairs);
    let mut probe = Box::pin(run(pairs, Instant::now() + PROBE_TIMEOUT, |url| {
        requests.request(url)
    }));
    assert!(poll!(&mut probe).is_pending());
    drop(probe);
    assert!(
        seen.lock()
            .unwrap()
            .iter()
            .all(|endpoint| replies[endpoint].is_closed())
    );
}

/// Expiry does not conflate an omitted port with an explicit one, or remove a newer answer.
#[tokio::test(start_paused = true)]
async fn caller_cache_expires_at_ten_minutes_and_old_failures_keep_new_entries() {
    let cache = ProbeCache::default();
    let old = ProbeCache::store(
        Some(&cache),
        "EXAMPLE.test",
        0,
        "https://example.test".into(),
    );
    assert!(cache.lookup("example.TEST", 0).is_some());
    assert!(cache.lookup("[[example.test]]", 0).is_none());
    assert!(cache.lookup("example.test", 19132).is_none());
    let current = ProbeCache::store(
        Some(&cache),
        "example.test",
        0,
        "http://example.test:19132".into(),
    );
    old.forget();
    assert_eq!(
        cache.lookup("example.test", 0).unwrap().endpoint(),
        current.endpoint()
    );
    tokio::time::advance(Duration::from_secs(599)).await;
    assert!(cache.lookup("example.test", 0).is_some());
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(cache.lookup("example.test", 0).is_none());
    assert_eq!(old.login_address(), "https://example.test:443");
    for endpoint in [
        "https://[::1]",
        "https://[::1]:443",
        "http://h:80",
        "http://h:19132",
    ] {
        let selection = ProbeCache::store(None, "h", 0, endpoint.into());
        assert_eq!(
            selection.login_address(),
            if endpoint == "https://[::1]" {
                "https://[::1]:443"
            } else {
                endpoint
            }
        );
    }
}

/// An already elapsed attempt invalidates only the choice it would have dialed.
#[tokio::test(start_paused = true)]
async fn failed_dial_forgets_the_selected_cache_entry() {
    let cache = ProbeCache::default();
    let selection = ProbeCache::store(Some(&cache), "h", 19132, "http://h:19132".into());
    let signaling = HttpProbe::new(Client::builder())
        .unwrap()
        .signaling("local".into());
    assert!(matches!(
        selection
            .connect(signaling, Default::default(), Instant::now())
            .await,
        Err(crate::NetherError::Timeout)
    ));
    assert!(cache.lookup("h", 19132).is_none());
}
