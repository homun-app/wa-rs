use crate::client::Client;
use crate::request::IqError;
use log::{debug, warn};
use rand::Rng;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use wa_rs_core::iq::keepalive::KeepaliveSpec;

const KEEP_ALIVE_INTERVAL_MIN: Duration = Duration::from_secs(20);
const KEEP_ALIVE_INTERVAL_MAX: Duration = Duration::from_secs(30);
const KEEP_ALIVE_MAX_FAIL_TIME: Duration = Duration::from_secs(180);
const KEEP_ALIVE_RESPONSE_DEADLINE: Duration = Duration::from_secs(20);
/// How long without receiving anything after a send marks the socket dead
/// (WA Web `deadSocketTime` is 20s; we use 60s because we lack oxidezap #1543's
/// pending-IQ probe, so a tighter deadline could false-positive on slow IQs).
const DEAD_SOCKET_TIME: Duration = Duration::from_secs(60);

/// Milliseconds on a monotonic clock (immune to NTP steps), from process start.
fn monotonic_ms() -> u64 {
    static BASE: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    BASE.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Dead-socket watchdog (WA Web `deadSocketTimer`, ported from oxidezap #995):
/// armed on the FIRST send after a receive (`onOrBefore` keeps the earliest
/// deadline), cancelled on every receive. Anchoring to the first — not the
/// latest — send is what keeps outgoing traffic from pushing the deadline out
/// and hiding a half-open socket.
#[derive(Debug, Default)]
pub(crate) struct DataWatchdog {
    /// Monotonic ms when armed; 0 = unarmed.
    armed_ms: AtomicU64,
    /// Monotonic ms of the last received data.
    last_recv_ms: AtomicU64,
}

impl DataWatchdog {
    /// Record an outgoing stanza at `now_ms`.
    pub(crate) fn on_send_at(&self, now_ms: u64) {
        // Re-arm when unset or stale (anchor <= last receive): a send that
        // captured `now` before a concurrent receive-reset must not leave a
        // pre-receive timestamp stuck as the anchor.
        let last_recv = self.last_recv_ms.load(Ordering::Relaxed);
        let anchor = self.armed_ms.load(Ordering::Relaxed);
        if anchor == 0 || anchor <= last_recv {
            self.armed_ms.store(now_ms, Ordering::Relaxed);
        }
    }

    /// Record an incoming stanza at `now_ms`.
    pub(crate) fn on_receive_at(&self, now_ms: u64) {
        self.last_recv_ms.store(now_ms, Ordering::Relaxed);
        // A receive cancels the deadline; the next send re-arms it.
        self.armed_ms.store(0, Ordering::Relaxed);
    }

    /// True when `deadline` elapsed since the watchdog was armed without any
    /// receive cancelling it.
    pub(crate) fn is_dead_socket_at(&self, now_ms: u64, deadline: Duration) -> bool {
        let anchor = self.armed_ms.load(Ordering::Relaxed);
        if anchor == 0 {
            return false; // Not armed (nothing sent since the last receive).
        }
        let last_recv = self.last_recv_ms.load(Ordering::Relaxed);
        if last_recv >= anchor {
            return false; // Received data cancelled the deadline.
        }
        now_ms.saturating_sub(anchor) > deadline.as_millis() as u64
    }

    pub(crate) fn on_send(&self) {
        self.on_send_at(monotonic_ms());
    }

    pub(crate) fn on_receive(&self) {
        self.on_receive_at(monotonic_ms());
    }
}

impl Client {
    async fn send_keepalive(&self) -> bool {
        if !self.is_connected() {
            return false;
        }

        debug!(target: "Client/Keepalive", "Sending keepalive ping");

        match self
            .execute(KeepaliveSpec::with_timeout(KEEP_ALIVE_RESPONSE_DEADLINE))
            .await
        {
            Ok(()) => {
                debug!(target: "Client/Keepalive", "Received keepalive pong");
                true
            }
            Err(e) => {
                warn!(target: "Client/Keepalive", "Keepalive ping failed: {e:?}");
                !matches!(e, IqError::Socket(_) | IqError::Disconnected(_))
            }
        }
    }

    pub(crate) async fn keepalive_loop(self: Arc<Self>, epoch: u64) {
        // Monotonic clock for the failure deadline: a wall-clock step (NTP
        // adjustment) must neither disarm the dead-socket detection nor force
        // a spurious reconnect (oxidezap #1379 ported; `chrono::Utc` jumps).
        let mut last_success = Instant::now();
        let mut error_count = 0u32;

        loop {
            let interval_ms = rand::rng().random_range(
                KEEP_ALIVE_INTERVAL_MIN.as_millis()..=KEEP_ALIVE_INTERVAL_MAX.as_millis(),
            );
            let interval = Duration::from_millis(interval_ms as u64);

            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    if self.connect_epoch.load(Ordering::SeqCst) != epoch {
                        debug!(target: "Client/Keepalive", "Newer connection took over, exiting keepalive loop.");
                        return;
                    }
                    if !self.is_connected() {
                        debug!(target: "Client/Keepalive", "Not connected, exiting keepalive loop.");
                        return;
                    }

                    // WA Web deadSocketTimer: checked on EVERY tick — not just
                    // after a failed ping — to catch a socket that died right
                    // after a successful pong.
                    if self.data_watchdog.is_dead_socket_at(monotonic_ms(), DEAD_SOCKET_TIME) {
                        warn!(
                            target: "Client/Keepalive",
                            "No data received for over {}s after send (dead socket), forcing reconnect.",
                            DEAD_SOCKET_TIME.as_secs()
                        );
                        if self.enable_auto_reconnect.load(Ordering::Relaxed) {
                            self.disconnect().await;
                        }
                        return;
                    }

                    let is_success = self.send_keepalive().await;

                    if is_success {
                        if error_count > 0 {
                            debug!(target: "Client/Keepalive", "Keepalive restored.");
                        }
                        error_count = 0;
                        last_success = Instant::now();
                    } else {
                        error_count += 1;
                        warn!(target: "Client/Keepalive", "Keepalive timeout, error count: {error_count}");

                        if self.enable_auto_reconnect.load(Ordering::Relaxed)
                            && last_success.elapsed() > KEEP_ALIVE_MAX_FAIL_TIME
                        {
                            warn!(target: "Client/Keepalive", "Forcing reconnect due to keepalive failure for over {} seconds.", KEEP_ALIVE_MAX_FAIL_TIME.as_secs());
                            self.disconnect().await;
                            return;
                        }
                    }
                },
                _ = self.shutdown_notifier.notified() => {
                    debug!(target: "Client/Keepalive", "Shutdown signaled, exiting keepalive loop.");
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DataWatchdog;
    use std::time::Duration;

    const DEADLINE: Duration = Duration::from_secs(60);

    #[test]
    fn unarmed_until_first_send() {
        let wd = DataWatchdog::default();
        assert!(!wd.is_dead_socket_at(1_000_000, DEADLINE));
    }

    #[test]
    fn receive_cancels_the_deadline() {
        let wd = DataWatchdog::default();
        wd.on_send_at(1_000);
        wd.on_receive_at(2_000);
        assert!(!wd.is_dead_socket_at(1_000_000, DEADLINE));
        // Stays disarmed until the next send re-arms it.
        assert!(!wd.is_dead_socket_at(1_000_000, DEADLINE));
    }

    #[test]
    fn fires_after_deadline_with_no_receive() {
        let wd = DataWatchdog::default();
        wd.on_send_at(1_000);
        assert!(!wd.is_dead_socket_at(1_000 + 59_999, DEADLINE));
        assert!(wd.is_dead_socket_at(1_000 + 60_001, DEADLINE));
    }

    /// The core of oxidezap #995: continued outgoing traffic must NOT push the
    /// deadline out — only the first send after a receive anchors it.
    #[test]
    fn later_sends_do_not_push_the_deadline_out() {
        let wd = DataWatchdog::default();
        wd.on_send_at(1_000);
        wd.on_send_at(50_000); // Still nothing received.
        // Deadline anchored at 1_000, not 50_000.
        assert!(wd.is_dead_socket_at(1_000 + 60_001, DEADLINE));
    }

    /// A send whose timestamp was captured before a concurrent receive-reset
    /// must not leave a stale pre-receive anchor (oxidezap #995 stale check).
    #[test]
    fn stale_anchor_is_rearmed_on_next_send() {
        let wd = DataWatchdog::default();
        wd.on_send_at(1_000);
        wd.on_receive_at(2_000); // Cancels.
        // Send races: its `now` (1_500) predates the receive-reset (2_000).
        wd.on_send_at(1_500);
        // Anchor is stale (<= last receive), so it must have been re-armed to
        // 1_500... which is still <= last_recv: the NEXT send re-arms for real.
        wd.on_send_at(3_000);
        assert!(!wd.is_dead_socket_at(3_000 + 59_999, DEADLINE));
        assert!(wd.is_dead_socket_at(3_000 + 60_001, DEADLINE));
    }
}
