/// The longest one system-resolver question may take: a blocklist that does not answer is
/// reported as such instead of holding up the lookup.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(8);

/// Maximum live native resolver calls, including calls whose waiting client timed out.
/// Native getaddrinfo cannot be cancelled; capacity is returned only when its worker exits.
const MAX_SYSTEM_RESOLVERS: usize = 8;
static LIVE_SYSTEM_RESOLVERS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

struct ResolverWorkerSlot(&'static std::sync::atomic::AtomicUsize);

impl Drop for ResolverWorkerSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

fn reserve_resolver_worker(
    active: &'static std::sync::atomic::AtomicUsize,
    capacity: usize,
) -> Option<ResolverWorkerSlot> {
    use std::sync::atomic::Ordering;
    let mut count = active.load(Ordering::Acquire);
    loop {
        if count >= capacity {
            return None;
        }
        match active.compare_exchange_weak(count, count + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(ResolverWorkerSlot(active)),
            Err(observed) => count = observed,
        }
    }
}

/// Ask the native resolver on a bounded worker thread. Timed-out workers continue to
/// occupy capacity until they exit, preventing unbounded native-thread accumulation.
fn system_resolve(name: &str, timeout: Duration) -> Result<Vec<IpAddr>, TransportFailure> {
    use std::net::ToSocketAddrs as _;
    let asked = name.to_owned();
    system_resolve_with(
        name,
        timeout,
        &LIVE_SYSTEM_RESOLVERS,
        MAX_SYSTEM_RESOLVERS,
        move || {
            (asked.as_str(), 0).to_socket_addrs().map(|addresses| {
                let mut ips: Vec<IpAddr> = addresses.map(|address| address.ip()).collect();
                ips.sort_unstable();
                ips.dedup();
                ips
            })
        },
    )
}

/// Resolver injection keeps saturation and worker-lifetime tests offline and deterministic.
fn system_resolve_with<F>(
    name: &str,
    timeout: Duration,
    active: &'static std::sync::atomic::AtomicUsize,
    capacity: usize,
    resolve: F,
) -> Result<Vec<IpAddr>, TransportFailure>
where
    F: FnOnce() -> io::Result<Vec<IpAddr>> + Send + 'static,
{
    system_resolve_with_spawner(
        name,
        timeout,
        active,
        capacity,
        resolve,
        |permit, sender, resolve| {
            std::thread::Builder::new()
                .name("resolve".into())
                .spawn(move || {
                    // Owned by the worker, not the timed-out caller. Also released on panic.
                    let _permit = permit;
                    let _ = sender.send(resolve());
                })
                .map(|_| ())
        },
    )
}

/// The injected spawner makes failed thread creation testable without exhausting OS resources.
fn system_resolve_with_spawner<F, S>(
    name: &str,
    timeout: Duration,
    active: &'static std::sync::atomic::AtomicUsize,
    capacity: usize,
    resolve: F,
    spawn: S,
) -> Result<Vec<IpAddr>, TransportFailure>
where
    F: FnOnce() -> io::Result<Vec<IpAddr>> + Send + 'static,
    S: FnOnce(
        ResolverWorkerSlot,
        std::sync::mpsc::Sender<io::Result<Vec<IpAddr>>>,
        F,
    ) -> io::Result<()>,
{
    let failure = |detail: String| TransportFailure {
        kind: SourceOutcomeKind::DnsFailure,
        detail,
        blocked: false,
    };
    if timeout.is_zero() {
        // An expired deadline must not launch a native call that cannot be cancelled.
        return Err(failure(format!("{name}: no answer within {timeout:?}")));
    }
    let permit = reserve_resolver_worker(active, capacity).ok_or_else(|| {
        failure(format!(
            "{name}: native resolver capacity exhausted ({capacity} workers in flight)"
        ))
    })?;
    let (sender, receiver) = std::sync::mpsc::channel();
    spawn(permit, sender, resolve).map_err(|e| failure(format!("resolver thread: {e}")))?;
    match receiver.recv_timeout(timeout) {
        Ok(Ok(addresses)) => Ok(addresses),
        Ok(Err(error)) if names_no_address(&error.to_string()) => Ok(Vec::new()),
        Ok(Err(error)) => Err(failure(format!("{name}: {error}"))),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            Err(failure(format!("{name}: no answer within {timeout:?}")))
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(failure(format!(
            "{name}: native resolver worker stopped without an answer"
        ))),
    }
}
