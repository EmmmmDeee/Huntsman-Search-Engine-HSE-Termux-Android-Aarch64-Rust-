use huntsman_search_engine::{MAX_BLOCKING_THREADS, WORKER_THREADS, cli};

fn main() {
    install_broken_pipe_guard();

    // Build the runtime by hand (instead of `#[tokio::main]`) so the blocking
    // pool can be bounded: tokio defaults to 512 blocking threads, which on a
    // low-RAM Termux/aarch64 phone lets a burst of synchronous sqlite / fs work
    // spawn hundreds of OS threads. HSE is network/IO-bound on a 2-worker
    // runtime, so a small pool is ample. `enable_all()` matches the IO + time
    // drivers the macro would have enabled.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKER_THREADS)
        .max_blocking_threads(MAX_BLOCKING_THREADS)
        .enable_all()
        .build()
        .expect("failed to build the tokio runtime");

    if let Err(e) = runtime.block_on(cli::run()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

/// Exit quietly when stdout is closed by the downstream reader.
///
/// Rust ignores `SIGPIPE` at startup (`SIG_IGN`), so a write to a closed stdout —
/// `hse scan | head`, `hse export … | less` then `q`, a dropped SSH pipe — makes
/// the `print!`/`println!` machinery hit `EPIPE` and **panic** with a backtrace
/// instead of the process ending cleanly like every other Unix tool. A scan that
/// prints dozens of entity rows trips this constantly on a phone.
///
/// The obvious fix used by ripgrep/fd — resetting `SIGPIPE` to `SIG_DFL` — is
/// **wrong for HSE**: it is network-heavy, and under `SIG_DFL` a socket write to a
/// peer that has closed would deliver `SIGPIPE` synchronously and kill the process
/// mid-scan, *before* tokio/reqwest could surface the `EPIPE` as a recoverable
/// error. So `SIGPIPE` is deliberately left ignored (sockets keep returning
/// `EPIPE` as errors) and ONLY the benign stdout-broken-pipe panic is intercepted:
/// the hook recognises that specific panic and exits 0 (the consumer simply left
/// early — we did our job), while every other panic flows through the default hook
/// untouched. Installed before the runtime spawns any thread so it covers the
/// whole process.
fn install_broken_pipe_guard() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if is_broken_pipe_panic(info.payload()) {
            std::process::exit(0);
        }
        default_hook(info);
    }));
}

/// True if a panic payload is the `print!`/`println!` broken-pipe failure (and
/// nothing else). The print machinery panics with a formatted `String` payload,
/// e.g. `"failed printing to stdout: Broken pipe (os error 32)"`. Matching both
/// the "failed printing to" prefix AND "Broken pipe" keeps a genuine output
/// failure (disk full on a redirect, etc.) loud while swallowing only the benign
/// downstream-closed-the-pipe case. Pure + payload-only, so it is unit-testable.
fn is_broken_pipe_panic(payload: &(dyn std::any::Any + Send)) -> bool {
    let msg = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("");
    msg.contains("failed printing to") && msg.contains("Broken pipe")
}

#[cfg(test)]
mod tests {
    include!("main_tests.rs");
}
