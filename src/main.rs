use huntsman_search_engine::{MAX_BLOCKING_THREADS, WORKER_THREADS, cli};

fn main() {
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
