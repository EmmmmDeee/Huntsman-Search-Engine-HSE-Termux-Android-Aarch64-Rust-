use huntsman_search_engine::cli;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    if let Err(e) = cli::run().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
