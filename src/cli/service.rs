//! Binary adapter commands. Business logic stays in the library crate.

use std::env;
use std::process::ExitCode;

use super::{EX_DATAERR, EX_UNAVAILABLE, EX_USAGE, fail};
use huntsman_recon::error::Error;
use huntsman_recon::web_server::{ServeConfig, Server, resolve_serve_bind};

pub(super) fn serve_cmd(args: &[String]) -> ExitCode {
    let hse_bind = env::var("HSE_BIND").ok();
    let railway_port = env::var("PORT").ok();
    let railway = [
        "RAILWAY_ENVIRONMENT",
        "RAILWAY_ENVIRONMENT_ID",
        "RAILWAY_PROJECT_ID",
        "RAILWAY_SERVICE_ID",
    ]
    .iter()
    .any(|name| env::var_os(name).is_some());
    let mut bind = match resolve_serve_bind(hse_bind.as_deref(), railway_port.as_deref(), railway) {
        Ok(bind) => bind,
        Err(Error::Invalid(message)) => return fail(EX_DATAERR, &message),
        Err(error) => return fail(EX_UNAVAILABLE, &error.to_string()),
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--bind" => {
                let Some(value) = args.get(index + 1) else {
                    return fail(EX_USAGE, "serve --bind needs ADDR");
                };
                bind.clone_from(value);
                index += 2;
            }
            other => {
                return fail(
                    EX_USAGE,
                    &format!(
                        "unknown serve option: {other}\nusage: huntsman-recon serve [--bind ADDR]"
                    ),
                );
            }
        }
    }

    let token = env::var("HSE_AUTH_TOKEN").ok();
    let config = match ServeConfig::parse(&bind, token) {
        Ok(config) => config,
        Err(Error::Invalid(message)) => return fail(EX_DATAERR, &message),
        Err(error) => return fail(EX_UNAVAILABLE, &error.to_string()),
    };
    let server = match Server::bind(config) {
        Ok(server) => server,
        Err(error) => return fail(EX_UNAVAILABLE, &error.to_string()),
    };
    match server.local_addr() {
        Ok(addr) => println!("serving=http://{addr}/"),
        Err(error) => return fail(EX_UNAVAILABLE, &error.to_string()),
    }
    match server.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(EX_UNAVAILABLE, &error.to_string()),
    }
}
