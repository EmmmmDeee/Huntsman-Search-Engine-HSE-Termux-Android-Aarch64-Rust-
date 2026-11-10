//! Android JNI adapter for the canonical HUNTSMAN Rust CLI and source-labelled
//! credential monitor. This cdylib is loaded from the signed ARM64 APK. There
//! are no copied CLI modules, copied API clients, Java business rules or keys.
//! Android's Activity/WebView and JobScheduler must be used through its framework.

use std::ffi::OsString;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use jni::objects::{JClass, JString};
use jni::sys::jint;
use jni::JNIEnv;

// One source of CLI behaviour: compile the existing modules into this native
// Android library, rather than executing an ELF from a writable APK data dir.
#[path = "../../../src/cli/mod.rs"]
mod cli;

// Reuse the exact Rust monitor also used as a Termux CLI binary. Native checks
// accept the explicit Android app files directory, not a mutable process HOME.
#[path = "../../../src/bin/huntsman-key-health.rs"]
mod credential_monitor;

static SERVER_STARTED: AtomicBool = AtomicBool::new(false);

fn java_home(env: &mut JNIEnv<'_>, raw: &JString<'_>) -> Result<String, jint> {
    let text: String = env.get_string(raw).map_err(|_| -1)?.into();
    if text.len() > 4096 || !text.starts_with('/') || text.contains('\0') {
        return Err(-2);
    }
    Ok(text)
}

fn launch(home: &str) -> jint {
    if SERVER_STARTED.swap(true, Ordering::AcqRel) {
        return 1; // another Activity owns the still-running native server
    }
    if huntsman_recon::environment::set_android_app_home(Path::new(home)).is_err() {
        SERVER_STARTED.store(false, Ordering::Release);
        return -3;
    }
    let handle = std::thread::Builder::new()
        .name("huntsman-native-web-server".to_owned())
        .spawn(|| {
            let args: Vec<OsString> = ["serve", "--bind", "127.0.0.1:8080"]
                .into_iter().map(OsString::from).collect();
            // No Rust panic or CLI error escapes into Java's UI thread.
            let _ = std::panic::catch_unwind(|| cli::run(args));
            SERVER_STARTED.store(false, Ordering::Release);
        });
    if handle.is_err() {
        SERVER_STARTED.store(false, Ordering::Release);
        return -4;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_huntsman_app_HuntsmanActivity_nativeStart(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    home: JString<'_>,
) -> jint {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        java_home(&mut env, &home).map_or_else(|error| error, |path| launch(&path))
    })).unwrap_or(-5)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_huntsman_app_HuntsmanActivity_nativeRefresh(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    home: JString<'_>,
    active_probe: jni::sys::jboolean,
) -> jint {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let path = match java_home(&mut env, &home) { Ok(path) => path, Err(error) => return error };
        if credential_monitor::refresh_in_home(Path::new(&path), active_probe != 0).is_ok() {
            0
        } else {
            -6
        }
    })).unwrap_or(-7)
}
