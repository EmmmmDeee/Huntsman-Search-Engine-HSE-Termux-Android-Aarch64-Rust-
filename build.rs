use std::{env, fs, path::PathBuf};

#[path = "src/web_server/page_asset.rs"]
mod page_asset;

fn main() -> std::io::Result<()> {
    const INPUT: &str = "src/web_ui.html";
    println!("cargo:rerun-if-changed={INPUT}");
    println!("cargo:rerun-if-changed=src/web_server/page_asset.rs");

    let source = fs::read_to_string(INPUT)?;
    let (id, page) = page_asset::render(&source);
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    fs::write(output.join("huntsman-page.id"), id)?;
    fs::write(output.join("huntsman-page.html"), &page)?;

    let input = page.as_bytes();
    let deflate = miniz_oxide::deflate::compress_to_vec(input, 6);
    let mut gzip = Vec::with_capacity(10 + deflate.len() + 8);
    // RFC 1952 header: deflate, no optional flags or timestamp, OS unknown.
    gzip.extend_from_slice(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255]);
    gzip.extend_from_slice(&deflate);
    gzip.extend_from_slice(&crc32fast::hash(input).to_le_bytes());
    gzip.extend_from_slice(
        &u32::try_from(input.len())
            .expect("embedded page below 4 GiB")
            .to_le_bytes(),
    );
    fs::write(output.join("huntsman-page.gz"), gzip)
}
