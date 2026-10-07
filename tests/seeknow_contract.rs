use std::fs;

#[test]
fn seeknow_contract_pins_current_public_paths_and_bounds() {
    let client = fs::read_to_string("src/seeknow.rs").expect("SeekNow client");
    for required in [
        "https://see-know.ru/api/v1",
        "pub const SEARCH_PATH: &str = \"/search\";",
        "pub const STEALER_PATH: &str = \"/stealer\";",
        "pub const SEARCH_LIMIT_MAX: u16 = 1000;",
        "Self::Name => Some(\"name\")",
        "Self::Hash => Some(\"hash\")",
        "Self::Url => Some(\"url\")",
        "Self::MachineId => Some(\"machine_id\")",
        "supports_search",
        "supports_stealer",
    ] {
        assert!(
            client.contains(required),
            "SeekNow client contract must contain {required:?}"
        );
    }
    assert!(
        !client.contains("\"/search/deep\""),
        "deprecated undocumented /search/deep route must not return"
    );
}

#[test]
fn seeknow_contract_documents_live_verification_boundary() {
    let doc = fs::read_to_string("docs/SEEKNOW_CONTRACT.md").expect("SeekNow contract");
    for required in [
        "Observed and re-verified: **2026-10-07**",
        "https://see-know.ru/api/v1",
        "Authorization: Bearer seek-YOUR_API_KEY",
        "X-API-Key",
        "POST | `/search` | 1 credit",
        "POST | `/stealer` | 2 credits",
        "auto email username phone ip domain name hash",
        "auto email username ip domain url machine_id",
        "does **not** define",
        "no `HUNTSMAN_SEEKNOW_KEY` is configured",
    ] {
        assert!(
            doc.contains(required),
            "SeekNow contract documentation must contain {required:?}"
        );
    }
}
