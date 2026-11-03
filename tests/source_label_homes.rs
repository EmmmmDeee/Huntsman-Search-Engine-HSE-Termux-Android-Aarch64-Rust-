//! Source labels live with the collector or reading that records them; the CLI front-ends
//! re-export them from their old paths, which stay public and print the same labels.

use huntsman_recon::{
    dehashed, exposure_cli, hibp, lookup_modules, module, network_cli, oathnet, oui, phone_cli,
    phone_intl, scan_route::ScanKind, stolen_tax,
};

#[test]
fn every_front_end_label_is_its_home_label_unchanged() {
    for (old, home, label) in [
        (exposure_cli::SOURCE, hibp::ACCOUNT_SOURCE, "hibp_account"),
        (
            exposure_cli::STOLEN_TAX_SOURCE,
            stolen_tax::SOURCE,
            "stolen_tax",
        ),
        (exposure_cli::OATHNET_SOURCE, oathnet::SOURCE, "oathnet"),
        (
            exposure_cli::DEHASHED_SOURCE,
            dehashed::COLLECTOR_ID,
            "dehashed",
        ),
        (
            phone_cli::NANP_SOURCE,
            phone_intl::NANP_SOURCE,
            "phone_nanp",
        ),
        (phone_cli::AU_SOURCE, phone_intl::AU_SOURCE, "phone_au"),
        (network_cli::OUI_SOURCE, oui::SOURCE, "oui"),
    ] {
        assert_eq!(old, home);
        assert_eq!(home, label);
    }
}

#[test]
fn phone_offline_labels_match_the_catalogue_outcomes_and_evidence() {
    let sources = [
        phone_intl::SOURCE,
        phone_intl::AU_SOURCE,
        phone_intl::NANP_SOURCE,
    ];
    assert_eq!(sources, ["phone_intl", "phone_au", "phone_nanp"]);
    assert_eq!(lookup_modules::offline_runs(ScanKind::Phone), sources);

    for source in sources {
        assert!(
            module::reachable_modules()
                .iter()
                .any(|entry| entry.name == source && !entry.network),
            "offline phone source missing from the catalogue: {source}"
        );
        assert_eq!(lookup_modules::lookups_running_offline(source), ["phone"]);
    }

    let phone_cli::PhoneRun::Printed { text, report } = phone_cli::run("+44 20 7183 8750", 1)
    else {
        panic!("offline phone lookup must run without keys or network");
    };
    let reported: Vec<&str> = report
        .outcomes
        .iter()
        .map(|outcome| outcome.module.as_str())
        .collect();
    assert_eq!(reported, sources);
    assert!(text.contains("phone_intl\tsuccess\tfound=1"), "{text}");
    assert!(
        report.entities.iter().any(|entity| entity
            .evidence
            .iter()
            .any(|evidence| evidence.provenance.source == phone_intl::SOURCE)),
        "the primary phone outcome and its evidence must use the same canonical label"
    );
}
