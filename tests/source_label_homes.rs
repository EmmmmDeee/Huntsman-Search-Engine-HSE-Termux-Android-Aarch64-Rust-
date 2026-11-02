//! Source labels live with the collector or reading that records them; the CLI front-ends
//! re-export them from their old paths, which stay public and print the same labels.

use huntsman_recon::{
    dehashed, exposure_cli, hibp, network_cli, oathnet, oui, phone_cli, phone_intl, stolen_tax,
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
