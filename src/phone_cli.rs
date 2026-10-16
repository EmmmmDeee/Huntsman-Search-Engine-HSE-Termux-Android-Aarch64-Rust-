fn usacallerlookup_evidence(entity: &mut Entity, p: &usacallerlookup::Profile) {
    if p.toll_free {
        entity.tag("toll-free");
    }
    if p.complaint_total > 0 {
        entity.tag("ftc-complaints");
    }
    let summary = match (p.carrier.as_deref(), p.complaint_total) {
        (Some(carrier), n) if n > 0 => {
            format!("USACallerLookup: {carrier}, {n} FTC complaint(s)")
        }
        (Some(carrier), _) => format!("USACallerLookup: {carrier}"),
        (None, n) if n > 0 => format!("USACallerLookup: {n} FTC complaint(s)"),
        _ => "USACallerLookup: no carrier or complaints".to_owned(),
    };
    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(usacallerlookup::SOURCE, &entity.scan_id),
        summary,
    )
    .with_optional_attrs([
        ("carrier", p.carrier.as_deref()),
        ("city", p.city.as_deref()),
        ("state", p.state.as_deref()),
        ("first_seen", p.first_seen.as_deref()),
        ("last_seen", p.last_seen.as_deref()),
    ])
    .with_attr("complaint_total", p.complaint_total.to_string())
    .with_attr("robocall_total", p.robocall_total.to_string())
    .with_attr("states_reporting", p.states_reporting.to_string())
    .with_attr("raw_answer", p.raw_answer.as_str());
    entity.add_evidence(evidence);
}
