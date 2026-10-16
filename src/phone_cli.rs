use crate::source_outcome::SourceExecutionOutcome;
use crate::tellows;
use crate::usacallerlookup;

/// [`run`], then the Numverify leg, Tellows for any E.164 number, USACallerLookup for US numbers,
/// and every indicator source for the number that `keys` enables and the transport's lookup asks
/// ([`Transport::runs_module`]).
#[must_use]
pub fn run_keyed<T: Transport + ?Sized>(
    transport: &T,
    keys: &Keys,
    phone: &str,
    now_unix: u64,
) -> PhoneRun {
    let offline = run(phone, now_unix);
    let mut report = match offline {
        PhoneRun::Printed { report, .. } => report,
        failed @ PhoneRun::Failed(_) => return failed,
    };
    let Some(entity) = report.entities.first_mut() else {
        return PhoneRun::Failed("phone lookup produced no entity".into());
    };
    let (canonical, scan_id) = (entity.raw_value.clone(), entity.scan_id.clone());
    let indicator = Indicator::Phone(&canonical);
    let numverify_wanted = numverify::API.runs(transport, keys);
    let tellows_wanted =
        transport.runs_module(tellows::SOURCE) && tellows::url(&canonical).is_some();
    let ucl_wanted =
        transport.runs_module(usacallerlookup::SOURCE) && usacallerlookup::url(&canonical).is_some();
    if !numverify_wanted
        && !tellows_wanted
        && !ucl_wanted
        && indicator_legs::planned(indicator, keys).is_empty()
    {
        return match render(&report) {
            Ok(text) => PhoneRun::Printed { text, report },
            Err(message) => PhoneRun::Failed(message),
        };
    }
    if numverify_wanted {
        let api = &numverify::API;
        let outcome = match numverify::verify(transport, keys, &canonical, now_unix) {
            Ok(v) => {
                numverify_evidence(entity, &v);
                SourceExecutionOutcome::success(api.source, now_unix, 1).with_http_status(200)
            }
            Err(err) => err.outcome(api, now_unix),
        };
        report.outcomes.push(outcome);
    }
    if tellows_wanted {
        match tellows::lookup(transport, &canonical, now_unix) {
            Ok(Some(score)) => {
                tellows_evidence(entity, &score);
                report.outcomes.push(
                    SourceExecutionOutcome::success(tellows::SOURCE, now_unix, 1)
                        .with_http_status(200),
                );
            }
            Ok(None) => report
                .outcomes
                .push(SourceExecutionOutcome::valid_zero(tellows::SOURCE, now_unix)),
            Err(err) => report.outcomes.push(err.outcome(&tellows::API, now_unix)),
        }
    }
    if ucl_wanted {
        match usacallerlookup::lookup(transport, &canonical, now_unix) {
            Ok(Some(profile)) => {
                usacallerlookup_evidence(entity, &profile);
                report.outcomes.push(
                    SourceExecutionOutcome::success(usacallerlookup::SOURCE, now_unix, 1)
                        .with_http_status(200),
                );
            }
            Ok(None) => report.outcomes.push(SourceExecutionOutcome::valid_zero(
                usacallerlookup::SOURCE,
                now_unix,
            )),
            Err(err) => report
                .outcomes
                .push(err.outcome(&usacallerlookup::API, now_unix)),
        }
    }
    let legs = indicator_legs::run(transport, keys, indicator, &scan_id, now_unix);
    report.entities.extend(legs.entities);
    report.outcomes.extend(legs.outcomes);
    merge_by_uid(&mut report.entities);
    match render(&report) {
        Ok(text) => PhoneRun::Printed { text, report },
        Err(message) => PhoneRun::Failed(message),
    }
}

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
