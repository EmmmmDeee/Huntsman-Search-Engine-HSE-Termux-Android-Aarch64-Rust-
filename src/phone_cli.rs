use crate::tellows;

/// [`run`], then the Numverify leg, Tellows for any E.164 number, and every indicator source
/// for the number that `keys` enables and the transport's lookup asks ([`Transport::runs_module`]).
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
    let tellows_wanted = transport.runs_module(tellows::SOURCE) && tellows::url(&canonical).is_some();
    if !numverify_wanted && !tellows_wanted && indicator_legs::planned(indicator, keys).is_empty() {
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
    let legs = indicator_legs::run(transport, keys, indicator, &scan_id, now_unix);
    report.entities.extend(legs.entities);
    report.outcomes.extend(legs.outcomes);
    merge_by_uid(&mut report.entities);
    match render(&report) {
        Ok(text) => PhoneRun::Printed { text, report },
        Err(message) => PhoneRun::Failed(message),
    }
}

fn tellows_evidence(entity: &mut Entity, s: &tellows::Score) {
    if s.score >= 7 {
        entity.tag("tellows-dubious");
    }
    let summary = format!("Tellows: score {} ({}) searches, {} comments", s.score, s.searches, s.comments);
    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(tellows::SOURCE, &entity.scan_id),
        summary,
    )
    .with_attr("score", s.score.to_string())
    .with_attr("searches", s.searches.to_string())
    .with_attr("comments", s.comments.to_string())
    .with_optional_attrs([
        ("location", s.location.as_deref()),
        ("country", s.country.as_deref()),
        ("caller_type", s.caller_type.as_deref()),
    ])
    .with_attr("raw_answer", s.raw_answer.as_str());
    entity.add_evidence(evidence);
}
