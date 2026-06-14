//! Folding scan events into [`LogSignals`].

use super::types::LogSignals;

/// Fold a stored scan's events into auditor [`LogSignals`]: every
/// `ExpansionStop` reason and every `EntityExcluded` reason (counted), so the
/// recursion/admission ledger is available to the audit without a debug-log
/// upload. Shared by the web audit endpoint and the CLI debug bundle so the two
/// can never diverge.
pub fn fold_events(sig: &mut LogSignals, events: &[crate::core::event::Event]) {
    use crate::core::event::EventKind;
    for ev in events {
        match &ev.kind {
            EventKind::ExpansionStop { reason } => sig.expansion_stops.push(reason.clone()),
            EventKind::EntityExcluded { reason, .. } => {
                *sig.excluded_reasons.entry(reason.clone()).or_default() += 1;
            }
            EventKind::ModuleError { module, .. } => {
                *sig.module_errors.entry(module.clone()).or_default() += 1;
            }
            _ => {}
        }
    }
}
