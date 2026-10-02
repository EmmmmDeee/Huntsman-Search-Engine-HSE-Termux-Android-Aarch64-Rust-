use crate::util::http::urlencode;

use super::API;

pub(super) fn search_url(q: &str) -> String {
    format!(
        "{API}?action=wbsearchentities&search={}&language=en&format=json&type=item&limit=10",
        urlencode(q)
    )
}

pub(super) fn entities_url(qid: &str) -> String {
    format!("{API}?action=wbgetentities&ids={qid}&format=json&props=claims%7Clabels%7Cdescriptions")
}
