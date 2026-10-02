//! `MediaWiki` Action API HTTP-200 error envelope helpers.

use serde::Deserialize;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct MwError {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub info: String,
}

impl MwError {
    /// # Errors
    ///
    /// Returns [`crate::Error::Invalid`] when the envelope carries a
    /// `MediaWiki` API error object.
    pub fn check(error: &Option<Self>, module: &'static str) -> Result<(), crate::Error> {
        match error {
            Some(err) => Err(crate::Error::Invalid(format!(
                "{module}: MediaWiki API error [{}]: {}",
                err.code.trim(),
                err.info.trim()
            ))),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MwError;
    use serde::Deserialize;

    #[derive(Debug, Default, Deserialize)]
    struct Response {
        #[serde(default)]
        items: Vec<String>,
        #[serde(default)]
        error: Option<MwError>,
    }

    #[test]
    fn surfaces_http_200_error_envelopes() {
        let response: Response = serde_json::from_str(
            r#"{"error":{"code":"maxlag","info":"Waiting for a database server"}}"#,
        )
        .expect("response");
        assert!(response.items.is_empty(), "{:?}", response.items);
        let err = MwError::check(&response.error, "wiki_test").expect_err("must error");
        let text = err.to_string();
        assert!(text.contains("wiki_test"));
        assert!(text.contains("maxlag"));
    }

    #[test]
    fn passes_normal_and_empty_results() {
        let ok: Response = serde_json::from_str(r#"{"items":["a","b"]}"#).expect("response");
        assert_eq!(ok.items.len(), 2);
        assert!(MwError::check(&ok.error, "wiki_test").is_ok());

        let empty: Response = serde_json::from_str(r#"{"items":[]}"#).expect("response");
        assert!(empty.items.is_empty(), "{:?}", empty.items);
        assert!(MwError::check(&empty.error, "wiki_test").is_ok());
    }
}
