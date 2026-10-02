use std::cell::RefCell;
use std::collections::VecDeque;

use huntsman_recon::active_probe::{ProbeOptions, probe};
use huntsman_recon::http::{Request, Response, Transport, TransportFailure};

struct Fake {
    script: RefCell<VecDeque<Result<Response, TransportFailure>>>,
}

impl Fake {
    fn new(response: Response) -> Self {
        Self {
            script: RefCell::new(VecDeque::from([Ok(response)])),
        }
    }
}

impl Transport for Fake {
    fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
        self.script.borrow_mut().pop_front().expect("one request")
    }
}

#[test]
fn hostile_page_cannot_amplify_pivots_without_bound() {
    let mut body = String::from("<html><body>");
    for index in 0..300 {
        body.push_str(&format!(r#"<a href="/pivot-{index}">x</a>"#));
    }
    body.push_str(&format!(r#"<a href="/{}">long</a>"#, "x".repeat(3_000)));
    body.push_str("</body></html>");

    let f = Fake::new(Response {
        status: 200,
        headers: vec![("content-type".into(), "text/html".into())],
        body: body.into_bytes(),
        truncated: false,
    });

    let report = probe(
        &f,
        "https://example.com",
        &ProbeOptions { max_requests: 1 },
        100,
    )
    .expect("bounded active probe");

    assert!(report.pivots.len() <= 256, "pivot count must be hard bounded");
    assert!(
        report.pivots.iter().all(|pivot| pivot.url.len() <= 2_048),
        "oversized pivot URLs must be rejected"
    );
}
