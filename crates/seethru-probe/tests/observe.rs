use std::io;
use std::net::IpAddr;
use std::time::Duration;

use seethru_core::LimitationCode;
use seethru_guard::{
    Audit, Clock, Entry, Environment, Raw, Target, Token, Transport, TransportError,
    WELL_KNOWN_PATH, Wire,
};
use seethru_probe::{CORS_ORIGIN, Cors, Header, Kind, Outcome, observe};

type Answer = Box<dyn FnMut(&str, Option<&str>) -> Result<Raw, TransportError>>;
type Sent = Vec<(String, Option<String>)>;
type Pairs = Vec<(&'static str, &'static str)>;

struct Net {
    sent: Sent,
    answer: Answer,
}

impl Transport for Net {
    fn send(&mut self, wire: &Wire<'_>) -> Result<Raw, TransportError> {
        self.sent
            .push((wire.path.to_owned(), wire.origin.map(str::to_owned)));
        (self.answer)(wire.path, wire.origin).map(|mut raw| {
            if raw.body == OWNED.as_bytes() {
                raw.body = token().file_line(wire.target).into_bytes();
            }
            raw
        })
    }
}

#[derive(Default)]
struct Log(Vec<Entry>);

impl Audit for Log {
    fn record(&mut self, entry: &Entry) -> io::Result<()> {
        self.0.push(entry.clone());
        Ok(())
    }
}

#[derive(Default)]
struct Time(Duration);

impl Clock for Time {
    fn elapsed(&self) -> Duration {
        self.0
    }

    fn unix_seconds(&self) -> u64 {
        0
    }

    fn sleep(&mut self, time: Duration) {
        self.0 += time;
    }
}

const REMOTE: &str = "203.0.113.5";

fn token() -> Token {
    Token::from_random(&[5u8; 32])
}

const OWNED: &str = "the line seethru own printed";

fn raw(status: u16, headers: &[(&str, &str)], body: &str) -> Raw {
    Raw {
        status,
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
        body: body.as_bytes().to_vec(),
        remote: REMOTE.parse::<IpAddr>().ok(),
    }
}

fn app(page: Pairs, cors: Pairs) -> Answer {
    Box::new(move |path, origin| {
        if path == WELL_KNOWN_PATH {
            return Ok(raw(200, &[], OWNED));
        }
        let mut headers = page.clone();
        if origin.is_some() {
            headers.extend(cors.iter().copied());
        }
        Ok(raw(200, &headers, "<html>the page</html>"))
    })
}

fn run(url: &str, answer: Answer) -> (Outcome, Sent, Vec<Entry>) {
    let mut net = Net {
        sent: Vec::new(),
        answer,
    };
    let mut log = Log::default();
    let mut time = Time::default();
    let target = match Target::parse(url) {
        Ok(target) => target,
        Err(error) => unreachable!("{error}"),
    };
    let outcome = observe(
        target,
        token(),
        Environment::Staging,
        &mut net,
        &mut log,
        &mut time,
    );
    (outcome, net.sent, log.0)
}

const GOOD: [(&str, &str); 5] = [
    ("Content-Type", "text/html; charset=utf-8"),
    (
        "Content-Security-Policy",
        "default-src 'self'; frame-ancestors 'none'",
    ),
    ("X-Content-Type-Options", "nosniff"),
    ("Strict-Transport-Security", "max-age=31536000"),
    ("Set-Cookie", "session=keep-out"),
];

fn kinds(outcome: &Outcome) -> Vec<Kind> {
    outcome.facts.iter().map(|fact| fact.kind).collect()
}

#[test]
fn a_well_configured_app_has_no_findings_after_three_requests() {
    let (outcome, sent, log) = run("https://app.example", app(GOOD.to_vec(), Vec::new()));
    assert!(outcome.verified);
    assert!(outcome.facts.is_empty(), "{:?}", outcome.facts);
    assert!(outcome.problems.is_empty(), "{:?}", outcome.problems);
    assert_eq!(outcome.requests, 3);
    assert_eq!(
        sent,
        [
            (WELL_KNOWN_PATH.to_owned(), None),
            ("/".to_owned(), None),
            ("/".to_owned(), Some(CORS_ORIGIN.to_owned())),
        ]
    );
    assert_eq!(log.len(), 6);
}

#[test]
fn missing_headers_are_reported_one_by_one_with_the_request_that_shows_it() {
    let (outcome, _, _) = run(
        "https://app.example",
        app(
            vec![
                ("Content-Type", "text/html"),
                ("Set-Cookie", "session=keep-out"),
            ],
            Vec::new(),
        ),
    );
    assert_eq!(
        kinds(&outcome),
        [
            Kind::HeaderMissing(Header::ContentSecurityPolicy),
            Kind::HeaderMissing(Header::ContentTypeOptions),
            Kind::HeaderMissing(Header::FrameProtection),
            Kind::HeaderMissing(Header::StrictTransportSecurity),
        ]
    );
    let ids: Vec<String> = outcome.facts.iter().map(|fact| fact.id()).collect();
    assert_eq!(
        ids,
        [
            "security-header-missing:header:content-security-policy",
            "security-header-missing:header:x-content-type-options",
            "security-header-missing:header:frame-protection",
            "security-header-missing:header:strict-transport-security",
        ]
    );
    assert_eq!(
        outcome.facts[0].proof_file(),
        "proof/security-header-missing-header-content-security-policy.json"
    );
    let text = format!("{outcome:?}");
    assert!(!text.contains("keep-out") && !text.contains("the page"));
    assert!(!text.contains("app.example") && !text.contains(REMOTE));
    assert_eq!(outcome.facts[0].steps[0].request, 2);
}

#[test]
fn weak_values_do_not_count_as_protection() {
    let (outcome, _, _) = run(
        "https://app.example",
        app(
            vec![
                ("Content-Type", "text/html"),
                ("Content-Security-Policy", "default-src *"),
                ("X-Content-Type-Options", "sniff"),
                ("X-Frame-Options", "ALLOWALL"),
                ("Strict-Transport-Security", "max-age=0"),
            ],
            Vec::new(),
        ),
    );
    assert_eq!(
        kinds(&outcome),
        [
            Kind::HeaderMissing(Header::ContentTypeOptions),
            Kind::HeaderMissing(Header::FrameProtection),
            Kind::HeaderMissing(Header::StrictTransportSecurity),
        ]
    );
    let (framed, _, _) = run(
        "http://localhost:3000",
        Box::new(|path, _| {
            let mut answer = if path == WELL_KNOWN_PATH {
                raw(200, &[], OWNED)
            } else {
                raw(
                    200,
                    &[
                        ("Content-Type", "text/html"),
                        ("Content-Security-Policy", "default-src 'self'"),
                        ("X-Content-Type-Options", "NoSniff"),
                        ("X-Frame-Options", "sameorigin"),
                    ],
                    "",
                )
            };
            answer.remote = "127.0.0.1".parse().ok();
            Ok(answer)
        }),
    );
    assert!(framed.facts.is_empty(), "{:?}", framed.facts);
}

#[test]
fn an_app_that_lets_any_site_read_it_with_cookies_is_reported() {
    let cases: [(Pairs, Option<Cors>); 5] = [
        (
            vec![
                ("Access-Control-Allow-Origin", CORS_ORIGIN),
                ("Access-Control-Allow-Credentials", "true"),
            ],
            Some(Cors::ReflectsWithCredentials),
        ),
        (
            vec![
                ("Access-Control-Allow-Origin", "*"),
                ("Access-Control-Allow-Credentials", "TRUE"),
            ],
            Some(Cors::WildcardWithCredentials),
        ),
        (vec![("Access-Control-Allow-Origin", CORS_ORIGIN)], None),
        (vec![("Access-Control-Allow-Origin", "*")], None),
        (
            vec![
                ("Access-Control-Allow-Origin", "https://app.example"),
                ("Access-Control-Allow-Credentials", "true"),
            ],
            None,
        ),
    ];
    for (cors, expected) in cases {
        let (outcome, _, _) = run("https://app.example", app(GOOD.to_vec(), cors.clone()));
        assert_eq!(
            kinds(&outcome),
            expected.map(Kind::CorsOpen).into_iter().collect::<Vec<_>>(),
            "{cors:?}"
        );
        if let Some(fact) = outcome.facts.first() {
            assert_eq!(fact.id(), "cors-allows-any-origin-with-credentials:app");
            assert_eq!(
                fact.steps[0].sent,
                [("origin".to_owned(), CORS_ORIGIN.to_owned())]
            );
        }
    }
}

#[test]
fn an_app_that_is_not_proved_to_be_yours_gets_one_request_and_no_checks() {
    let (outcome, sent, _) = run(
        "https://app.example",
        Box::new(|_, _| Ok(raw(200, &[("Content-Type", "text/html")], "<html></html>"))),
    );
    assert!(!outcome.verified);
    assert!(outcome.facts.is_empty());
    assert_eq!(outcome.problems, [LimitationCode::OwnershipNotVerified]);
    assert_eq!(sent, [(WELL_KNOWN_PATH.to_owned(), None)]);
}

#[test]
fn a_redirect_to_another_site_ends_the_run() {
    let (outcome, sent, _) = run(
        "https://app.example",
        Box::new(|path, _| {
            if path == WELL_KNOWN_PATH {
                Ok(raw(200, &[], OWNED))
            } else {
                Ok(raw(302, &[("Location", "https://login.example/")], ""))
            }
        }),
    );
    assert!(outcome.verified);
    assert!(outcome.facts.is_empty());
    assert_eq!(outcome.problems, [LimitationCode::ProbeRedirectedOutside]);
    assert_eq!(sent.len(), 2);
    assert_eq!(outcome.requests, 2);
}

#[test]
fn an_app_that_stops_answering_or_serves_no_page_is_a_limitation() {
    let (silent, sent, _) = run(
        "https://app.example",
        Box::new(|path, _| {
            if path == WELL_KNOWN_PATH {
                Ok(raw(200, &[], OWNED))
            } else {
                Err(TransportError::TimedOut)
            }
        }),
    );
    assert_eq!(silent.problems, [LimitationCode::ProbeTargetNotResponding]);
    assert!(silent.facts.is_empty());
    assert_eq!(sent.len(), 2);
    let (api, sent, _) = run(
        "https://app.example",
        app(vec![("Content-Type", "application/json")], Vec::new()),
    );
    assert_eq!(api.problems, [LimitationCode::ProbePageNotRead]);
    assert!(api.facts.is_empty());
    assert_eq!(sent.len(), 3);
}
