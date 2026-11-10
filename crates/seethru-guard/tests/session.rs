use std::cell::RefCell;
use std::io;
use std::net::IpAddr;
use std::rc::Rc;
use std::time::Duration;

use seethru_guard::{
    Audit, Clock, Entry, Environment, MAX_REQUESTS, MIN_GAP, Phase, Purpose, REVERIFY_AFTER,
    REVERIFY_EVERY, Raw, Session, Stop, Target, Token, Transport, TransportError, WELL_KNOWN_PATH,
    Wire,
};

type Events = Rc<RefCell<Vec<String>>>;
type Answer = Box<dyn FnMut(&str, usize) -> Result<Raw, TransportError>>;

struct Net {
    events: Events,
    pins: Vec<Option<IpAddr>>,
    answer: Answer,
}

impl Transport for Net {
    fn send(&mut self, wire: &Wire<'_>) -> Result<Raw, TransportError> {
        self.events.borrow_mut().push(format!("net {}", wire.path));
        self.pins.push(wire.pin);
        let count = self.pins.len();
        (self.answer)(wire.path, count).map(|raw| published(raw, wire))
    }
}

struct Log {
    events: Events,
    entries: Vec<Entry>,
    broken: bool,
}

impl Audit for Log {
    fn record(&mut self, entry: &Entry) -> io::Result<()> {
        if self.broken {
            return Err(io::Error::other("disk full"));
        }
        self.events
            .borrow_mut()
            .push(format!("log {} {}", entry.phase.as_str(), entry.path));
        self.entries.push(entry.clone());
        Ok(())
    }
}

#[derive(Default)]
struct Time {
    now: Duration,
    sleeps: Vec<Duration>,
}

impl Clock for Time {
    fn elapsed(&self) -> Duration {
        self.now
    }

    fn unix_seconds(&self) -> u64 {
        1_000 + self.now.as_secs()
    }

    fn sleep(&mut self, time: Duration) {
        self.sleeps.push(time);
        self.now += time;
    }
}

fn token() -> Token {
    Token::from_random(&[3u8; 32])
}

const OWNED: &str = "the line seethru own printed";

fn published(mut raw: Raw, wire: &Wire<'_>) -> Raw {
    if raw.body == OWNED.as_bytes() {
        raw.body = token().file_line(wire.target).into_bytes();
    }
    raw
}

fn ip(text: &str) -> Option<IpAddr> {
    text.parse().ok()
}

fn answer(status: u16, headers: &[(&str, &str)], body: &str, remote: &str) -> Raw {
    Raw {
        status,
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
        body: body.as_bytes().to_vec(),
        remote: ip(remote),
    }
}

fn owned(remote: &'static str) -> Answer {
    Box::new(move |path, _| {
        if path == WELL_KNOWN_PATH {
            Ok(answer(200, &[], OWNED, remote))
        } else {
            Ok(answer(
                200,
                &[("Content-Type", "text/html")],
                "page",
                remote,
            ))
        }
    })
}

fn parts(answer: Answer) -> (Net, Log, Time, Events) {
    let events: Events = Rc::default();
    (
        Net {
            events: events.clone(),
            pins: Vec::new(),
            answer,
        },
        Log {
            events: events.clone(),
            entries: Vec::new(),
            broken: false,
        },
        Time::default(),
        events,
    )
}

fn target(text: &str) -> Target {
    match Target::parse(text) {
        Ok(target) => target,
        Err(error) => unreachable!("{error}"),
    }
}

#[test]
fn nothing_is_sent_to_production_without_confirmation() {
    let (mut net, mut log, mut time, events) = parts(owned("203.0.113.5"));
    let opened = Session::open(
        target("https://app.example"),
        token(),
        Environment::Production { confirmed: false },
        &mut net,
        &mut log,
        &mut time,
    );
    assert_eq!(opened.err(), Some(Stop::ProductionNotConfirmed));
    assert!(events.borrow().is_empty());
}

#[test]
fn the_first_request_is_the_ownership_file_and_a_wrong_answer_ends_the_run() {
    for (status, body) in [
        (200, "seethru-ownership=nope".to_owned()),
        (404, OWNED.to_owned()),
        (302, OWNED.to_owned()),
        (200, String::new()),
    ] {
        let (mut net, mut log, mut time, events) = parts(Box::new(move |_, _| {
            Ok(answer(
                status,
                &[("Location", "/elsewhere")],
                &body,
                "203.0.113.5",
            ))
        }));
        let opened = Session::open(
            target("https://app.example"),
            token(),
            Environment::Staging,
            &mut net,
            &mut log,
            &mut time,
        );
        assert_eq!(opened.err(), Some(Stop::NotOwned));
        assert_eq!(
            *events.borrow(),
            [
                format!("log sending {WELL_KNOWN_PATH}"),
                format!("net {WELL_KNOWN_PATH}"),
                format!("log answered {WELL_KNOWN_PATH}"),
            ]
        );
    }
}

#[test]
fn every_request_is_written_down_before_it_is_sent_and_spaced_out() {
    let (mut net, mut log, mut time, events) = parts(owned("203.0.113.5"));
    let session = Session::open(
        target("https://app.example"),
        token(),
        Environment::Production { confirmed: true },
        &mut net,
        &mut log,
        &mut time,
    );
    let Ok(mut session) = session else {
        unreachable!("the app is owned");
    };
    for _ in 0..3 {
        assert!(session.get("/", Purpose::Headers, None).is_ok());
    }
    assert_eq!(session.requests(), 4);
    let events = events.borrow();
    for (at, event) in events.iter().enumerate() {
        if event.starts_with("net ") {
            assert!(
                at > 0 && events[at - 1].starts_with("log sending"),
                "{events:?}"
            );
        }
    }
    assert_eq!(time.sleeps, [MIN_GAP; 3]);
    assert_eq!(log.entries.len(), 8);
    assert_eq!(log.entries[1].status, Some(200));
    assert_eq!(log.entries[2].purpose, Purpose::Headers);
    assert!(log.entries[2].line().contains(r#""phase":"sending""#));
}

#[test]
fn a_failing_audit_log_means_no_request() {
    let (mut net, mut log, mut time, events) = parts(owned("203.0.113.5"));
    log.broken = true;
    let opened = Session::open(
        target("https://app.example"),
        token(),
        Environment::Staging,
        &mut net,
        &mut log,
        &mut time,
    );
    assert_eq!(opened.err(), Some(Stop::AuditFailed));
    assert!(events.borrow().is_empty());
}

#[test]
fn ownership_is_checked_again_and_the_run_has_a_hard_cap() {
    let (mut net, mut log, mut time, events) = parts(owned("203.0.113.5"));
    let Ok(mut session) = Session::open(
        target("https://app.example"),
        token(),
        Environment::Staging,
        &mut net,
        &mut log,
        &mut time,
    ) else {
        unreachable!("the app is owned");
    };
    let mut last = Ok(());
    for _ in 0..MAX_REQUESTS {
        last = session.get("/", Purpose::Headers, None).map(|_| ());
        if last.is_err() {
            break;
        }
    }
    assert_eq!(last, Err(Stop::TooManyRequests));
    assert_eq!(session.requests(), MAX_REQUESTS);
    let sent: Vec<String> = events
        .borrow()
        .iter()
        .filter(|event| event.starts_with("net "))
        .cloned()
        .collect();
    assert_eq!(sent.len() as u32, MAX_REQUESTS);
    let proofs: Vec<usize> = sent
        .iter()
        .enumerate()
        .filter(|(_, event)| event.ends_with(WELL_KNOWN_PATH))
        .map(|(at, _)| at)
        .collect();
    assert_eq!(proofs, [0, REVERIFY_EVERY as usize + 1]);
}

#[test]
fn time_alone_triggers_a_new_ownership_check() {
    let events: Events = Rc::default();
    let mut net = Net {
        events: events.clone(),
        pins: Vec::new(),
        answer: Box::new(|path, count| {
            if path == WELL_KNOWN_PATH && count > 1 {
                Ok(answer(200, &[], "gone", "203.0.113.5"))
            } else if path == WELL_KNOWN_PATH {
                Ok(answer(200, &[], OWNED, "203.0.113.5"))
            } else {
                Ok(answer(200, &[], "", "203.0.113.5"))
            }
        }),
    };
    let mut log = Log {
        events: events.clone(),
        entries: Vec::new(),
        broken: false,
    };
    struct Jumping(Time);
    impl Clock for Jumping {
        fn elapsed(&self) -> Duration {
            self.0.now
        }
        fn unix_seconds(&self) -> u64 {
            0
        }
        fn sleep(&mut self, _: Duration) {
            self.0.now += REVERIFY_AFTER;
        }
    }
    let mut time = Jumping(Time::default());
    let Ok(mut session) = Session::open(
        target("https://app.example"),
        token(),
        Environment::Staging,
        &mut net,
        &mut log,
        &mut time,
    ) else {
        unreachable!("the app is owned");
    };
    assert!(session.get("/", Purpose::Headers, None).is_ok());
    assert_eq!(
        session.get("/", Purpose::Headers, None).err(),
        Some(Stop::NotOwned)
    );
    let sent = events
        .borrow()
        .iter()
        .filter(|event| event.starts_with("net "))
        .count();
    assert_eq!(sent, 3);
}

#[test]
fn the_address_is_pinned_and_odd_addresses_are_refused() {
    let (mut net, mut log, mut time, _) = parts(Box::new(|path, count| {
        let remote = if count < 3 {
            "203.0.113.5"
        } else {
            "203.0.113.99"
        };
        if path == WELL_KNOWN_PATH {
            Ok(answer(200, &[], OWNED, remote))
        } else {
            Ok(answer(200, &[], "", remote))
        }
    }));
    let Ok(mut session) = Session::open(
        target("https://app.example"),
        token(),
        Environment::Staging,
        &mut net,
        &mut log,
        &mut time,
    ) else {
        unreachable!("the app is owned");
    };
    assert!(session.get("/", Purpose::Headers, None).is_ok());
    assert_eq!(
        session.get("/", Purpose::Headers, None).err(),
        Some(Stop::AddressNotAllowed)
    );
    drop(session);
    assert_eq!(net.pins, [None, ip("203.0.113.5"), ip("203.0.113.5")]);
    assert_eq!(
        log.entries.last().map(|entry| entry.phase),
        Some(Phase::Failed)
    );

    for (url, remote) in [
        ("https://app.example", "169.254.169.254"),
        ("https://app.example", "0.0.0.0"),
        ("https://app.example", ""),
        ("http://localhost:3000", "10.0.0.7"),
        ("http://127.0.0.1:3000", "127.0.0.2"),
    ] {
        let (mut net, mut log, mut time, _) = parts(owned(remote));
        let opened = Session::open(
            target(url),
            token(),
            Environment::Staging,
            &mut net,
            &mut log,
            &mut time,
        );
        assert_eq!(
            opened.err(),
            Some(Stop::AddressNotAllowed),
            "{url} {remote}"
        );
        assert_eq!(net.pins.len(), 1);
    }
    let (mut net, mut log, mut time, _) = parts(owned("127.0.0.1"));
    assert!(
        Session::open(
            target("http://localhost:3000"),
            token(),
            Environment::Staging,
            &mut net,
            &mut log,
            &mut time,
        )
        .is_ok()
    );
    assert_eq!(net.pins, [ip("127.0.0.1")]);
}

#[test]
fn only_plain_paths_on_the_target_are_requested() {
    let (mut net, mut log, mut time, events) = parts(owned("203.0.113.5"));
    let Ok(mut session) = Session::open(
        target("https://app.example"),
        token(),
        Environment::Staging,
        &mut net,
        &mut log,
        &mut time,
    ) else {
        unreachable!("the app is owned");
    };
    for path in [
        "//other.example/",
        "/a?token=1",
        "/a#b",
        "/../etc",
        "/a b",
        "relative",
        "",
        "/a\r\nHost: x",
        "https://other.example/",
    ] {
        assert!(session.get(path, Purpose::Headers, None).is_err(), "{path}");
    }
    assert!(
        session
            .get(WELL_KNOWN_PATH, Purpose::Ownership, None)
            .is_err()
    );
    assert_eq!(session.requests(), 1);
    assert_eq!(events.borrow().len(), 3);
}

#[test]
fn redirects_are_followed_only_inside_the_target() {
    let run = |location: &'static str| {
        let (mut net, mut log, mut time, events) = parts(Box::new(move |path, _| {
            if path == WELL_KNOWN_PATH {
                Ok(answer(200, &[], OWNED, "203.0.113.5"))
            } else if path == "/" {
                Ok(answer(302, &[("Location", location)], "", "203.0.113.5"))
            } else {
                Ok(answer(200, &[("Set-Cookie", "sid=1")], "", "203.0.113.5"))
            }
        }));
        let Ok(mut session) = Session::open(
            target("https://app.example"),
            token(),
            Environment::Staging,
            &mut net,
            &mut log,
            &mut time,
        ) else {
            unreachable!("the app is owned");
        };
        let result = session.follow("/", Purpose::Headers);
        let sent: Vec<String> = events
            .borrow()
            .iter()
            .filter_map(|event| event.strip_prefix("net ").map(str::to_owned))
            .collect();
        (result, sent)
    };
    for (location, landed) in [
        ("/login?next=%2Fsecret", "/login"),
        ("https://app.example/home#top", "/home"),
        ("HTTPS://APP.EXAMPLE:443/x", "/x"),
        ("https://app.example", "/"),
        ("docs/start", "/docs/start"),
    ] {
        let (result, sent) = run(location);
        if landed == "/" {
            assert!(
                result.is_ok_and(|response| response.is_redirect()),
                "{location}"
            );
            assert_eq!(sent.len(), 5, "{location}");
            continue;
        }
        assert!(
            result.is_ok_and(|response| response.path == landed
                && response.status == 200
                && response.kept().is_empty()),
            "{location}"
        );
        assert_eq!(sent, [WELL_KNOWN_PATH, "/", landed], "{location}");
    }
    for location in [
        "https://other.example/",
        "http://app.example/",
        "https://app.example:8443/",
        "https://app.example.other.example/",
        "https://app.example@other.example/",
        "//other.example/",
        "javascript:alert(1)",
        "",
        "/a b",
    ] {
        let (result, sent) = run(location);
        assert_eq!(result.err(), Some(Stop::RedirectedOutside), "{location}");
        assert_eq!(sent, [WELL_KNOWN_PATH, "/"], "{location}");
    }
}

#[test]
fn only_the_headers_the_checks_need_are_kept() {
    let (mut net, mut log, mut time, _) = parts(Box::new(|path, _| {
        if path == WELL_KNOWN_PATH {
            Ok(answer(200, &[], OWNED, "203.0.113.5"))
        } else {
            Ok(answer(
                200,
                &[
                    ("Set-Cookie", "session=abc"),
                    ("Authorization", "Bearer x"),
                    ("X-Frame-Options", " DENY "),
                    ("X-FRAME-OPTIONS", "SAMEORIGIN"),
                    ("Location", "/next?code=abc#frag"),
                    ("Server", "x"),
                ],
                "the whole page",
                "203.0.113.5",
            ))
        }
    }));
    let Ok(mut session) = Session::open(
        target("https://app.example"),
        token(),
        Environment::Staging,
        &mut net,
        &mut log,
        &mut time,
    ) else {
        unreachable!("the app is owned");
    };
    let Ok(response) = session.get("/", Purpose::Headers, None) else {
        unreachable!("the app answers");
    };
    assert_eq!(
        response.kept(),
        [
            ("x-frame-options".to_owned(), "DENY".to_owned()),
            ("x-frame-options".to_owned(), "SAMEORIGIN".to_owned()),
            ("location".to_owned(), "/next".to_owned()),
        ]
    );
    assert_eq!(
        response.header("x-frame-options").as_deref(),
        Some("DENY, SAMEORIGIN")
    );
    assert_eq!(response.header("set-cookie"), None);
    let text = format!("{response:?}{:?}", log.entries);
    assert!(!text.contains("abc") && !text.contains("whole page"));
}
