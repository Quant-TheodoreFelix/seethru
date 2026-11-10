use seethru_core::LimitationCode;
use seethru_guard::{
    Audit, Clock, Environment, Purpose, Response, Scheme, Session, Stop, Target, Token, Transport,
};

pub const CORS_ORIGIN: &str = "https://seethru-cors-check.invalid";
const ROOT: &str = "/";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Header {
    ContentSecurityPolicy,
    ContentTypeOptions,
    FrameProtection,
    StrictTransportSecurity,
}

impl Header {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ContentSecurityPolicy => "content-security-policy",
            Self::ContentTypeOptions => "x-content-type-options",
            Self::FrameProtection => "frame-protection",
            Self::StrictTransportSecurity => "strict-transport-security",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cors {
    ReflectsWithCredentials,
    WildcardWithCredentials,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    HeaderMissing(Header),
    CorsOpen(Cors),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub request: u32,
    pub method: &'static str,
    pub path: String,
    pub sent: Vec<(String, String)>,
    pub status: u16,
    pub seen: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    pub kind: Kind,
    pub steps: Vec<Step>,
}

impl Fact {
    pub fn id(&self) -> String {
        match self.kind {
            Kind::HeaderMissing(header) => {
                format!("security-header-missing:header:{}", header.as_str())
            }
            Kind::CorsOpen(_) => "cors-allows-any-origin-with-credentials:app".to_owned(),
        }
    }

    pub fn proof_file(&self) -> String {
        let name: String = self
            .id()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        format!("proof/{name}.json")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    pub facts: Vec<Fact>,
    pub problems: Vec<LimitationCode>,
    pub requests: u32,
    pub verified: bool,
}

fn problem(stop: Stop) -> LimitationCode {
    match stop {
        Stop::NotOwned | Stop::ProductionNotConfirmed => LimitationCode::OwnershipNotVerified,
        Stop::RedirectedOutside => LimitationCode::ProbeRedirectedOutside,
        Stop::NotResponding | Stop::AddressNotAllowed => LimitationCode::ProbeTargetNotResponding,
        Stop::TooManyRequests | Stop::AuditFailed => LimitationCode::ProbeStoppedBySeethru,
    }
}

fn step(response: &Response, sent: Vec<(String, String)>, wanted: &[&str]) -> Step {
    Step {
        request: response.request,
        method: "GET",
        path: response.path.clone(),
        sent,
        status: response.status,
        seen: response
            .kept()
            .iter()
            .filter(|(name, _)| wanted.contains(&name.as_str()))
            .cloned()
            .collect(),
    }
}

fn directive(policy: &str, name: &str) -> bool {
    policy.split([';', ',']).any(|part| {
        part.split_ascii_whitespace()
            .next()
            .is_some_and(|first| first.eq_ignore_ascii_case(name))
    })
}

fn max_age(value: &str) -> Option<u64> {
    value.split(';').find_map(|part| {
        let (name, number) = part.trim().split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("max-age")
            .then(|| number.trim().trim_matches('"').parse::<u64>().ok())
            .flatten()
    })
}

fn missing_headers(target: &Target, page: &Response) -> Vec<Header> {
    let mut missing = Vec::new();
    let policy = page.header("content-security-policy");
    if policy
        .as_deref()
        .is_none_or(|policy| policy.trim().is_empty())
    {
        missing.push(Header::ContentSecurityPolicy);
    }
    let sniff = page.header("x-content-type-options");
    if !sniff.is_some_and(|value| {
        value
            .split(',')
            .any(|part| part.trim().eq_ignore_ascii_case("nosniff"))
    }) {
        missing.push(Header::ContentTypeOptions);
    }
    let framed = page.header("x-frame-options").is_some_and(|value| {
        value.split(',').any(|part| {
            let part = part.trim();
            part.eq_ignore_ascii_case("deny") || part.eq_ignore_ascii_case("sameorigin")
        })
    });
    let ancestors = policy
        .as_deref()
        .is_some_and(|policy| directive(policy, "frame-ancestors"));
    if !framed && !ancestors {
        missing.push(Header::FrameProtection);
    }
    if target.scheme() == Scheme::Https && !target.is_loopback() {
        let strict = page
            .header("strict-transport-security")
            .and_then(|value| max_age(&value));
        if !strict.is_some_and(|seconds| seconds > 0) {
            missing.push(Header::StrictTransportSecurity);
        }
    }
    missing
}

fn is_page(response: &Response) -> bool {
    (200..300).contains(&response.status)
        && response.header("content-type").is_some_and(|kind| {
            let kind = kind.to_ascii_lowercase();
            kind.starts_with("text/html") || kind.starts_with("application/xhtml+xml")
        })
}

fn checks(session: &mut Session<'_>, outcome: &mut Outcome) -> Result<(), Stop> {
    let page = session.follow(ROOT, Purpose::Headers)?;
    if is_page(&page) {
        let target = session.target().clone();
        for header in missing_headers(&target, &page) {
            let wanted: &[&str] = match header {
                Header::ContentSecurityPolicy => &["content-type", "content-security-policy"],
                Header::ContentTypeOptions => &["content-type", "x-content-type-options"],
                Header::FrameProtection => {
                    &["content-type", "content-security-policy", "x-frame-options"]
                }
                Header::StrictTransportSecurity => &["content-type", "strict-transport-security"],
            };
            outcome.facts.push(Fact {
                kind: Kind::HeaderMissing(header),
                steps: vec![step(&page, Vec::new(), wanted)],
            });
        }
    } else {
        outcome.problems.push(LimitationCode::ProbePageNotRead);
    }
    if page.is_redirect() {
        return Ok(());
    }
    let crossed = session.get(&page.path, Purpose::Cors, Some(CORS_ORIGIN))?;
    let allowed = crossed.header("access-control-allow-origin");
    let credentials = crossed
        .header("access-control-allow-credentials")
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"));
    let kind = match allowed.as_deref().map(str::trim) {
        Some(CORS_ORIGIN) if credentials => Some(Cors::ReflectsWithCredentials),
        Some("*") if credentials => Some(Cors::WildcardWithCredentials),
        _ => None,
    };
    if let Some(kind) = kind {
        outcome.facts.push(Fact {
            kind: Kind::CorsOpen(kind),
            steps: vec![step(
                &crossed,
                vec![("origin".to_owned(), CORS_ORIGIN.to_owned())],
                &[
                    "access-control-allow-origin",
                    "access-control-allow-credentials",
                ],
            )],
        });
    }
    Ok(())
}

pub fn observe(
    target: Target,
    token: Token,
    environment: Environment,
    transport: &mut dyn Transport,
    audit: &mut dyn Audit,
    clock: &mut dyn Clock,
) -> Outcome {
    let mut outcome = Outcome::default();
    let mut session = match Session::open(target, token, environment, transport, audit, clock) {
        Ok(session) => session,
        Err(stop) => {
            outcome.problems.push(problem(stop));
            return outcome;
        }
    };
    outcome.verified = true;
    if let Err(stop) = checks(&mut session, &mut outcome) {
        outcome.problems.push(problem(stop));
    }
    outcome.requests = session.requests();
    outcome.facts.sort_by_key(|fact| fact.kind);
    outcome
}
