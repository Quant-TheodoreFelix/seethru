use std::io;
use std::net::IpAddr;
use std::time::Duration;

use crate::target::address_allowed;
use crate::{Scheme, Target, Token, WELL_KNOWN_PATH};

pub const MIN_GAP: Duration = Duration::from_millis(500);
pub const MAX_REQUESTS: u32 = 40;
pub const REVERIFY_EVERY: u32 = 20;
pub const REVERIFY_AFTER: Duration = Duration::from_secs(300);
pub const MAX_REDIRECTS: u32 = 3;
pub const MAX_BODY_BYTES: usize = 4096;
const MAX_PATH_BYTES: usize = 512;
const MAX_HEADER_BYTES: usize = 4096;

const KEPT_HEADERS: [&str; 8] = [
    "access-control-allow-credentials",
    "access-control-allow-origin",
    "content-security-policy",
    "content-type",
    "location",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Environment {
    Staging,
    Production { confirmed: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Ownership,
    Headers,
    Cors,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ownership => "ownership",
            Self::Headers => "headers",
            Self::Cors => "cors",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Sending,
    Answered,
    Failed,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sending => "sending",
            Self::Answered => "answered",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub time: u64,
    pub request: u32,
    pub phase: Phase,
    pub method: &'static str,
    pub path: String,
    pub purpose: Purpose,
    pub status: Option<u16>,
}

impl Entry {
    pub fn line(&self) -> String {
        let mut value = serde_json::json!({
            "time": self.time,
            "request": self.request,
            "phase": self.phase.as_str(),
            "method": self.method,
            "path": self.path,
            "purpose": self.purpose.as_str(),
        });
        if let (Some(status), Some(object)) = (self.status, value.as_object_mut()) {
            object.insert("status".to_owned(), status.into());
        }
        value.to_string()
    }
}

#[derive(Debug)]
pub struct Wire<'a> {
    pub target: &'a Target,
    pub path: &'a str,
    pub origin: Option<&'a str>,
    pub body_limit: Option<usize>,
    pub pin: Option<IpAddr>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Raw {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub remote: Option<IpAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    Failed,
    TimedOut,
    Garbled,
}

pub trait Transport {
    fn send(&mut self, wire: &Wire<'_>) -> Result<Raw, TransportError>;
}

pub trait Clock {
    fn elapsed(&self) -> Duration;
    fn unix_seconds(&self) -> u64;
    fn sleep(&mut self, time: Duration);
}

pub trait Audit {
    fn record(&mut self, entry: &Entry) -> io::Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    ProductionNotConfirmed,
    NotOwned,
    NotResponding,
    RedirectedOutside,
    AddressNotAllowed,
    TooManyRequests,
    AuditFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub request: u32,
    pub path: String,
    pub status: u16,
    headers: Vec<(String, String)>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<String> {
        let values: Vec<&str> = self
            .headers
            .iter()
            .filter(|(known, _)| known == name)
            .map(|(_, value)| value.as_str())
            .collect();
        (!values.is_empty()).then(|| values.join(", "))
    }

    pub fn kept(&self) -> &[(String, String)] {
        &self.headers
    }

    pub fn is_redirect(&self) -> bool {
        matches!(self.status, 301 | 302 | 303 | 307 | 308)
    }
}

pub struct Session<'a> {
    target: Target,
    token: Token,
    transport: &'a mut dyn Transport,
    audit: &'a mut dyn Audit,
    clock: &'a mut dyn Clock,
    pin: Option<IpAddr>,
    sent: u32,
    last: Option<Duration>,
    since_proof: u32,
    proved_at: Duration,
}

fn path_ok(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && path.len() <= MAX_PATH_BYTES
        && path
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !matches!(byte, b'?' | b'#' | b'\\'))
        && !path.split('/').any(|part| part == "..")
}

fn without_query(text: &str) -> &str {
    &text[..text.find(['?', '#']).unwrap_or(text.len())]
}

fn keep(headers: Vec<(String, String)>) -> Vec<(String, String)> {
    headers
        .into_iter()
        .filter_map(|(name, value)| {
            let name = name.trim().to_ascii_lowercase();
            if !KEPT_HEADERS.contains(&name.as_str()) {
                return None;
            }
            let value = value.trim();
            let value = if name == "location" {
                without_query(value)
            } else {
                value
            };
            let clean: String = value
                .chars()
                .filter(|c| !c.is_control())
                .take(MAX_HEADER_BYTES)
                .collect();
            Some((name, clean))
        })
        .collect()
}

impl<'a> Session<'a> {
    pub fn open(
        target: Target,
        token: Token,
        environment: Environment,
        transport: &'a mut dyn Transport,
        audit: &'a mut dyn Audit,
        clock: &'a mut dyn Clock,
    ) -> Result<Self, Stop> {
        if environment == (Environment::Production { confirmed: false }) {
            return Err(Stop::ProductionNotConfirmed);
        }
        let pin = target.address();
        let mut session = Self {
            target,
            token,
            transport,
            audit,
            clock,
            pin,
            sent: 0,
            last: None,
            since_proof: 0,
            proved_at: Duration::ZERO,
        };
        session.prove()?;
        Ok(session)
    }

    pub fn target(&self) -> &Target {
        &self.target
    }

    pub fn requests(&self) -> u32 {
        self.sent
    }

    fn send(
        &mut self,
        path: &str,
        purpose: Purpose,
        origin: Option<&str>,
        body_limit: Option<usize>,
    ) -> Result<(Response, Vec<u8>), Stop> {
        if !path_ok(path) {
            return Err(Stop::RedirectedOutside);
        }
        if self.sent >= MAX_REQUESTS {
            return Err(Stop::TooManyRequests);
        }
        if let Some(last) = self.last {
            let since = self.clock.elapsed().saturating_sub(last);
            if since < MIN_GAP {
                self.clock.sleep(MIN_GAP - since);
            }
        }
        let request = self.sent + 1;
        let mut entry = Entry {
            time: self.clock.unix_seconds(),
            request,
            phase: Phase::Sending,
            method: "GET",
            path: path.to_owned(),
            purpose,
            status: None,
        };
        self.audit.record(&entry).map_err(|_| Stop::AuditFailed)?;
        self.sent = request;
        self.since_proof += 1;
        self.last = Some(self.clock.elapsed());
        let sent = self.transport.send(&Wire {
            target: &self.target,
            path,
            origin,
            body_limit,
            pin: self.pin,
        });
        self.last = Some(self.clock.elapsed());
        entry.time = self.clock.unix_seconds();
        let allowed = |raw: &Raw, pin: Option<IpAddr>, scheme: Scheme| match (raw.remote, pin) {
            (None, _) => false,
            (Some(remote), Some(pin)) => remote == pin,
            (Some(remote), None) => {
                address_allowed(remote) && (scheme == Scheme::Https || remote.is_loopback())
            }
        };
        let raw = match sent {
            Ok(raw) if (100..600).contains(&raw.status) => raw,
            _ => {
                entry.phase = Phase::Failed;
                let _ = self.audit.record(&entry);
                return Err(Stop::NotResponding);
            }
        };
        entry.status = Some(raw.status);
        if !allowed(&raw, self.pin, self.target.scheme()) {
            entry.phase = Phase::Failed;
            let _ = self.audit.record(&entry);
            return Err(Stop::AddressNotAllowed);
        }
        self.pin = raw.remote;
        entry.phase = Phase::Answered;
        self.audit.record(&entry).map_err(|_| Stop::AuditFailed)?;
        let mut body = raw.body;
        body.truncate(body_limit.unwrap_or(0).min(MAX_BODY_BYTES));
        Ok((
            Response {
                request,
                path: path.to_owned(),
                status: raw.status,
                headers: keep(raw.headers),
            },
            body,
        ))
    }

    fn prove(&mut self) -> Result<(), Stop> {
        let (response, body) = self.send(
            WELL_KNOWN_PATH,
            Purpose::Ownership,
            None,
            Some(MAX_BODY_BYTES),
        )?;
        if response.status != 200 || !self.token.proves(&self.target, &body) {
            return Err(Stop::NotOwned);
        }
        self.since_proof = 0;
        self.proved_at = self.clock.elapsed();
        Ok(())
    }

    pub fn get(
        &mut self,
        path: &str,
        purpose: Purpose,
        origin: Option<&str>,
    ) -> Result<Response, Stop> {
        if purpose == Purpose::Ownership {
            return Err(Stop::NotOwned);
        }
        if self.since_proof >= REVERIFY_EVERY
            || self.clock.elapsed().saturating_sub(self.proved_at) >= REVERIFY_AFTER
        {
            self.prove()?;
        }
        self.send(path, purpose, origin, None)
            .map(|(response, _)| response)
    }

    fn next_path(&self, from: &str, location: &str) -> Result<String, Stop> {
        let location = without_query(location.trim());
        let lower = location.to_ascii_lowercase();
        let path = if lower.starts_with("http://") || lower.starts_with("https://") {
            let after = location.find("://").map_or(0, |at| at + 3);
            let end = location[after..]
                .find('/')
                .map_or(location.len(), |at| after + at);
            let same = Target::parse(&location[..end]).is_ok_and(|other| other == self.target);
            if !same {
                return Err(Stop::RedirectedOutside);
            }
            match &location[end..] {
                "" => "/".to_owned(),
                path => path.to_owned(),
            }
        } else if location.starts_with('/') {
            location.to_owned()
        } else if location.is_empty() || location.contains(':') {
            return Err(Stop::RedirectedOutside);
        } else {
            let base = &from[..from.rfind('/').map_or(0, |at| at + 1)];
            format!("{base}{location}")
        };
        if path_ok(&path) {
            Ok(path)
        } else {
            Err(Stop::RedirectedOutside)
        }
    }

    pub fn follow(&mut self, path: &str, purpose: Purpose) -> Result<Response, Stop> {
        let mut path = path.to_owned();
        let mut hops = 0;
        loop {
            let response = self.get(&path, purpose, None)?;
            if !response.is_redirect() || hops == MAX_REDIRECTS {
                return Ok(response);
            }
            let Some(location) = response.header("location") else {
                return Ok(response);
            };
            path = self.next_path(&path, &location)?;
            hops += 1;
        }
    }
}
