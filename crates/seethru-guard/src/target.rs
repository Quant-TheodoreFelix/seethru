use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetError {
    Scheme,
    Credentials,
    Host,
    Port,
    Extra,
    PlainHttp,
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Scheme => "the address must start with https://",
            Self::Credentials => "the address must not contain a user name or password",
            Self::Host => "the address has no usable host name",
            Self::Port => "the port in the address is not a number from 1 to 65535",
            Self::Extra => {
                "give only the address of the app, such as https://staging.example.com, without a path"
            }
            Self::PlainHttp => {
                "http:// is only allowed for an app on this computer (localhost). Use https://"
            }
        })
    }
}

impl std::error::Error for TargetError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    scheme: Scheme,
    host: String,
    port: u16,
    address: Option<IpAddr>,
}

fn name_ok(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    let shaped = labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    });
    let numeric = labels
        .last()
        .is_some_and(|last| last.chars().all(|c| c.is_ascii_digit()) || last.starts_with("0x"));
    shaped && !numeric
}

impl Target {
    pub fn parse(text: &str) -> Result<Self, TargetError> {
        let lower = text.to_ascii_lowercase();
        let (scheme, rest) = if let Some(rest) = lower.strip_prefix("https://") {
            (Scheme::Https, rest)
        } else if let Some(rest) = lower.strip_prefix("http://") {
            (Scheme::Http, rest)
        } else {
            return Err(TargetError::Scheme);
        };
        let end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
        let (authority, extra) = rest.split_at(end);
        if !(extra.is_empty() || extra == "/") {
            return Err(TargetError::Extra);
        }
        if authority.contains('@') {
            return Err(TargetError::Credentials);
        }
        let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
            let (literal, after) = inner.split_once(']').ok_or(TargetError::Host)?;
            let port = match after {
                "" => None,
                after => Some(after.strip_prefix(':').ok_or(TargetError::Port)?),
            };
            (literal, port)
        } else {
            match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            }
        };
        let port = match port {
            None => scheme.default_port(),
            Some(port) => {
                if port.is_empty() || port.len() > 5 || !port.chars().all(|c| c.is_ascii_digit()) {
                    return Err(TargetError::Port);
                }
                match port.parse::<u16>() {
                    Ok(port) if port != 0 => port,
                    _ => return Err(TargetError::Port),
                }
            }
        };
        let bracketed = authority.starts_with('[');
        let address = if bracketed {
            Some(IpAddr::V6(
                host.parse::<Ipv6Addr>().map_err(|_| TargetError::Host)?,
            ))
        } else if let Ok(v4) = host.parse::<Ipv4Addr>() {
            Some(IpAddr::V4(v4))
        } else if host == "localhost" {
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        } else if name_ok(host) {
            None
        } else {
            return Err(TargetError::Host);
        };
        let target = Self {
            scheme,
            host: host.to_owned(),
            port,
            address,
        };
        if scheme == Scheme::Http && !target.is_loopback() {
            return Err(TargetError::PlainHttp);
        }
        if address.is_some_and(|address| !address_allowed(address)) {
            return Err(TargetError::Host);
        }
        Ok(target)
    }

    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn address(&self) -> Option<IpAddr> {
        self.address
    }

    pub fn is_loopback(&self) -> bool {
        self.address.is_some_and(|address| address.is_loopback())
    }

    fn host_text(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }

    pub fn origin(&self) -> String {
        if self.port == self.scheme.default_port() {
            format!("{}://{}", self.scheme.as_str(), self.host_text())
        } else {
            format!(
                "{}://{}:{}",
                self.scheme.as_str(),
                self.host_text(),
                self.port
            )
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!(
            "{}://{}:{}{path}",
            self.scheme.as_str(),
            self.host_text(),
            self.port
        )
    }

    pub fn slug(&self) -> String {
        let host: String = self
            .host
            .chars()
            .map(|c| if c == ':' { '_' } else { c })
            .collect();
        format!("{}-{host}-{}", self.scheme.as_str(), self.port)
    }
}

pub(crate) fn address_allowed(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast() || v4.is_link_local())
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return address_allowed(IpAddr::V4(v4));
            }
            !(v6.is_unspecified() || v6.is_multicast() || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_an_origin_and_nothing_else() {
        let target = Target::parse("https://Staging.Example.com/");
        assert_eq!(
            target.as_ref().map(Target::origin),
            Ok("https://staging.example.com".to_owned())
        );
        assert_eq!(
            Target::parse("https://a.example:8443").map(|t| t.url("/x")),
            Ok("https://a.example:8443/x".to_owned())
        );
        assert_eq!(
            Target::parse("https://a.example/path").err(),
            Some(TargetError::Extra)
        );
        assert_eq!(
            Target::parse("https://a.example?x=1").err(),
            Some(TargetError::Extra)
        );
        assert_eq!(
            Target::parse("https://user:pw@a.example").err(),
            Some(TargetError::Credentials)
        );
        assert_eq!(
            Target::parse("ftp://a.example").err(),
            Some(TargetError::Scheme)
        );
        assert_eq!(Target::parse("a.example").err(), Some(TargetError::Scheme));
        assert_eq!(
            Target::parse("https://a.example:0").err(),
            Some(TargetError::Port)
        );
        assert_eq!(
            Target::parse("https://a.example:99999").err(),
            Some(TargetError::Port)
        );
        assert_eq!(Target::parse("https://").err(), Some(TargetError::Host));
        assert_eq!(
            Target::parse("https://a_b.example").err(),
            Some(TargetError::Host)
        );
        assert_eq!(
            Target::parse("https://a.example\\@b.example").err(),
            Some(TargetError::Extra)
        );
    }

    #[test]
    fn plain_http_is_only_for_this_computer() {
        for ok in [
            "http://localhost:3000",
            "http://127.0.0.1:8080",
            "http://127.9.9.9",
            "http://[::1]:8080",
        ] {
            assert!(
                Target::parse(ok).is_ok_and(|target| target.is_loopback()),
                "{ok}"
            );
        }
        for refused in [
            "http://example.com",
            "http://localhost.example.com",
            "http://127.0.0.1.example.com",
            "http://10.0.0.5",
            "http://192.168.0.2:8080",
            "http://localhost.",
        ] {
            assert!(Target::parse(refused).is_err(), "{refused}");
        }
        for odd in [
            "https://2130706433",
            "https://0x7f.1",
            "https://127.1",
            "http://0x7f000001",
            "http://017700000001",
            "https://0.0.0.0",
            "https://169.254.169.254",
            "https://[fe80::1]",
            "https://[::ffff:169.254.169.254]",
        ] {
            assert!(Target::parse(odd).is_err(), "{odd}");
        }
        assert!(Target::parse("https://10.0.0.5").is_ok_and(|target| !target.is_loopback()));
    }

    #[test]
    fn names_a_store_file_without_path_characters() {
        assert_eq!(
            Target::parse("http://[::1]:8080").map(|t| t.slug()),
            Ok("http-__1-8080".to_owned())
        );
        assert_eq!(
            Target::parse("https://a.example").map(|t| t.slug()),
            Ok("https-a.example-443".to_owned())
        );
    }
}
