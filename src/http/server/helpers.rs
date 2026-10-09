//! Handlers for a plain HTTP listener: sending everything to HTTPS, and answering ACME's HTTP-01 challenges (RFC 8555
//! section 8.3), which a CA asks for over plain HTTP on port 80.

use super::{Handler, Request, Response};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// A handler that answers every request with a redirect to the same URL over HTTPS: 301 for GET and HEAD, 308 (which keeps
/// the method and the body) for the others. `https_port` is put in the URL unless it is 443 or `None`.
pub fn redirect_to_https(https_port: Option<u16>) -> impl Handler {
    move |req: Request| {
        let host = host_of(req.authority());
        if host.is_empty() {
            return Response::text(400, "no host to redirect to\n");
        }
        let port = match https_port {
            Some(p) if p != 443 => format!(":{p}"),
            _ => String::new(),
        };
        let path = if req.target().starts_with('/') { req.target().to_string() } else { format!("{}{}", req.path(), req.query().map(|q| format!("?{q}")).unwrap_or_default()) };
        let status = if matches!(req.method(), "GET" | "HEAD") { 301 } else { 308 };
        Response::redirect(status, &format!("https://{host}{port}{path}"))
    }
}

/// The host of an authority, without the port (an IPv6 literal keeps its brackets).
fn host_of(authority: &str) -> &str {
    if authority.starts_with('[') {
        return authority.find(']').map_or(authority, |i| &authority[..=i]);
    }
    authority.rsplit_once(':').map_or(authority, |(h, _)| h)
}

const CHALLENGE_PATH: &str = "/.well-known/acme-challenge/";

/// The HTTP-01 challenges an ACME client is waiting on: token to key authorization. Clones share the same set, so the
/// ACME client (B-113) adds and removes them while a server that [`wrap`](AcmeHttp01::wrap)s its handler answers them.
#[derive(Clone, Debug, Default)]
pub struct AcmeHttp01 {
    tokens: Arc<RwLock<HashMap<String, String>>>,
}

impl AcmeHttp01 {
    pub fn new() -> AcmeHttp01 {
        AcmeHttp01::default()
    }

    /// Starts answering the challenge with this token.
    pub fn insert(&self, token: &str, key_authorization: &str) {
        self.tokens.write().unwrap_or_else(|e| e.into_inner()).insert(token.to_string(), key_authorization.to_string());
    }

    /// Stops answering it.
    pub fn remove(&self, token: &str) {
        self.tokens.write().unwrap_or_else(|e| e.into_inner()).remove(token);
    }

    /// The answer, if the request is for a challenge's path: the key authorization for a token that is waiting, 404 for
    /// one that is not. `None` for any other path.
    pub fn answer(&self, req: &Request) -> Option<Response> {
        let token = req.path().strip_prefix(CHALLENGE_PATH)?;
        if !matches!(req.method(), "GET" | "HEAD") {
            return Some(Response::new(405).with_header("allow", "GET, HEAD"));
        }
        // tokens are base64url (RFC 8555 section 8.3)
        if token.is_empty() || !token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return Some(Response::new(404));
        }
        let tokens = self.tokens.read().unwrap_or_else(|e| e.into_inner());
        Some(match tokens.get(token) {
            Some(key_auth) => Response::bytes(200, "application/octet-stream", key_auth.as_bytes().to_vec()),
            None => Response::new(404),
        })
    }

    /// A handler that answers challenges and passes every other request to `next`.
    pub fn wrap(&self, next: impl Handler) -> impl Handler {
        let challenges = self.clone();
        move |req: Request| match challenges.answer(&req) {
            Some(response) => response,
            None => next.handle(req),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_util::request;
    use super::*;

    #[test]
    fn redirects_keep_the_host_the_path_and_the_method() {
        let h = redirect_to_https(None);
        let r = h.handle(request("GET", "/a/b?c=d", "example.com:80"));
        assert_eq!((r.status(), r.header("location")), (301, Some("https://example.com/a/b?c=d")));
        let r = h.handle(request("POST", "/form", "example.com"));
        assert_eq!((r.status(), r.header("location")), (308, Some("https://example.com/form")));
        let r = redirect_to_https(Some(8443)).handle(request("GET", "/", "[2001:db8::1]:8080"));
        assert_eq!(r.header("location"), Some("https://[2001:db8::1]:8443/"));
        let r = h.handle(request("GET", "http://example.org/x?y", "example.org"));
        assert_eq!(r.header("location"), Some("https://example.org/x?y"));
        assert_eq!(h.handle(request("GET", "/", "")).status(), 400);
    }

    #[test]
    fn challenges_are_answered_while_they_wait_and_the_rest_passes_through() {
        let acme = AcmeHttp01::new();
        let h = acme.wrap(|_req: Request| Response::text(200, "the site\n"));
        let path = |t: &str| format!("{CHALLENGE_PATH}{t}");
        assert_eq!(h.handle(request("GET", &path("tok_en-1"), "example.com")).status(), 404);
        acme.insert("tok_en-1", "tok_en-1.thumbprint");
        let r = h.handle(request("GET", &path("tok_en-1"), "example.com"));
        assert_eq!(r.status(), 200);
        assert!(matches!(r.body(), super::super::ResponseBody::Bytes(b) if b == b"tok_en-1.thumbprint"));
        assert_eq!(h.handle(request("POST", &path("tok_en-1"), "example.com")).status(), 405);
        assert_eq!(h.handle(request("GET", &path("../etc"), "example.com")).status(), 404);
        assert_eq!(h.handle(request("GET", "/index.html", "example.com")).status(), 200);
        acme.remove("tok_en-1");
        assert_eq!(h.handle(request("GET", &path("tok_en-1"), "example.com")).status(), 404);
    }
}
