//! Tests of the cookie jar in the clients ([`Client::cookie_jar`]): cookies set by responses (redirects too) go back to their host and
//! to no other, the caller's own `Cookie` wins, and the jar works the same over HTTP/2 and in the async client.

use super::cookie::CookieJar;
use super::h2_server::response as h2_response;
use super::h2_testserver::H2Server;
use super::testserver::{response, Reply, Seen, TestServer};
use super::Url;
use crate::asyncio::block_on;

fn cookie_server() -> TestServer {
    TestServer::start(|seen: &Seen| {
        let path = seen.path().to_string();
        Reply::Send(match path.as_str() {
            "/login" => response(200, &["Set-Cookie: session=s1; Path=/; HttpOnly", "Set-Cookie: pref=dark; Path=/app"], b"in"),
            "/hop" => response(302, &["Location: /app/next", "Set-Cookie: hop=h1; Path=/"], b""),
            "/logout" => response(200, &["Set-Cookie: session=; Max-Age=0; Path=/"], b"out"),
            p if p.starts_with("/to/") => {
                let to = p.trim_start_matches("/to/").to_string();
                let location = format!("Location: {to}");
                response(302, &[Box::leak(location.into_boxed_str())], b"")
            }
            _ => response(200, &[], seen.header("cookie").unwrap_or("-").as_bytes()),
        })
    })
}

#[test]
fn without_a_jar_cookies_are_neither_kept_nor_sent() {
    let server = cookie_server();
    let client = server.client();
    client.get(&server.url("/login")).unwrap();
    assert_eq!(client.get(&server.url("/app/x")).unwrap().text(), "-");
    assert!(client.cookies().is_none());
}

#[test]
fn cookies_go_back_by_path_and_are_deleted_when_the_server_says_so() {
    let server = cookie_server();
    let jar = CookieJar::new();
    let client = server.client().cookie_jar(jar.clone());
    assert_eq!(client.get(&server.url("/login")).unwrap().text(), "in");
    assert_eq!(client.get(&server.url("/app/x")).unwrap().text(), "pref=dark; session=s1");
    assert_eq!(client.get(&server.url("/other")).unwrap().text(), "session=s1");
    client.get(&server.url("/logout")).unwrap();
    assert_eq!(client.get(&server.url("/app/x")).unwrap().text(), "pref=dark");
    assert_eq!(jar.len(), 1);
    // the caller's own Cookie header goes as it is, and none from the jar with it
    let r = client.request("GET", &server.url("/app/x")).header("Cookie", "mine=1").send().unwrap();
    assert_eq!(r.text(), "mine=1");
}

#[test]
fn a_redirect_keeps_what_it_sets_and_each_hop_gets_its_own_hosts_cookies() {
    let server = cookie_server();
    let client = server.client().cookie_jar(CookieJar::new());
    // set on the redirect itself, sent on the hop it leads to
    assert_eq!(client.get(&server.url("/hop")).unwrap().text(), "hop=h1");
    // the same server under another name is another host: a redirect there carries none of 127.0.0.1's cookies
    let other = format!("http://localhost:{}/app/x", server.port);
    assert_eq!(client.get(&server.url(&format!("/to/{other}"))).unwrap().text(), "-");
    // and it comes back with them
    let back = server.url("/app/x");
    assert_eq!(client.get(&format!("http://localhost:{}/to/{back}", server.port)).unwrap().text(), "hop=h1");
}

#[test]
fn one_jar_can_serve_several_clients_and_be_filled_by_hand() {
    let server = cookie_server();
    let jar = CookieJar::new();
    let a = server.client().cookie_jar(jar.clone());
    let b = server.client().cookie_jar(jar.clone());
    a.get(&server.url("/login")).unwrap();
    assert_eq!(b.get(&server.url("/other")).unwrap().text(), "session=s1");
    assert!(jar.set_cookie(&Url::parse(&server.url("/")).unwrap(), "manual=1; Path=/"));
    assert_eq!(b.get(&server.url("/other")).unwrap().text(), "session=s1; manual=1");
    assert_eq!(jar.cookies_for(&Url::parse(&server.url("/other")).unwrap()), vec![("session".into(), "s1".into()), ("manual".into(), "1".into())]);
}

#[test]
fn the_async_client_keeps_and_sends_them_too() {
    let server = cookie_server();
    let client = server.client().cookie_jar(CookieJar::new()).into_async();
    block_on(client.get(&server.url("/login"))).unwrap();
    assert_eq!(block_on(client.get(&server.url("/app/x"))).unwrap().text(), "pref=dark; session=s1");
    // (/hop leads to /app/next, which is in the path of pref)
    assert_eq!(block_on(client.get(&server.url("/hop"))).unwrap().text(), "pref=dark; session=s1; hop=h1");
}

#[test]
fn over_http2() {
    let server = H2Server::start(|seen| match seen.path() {
        "/login" => h2_response(200, &[("set-cookie", "session=s2; Path=/; Secure"), ("set-cookie", "theme=light")], b"in"),
        _ => {
            let c = seen.header("cookie").unwrap_or("-").to_string();
            h2_response(200, &[], c.as_bytes())
        }
    });
    let client = server.client().cookie_jar(CookieJar::new());
    client.get(&server.url("/login")).unwrap();
    assert_eq!(client.get(&server.url("/x")).unwrap().text(), "session=s2; theme=light");
    assert_eq!(server.end_and_complaints(), Vec::<String>::new());
}
