# The scanning proxy: threat model

BACKLOG B-78 asked for this before anyone relies on the proxy, together with the independent review of B-23. It covers
`pratique::proxy` (`src/proxy/`) and what it stands on: the TLS 1.3 server (`src/tls/server.rs`, `src/tls/certs.rs`),
the HTTP server and its runtime (`src/http/server/`), the HTTP client that reaches the real hosts (`src/http/`), and the
signing code (`src/sign.rs`, `src/crypto/*_sign.rs`). It says what the proxy is for, what it protects, from whom, how,
and what it does not do. Where a claim can be checked, the test or script that checks it is named. How to run it on each
kind of network (a corporate proxy, Zscaler or Netskope, CI, containers, private mirrors) is in `PROXY_CONFIGURATION.md`.

## What it is for

A package manager on a developer's machine or a CI runner (pip, uv, Poetry, npm, Yarn, pnpm) is pointed at the proxy
with `HTTPS_PROXY` and told to trust the proxy's certificate authority for the length of one run. The proxy opens the TLS
of the package registries (by default PyPI's and npm's hosts), so that a scanner (Lazaret's) can see every request for a
package and every file the registry sends, and refuse what it judges malicious **before the package manager has a byte of
it**. Every other host is tunnelled untouched, or refused.

The proxy is a tool the user runs for their own processes. It is not a network control: a program that ignores
`HTTPS_PROXY` is not scanned (see "What it does not do").

## What is worth protecting

1. **The integrity of what the package manager installs**: a refused package must not arrive, in whole or in part, and the
   proxy must not let anyone but the real registry answer for it.
2. **The trust the user lends**: the package manager trusts the proxy's CA for as long as the run lasts. That trust must
   not be usable for anything but the registries, by anyone but the proxy.
3. **What passes through**: registry credentials (`Authorization` for a private registry), the names of what is installed.
4. **The machine**: the proxy must not become a way into the user's network for other users or other machines.

## Who may attack

| who | can | is in scope |
|-----|-----|-------------|
| A malicious package or registry mirror | serve any bytes on the registry's connection; try to get past the scanner (encodings, sizes, redirects) | yes |
| Someone on the network path to the registry | intercept, alter, impersonate the registry | yes |
| Another local user, or another machine on the network | connect to the proxy's port | yes |
| A process of the same user | read the proxy's memory and files, change its environment | no: it can do anything the user can |
| The scanner | is the user's (Lazaret's) own code, run inside the proxy | trusted |

## The trust boundaries

```
package manager ──plain HTTP──▶ proxy listener (127.0.0.1) ── CONNECT host:443
      │                              │
      └──TLS 1.3, proxy's CA────────▶│ TLS server (leaf for host, signed by the proxy's CA)
                                     │ HTTP/1.1 or HTTP/2 inside ──▶ scanner ──▶ HTTP client ──TLS, verified──▶ registry
```

Each request inside a tunnel is parsed by the strict HTTP server (B-111) and made again by the HTTP client: no byte of a
request is relayed as it came.

## Threats and what answers them

### T1. The proxy's CA is used to impersonate another site

The CA is the most dangerous thing the proxy makes: a client that trusts it would believe whatever it signs.

- **Limited by a critical name constraint** to the DNS names the proxy intercepts, with every IPv4 and IPv6 address
  excluded (RFC 5280 section 4.2.1.10). A leaf for any other name fails in every verifier the proxy's users run:
  OpenSSL (Python, Node.js, curl), Go, webpki (uv) and this crate's own. *Checked:* `proxy::tests::
  the_ca_is_limited_to_the_names_it_is_for` (this crate's verifier, and `openssl verify`: "permitted subtree violation");
  `tools/proxy_interop.sh` (pip, uv, npm, Yarn, pnpm, curl, Python and Go accept the leaves for the registries).
- **The key never leaves memory**: generated when the proxy is built (`ProxyCa::new`), never written, never exported (no
  API returns it), gone when the proxy is dropped. Only the certificate is written (`ca.pem`, `bundle.pem`).
- **Short-lived**: a day by default (`ProxyBuilder::ca_lifetime`), and every leaf expires with it.
- **Trusted only by the processes the proxy runs**: the variables (`Proxy::client_env`) are set for the child processes;
  nothing is added to the system's or the user's trust store.
- **Leaves only for the host of the CONNECT, only when the ClientHello names it**: `TunnelCert` answers a ClientHello
  whose `server_name` is that host; one that names another host, or none, gets no certificate and the handshake ends.
  *Checked:* `inside_a_tunnel_only_its_host_and_none_of_the_connections_fields`.
- *Residual:* a client that ignores name constraints would trust the CA for any name for its lifetime. No client among
  those above does; very old OpenSSL (before 1.0) and some embedded TLS stacks did.

### T2. Someone between the proxy and the registry

Once the package manager trusts the proxy for a registry, the proxy's check of the registry is the only one made. It must
be at least as strict as the package manager's own.

- The proxy reaches the registry with this crate's client: full path validation against the system's roots (or the roots
  given), the name checked, revocation as configured, TLS 1.3 or 1.2. A failure is a 502 to the package manager, never a
  response. *Checked:* `a_host_whose_certificate_does_not_verify_is_never_passed_on`.
- *Residual:* this is pratique's verifier (`src/x509.rs`, `src/tls/`), the subject of the B-23 review.

### T3. Getting a package past the scanner

- **Encodings**: the proxy asks registries only for codings the scanner can undo (gzip, deflate, identity: the client's
  `Accept-Encoding` is cut down to those); `Inspected::decoded` undoes them and refuses any other. *Checked:*
  `the_scanner_refuses_inspects_and_answers_in_the_hosts_place`, `the_fields_of_a_connection_are_not_passed_on`.
- **Size**: a body the scanner asked to inspect is read whole, in memory up to `inspect_in_memory` and then into a file,
  up to `max_inspect`; past it, the client gets a 502: **never the body unread**. *Checked:*
  `large_bodies_are_inspected_from_a_file_and_too_large_ones_are_never_passed_on`.
- **Time of check and time of use**: an inspected body is sent from the very bytes inspected (memory, or the spool file:
  in a directory of the proxy's, 0700, the file 0600, made with `create_new`, removed once sent or refused).
- **Another name for the same host**: inside a tunnel, a request must be for the tunnel's host (its `Host` or
  `:authority`), or it is answered 421; the TLS name must be the CONNECT's. A request smuggled by framing cannot be made:
  requests are parsed strictly and made again. *Checked:* `inside_a_tunnel_only_its_host_and_none_of_the_connections_fields`.
- **Hosts the proxy does not intercept**: a mirror, a CDN, an IP address are tunnelled, unscanned, unless
  `Others::Refuse` is set (which a CI runner that must scan everything should set). A redirect from a registry to such a
  host is passed to the client, which then asks the proxy for that host: scanned if intercepted, tunnelled or refused if
  not.
- **Pass**: a response the scanner chose to pass unread is streamed as it comes. That is the scanner's decision.
- **What `Exchange::package()` says** is read from the URL alone, after its escapes: a PyPI name as PEP 508 has it, a
  version of letters, digits and `.+!_-`, a file name with no `/`, `\`, control character or leading dot, so that a
  scanner may put them in a path or a log; a URL that would give anything else is not a package's (`None`), which a
  scanner should not take as harmless for a file. *Checked:* `registry::tests`, the fuzz target `proxy_registry`.
- **A package manager's own configuration** can name another proxy or registry: `PIP_PROXY` and `npm_config_*` (which
  the variables set) beat `pip.conf` and `.npmrc`; a private registry or mirror is not intercepted unless it is added
  (`PROXY_CONFIGURATION.md`). *Checked:* `tools/proxy_interop.sh pip` (a `proxy` in `pip.conf`).

### T4. Others using the proxy

- It listens where it is told, `127.0.0.1` in the examples; another machine cannot reach it.
- `ProxyBuilder::credentials` makes it require `Proxy-Authorization` (compared in constant time) of every request: a random
  password for each run keeps other local users out (the variables carry it in the proxy's URL). *Checked:*
  `other_hosts_are_tunnelled_or_refused_and_credentials_are_asked_for`, `tools/proxy_interop.sh auth`.
- Tunnels go to the ports allowed alone (443 by default), and a plain `http://` request to port 80 or one of those, so it
  is not a relay to any service of the network. *Checked:* the same test, `plain_http_requests_are_sent_on_and_scanned`,
  and `tools/proxy_interop.sh tunnel`.
- *Residual:* without credentials, any local user can use it, and through its tunnels reach port 443 of hosts the user can
  reach, which they could reach themselves.

### T5. Exhausting the proxy

The runtime's limits (B-112) hold: connections in all and from one address, a TLS handshake, idle connections, request
heads and bodies against time, writes, quiet tunnels. Request bodies sent on are read whole first, up to
`max_request_body` (413 past it). *Residual:* inspections at once each hold up to `inspect_in_memory` in memory.

### T6. What passes through

- Registry credentials (`Authorization`) are sent on to the registry, as they must be, and the scanner sees them in
  `Exchange::headers`: a scanner must not log them.
- The proxy's event log has URLs (package names and versions), not header fields or bodies.
- The proxy's own fields (`Proxy-Authorization`) and the connection's (`Connection` and what it names, `TE`, `Upgrade`,
  `Keep-Alive`, `Transfer-Encoding`) are never sent on. *Checked:* `the_fields_of_a_connection_are_not_passed_on`.

### T7. Behind a gateway that inspects TLS (Zscaler, Netskope, a corporate proxy)

On a company's machine the proxy's own connections to the registries are re-signed by the company's gateway, with a
root the administrator installed. The proxy then checks the gateway's certificate, not the registry's: it can be no
stricter than the gateway, whose own check of the registry stands in for it. What the proxy does:

- It trusts the roots this machine trusts (`local_roots`): the system's CA bundle file, the operating system's own store
  (the macOS Keychain, the Windows certificate store), where device management installs the company's root, and the files
  that `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS` and the like name. A machine without the gateway's
  root anywhere gets 502s, never responses. *Checked:* `behind_a_gateway_that_inspects_tls`; `tools/proxy_interop.sh
  gateway`, where a second proxy plays the gateway and re-signs PyPI and a tunnelled host.
- The bundle it hands the programs has those roots too, so the hosts it tunnels, which the gateway re-signs, still verify
  for them; `NODE_EXTRA_CA_CERTS` names the bundle, not the proxy's CA alone, so that a company root an administrator
  had put there is kept.
- It goes through the proxy `HTTPS_PROXY` names in its own environment (not the programs': theirs names it), except for
  the hosts `NO_PROXY` names, with Basic credentials if the URL has some; it refuses to start when that is itself.
- *Residual:* an explicit proxy that wants NTLM or Kerberos is not supported (the gateways' agents, Zscaler Client
  Connector and the Netskope Client, steer traffic without one); nor are PAC files. A gateway's policy may block a
  registry, a file or the proxy itself: the proxy passes the gateway's answer on, or fails. Reading the macOS Keychain is
  tested on a Mac by `tools/native_check.sh`, not on every run.

## What it does not do

- **Enforce**: a program that does not honour `HTTPS_PROXY`, or is told another registry, is not scanned. Enforcement is
  for the network (a firewall that lets only the proxy out).
- **HTTP/3**: package managers do not use it; a client that did would go around the proxy over UDP.
- **Client certificates to a registry**: the proxy ends the client's TLS, so it cannot present the client's certificate;
  a registry that wants one must be tunnelled, not intercepted.
- **Java**: its KeyStore is not written (`keytool -importcert` adds `ca.pem`).
- **TLS 1.2 to the package manager**: the proxy's TLS server speaks TLS 1.3 alone (B-116); every package manager above
  speaks it.
- **Run for longer than its CA lives**: build a new proxy (a new CA) for each run, or at least each day.

## For the reviewer (B-23)

Read `src/proxy/ca.rs` (the certificates written: the name constraint's encoding, the leaves), `src/proxy/mod.rs` (the
CONNECT: what is intercepted, tunnelled, refused; `TunnelSocket`), `src/proxy/relay.rs` (the fields sent on, the 421, the
inspection that fails closed, the spool files), and `TunnelCert` (the name in the ClientHello). The claims to try to
break: T1's "no certificate for another name, from the proxy or a leaked key that verifies", T2's "nothing unverified is
passed on", T3's "nothing refused, and nothing too large to inspect, reaches the client".
