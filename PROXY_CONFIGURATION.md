# Configuring the scanning proxy

How Lazaret should run `pratique::proxy` and point package managers at it, on each kind of network: a direct
connection, an explicit corporate proxy, a TLS-inspecting gateway (Zscaler, Netskope), a PAC file, CI runners and
containers. It is written to be moved into Lazaret's own documentation. What the proxy protects and how is in
`PROXY_THREAT_MODEL.md`; the API is documented in `src/proxy/`.

**Not to be relied on yet.** BACKLOG B-78 keeps the proxy behind the independent review of B-23.

## How it fits together

There are two sides, and each one has its own settings:

```
pip, npm, uv, ...  ──(the variables Lazaret sets for them)──▶  the proxy  ──(Lazaret's own environment)──▶  the internet
   trust the proxy's CA through the bundle                       trusts the machine's roots, goes through the
                                                                  corporate proxy if HTTPS_PROXY names one
```

- **Toward the package manager**: Lazaret starts the proxy and runs the package manager with the variables from
  `Proxy::client_env`. These name the proxy and a bundle of CA certificates: the machine's roots plus the proxy's CA.
  Lazaret sets them for that child process only, never in its own environment and never in a shell profile.
- **Toward the internet**: when it is built, the proxy reads **Lazaret's own** environment. It trusts the roots this
  machine trusts (`proxy::local_roots`), and it goes through the proxy that Lazaret's `HTTPS_PROXY` names, if there is
  one (except for the hosts `NO_PROXY` names).

## The minimum

```rust
use pratique::proxy::{Others, Proxy};
use std::process::Command;
use std::time::Duration;

let proxy = Proxy::builder(scanner)                 // Lazaret's Scanner
    .credentials("lazaret", &password)              // a random password per run: other local users stay out
    .others(Others::Tunnel)                         // Others::Refuse on CI (below)
    .events(|e| log_event(e))                       // keep the log: it is how failures are diagnosed
    .build()?;                                      // reads HTTPS_PROXY, NO_PROXY and the CA variables now
let server = proxy.start("127.0.0.1:0")?;           // a free port, on this machine alone
let files = proxy.write_trust_files(&run_dir)?;     // ca.pem and bundle.pem; the directory becomes 0700
let status = Command::new("pip")
    .args(["install", "-r", "requirements.txt"])
    .envs(proxy.client_env(server.local_addrs()[0], &files))
    .status()?;
server.shutdown(Duration::from_secs(5));
```

- **Start a new proxy for each run.** Its CA is created in memory, lasts a day, and is gone when the proxy is dropped.
  Never add it to the system's or the user's trust store.
- **`start` refuses** if Lazaret's own `HTTPS_PROXY` names the proxy itself. That happens when Lazaret runs inside a
  shell that already has the variables, for example a nested run. Clear the variable, or give the builder a client
  (see "Your own client").
- `examples/scan_proxy` is the same thing on the command line, for trying a network by hand:
  `cargo run --release --features server --example scan_proxy -- block=left-pad -- npm install left-pad`.

### The variables

`client_env` returns these, all pointing at the proxy's URL (with the credentials in it) or at `bundle.pem`:

| variable | read by |
|----------|---------|
| `HTTPS_PROXY`, `HTTP_PROXY` and the lower-case forms | pip, uv, Poetry, requests, urllib, npm, pnpm, Yarn 1, curl, Go, git |
| `PIP_PROXY` | pip, ahead of a `proxy =` in `pip.conf` (which would otherwise beat `HTTPS_PROXY`) |
| `npm_config_https_proxy`, `npm_config_proxy` | npm, pnpm, Yarn 1, ahead of an `.npmrc` |
| `YARN_HTTPS_PROXY`, `YARN_HTTP_PROXY` | Yarn 2 and later, ahead of `.yarnrc.yml` |
| `NO_PROXY`, `no_proxy`, `npm_config_noproxy` | all of the above. Set to `localhost,127.0.0.1,::1` alone, so an `.npmrc` or a user's `NO_PROXY` can't let a registry go around the proxy |
| `NODE_EXTRA_CA_CERTS` | Node.js (npm, pnpm, Yarn): added to Node's own roots |
| `SSL_CERT_FILE` | OpenSSL (Python's `ssl`, curl), uv, Go on Linux |
| `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO` | requests and Poetry, pip, curl, git |

`tools/proxy_interop.sh` tests pip, uv, npm, Yarn 1, pnpm, curl, Python's urllib and Go against the real registries.
Yarn 2+, Bun and Poetry are not tested.

## Which network is this?

The question that matters is what happens to an HTTPS connection to `pypi.org` from this machine. These commands show
it:

```sh
# who signed pypi.org's certificate, as this machine sees it: a public CA (direct), or a company's or a gateway's root
openssl s_client -connect pypi.org:443 -servername pypi.org </dev/null 2>/dev/null | openssl x509 -noout -issuer
# the proxy settings programs can see
env | grep -i _proxy
python3 -c 'import urllib.request; print(urllib.request.getproxies())'   # includes macOS's and Windows's static settings
scutil --proxy                                     # macOS: HTTPSProxy, ProxyAutoConfigURLString (a PAC file)
netsh winhttp show proxy                           # Windows (and Internet Options for the user's own settings)
```

| what you see | the network | what to do |
|--------------|-------------|------------|
| a public CA (DigiCert, Let's Encrypt, ...) and no proxy variables | direct | nothing |
| `HTTPS_PROXY` is set in the environment | explicit proxy | nothing: the proxy goes through it ([below](#an-explicit-corporate-proxy)) |
| `Zscaler Root CA`, `Netskope`, or a company's own CA | a gateway that inspects TLS | usually nothing ([below](#a-gateway-that-inspects-tls-zscaler-netskope)) |
| a proxy in `scutil --proxy` or Internet Options, but not in the environment | a system proxy | nothing: the proxy reads it ([below](#a-system-proxy-or-a-pac-file)) |
| `ProxyAutoConfigURLString`, `AutoConfigURL`, "Automatically detect settings" | a PAC file | reported, not followed: set `HTTPS_PROXY` ([below](#a-system-proxy-or-a-pac-file)) |

### An explicit corporate proxy

`HTTPS_PROXY=http://proxy.corp:8080` in Lazaret's environment is enough. The proxy then sends both its own
connections to the registries and the tunnels it makes for other hosts through that proxy. It keeps out the hosts in
`NO_PROXY` (internal ones), which it reaches directly.

- **Basic credentials** in the URL work: `http://user:password@proxy.corp:8080`, percent-encoded.
- **NTLM and Kerberos (Negotiate) are not supported.** A proxy that answers `407` with
  `Proxy-Authenticate: Negotiate` or `NTLM` will make every registry request fail (a `Fail` event with the
  proxy's 407). The
  usual fix is a local helper that does that authentication, such as Px or Cntlm, run by the user, with
  Lazaret's `HTTPS_PROXY` pointing at it. pip and npm already need the same helper on such a network.

### A gateway that inspects TLS (Zscaler, Netskope)

The gateway's agent (Zscaler Client Connector, the Netskope Client) captures traffic below the applications, then
signs every site again with the company's root. No proxy variable is involved, so there's nothing to chain through.
The only question is trust: the proxy has to trust that root on its way to the registries, and it does when the root
is in any of these places:

- the operating system's store: the **macOS Keychain** (the System keychain, where device management installs it) or
  the **Windows certificate store**;
- the system's CA bundle file (`/etc/ssl/certs/ca-certificates.crt` and the other usual places);
- a file named by `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `PIP_CERT`,
  `GIT_SSL_CAINFO` or `AWS_CA_BUNDLE` in Lazaret's environment. IT departments often hand the root to developers this
  way.

The bundle the package managers get includes those roots as well. The hosts the proxy tunnels, which the gateway also
signs again, still verify for them.

- **Symptom of a missing root**: every intercepted request is a `502`, with a `Fail` event that says the certificate
  did not verify. Fix: find the company root (the issuer from `openssl s_client` above; IT usually publishes it) and
  set `SSL_CERT_FILE` (or any of the variables above) to a PEM file with it **in Lazaret's environment**.
- **The gateway's policy** can block a registry, a package or the proxy's connections. The proxy passes the
  gateway's answer on, or fails; it never goes around the gateway.
- **Checking the Keychain path without a gateway**: `tools/gateway_check_mac.sh`, run in Terminal on any Mac, plays the
  gateway with a second `scan_proxy` that re-signs PyPI. It puts that gateway's root in the Keychain for the length of
  the run and nowhere else, and checks that pip gets a package through both proxies. Before the root is added and after
  it is taken out, the same run must fail with a `502`. `--admin` puts the root where device management does (the
  System keychain, administrator's trust settings) instead of your login keychain. It passed on an M5 Mac both ways
  (2026-10-09). On a Mac behind a real Zscaler or Netskope, `scan_proxy -- pip download six` is the
  check.

### A system proxy, or a PAC file

The proxy's default client reads the environment first and, when the environment says nothing about proxies (none of
`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, `NO_PROXY` is set, in either case), the operating system's settings
(`Client::proxy_from_system`, B-117). That is the order Python's urllib keeps, so the proxy goes where pip would.

- **A static system proxy** (set in System Settings or Internet Options, or by device management) is used:
  - **macOS**: the "Secure web proxy (HTTPS)" of the network in use, and its "Bypass proxy settings for these hosts &
    domains" (globs such as `*.local`, address prefixes such as `169.254/16`) and "Exclude simple hostnames";
  - **Windows**: `ProxyServer` under `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` when
    `ProxyEnable` is set (one `host:port` for every scheme, or the `https=` entry of a list), and `ProxyOverride`
    (with `<local>`).

  A web proxy for plain http alone is not used for https, as in Python. The settings are read once, when the proxy is
  built; a change made later needs a new proxy. `Proxy::upstream_notes()` says which proxy was taken from them, for
  Lazaret's log. `localhost` and loopback addresses always go direct.
- **A PAC file** (a `FindProxyForURL` script, often found through WPAD) is **reported and not followed**:
  `upstream_notes()` says the settings name one (its URL without the query) and that it is not followed, and the same
  for "Automatically detect settings" and a SOCKS proxy. pip, uv and npm don't read PAC files either. On such networks
  developers already set `HTTPS_PROXY` by hand for those tools, and the proxy picks up the same setting. To find the
  value, see which proxy the PAC file gives for `pypi.org` (open the file and read it, or ask IT) and set it in
  Lazaret's environment. Lazaret should show the notes to the user when the run fails with "connect" errors. Running
  the PAC file through the operating system's own evaluator (WinHTTP, CFNetwork) is possible later if users need it;
  NTLM or Kerberos would probably have to come with it.
- **Checking it on a Mac without such a network**: `tools/system_proxy_check_mac.sh`, run in Terminal, plays the
  company's proxy with a second `scan_proxy`, sets it as the secure web proxy of the network in use for the length of
  the run (with `sudo networksetup`, put back when it ends), and checks that pip gets a package through both, that a
  host in the bypass list goes direct, that an environment that says anything takes the settings out of play, and that
  a PAC file is reported. It refuses to run where a secure web proxy or a PAC file is set already. It passed on an M5
  Mac (2026-10-09), 5 of 5. `networksetup` cannot empty the server field, so after the run the secure web proxy is off
  and still shows `127.0.0.1` and the check's port; clear it in System Settings if you like (it does nothing while off).
- **A rule for the proxy**: `Client::allowed_proxies(HostRules::new(["proxy.corp.example:3128"])?)` on the proxy's
  client (see "Your own client") refuses a proxy that is not in it, however it was named; a request is then refused,
  never sent direct. Use it when the corporate proxy is known, so that a variable set by something else cannot send
  the proxy's connections elsewhere.

### CI runners

- **`Others::Refuse`**: hosts the proxy doesn't intercept get a `403` instead of an unscanned tunnel. Nothing reaches
  the build without being scanned or refused. Add the hosts the build really needs to `intercept`, or accept them
  as tunnels on purpose.
- **Make it enforced, not voluntary.** A program that ignores `HTTPS_PROXY` isn't scanned. On a runner whose network
  you control, let only the proxy reach the internet (a firewall or the runner's egress settings). Then a program
  that tries to go around it fails instead of slipping through.
- Credentials are still worth having on a shared runner.

### Containers (`docker build`, devcontainers)

A proxy on `127.0.0.1` of the host can't be reached from inside a container.

- **Listen on the address the containers can reach**: the Docker bridge (`172.17.0.1`), or `host.docker.internal`
  where it exists. Always use credentials then, since other containers can reach that address too.
- **Write the variables with that address.** `client_env` would give `127.0.0.1` for `0.0.0.0`.
- **Mount `bundle.pem` into the container** at the path the variables name.
- For `docker build`, pass the variables as build arguments (`--build-arg HTTPS_PROXY=...`; Docker treats the proxy
  variables specially and keeps them out of the image's history).

## Private registries and mirrors

**The most common way packages go unscanned in a company.** Artifactory, Nexus, devpi, Verdaccio, GitHub Packages and
the like aren't in `PACKAGE_REGISTRIES`. A package manager configured to use one gets its tunnel, and the proxy sees
nothing inside it. The configuration can come from any of these:

- `pip.conf` or `PIP_INDEX_URL`
- `uv.toml`, `[tool.uv]` or `UV_INDEX_URL`
- `.npmrc` `registry=`
- `.yarnrc.yml` `npmRegistryServer`

Lazaret should:

1. **Find the registry in effect**: `pip config list`, `npm config get registry`, `pnpm config get registry`,
   `yarn config get npmRegistryServer`, and the project's own files.
2. **Intercept it**: `ProxyBuilder::intercept(&[...PACKAGE_REGISTRIES, "artifactory.corp"])`. Its name goes into the CA's
   name constraint, so the CA is valid for that host too.
3. **Read its URLs itself.** `Exchange::package()` only knows the public URL forms (`proxy::registry`). On a mirror's
   paths, such as `/api/pypi/pypi-remote/simple/...` or `/artifactory/api/npm/...`, it returns `None`, so the scanner
   has to map the mirror's layout to a package. The public forms usually sit under a prefix there, so stripping the
   prefix and calling `proxy::registry::package` with the public host often works.
4. **Treat `None` for an intercepted host with care.** A file request that can't be tied to a package is safer
   inspected (`BodyAction::Inspect`) or blocked than passed on unread.

The mirror's certificate must verify for the proxy: an internal CA has to be in the machine's store or in one of the
variables above, as for a gateway.

## Your own client

When the defaults don't fit (a different set of roots, a rule for the proxy, other timeouts), give the builder its own
client. It replaces both defaults, so set them again:

```rust
use pratique::http::{Client, HostRules};
use pratique::proxy::local_roots;
use pratique::tls::ClientConfig;

let client = Client::with_tls_config(ClientConfig::new(local_roots()?))   // or a TrustStore of your own
    .proxy_from_system()                                                  // or .proxy(url)?, .proxy_from_env(), or no proxy
    .allowed_proxies(HostRules::new(["proxy.corp:8080"])?);               // optional: the proxies it may use
let proxy = Proxy::builder(scanner).client(client).build()?;
```

The proxy turns off redirects, decoding and the body limit on that client. A client given this way also skips the
`start` check for a proxy that names itself (the default client's check covers `HTTPS_PROXY` and the system's setting).

## When it doesn't work

| symptom | likely cause | what to do |
|---------|--------------|------------|
| every intercepted request is a `502`, `Fail` "certificate" events | the proxy doesn't trust the gateway's or the mirror's root | put the root in `SSL_CERT_FILE` (or the like) in Lazaret's environment |
| every request a `502` or a timeout, `Fail` "connect" events | direct connections are blocked, and the proxy doesn't know the corporate proxy (a PAC file, or a proxy variable that takes the system's setting out of play) | look at `upstream_notes()`; set `HTTPS_PROXY` for Lazaret ([above](#a-system-proxy-or-a-pac-file)) |
| `Fail` events "proxy not allowed" | the client's `allowed_proxies` rule does not name the proxy that was found | add it to the rule, or find who set the variable |
| `Fail` events naming a `407` | the corporate proxy wants credentials, or NTLM or Kerberos | Basic: put them in the URL; NTLM or Kerberos: Px or Cntlm |
| the package manager: "certificate verify failed", "self-signed certificate in chain" | it isn't using the bundle: a config file names other CAs (`.npmrc` `cafile=` or `ca=`, `pip.conf` `cert=` is overridden by `PIP_CERT`), or it keeps its own (Java) | set its own CA option to `bundle.pem` for the run (`npm_config_cafile`), or remove the config entry |
| the package manager: `407` from the proxy | a tool that doesn't take credentials from the proxy URL | turn credentials off for that run, or set the tool's own proxy credentials |
| nothing is scanned, but installs work | a mirror the proxy doesn't intercept, or a tool that ignores the variables | see "Private registries and mirrors"; on CI, `Others::Refuse` and a firewall |
| `start` fails: "names this proxy itself" | Lazaret's own environment (or the system's setting) already points at a proxy of Lazaret's | clear `HTTPS_PROXY` for Lazaret, or pass a client |
| `413` on a publish | a request body over `max_request_body` (256 MiB) | raise it |

The event log (`ProxyBuilder::events`) has the host or URL, the action, the status and the reason. Log it at least
when a run fails.

## Not supported

These are deliberate, or left for later:

- **NTLM or Kerberos** to a corporate proxy, and **PAC files** (reported, not followed): see above.
- **Clients that speak only TLS 1.2**: the proxy's TLS server is TLS 1.3 only (B-116). Every package manager above
  speaks TLS 1.3.
- **HTTP/3**: package managers don't use it.
- **Java**: its KeyStore isn't written. Use `keytool -importcert` with `ca.pem` into a KeyStore made for the run.
- **Client certificates to a registry**: such a registry must be tunnelled, not intercepted.
- **Programs that ignore the proxy variables**: only the network can enforce this (see "CI runners").
