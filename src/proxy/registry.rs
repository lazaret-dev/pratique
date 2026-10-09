//! What a request to a package registry is for: the package, and whether it asks for the package's metadata or for one
//! of its files (B-78). For the scanner, which decides by package; read from the URL alone.
//!
//! | registry | metadata | files |
//! |----------|----------|-------|
//! | npm (`registry.npmjs.org`, `registry.yarnpkg.com`) | `/name`, `/@scope%2fname` (or `/@scope/name`), `/name/1.2.3` | `/name/-/name-1.2.3.tgz`, `/@scope/name/-/name-1.2.3.tgz` |
//! | PyPI (`pypi.org`, `test.pypi.org`) | `/simple/name/`, `/pypi/name/json`, `/pypi/name/1.2.3/json` | |
//! | PyPI's files (`files.pythonhosted.org`) | `....whl.metadata` (PEP 658) | `/packages/../name-1.2.3-py3-none-any.whl`, `/packages/../name-1.2.3.tar.gz` |
//!
//! PyPI names come back normalized as PEP 503 says (lower case, each run of `-`, `_` and `.` one `-`); npm names as they
//! are. A version is only ever letters, digits and `.+!_-` (npm's semver and PyPI's PEP 440 need no more), and a file name
//! has no `/`, `\`, control character or leading dot, whatever the URL's escapes said: both are safe to put in a path
//! or a log. A URL that would give anything else is not read as a package's (`None`).

/// Which registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Ecosystem {
    Npm,
    PyPI,
}

/// What of the package is asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// What the registry says of the package (its versions and their files), or of one version.
    Metadata,
    /// A file of the package: a tarball, a wheel, an sdist.
    Artifact,
}

/// A package a request is for.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Package {
    pub ecosystem: Ecosystem,
    pub name: String,
    /// The version, when the URL names one.
    pub version: Option<String>,
    pub kind: Kind,
    /// The file's name, for a file (and PEP 658 metadata).
    pub file: Option<String>,
}

impl Package {
    pub fn is_artifact(&self) -> bool {
        self.kind == Kind::Artifact
    }
}

/// The package a request to `host` for `target` (a path and query) is for, if `host` is a registry this module knows and
/// the path one of its forms.
pub fn package(host: &str, target: &str) -> Option<Package> {
    let path = target.split(['?', '#']).next().unwrap_or("");
    match host.trim_end_matches('.').to_ascii_lowercase().as_str() {
        "registry.npmjs.org" | "registry.yarnpkg.com" => npm(path),
        "pypi.org" | "test.pypi.org" => pypi_index(path),
        "files.pythonhosted.org" | "test-files.pythonhosted.org" => pypi_file(path),
        _ => None,
    }
}

/// `%XX` decoded; `None` for a bad escape or bytes that are not UTF-8.
fn percent_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// An npm package name: `name` or `@scope/name`, each part of URL-safe characters, at most 214 in all.
fn npm_name(name: &str) -> bool {
    let part = |p: &str| !p.is_empty() && !p.starts_with('.') && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~!*'()".contains(&b));
    name.len() <= 214
        && match name.strip_prefix('@') {
            Some(scoped) => scoped.split_once('/').is_some_and(|(s, n)| part(s) && part(n)),
            None => part(name),
        }
}

/// A version as registries write them (npm's semver, PyPI's PEP 440, a dist-tag): letters, digits and `.+!_-`.
fn version_ok(v: &str) -> bool {
    !v.is_empty() && v.len() <= 128 && v.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+!-".contains(&b))
}

/// A file name that is one name and nothing more: printable ASCII, no `/` or `\`, not hidden, not `..`.
fn file_ok(f: &str) -> bool {
    !f.is_empty() && f.len() <= 255 && !f.starts_with('.') && f.bytes().all(|b| b.is_ascii_graphic() && b != b'/' && b != b'\\')
}

fn npm(path: &str) -> Option<Package> {
    let p = path.strip_prefix('/')?;
    if p.is_empty() || p.starts_with("-/") {
        return None; // the registry's own endpoints: search, audit, login
    }
    let segs: Vec<String> = p.split('/').map(percent_decode).collect::<Option<_>>()?;
    let (name, rest) = if segs[0].starts_with('@') && !segs[0].contains('/') {
        (format!("{}/{}", segs[0], segs.get(1)?), &segs[2..])
    } else {
        (segs[0].clone(), &segs[1..])
    };
    if !npm_name(&name) {
        return None;
    }
    let base = name.rsplit('/').next().unwrap_or(&name);
    let package = |version: Option<String>, kind, file: Option<String>| Some(Package { ecosystem: Ecosystem::Npm, name: name.clone(), version, kind, file });
    match rest {
        [] => package(None, Kind::Metadata, None),
        [v] if v.is_empty() => package(None, Kind::Metadata, None),
        [v] if version_ok(v) => package(Some(v.clone()), Kind::Metadata, None),
        [dash, file] if dash == "-" => {
            let version = file.strip_prefix(base)?.strip_prefix('-')?.strip_suffix(".tgz")?;
            (version_ok(version) && file_ok(file)).then_some(())?;
            package(Some(version.to_string()), Kind::Artifact, Some(file.clone()))
        }
        _ => None,
    }
}

/// PEP 503's normal form of a Python project name.
pub fn pypi_normalize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut sep = false;
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            sep = true;
        } else {
            if sep && !out.is_empty() {
                out.push('-');
            }
            sep = false;
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

/// A Python project name as PEP 508 has it: letters and digits, with `-`, `_` and `.` between them.
fn pypi_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 200
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(c))
}

fn pypi_index(path: &str) -> Option<Package> {
    let segs: Vec<&str> = path.strip_prefix('/')?.split('/').collect();
    let (name, version) = match segs.as_slice() {
        ["simple", name] | ["simple", name, ""] => (*name, None),
        ["pypi", name, "json"] | ["pypi", name, "json", ""] => (*name, None),
        ["pypi", name, version, "json"] | ["pypi", name, version, "json", ""] => (*name, Some(version.to_string())),
        _ => return None,
    };
    let name = percent_decode(name)?;
    if version.as_deref().is_some_and(|v| !version_ok(v)) {
        return None;
    }
    pypi_name(&name).then(|| Package { ecosystem: Ecosystem::PyPI, name: pypi_normalize(&name), version, kind: Kind::Metadata, file: None })
}

fn pypi_file(path: &str) -> Option<Package> {
    let rest = path.strip_prefix("/packages/")?;
    let file = percent_decode(rest.rsplit('/').next()?)?;
    if !file_ok(&file) {
        return None;
    }
    let (stem, kind) = match file.strip_suffix(".metadata") {
        Some(f) => (f, Kind::Metadata),
        None => (file.as_str(), Kind::Artifact),
    };
    let (name, version) = if let Some(wheel) = stem.strip_suffix(".whl") {
        // {name}-{version}(-{build})?-{python}-{abi}-{platform}.whl
        let parts: Vec<&str> = wheel.split('-').collect();
        if parts.len() < 5 {
            return None;
        }
        (parts[0].to_string(), parts[1].to_string())
    } else {
        let sdist = [".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".zip", ".tar"].iter().find_map(|ext| stem.strip_suffix(ext))?;
        // {name}-{version}: the version begins after the last hyphen that a digit follows
        let at = sdist.char_indices().filter(|&(i, c)| c == '-' && sdist[i + 1..].starts_with(|d: char| d.is_ascii_digit())).map(|(i, _)| i).next_back()?;
        (sdist[..at].to_string(), sdist[at + 1..].to_string())
    };
    (pypi_name(&name) && version_ok(&version)).then(|| Package { ecosystem: Ecosystem::PyPI, name: pypi_normalize(&name), version: Some(version), kind, file: Some(file.clone()) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(e: Ecosystem, name: &str, version: Option<&str>, kind: Kind) -> Package {
        Package { ecosystem: e, name: name.into(), version: version.map(str::to_string), kind, file: None }
    }

    fn without_file(p: Option<Package>) -> Option<Package> {
        p.map(|p| Package { file: None, ..p })
    }

    #[test]
    fn npm_urls() {
        let n = |path: &str| without_file(package("registry.npmjs.org", path));
        assert_eq!(n("/left-pad"), Some(p(Ecosystem::Npm, "left-pad", None, Kind::Metadata)));
        assert_eq!(n("/left-pad/"), Some(p(Ecosystem::Npm, "left-pad", None, Kind::Metadata)));
        assert_eq!(n("/left-pad/1.3.0"), Some(p(Ecosystem::Npm, "left-pad", Some("1.3.0"), Kind::Metadata)));
        assert_eq!(n("/left-pad/-/left-pad-1.3.0.tgz"), Some(p(Ecosystem::Npm, "left-pad", Some("1.3.0"), Kind::Artifact)));
        assert_eq!(n("/@types%2fnode"), Some(p(Ecosystem::Npm, "@types/node", None, Kind::Metadata)));
        assert_eq!(n("/@types%2Fnode?write=true"), Some(p(Ecosystem::Npm, "@types/node", None, Kind::Metadata)));
        assert_eq!(n("/@types/node"), Some(p(Ecosystem::Npm, "@types/node", None, Kind::Metadata)));
        assert_eq!(n("/@types/node/-/node-20.11.5.tgz"), Some(p(Ecosystem::Npm, "@types/node", Some("20.11.5"), Kind::Artifact)));
        assert_eq!(n("/a-b/-/a-b-1.0.0-beta.1.tgz"), Some(p(Ecosystem::Npm, "a-b", Some("1.0.0-beta.1"), Kind::Artifact)));
        assert_eq!(package("registry.yarnpkg.com", "/react/-/react-18.2.0.tgz").unwrap().file.as_deref(), Some("react-18.2.0.tgz"));
        for bad in ["/", "/-/v1/search?text=x", "/-/npm/v1/security/advisories/bulk", "/a/-/b-1.0.0.tgz", "/a/-/a-.tgz", "/a/b/c", "/%zz", "/.hidden", "/@scope"] {
            assert_eq!(n(bad), None, "{bad}");
        }
        assert_eq!(package("example.com", "/left-pad"), None);
    }

    #[test]
    fn pypi_urls() {
        let i = |path: &str| without_file(package("pypi.org", path));
        assert_eq!(i("/simple/Requests/"), Some(p(Ecosystem::PyPI, "requests", None, Kind::Metadata)));
        assert_eq!(i("/simple/zope.interface/"), Some(p(Ecosystem::PyPI, "zope-interface", None, Kind::Metadata)));
        assert_eq!(i("/pypi/Django/json"), Some(p(Ecosystem::PyPI, "django", None, Kind::Metadata)));
        assert_eq!(i("/pypi/django/5.0/json"), Some(p(Ecosystem::PyPI, "django", Some("5.0"), Kind::Metadata)));
        assert_eq!(i("/simple/"), None);
        assert_eq!(i("/project/requests/"), None);
        let f = |file: &str| package("files.pythonhosted.org", &format!("/packages/f9/9b/335f9764261e915ed497fcdeb11df5dfd6f7bf257d4a6a2a686d80da4d54/{file}"));
        let wheel = f("requests-2.32.3-py3-none-any.whl").unwrap();
        assert_eq!((wheel.name.as_str(), wheel.version.as_deref(), wheel.kind), ("requests", Some("2.32.3"), Kind::Artifact));
        assert_eq!(wheel.file.as_deref(), Some("requests-2.32.3-py3-none-any.whl"));
        let w = f("typing_extensions-4.12.2-py3-none-any.whl").unwrap();
        assert_eq!((w.name.as_str(), w.version.as_deref()), ("typing-extensions", Some("4.12.2")));
        let w = f("numpy-2.1.0-1-cp312-cp312-manylinux_2_17_x86_64.whl").unwrap();
        assert_eq!((w.name.as_str(), w.version.as_deref()), ("numpy", Some("2.1.0")));
        let s = f("python-dateutil-2.9.0.post0.tar.gz").unwrap();
        assert_eq!((s.name.as_str(), s.version.as_deref(), s.kind), ("python-dateutil", Some("2.9.0.post0"), Kind::Artifact));
        let m = f("requests-2.32.3-py3-none-any.whl.metadata").unwrap();
        assert_eq!((m.name.as_str(), m.kind), ("requests", Kind::Metadata));
        assert_eq!(f("six-1.16.0.zip").unwrap().version.as_deref(), Some("1.16.0"));
        for bad in ["README", "noversion.tar.gz", "a-b.whl", "x-1.0.exe"] {
            assert_eq!(f(bad), None, "{bad}");
        }
        assert_eq!(package("files.pythonhosted.org", "/elsewhere/six-1.16.0.tar.gz"), None);
        assert_eq!(pypi_normalize("Foo__Bar..baz-"), "foo-bar-baz");
        assert_eq!(f("zope.interface-6.0-cp312-cp312-win_amd64.whl").unwrap().name, "zope-interface");
        assert_eq!(f("pkg-1.0+local.7-py3-none-any.whl").unwrap().version.as_deref(), Some("1.0+local.7"));
    }

    #[test]
    fn what_the_fuzzer_found_is_not_read_as_a_package() {
        // proxy_registry (B-114): a name of separators alone normalized to nothing, an empty version, and escapes that
        // put a path into a file name or a version
        for (host, target) in [
            ("pypi.org", "/simple/---/"),
            ("pypi.org", "/simple/_a/"),
            ("pypi.org", "/simple/a./"),
            ("pypi.org", "/pypi/six//json"),
            ("pypi.org", "/pypi/six/1.0%2f..%2f..%2fx/json"),
            ("files.pythonhosted.org", "/packages/aa/six-1.0%2f..%2f..%2fevil.tar.gz"),
            ("files.pythonhosted.org", "/packages/aa/..%5cx-1.0.tar.gz"),
            ("files.pythonhosted.org", "/packages/aa/six-1.0%0a.tar.gz"),
            ("files.pythonhosted.org", "/packages/aa/six-1.0%00-py3-none-any.whl"),
            ("registry.npmjs.org", "/a/-/a-1.0%2f..%2f..%2fx.tgz"),
            ("registry.npmjs.org", "/a/1.0%2fx"),
            ("registry.npmjs.org", "/a/1.0%0a"),
        ] {
            assert_eq!(package(host, target), None, "{host}{target}");
        }
    }
}
