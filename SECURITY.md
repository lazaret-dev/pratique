# Security policy

## Reporting a vulnerability

Please report security problems privately, through GitHub: the repository's **Security** tab, **Report a
vulnerability** (<https://github.com/lazaret-dev/pratique/security/advisories/new>). Please do not open a public
issue or pull request for one.

The most useful report says which commit it is about, gives the input (a certificate, a byte string, a fuzz input or a
failing test), and says what the library does with it and what it should do. A reproducer helps most, but a report
without one is welcome too.

The report stays private while it is looked at and fixed. The fix and an advisory are published together, crediting
the reporter unless they would rather not be named.

## What counts

The worst failure is accepting what should be refused:

- a forged signature;
- a certificate chain that does not reach a trusted root;
- a transparency-log proof for a record that is not in the log;
- an attestation whose signer is not who it says.

`SECURITY_REVIEW.md` (section 5) lists the claims the verification code makes.

These are security problems too:

- a panic, or unbounded memory or time, on hostile input;
- a timing leak of a secret in the constant-time code;
- a way around the egress policy: host rules, URL limits, the credentials given to each hop.

## Status

pratique is hand-written cryptography and parsing that no one outside the project has reviewed yet (README, "Security
warning"). `SECURITY_REVIEW.md` is the brief for that review.

The TLS server and the signing code behind the `server` feature exist for tests and tools only and are not for
production; reports about them are still welcome.

## Versions

There are no releases yet: fixes go to `main`. pratique is built into Lazaret (<https://github.com/lazaret-dev/lazaret>),
whose releases take them.
