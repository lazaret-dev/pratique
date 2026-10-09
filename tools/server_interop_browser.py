"""Loads pages from pratique's TLS server in headless Chromium (Playwright), for tools/server_interop.sh.

    python3 tools/server_interop_browser.py URL EXPECTED_BYTES [URL EXPECTED_BYTES ...]

The root certificate must already be in the NSS database under $HOME/.pki/nssdb (the shell script makes a
throwaway $HOME for that), so Chromium verifies the server as it would any other: no flag that turns
checking off. Prints one line per page, `ok PROTOCOL BYTES` or `error MESSAGE`, and exits 1 if any page
failed or came back with the wrong length.
"""

import sys

from playwright.sync_api import Error, sync_playwright


def main() -> int:
    args = sys.argv[1:]
    pages = list(zip(args[0::2], (int(n) for n in args[1::2])))
    failed = 0
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for url, want in pages:
            # a fresh context per page, so each one is a new connection and a full handshake
            context = browser.new_context()
            page = context.new_page()
            try:
                response = page.goto(url, timeout=20_000)
                body = response.body() if response else b""
                protocol = page.evaluate("performance.getEntriesByType('navigation')[0].nextHopProtocol")
                status = response.status if response else 0
                if status == 200 and len(body) == want:
                    print(f"ok {protocol} {len(body)}")
                else:
                    print(f"error status {status}, {len(body)} bytes, {protocol}")
                    failed = 1
            except Error as e:
                print("error " + str(e).splitlines()[0])
                failed = 1
            context.close()
        browser.close()
    return failed


if __name__ == "__main__":
    sys.exit(main())
