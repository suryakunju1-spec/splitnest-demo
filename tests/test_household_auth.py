import glob
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request


REPO_ROOT = Path(__file__).resolve().parent.parent


def find_node_binary() -> str:
    found = shutil.which("node")
    if found:
        return found
    nvm_candidates = sorted(glob.glob(str(Path.home() / ".nvm/versions/node/*/bin/node")))
    if nvm_candidates:
        return nvm_candidates[-1]
    raise RuntimeError("Could not locate node binary")


def find_playwright_python() -> str | None:
    candidates = [
        sys.executable,
        str(Path.home() / ".pyenv/shims/python3"),
        "/opt/jules/playwright/bin/python",
        shutil.which("python3") or "",
    ]
    for candidate in candidates:
        if not candidate or not os.path.exists(candidate):
            continue
        res = subprocess.run(
            [candidate, "-c", "import playwright.sync_api"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if res.returncode == 0:
            return candidate
    return None


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def launch_chromium(playwright):
    try:
        return playwright.chromium.launch(headless=True, args=["--no-sandbox"])
    except Exception:
        return playwright.chromium.launch(
            headless=True,
            executable_path="/usr/bin/google-chrome",
            args=["--no-sandbox"],
        )


def start_server(session_ttl_ms: int = 86_400_000):
    port = get_free_port()
    env = os.environ.copy()
    env["PORT"] = str(port)
    env["HOST"] = "127.0.0.1"
    env["SESSION_TTL_MS"] = str(session_ttl_ms)
    proc = subprocess.Popen(
        [find_node_binary(), str(REPO_ROOT / "server.js")],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 10.0
    while time.time() < deadline:
        if proc.poll() is not None:
            out, err = proc.communicate(timeout=2)
            raise RuntimeError(f"Server exited early ({proc.returncode}): {out}\n{err}")
        try:
            with urllib.request.urlopen(f"{base_url}/", timeout=1) as resp:
                if resp.status == 200:
                    return proc, base_url
        except Exception:
            time.sleep(0.05)
    stop_server(proc)
    raise TimeoutError("Timed out waiting for SplitNest server to listen")


def stop_server(proc: subprocess.Popen):
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
    finally:
        if proc.stdout:
            proc.stdout.close()
        if proc.stderr:
            proc.stderr.close()


def http_json(url: str, method: str = "GET", payload=None, cookie: str | None = None):
    headers = {}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, dict(resp.headers.items()), json.loads(raw) if raw else None
    except urllib.error.HTTPError as err:
        raw = err.read().decode("utf-8")
        parsed = None
        if raw:
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = raw
        return err.code, dict(err.headers.items()), parsed


def extract_cookie_pair(headers: dict) -> str:
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            return v.split(";", 1)[0]
    raise AssertionError(f"Missing Set-Cookie header in {headers}")


class HouseholdLedgerAuthorizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_proc, cls.base_url = start_server()

    @classmethod
    def tearDownClass(cls):
        stop_server(cls.server_proc)

    def test_01_static_households_json_is_not_publicly_accessible(self):
        # Bypass check #1: Direct unauthenticated request to /data/households.json must return 401, 403, or 404
        req = urllib.request.Request(f"{self.base_url}/data/households.json", method="GET")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=3)
        self.assertIn(ctx.exception.code, (401, 403, 404))

        # Private server files must also be inaccessible over HTTP
        for private_path in ("/server/private/households.json", "/server/private/users.json", "/server.js"):
            req_priv = urllib.request.Request(f"{self.base_url}{private_path}", method="GET")
            with self.assertRaises(urllib.error.HTTPError) as priv_ctx:
                urllib.request.urlopen(req_priv, timeout=3)
            self.assertIn(priv_ctx.exception.code, (403, 404))

        # index.html remains public
        with urllib.request.urlopen(f"{self.base_url}/index.html", timeout=3) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("SplitNest", resp.read().decode("utf-8"))

    def test_02_api_requires_session_and_enforces_household_membership(self):
        # Unauthenticated requests must return 401
        status, _, _ = http_json(f"{self.base_url}/api/household")
        self.assertEqual(status, 401)
        status_flat, _, _ = http_json(f"{self.base_url}/api/household?flat=2A")
        self.assertEqual(status_flat, 401)

        # Register a user in Flat 4B and verify HttpOnly session cookie
        signup_status, signup_headers, signup_body = http_json(
            f"{self.base_url}/api/signup",
            method="POST",
            payload={
                "firstName": "Alex",
                "lastName": "Rivera",
                "email": "alex.4b.test@example.com",
                "password": "StrongPassword1!",
                "unit": "Flat 4B",
            },
        )
        self.assertEqual(signup_status, 201)
        self.assertEqual(signup_body["flat"], "4B")
        raw_set_cookie = next(v for k, v in signup_headers.items() if k.lower() == "set-cookie")
        self.assertIn("HttpOnly", raw_set_cookie)
        self.assertIn("SameSite=Lax", raw_set_cookie)
        cookie_4b = extract_cookie_pair(signup_headers)

        # Authorized household fetch returns ONLY Flat 4B rows
        ok_status, _, ledger = http_json(f"{self.base_url}/api/household", cookie=cookie_4b)
        self.assertEqual(ok_status, 200)
        self.assertEqual(ledger["flat"], "4B")
        self.assertEqual(len(ledger["payments"]), 3)
        self.assertTrue(all(p["email"].endswith(".4b@example.com") for p in ledger["payments"]))

        # Requesting own flat explicitly succeeds
        same_status, _, same_ledger = http_json(f"{self.base_url}/api/household?flat=4B", cookie=cookie_4b)
        self.assertEqual(same_status, 200)
        self.assertEqual(same_ledger["flat"], "4B")

        # Cross-flat requests must be rejected with 403 and expose zero payment rows
        for unauthorized_flat in ("2A", "7C", "*", ""):
            forb_status, _, forb_body = http_json(
                f"{self.base_url}/api/household?flat={unauthorized_flat}",
                cookie=cookie_4b,
            )
            self.assertEqual(forb_status, 403)
            self.assertNotIn("payments", forb_body)

        # Logout invalidates server session; subsequent login issues a new valid session
        logout_status, _, _ = http_json(f"{self.base_url}/api/logout", method="POST", cookie=cookie_4b)
        self.assertEqual(logout_status, 200)
        after_logout_status, _, _ = http_json(f"{self.base_url}/api/household", cookie=cookie_4b)
        self.assertEqual(after_logout_status, 401)

        login_status, login_headers, login_body = http_json(
            f"{self.base_url}/api/login",
            method="POST",
            payload={"email": "alex.4b.test@example.com", "password": "StrongPassword1!"},
        )
        self.assertEqual(login_status, 200)
        self.assertEqual(login_body["flat"], "4B")
        relogin_cookie = extract_cookie_pair(login_headers)
        recheck_status, _, _ = http_json(f"{self.base_url}/api/household", cookie=relogin_cookie)
        self.assertEqual(recheck_status, 200)

    def test_03_expired_session_returns_401(self):
        short_proc, short_url = start_server(session_ttl_ms=200)
        try:
            login_status, login_headers, _ = http_json(
                f"{short_url}/api/login",
                method="POST",
                payload={"email": "leo.2a@example.com", "password": "SplitNest!2026"},
            )
            self.assertEqual(login_status, 200)
            cookie = extract_cookie_pair(login_headers)

            active_status, _, data = http_json(f"{short_url}/api/household", cookie=cookie)
            self.assertEqual(active_status, 200)
            self.assertEqual(data["flat"], "2A")

            time.sleep(0.3)
            expired_status, _, _ = http_json(f"{short_url}/api/household", cookie=cookie)
            self.assertEqual(expired_status, 401)
        finally:
            stop_server(short_proc)

    def test_04_browser_bypass_checks_and_authenticated_flows(self):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            pw_python = find_playwright_python()
            self.assertIsNotNone(pw_python, "Playwright Python runtime must be available")
            res = subprocess.run(
                [
                    pw_python,
                    "-m",
                    "unittest",
                    "tests.test_household_auth.HouseholdLedgerAuthorizationTests.test_04_browser_bypass_checks_and_authenticated_flows",
                ],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
            )
            if res.returncode != 0:
                self.fail(f"Delegated Playwright browser test failed:\n{res.stdout}\n{res.stderr}")
            return

        with sync_playwright() as p:
            browser = launch_chromium(p)
            try:
                # Bypass check #2: Unauthenticated ?flat=2A visit must not render Flat 2A payment rows in #bills
                ctx_unauth = browser.new_context()
                page = ctx_unauth.new_page()
                page.goto(f"{self.base_url}/dashboard.html?flat=2A", wait_until="load", timeout=5000)
                page.wait_for_url("**/login.html**", timeout=5000)
                self.assertEqual(page.locator("#bills tr").count(), 0)
                html_unauth = page.content()
                for secret in ("leo.2a@example.com", "ana.2a@example.com", "kenji.2a@example.com", "1950"):
                    self.assertNotIn(secret, html_unauth)
                ctx_unauth.close()

                # Bypass check #3a: Unauthenticated localStorage role='admin' must not unlock households
                ctx_admin_unauth = browser.new_context()
                page_admin = ctx_admin_unauth.new_page()
                page_admin.add_init_script("window.localStorage.setItem('role', 'admin');")
                page_admin.goto(f"{self.base_url}/dashboard.html", wait_until="load", timeout=5000)
                page_admin.wait_for_url("**/login.html**", timeout=5000)
                self.assertEqual(page_admin.locator("#bills tr").count(), 0)
                self.assertNotIn("shanaya.4b@example.com", page_admin.content())
                self.assertNotIn("leo.2a@example.com", page_admin.content())
                ctx_admin_unauth.close()

                # Login redirect flow: unauthenticated /dashboard.html -> login.html -> dashboard.html (Flat 4B)
                ctx_login = browser.new_context()
                page_login = ctx_login.new_page()
                page_login.goto(f"{self.base_url}/dashboard.html", wait_until="load", timeout=5000)
                page_login.wait_for_url("**/login.html**", timeout=5000)
                page_login.fill("#email", "shanaya.4b@example.com")
                page_login.fill("#pw", "SplitNest!2026")
                page_login.click("button[type='submit']")
                page_login.wait_for_url("**/dashboard.html", timeout=5000)
                page_login.locator("#bills tr").nth(1).wait_for(timeout=5000)
                self.assertEqual(page_login.locator("#title").text_content(), "Flat 4B")
                self.assertEqual(page_login.locator("#bills tr").count(), 4)
                self.assertIn("shanaya.4b@example.com", page_login.locator("#bills").text_content())
                self.assertNotIn("leo.2a@example.com", page_login.locator("#bills").text_content())
                ctx_login.close()

                # End-to-end signup.html flow + Bypass check #3b (authenticated user with localStorage role='admin')
                ctx_member = browser.new_context()
                page_member = ctx_member.new_page()
                page_member.add_init_script("window.localStorage.setItem('role', 'admin');")
                page_member.goto(f"{self.base_url}/signup.html", wait_until="load", timeout=5000)
                page_member.fill("#first", "Casey")
                page_member.fill("#last", "Ng")
                page_member.fill("#email", "casey.2a.browser@example.com")
                page_member.fill("#pw", "ValidPass123!")
                page_member.fill("#pw2", "ValidPass123!")
                page_member.fill("#unit", "2A")
                page_member.fill("#routing", "121000358")
                page_member.fill("#acct", "000123456789")
                page_member.click("button[type='submit']")
                page_member.wait_for_url("**/dashboard.html", timeout=5000)
                page_member.locator("#bills tr").nth(1).wait_for(timeout=5000)

                # Verify HttpOnly cookie is hidden from document.cookie and credentials are not in localStorage
                self.assertNotIn("splitnest_session", page_member.evaluate("document.cookie"))
                self.assertIsNone(page_member.evaluate("localStorage.getItem('splitnest_user')"))

                # Even with role='admin' in localStorage, only Flat 2A (1 header + 3 data rows) is rendered
                self.assertEqual(page_member.locator("#title").text_content(), "Flat 2A")
                self.assertEqual(page_member.locator("#bills tr").count(), 4)
                rendered_table = page_member.locator("#bills").text_content()
                self.assertIn("leo.2a@example.com", rendered_table)
                self.assertNotIn("shanaya.4b@example.com", rendered_table)
                self.assertNotIn("rosa.7c@example.com", rendered_table)

                # Navigating authenticated Flat 2A session to ?flat=4B shows Access denied and 0 rows
                page_member.goto(f"{self.base_url}/dashboard.html?flat=4B", wait_until="load", timeout=5000)
                page_member.wait_for_function(
                    "document.getElementById('title').textContent === 'Access denied'",
                    timeout=5000,
                )
                self.assertEqual(page_member.locator("#bills tr").count(), 0)
                self.assertNotIn("shanaya.4b@example.com", page_member.content())
                ctx_member.close()
            finally:
                browser.close()

    def test_05_dashboard_renders_cells_with_textcontent_without_html_injection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            malicious_payload = "<img id='injected-xss' src=x onerror='window.__xss=true'>"
            (tmp_path / "households.json").write_text(
                json.dumps(
                    [
                        {
                            "flat": "8X",
                            "neighborhood": "Castro",
                            "payments": [
                                {
                                    "name": malicious_payload,
                                    "email": "test.8x@example.com",
                                    "amount": 1200.0,
                                    "card": "•••• 0001",
                                }
                            ],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            port = get_free_port()
            node_script = (
                "const { createApp } = require('./server.js');"
                f"const srv = createApp({{ privateDir: {json.dumps(str(tmp_path))} }});"
                f"srv.listen({port}, '127.0.0.1');"
            )
            proc = subprocess.Popen(
                [find_node_binary(), "-e", node_script],
                cwd=str(REPO_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            base_url = f"http://127.0.0.1:{port}"
            try:
                deadline = time.time() + 10.0
                while time.time() < deadline:
                    try:
                        with urllib.request.urlopen(f"{base_url}/", timeout=1) as resp:
                            if resp.status == 200:
                                break
                    except Exception:
                        time.sleep(0.05)

                pw_python = find_playwright_python()
                self.assertIsNotNone(pw_python)
                verify_code = f"""
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    try:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
    except Exception:
        browser = p.chromium.launch(headless=True, executable_path="/usr/bin/google-chrome", args=["--no-sandbox"])
    ctx = browser.new_context()
    page = ctx.new_page()
    page.goto("{base_url}/signup.html", wait_until="load", timeout=5000)
    page.fill("#email", "user.8x@example.com")
    page.fill("#pw", "ValidPass123!")
    page.fill("#pw2", "ValidPass123!")
    page.fill("#unit", "8X")
    page.fill("#routing", "121000358")
    page.fill("#acct", "000123456789")
    page.click("button[type='submit']")
    page.wait_for_url("**/dashboard.html", timeout=5000)
    page.locator("#bills tr").nth(1).wait_for(timeout=5000)
    assert page.locator("#injected-xss").count() == 0, "HTML tag must not be parsed"
    assert page.evaluate("Boolean(window.__xss)") is False, "Script must not execute"
    cell_text = page.locator("#bills tr").nth(1).locator("td").nth(1).text_content()
    assert cell_text == {malicious_payload!r}, f"Unexpected cell text: {{cell_text}}"
    browser.close()
"""
                res = subprocess.run([pw_python, "-c", verify_code], capture_output=True, text=True)
                if res.returncode != 0:
                    self.fail(f"textContent XSS verification failed:\n{res.stdout}\n{res.stderr}")
            finally:
                stop_server(proc)


if __name__ == "__main__":
    unittest.main()
