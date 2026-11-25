"""Checks the installer workflow runs against a freshly installed console (stdlib only).

  installer-check.py setup  INSTALL_LOG [URL]   the first visit's registration form creates the admin
  installer-check.py login  USER PASSWORD [URL] sign in; prints a token (stdout)
  installer-check.py get    TOKEN PATH [URL]    GET a JSON API path with a token; prints the body
  installer-check.py listeners PORT...          nothing listens on 0.0.0.0 / [::] on these ports
"""
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request

PW = "ci-admin-password-123"


def _req(url, data=None, token=None):
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                 headers={"Content-Type": "application/json",
                                          **({"Authorization": "Bearer " + token} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def setup(log, url="http://127.0.0.1:8080"):
    """A console on 127.0.0.1: the installer's last lines point at the registration form (no
    setup code), the form creates the admin, and the API is refused until then."""
    text = open(log, encoding="utf-8", errors="replace").read()
    tail = [l for l in text.splitlines() if l.strip()][-2:]
    assert "create your account: full name, email, username and password" in tail[0], tail
    assert "The first account becomes the administrator" in tail[1], tail
    assert "Setup code :" not in text, "a 127.0.0.1 console needs no setup code"
    st, page = _req(url + "/")
    assert st == 200 and "Create your Corvex-RedOps account" in page
    status = json.loads(_req(url + "/setup/status")[1])
    assert status["setup_required"] is True and status["signup"] == "form", status
    assert status["setup_code_required"] is False, status
    assert _req(url + "/engagements")[0] == 503                      # refused until set up
    st, body = _req(url + "/setup/register", {"full_name": "CI Admin", "email": "ci-admin@example.com",
                                              "username": "admin", "password": PW, "password_confirm": PW})
    assert st == 201, body
    assert json.loads(_req(url + "/setup/status")[1])["setup_required"] is False
    st, body = _req(url + "/auth/login", {"username": "admin", "password": PW})
    assert st == 200, body
    print("admin registered through the form")


def login(user, pw, url="http://127.0.0.1:8080"):
    st, body = _req(url + "/auth/login", {"username": user, "password": pw})
    assert st == 200, body
    print(json.loads(body)["token"])


def get(token, path, url="http://127.0.0.1:8080"):
    st, body = _req(url + path, token=token)
    assert st == 200, (st, body)
    print(body)


def listeners(*ports):
    out = subprocess.run(["sudo", "ss", "-ltnpH"], capture_output=True, text=True).stdout
    bad = [l for l in out.splitlines()
           if re.search(r"(0\.0\.0\.0|\[::\]|\*):(%s)\b" % "|".join(ports), l) or
           ("docker-proxy" in l and not re.search(r"\s(127\.0\.0\.1|\[::1\]):", l))]
    assert not bad, "listening on every interface:\n" + "\n".join(bad)
    print("no listener on 0.0.0.0 / [::] for", ", ".join(ports), "and every published port is on loopback")


if __name__ == "__main__":
    {"setup": setup, "login": login, "get": get, "listeners": listeners}[sys.argv[1]](*sys.argv[2:])
