"""D8: the console has the forced-change overlay and no longer mentions a default login."""
from pathlib import Path

HTML = (Path(__file__).resolve().parents[1] / "pentestiq/api/static/index.html").read_text(encoding="utf-8")


def test_no_default_login_text():
    assert "corvex / corvex" not in HTML


def test_forced_change_overlay_and_hooks():
    assert 'id="pwforce"' in HTML and 'role="dialog"' in HTML and 'aria-modal="true"' in HTML
    for hook in ("function showPwForce(", "async function forcedPasswordChange(",
                 'd.detail.error==="password_change_required"', "if(d.password_change_required)",
                 "if(me.password_change_required){showPwForce();return;}"):
        assert hook in HTML, hook
    # labels are tied to inputs
    for i in ("pwf_cur", "pwf_new", "pwf_new2"):
        assert f'for="{i}"' in HTML and f'id="{i}"' in HTML


def test_console_swaps_to_the_fresh_token_after_a_password_change():
    assert HTML.count('if(j&&j.token){TOKEN=j.token;try{localStorage.setItem("ptiq_token",TOKEN)}') == 2


def test_first_visit_setup_page():
    assert 'id="setup"' in HTML and "Set up Corvex-RedOps" in HTML
    for i in ("su_code", "su_user", "su_pw", "su_pw2"):
        assert f'for="{i}"' in HTML and f'id="{i}"' in HTML
    assert 'id="su_user" value="admin"' in HTML                       # default username
    for hook in ('fetch("/setup/status")', 'fetch("/setup",', "password_confirm:pw2",
                 'd.detail.error==="setup_required"){showSetup()', "if(d.setup_required){showSetup(d);return;}"):
        assert hook in HTML, hook


def test_sign_in_hint_has_the_docker_reset_command_and_no_installer_password():
    assert "sudo docker exec -it corvex-redops-console corvex reset-password &lt;user&gt;" in HTML
    assert "one-time password from the installer" not in HTML and "one-time admin password to the server log" not in HTML
