"""D8: the console has the forced-change overlay and no longer mentions a default login."""
from pathlib import Path

HTML = (Path(__file__).resolve().parents[1] / "pentestiq/api/static/index.html").read_text()


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
