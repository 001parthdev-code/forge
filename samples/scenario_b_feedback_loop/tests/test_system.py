from unittest.mock import patch
from app.system import resolve_hostname


def test_resolver_preserves_check_semantics():
    with patch("subprocess.run") as run:
        resolve_hostname("example.com")
        run.assert_called_once()
        assert run.call_args.kwargs.get("check") is True
