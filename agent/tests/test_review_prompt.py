from unittest.mock import patch, MagicMock

from review_prompt import prompt_review_request


def test_returns_none_when_tk_is_unavailable():
    with patch("review_prompt.tk.Tk", side_effect=RuntimeError("no display")):
        result = prompt_review_request("Policy blocked a credit card paste")
    assert result is None


def test_returns_none_on_dialog_setup_error():
    fake_root = MagicMock()
    fake_root.title.side_effect = RuntimeError("boom")
    with patch("review_prompt.tk.Tk", return_value=fake_root):
        result = prompt_review_request("Policy blocked a credit card paste")
    assert result is None
    fake_root.destroy.assert_not_called()  # never got far enough to need cleanup
