import threading
import time
from review_prompt import offer_review
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


class TestOfferReview:
    """
    Every channel that stops something owes the user an explanation.

    Drag and drop, screenshots and file-picker uploads all blocked silently:
    the file did not arrive, the paste produced nothing, and there was no way
    to object. A block nobody can see is indistinguishable from the tool being
    broken -- which is how a DLP agent gets uninstalled. This is the one place
    that explanation is offered, rather than a fourth copy of the same
    pattern.
    """

    def _wait_for_threads(self):
        for t in threading.enumerate():
            if t.name == "review-prompt":
                t.join(timeout=3)

    def test_a_requested_review_reaches_the_right_endpoint_for_an_attempt(self):
        client = MagicMock()
        with patch("review_prompt.prompt_review_request", return_value="I need this for work"):
            offer_review(client, "attempt", "att-1", "reason", "DRAG-DROP")
            self._wait_for_threads()

        client.request_review_ai_leak_attempt.assert_called_once_with("att-1", "I need this for work")
        client.request_review_incident.assert_not_called()

    def test_an_incident_uses_the_incident_endpoint(self):
        # The two are stored in different tables and reviewed through
        # different endpoints; sending one to the other silently loses it.
        client = MagicMock()
        with patch("review_prompt.prompt_review_request", return_value=""):
            offer_review(client, "incident", "inc-1", "reason", "SCREENSHOT")
            self._wait_for_threads()

        client.request_review_incident.assert_called_once_with("inc-1", None)
        client.request_review_ai_leak_attempt.assert_not_called()

    def test_an_empty_note_is_still_a_review_request(self):
        # Clicking the button without typing is a request; only a dismissal
        # is not.
        client = MagicMock()
        with patch("review_prompt.prompt_review_request", return_value=""):
            offer_review(client, "attempt", "att-1", "reason", "TAG")
            self._wait_for_threads()

        client.request_review_ai_leak_attempt.assert_called_once_with("att-1", None)

    def test_a_dismissal_records_nothing(self):
        client = MagicMock()
        with patch("review_prompt.prompt_review_request", return_value=None):
            offer_review(client, "attempt", "att-1", "reason", "TAG")
            self._wait_for_threads()

        client.request_review_ai_leak_attempt.assert_not_called()

    def test_it_never_blocks_the_caller(self):
        # prompt_review_request waits on a person. A monitor's poll loop must
        # never wait with it -- the block is already applied, and every other
        # channel would stop being watched meanwhile.
        client = MagicMock()
        started = threading.Event()

        def _slow(*_a, **_kw):
            started.set()
            time.sleep(2)
            return None

        t0 = time.monotonic()
        with patch("review_prompt.prompt_review_request", side_effect=_slow):
            offer_review(client, "attempt", "att-1", "reason", "TAG")
            elapsed = time.monotonic() - t0
            assert started.wait(timeout=2)
        assert elapsed < 0.5

    def test_the_reason_reaches_the_dialog(self):
        client = MagicMock()
        with patch("review_prompt.prompt_review_request", return_value=None) as prompt:
            offer_review(client, "attempt", "a", "'cards.csv' was blocked from being uploaded.", "TAG")
            self._wait_for_threads()

        assert "cards.csv" in prompt.call_args[0][0]


class TestEveryBlockingChannelExplainsItself:
    """
    The helper passing its own tests proves nothing if no monitor calls it.

    Three channels blocked in total silence for months: the drag was
    cancelled, the screenshot was wiped, the upload dialog closed -- each
    looking exactly like the feature being broken. This pins the wiring, not
    the helper.
    """

    import pathlib as _pathlib

    CHANNELS = [
        ("drag_drop_monitor", "DRAG-DROP"),
        ("file_dialog_monitor", "FILE-DIALOG"),
        ("screenshot_monitor", "SCREENSHOT"),
        ("clipboard_watcher", "CLIPBOARD"),
    ]

    def _source(self, module_name):
        import importlib
        mod = importlib.import_module(module_name)
        return self._pathlib.Path(mod.__file__).read_text(encoding="utf-8")

    def test_each_blocking_channel_offers_a_review(self):
        missing = []
        for module_name, _tag in self.CHANNELS:
            src = self._source(module_name)
            if "offer_review(" not in src and "prompt_review_request(" not in src:
                missing.append(module_name)
        assert not missing, f"these block without telling the user: {missing}"

    def test_the_offer_is_guarded_on_something_actually_being_blocked(self):
        # An ALERT-only outcome stops nothing, so a popup claiming otherwise
        # would be a lie told by the tool about itself.
        for module_name in ("drag_drop_monitor", "file_dialog_monitor", "screenshot_monitor"):
            src = self._source(module_name)
            if "offer_review(" not in src:
                continue
            before = src.split("offer_review(")[0]
            tail = before[-400:]
            assert ("if b and" in tail) or ("if cleared and" in tail), \
                f"{module_name} offers a review without checking it blocked anything"
