from unittest.mock import MagicMock, patch

import pytest

import usb_monitor
from usb_monitor import (
    UsbFileScanner,
    drive_of,
    removable_drives,
    safe_to_remove,
    wait_until_settled,
)

SENSITIVE = {
    "risk_score": 0.95,
    "detections": [{"type": "credit_card", "rule": "PCI-DSS"}],
}
CLEAN = {"risk_score": 0.1, "detections": []}


@pytest.fixture(autouse=True)
def _reset_window():
    """The repeat window is module-level, as it is for a real agent."""
    usb_monitor._REPEATS.__init__(usb_monitor._REPEATS._cooldown)
    yield


def _client(classify=SENSITIVE):
    client = MagicMock()
    client.classify.return_value = classify
    client.create_incident.return_value = {"id": "inc-1"}
    client.repeat_incident.return_value = {"id": "inc-1", "attempts": 2}
    client.post_ueba_event.return_value = {"id": "ev-1"}
    return client


def _resolver(action="BLOCK"):
    r = MagicMock()
    r.resolve.return_value = {"id": "p1", "action": action, "name": "PCI-DSS",
                              "severity": "HIGH"}
    return r


def _sensitive_file(tmp_path, name="customers.csv"):
    f = tmp_path / name
    f.write_text("name,card\nSarah Okafor,4111111111111111\n", encoding="utf-8")
    return str(f)


class TestDriveEnumeration:
    """Which volumes are removable, and nothing else."""

    def test_only_removable_letters_are_returned(self):
        # C: fixed, E: removable, Z: network -- bits 2, 4 and 25.
        mask = (1 << 2) | (1 << 4) | (1 << 25)
        types = {"C:\\": 3, "E:\\": usb_monitor.DRIVE_REMOVABLE, "Z:\\": 4}
        k = MagicMock()
        k.GetLogicalDrives.return_value = mask
        k.GetDriveTypeW.side_effect = lambda root: types.get(root, 0)

        with patch("usb_monitor._kernel32", return_value=k):
            assert removable_drives() == {"E:\\"}

    def test_an_api_failure_reports_no_drives_rather_than_raising(self):
        # A monitor thread that dies takes the whole channel with it, silently.
        with patch("usb_monitor._kernel32", side_effect=OSError("boom")):
            assert removable_drives() == set()

    def test_drive_of_finds_the_volume_root(self):
        assert drive_of("E:\\folder\\cards.csv").upper() == "E:\\"


class TestSafetyGuard:
    """
    The difference between acting on a memory stick and acting on somebody's
    C: drive is one check, so it is made again immediately before anything is
    moved -- never once and remembered.
    """

    def test_a_fixed_disk_is_refused(self, tmp_path):
        path = _sensitive_file(tmp_path)
        # tmp_path is on a fixed disk; no patching needed for the real answer.
        assert safe_to_remove(path) is False

    def test_a_removable_volume_is_allowed(self, tmp_path):
        path = _sensitive_file(tmp_path)
        with patch("usb_monitor.is_removable", return_value=True):
            assert safe_to_remove(path) is True

    def test_a_path_that_is_gone_is_refused(self, tmp_path):
        with patch("usb_monitor.is_removable", return_value=True):
            assert safe_to_remove(str(tmp_path / "never-existed.csv")) is False

    def test_a_sensitive_file_on_a_fixed_disk_is_never_moved(self, tmp_path):
        # The end-to-end version of the guard: even with a BLOCK policy and
        # content that classifies at 0.95, the file stays where it is.
        path = _sensitive_file(tmp_path)
        with patch("usb_monitor.quarantine_file") as quarantine, \
             patch("usb_monitor.offer_review"):
            UsbFileScanner(_client(), "agent-1", _resolver()).scan(path)
        quarantine.assert_not_called()


class TestSettling:
    """
    watchdog announces a file the instant it is created, which during a copy
    is before its contents exist. Classifying it then reads zero bytes and
    calls it clean.
    """

    def test_a_stable_file_reports_its_size(self, tmp_path):
        path = _sensitive_file(tmp_path)
        assert wait_until_settled(path) == len(
            open(path, "rb").read()
        )

    def test_a_file_that_vanished_reports_nothing(self, tmp_path):
        assert wait_until_settled(str(tmp_path / "gone.csv"), timeout=1.0) is None

    def test_an_empty_file_is_not_mistaken_for_a_settled_one(self, tmp_path):
        empty = tmp_path / "empty.csv"
        empty.write_text("", encoding="utf-8")
        assert wait_until_settled(str(empty), timeout=1.0) is None


class TestScanning:
    """What happens to a file that lands on a stick."""

    def test_a_sensitive_file_is_removed_from_the_volume(self, tmp_path):
        path = _sensitive_file(tmp_path)
        client = _client()
        with patch("usb_monitor.safe_to_remove", return_value=True), \
             patch("usb_monitor.quarantine_file", return_value="Q:\\held") as quarantine, \
             patch("usb_monitor.offer_review"):
            outcome = UsbFileScanner(client, "agent-1", _resolver()).scan(path)

        assert outcome == "removed"
        quarantine.assert_called_once_with(path)
        client.create_incident.assert_called_once()

    def test_the_incident_is_filed_on_the_usb_channel(self, tmp_path):
        path = _sensitive_file(tmp_path)
        client = _client()
        with patch("usb_monitor.safe_to_remove", return_value=True), \
             patch("usb_monitor.quarantine_file", return_value="Q:\\held"), \
             patch("usb_monitor.offer_review"):
            UsbFileScanner(client, "agent-1", _resolver()).scan(path)

        kwargs = client.create_incident.call_args.kwargs
        assert kwargs["channel"] == "USB"
        assert "customers.csv" in kwargs["evidence"]

    def test_the_incident_says_removed_not_blocked(self, tmp_path):
        # The write itself could not be prevented from user mode. An incident
        # claiming a block would make a stronger claim than the evidence.
        path = _sensitive_file(tmp_path)
        client = _client()
        with patch("usb_monitor.safe_to_remove", return_value=True), \
             patch("usb_monitor.quarantine_file", return_value="Q:\\held"), \
             patch("usb_monitor.offer_review"):
            UsbFileScanner(client, "agent-1", _resolver()).scan(path)

        evidence = client.create_incident.call_args.kwargs["evidence"]
        assert "removed" in evidence
        assert "blocked" not in evidence.lower()

    def test_a_block_that_could_not_be_carried_out_is_not_recorded_as_one(self, tmp_path):
        # The volume stopped being removable between the watch and the scan.
        # The file is still on it, so BLOCK would be a claim the evidence
        # field contradicts two columns away.
        path = _sensitive_file(tmp_path)
        client = _client()
        with patch("usb_monitor.safe_to_remove", return_value=False), \
             patch("usb_monitor.offer_review"):
            UsbFileScanner(client, "agent-1", _resolver()).scan(path)

        kwargs = client.create_incident.call_args.kwargs
        assert kwargs["action_taken"] == "ALERT"
        assert "left in place" in kwargs["evidence"]

    def test_a_block_that_worked_is_recorded_as_a_block(self, tmp_path):
        path = _sensitive_file(tmp_path)
        client = _client()
        with patch("usb_monitor.safe_to_remove", return_value=True), \
             patch("usb_monitor.quarantine_file", return_value="Q:\\held"), \
             patch("usb_monitor.offer_review"):
            UsbFileScanner(client, "agent-1", _resolver()).scan(path)

        assert client.create_incident.call_args.kwargs["action_taken"] == "BLOCK"

    def test_a_clean_file_is_left_alone(self, tmp_path):
        path = _sensitive_file(tmp_path, "notes.txt")
        client = _client(CLEAN)
        with patch("usb_monitor.quarantine_file") as quarantine:
            outcome = UsbFileScanner(client, "agent-1", _resolver()).scan(path)

        assert outcome == "clean"
        quarantine.assert_not_called()
        client.create_incident.assert_not_called()

    def test_a_dead_classifier_does_not_quarantine_on_a_guess(self, tmp_path):
        # An unreachable classifier is not evidence of anything, and moving a
        # user's files on a guess is worse than the gap it would cover.
        path = _sensitive_file(tmp_path)
        client = _client()
        client.classify.return_value = None
        with patch("usb_monitor.quarantine_file") as quarantine:
            outcome = UsbFileScanner(client, "agent-1", _resolver()).scan(path)

        assert outcome == "classifier-down"
        quarantine.assert_not_called()

    def test_the_drives_own_housekeeping_is_ignored(self, tmp_path):
        sysdir = tmp_path / "System Volume Information"
        sysdir.mkdir()
        junk = sysdir / "tracking.log"
        junk.write_text("4111111111111111", encoding="utf-8")
        client = _client()
        assert UsbFileScanner(client, "agent-1", _resolver()).scan(str(junk)) == "excluded"
        client.classify.assert_not_called()

    def test_a_partial_copy_is_ignored(self, tmp_path):
        part = tmp_path / "customers.csv.part"
        part.write_text("4111111111111111", encoding="utf-8")
        client = _client()
        assert UsbFileScanner(client, "agent-1", _resolver()).scan(str(part)) == "excluded"
        client.classify.assert_not_called()

    def test_one_copy_is_scanned_once_despite_several_events(self, tmp_path):
        # A single copy fires created plus several modified events.
        path = _sensitive_file(tmp_path)
        client = _client()
        scanner = UsbFileScanner(client, "agent-1", _resolver())
        with patch("usb_monitor.safe_to_remove", return_value=True), \
             patch("usb_monitor.quarantine_file", return_value="Q:\\held"), \
             patch("usb_monitor.offer_review"):
            scanner.scan(path)
            second = scanner.scan(path)

        assert second == "debounced"
        client.create_incident.assert_called_once()


class TestPolicyActions:
    def test_alert_records_the_event_without_removing_the_file(self, tmp_path):
        path = _sensitive_file(tmp_path)
        client = _client()
        with patch("usb_monitor.quarantine_file") as quarantine, \
             patch("usb_monitor.offer_review"):
            outcome = UsbFileScanner(client, "agent-1", _resolver("ALERT")).scan(path)

        assert outcome == "alert"
        quarantine.assert_not_called()
        client.create_incident.assert_called_once()

    def test_below_every_rung_records_nothing(self, tmp_path):
        # NONE is not ALLOW: ALLOW is a decision to permit and is recorded,
        # NONE means this confidence is not covered by the policy at all.
        path = _sensitive_file(tmp_path)
        client = _client()
        resolver = MagicMock()
        resolver.resolve.return_value = {"id": "p1", "action": "NONE", "name": "PCI-DSS"}
        outcome = UsbFileScanner(client, "agent-1", resolver).scan(path)

        assert outcome == "not-covered"
        client.create_incident.assert_not_called()

    def test_the_policy_is_resolved_for_the_usb_channel(self, tmp_path):
        path = _sensitive_file(tmp_path)
        resolver = _resolver()
        with patch("usb_monitor.safe_to_remove", return_value=True), \
             patch("usb_monitor.quarantine_file", return_value="Q:\\held"), \
             patch("usb_monitor.offer_review"):
            UsbFileScanner(_client(), "agent-1", resolver).scan(path)

        assert resolver.resolve.call_args.kwargs["channel"] == "USB"


class TestRepeats:
    """Re-copying the same file is one row with a count, as on every channel."""

    def test_the_same_file_again_counts_onto_one_incident(self, tmp_path):
        path = _sensitive_file(tmp_path)
        client = _client()
        scanner = UsbFileScanner(client, "agent-1", _resolver())
        with patch("usb_monitor.safe_to_remove", return_value=True), \
             patch("usb_monitor.quarantine_file", return_value="Q:\\held"), \
             patch("usb_monitor.offer_review"):
            scanner.scan(path)
            scanner._seen.clear()          # a new copy, not a duplicate event
            scanner.scan(path)

        client.create_incident.assert_called_once()
        client.repeat_incident.assert_called_once_with("inc-1")

    def test_a_different_file_is_its_own_incident(self, tmp_path):
        # Time cannot tell a repeat from a new leak; only the content can.
        first = _sensitive_file(tmp_path, "customers.csv")
        second = _sensitive_file(tmp_path, "patients.csv")
        client = _client()
        scanner = UsbFileScanner(client, "agent-1", _resolver())
        with patch("usb_monitor.safe_to_remove", return_value=True), \
             patch("usb_monitor.quarantine_file", return_value="Q:\\held"), \
             patch("usb_monitor.offer_review"):
            scanner.scan(first)
            scanner.scan(second)

        assert client.create_incident.call_count == 2
        client.repeat_incident.assert_not_called()


class TestUebaSignal:
    """
    The reason the usb component of every risk score was permanently zero:
    UEBA weighted USB_INSERT at 20% and nothing ever posted one.
    """

    def test_inserting_a_drive_posts_a_usb_insert_event(self):
        client = _client()
        stop = MagicMock()
        stop.is_set.side_effect = [False, False, True]   # one pass, then exit
        stop.wait.return_value = None

        with patch("usb_monitor.removable_drives", side_effect=[set(), {"E:\\"}]), \
             patch("usb_monitor.volume_info", return_value={
                 "drive": "E:\\", "volumeLabel": "SanDisk", "sizeMB": 32768}), \
             patch("usb_monitor._watch"), patch("usb_monitor._unwatch"):
            usb_monitor._usb_loop(client, "agent-1", stop, _resolver(), None)

        posted = [c for c in client.post_ueba_event.call_args_list
                  if c.kwargs.get("event_type") == "USB_INSERT"]
        assert len(posted) == 1
        assert posted[0].kwargs["metadata"]["volumeLabel"] == "SanDisk"

    def test_a_drive_already_mounted_at_startup_is_not_an_insert(self):
        # The agent restarting is not the user plugging anything in, and a
        # fabricated insert is a fabricated UEBA signal.
        client = _client()
        stop = MagicMock()
        stop.is_set.side_effect = [False, True]
        stop.wait.return_value = None

        with patch("usb_monitor.removable_drives", return_value={"E:\\"}), \
             patch("usb_monitor._watch"), patch("usb_monitor._unwatch"):
            usb_monitor._usb_loop(client, "agent-1", stop, _resolver(), None)

        client.post_ueba_event.assert_not_called()

    def test_a_large_copy_is_reported_even_when_it_has_no_readable_text(self, tmp_path):
        path = tmp_path / "archive.zip"
        path.write_bytes(b"\x00" * 32)
        client = _client()
        scanner = UsbFileScanner(client, "agent-1", _resolver())

        with patch("usb_monitor._LARGE_FILE_THRESHOLD_BYTES", 8):
            scanner.scan(str(path))

        kinds = [c.kwargs.get("event_type") for c in client.post_ueba_event.call_args_list]
        assert "LARGE_FILE_TRANSFER" in kinds

    def test_removing_a_drive_forgets_its_repeat_window(self):
        client = _client()
        stop = MagicMock()
        stop.is_set.side_effect = [False, False, True]
        stop.wait.return_value = None
        usb_monitor._REPEATS.repeat_of("USB:E:\\", "print-1")
        usb_monitor._REPEATS.opened("USB:E:\\", "inc-old")

        with patch("usb_monitor.removable_drives", side_effect=[{"E:\\"}, set()]), \
             patch("usb_monitor._watch"), patch("usb_monitor._unwatch"):
            usb_monitor._usb_loop(client, "agent-1", stop, _resolver(), None)

        # The next stick in that letter must not inherit a count from this one.
        assert usb_monitor._REPEATS.repeat_of("USB:E:\\", "print-1") is None
