import pytest

from app_launch_monitor import _check_watchlist


@pytest.mark.parametrize("proc_name,expected_label", [
    ("teamviewer.exe".replace(".exe", ""), "TeamViewer remote access"),
    ("anydesk", "AnyDesk remote access"),
    ("filezilla", "FileZilla FTP"),
    ("winrar", "WinRAR archiver"),
    ("ngrok", "ngrok tunnel"),
    ("wireshark", "Wireshark packet capture"),
    ("qbittorrent", "qBittorrent"),
])
def test_watchlist_matches_known_tools(proc_name, expected_label):
    assert _check_watchlist(proc_name) == expected_label


def test_watchlist_no_match_for_ordinary_process():
    assert _check_watchlist("notepad") is None
    assert _check_watchlist("chrome") is None
    assert _check_watchlist("explorer") is None


def test_watchlist_is_substring_match():
    # "ftp" keyword should match any process name containing it
    assert _check_watchlist("myftpclient") == "FTP client"


def test_watchlist_specific_entries_win_over_generic_ones():
    # 7zg (7-Zip GUI) must be checked before the more generic "7z"
    assert _check_watchlist("7zg") == "7-Zip GUI"
    assert _check_watchlist("7zfm") == "7-Zip archiver"


def test_watchlist_case_insensitivity_is_caller_responsibility():
    # _check_watchlist itself does not lowercase; caller passes .lower() name
    assert _check_watchlist("TeamViewer") is None
    assert _check_watchlist("teamviewer") == "TeamViewer remote access"
