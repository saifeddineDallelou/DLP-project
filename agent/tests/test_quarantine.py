from pathlib import Path
from unittest.mock import patch

from quarantine import quarantine_file


def test_moves_file_into_quarantine_dir(tmp_path):
    quarantine_dir = tmp_path / "quarantine"
    src = tmp_path / "secret.txt"
    src.write_text("card: 4111111111111111")

    with patch("quarantine._QUARANTINE_DIR", quarantine_dir):
        result = quarantine_file(str(src))

    assert result is not None
    assert not src.exists()
    assert Path(result).is_file()
    assert result.startswith(str(quarantine_dir))


def test_preserves_original_content(tmp_path):
    quarantine_dir = tmp_path / "quarantine"
    src = tmp_path / "secret.txt"
    src.write_text("card: 4111111111111111")

    with patch("quarantine._QUARANTINE_DIR", quarantine_dir):
        result = quarantine_file(str(src))

    assert Path(result).read_text() == "card: 4111111111111111"


def test_creates_quarantine_dir_if_missing(tmp_path):
    quarantine_dir = tmp_path / "does" / "not" / "exist" / "yet"
    src = tmp_path / "secret.txt"
    src.write_text("x")

    with patch("quarantine._QUARANTINE_DIR", quarantine_dir):
        result = quarantine_file(str(src))

    assert result is not None
    assert quarantine_dir.is_dir()


def test_returns_none_when_file_does_not_exist(tmp_path):
    with patch("quarantine._QUARANTINE_DIR", tmp_path / "quarantine"):
        result = quarantine_file(str(tmp_path / "does_not_exist.txt"))
    assert result is None


def test_returns_none_on_move_failure(tmp_path):
    src = tmp_path / "secret.txt"
    src.write_text("x")
    with patch("quarantine._QUARANTINE_DIR", tmp_path / "quarantine"), \
         patch("quarantine.shutil.move", side_effect=OSError("locked")):
        result = quarantine_file(str(src))
    assert result is None
    assert src.exists()  # original untouched on failure


def test_two_same_named_files_do_not_collide(tmp_path):
    quarantine_dir = tmp_path / "quarantine"
    src1 = tmp_path / "a" / "secret.txt"
    src1.parent.mkdir()
    src1.write_text("first")
    src2 = tmp_path / "b" / "secret.txt"
    src2.parent.mkdir()
    src2.write_text("second")

    with patch("quarantine._QUARANTINE_DIR", quarantine_dir):
        result1 = quarantine_file(str(src1))
        result2 = quarantine_file(str(src2))

    assert result1 != result2
    assert Path(result1).read_text() == "first"
    assert Path(result2).read_text() == "second"
