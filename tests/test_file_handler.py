import pytest

from utils.file_handler import validate_upload


def test_validate_upload_rejects_empty_file():
    with pytest.raises(ValueError):
        validate_upload("bad.txt", 0)


def test_validate_upload_rejects_invalid_extension():
    with pytest.raises(ValueError):
        validate_upload("notes.txt", 1024)


def test_validate_upload_accepts_supported_csv():
    validate_upload("sample.csv", 1024)


def test_validate_upload_rejects_too_large_file():
    with pytest.raises(ValueError):
        validate_upload("sample.pcap", 60 * 1024 * 1024)
