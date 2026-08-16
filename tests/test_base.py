import pytest
from redump import Extractor, ExtractorError


class CleanupFailureExtractor(Extractor):
    name = "cleanup-test"

    def open(self):
        pass

    def close(self):
        raise RuntimeError("close failed")

    def get_functions(self):
        yield from ()


def test_cleanup_does_not_mask_active_exception(tmp_path, caplog):
    extractor = CleanupFailureExtractor(tmp_path / "sample")

    with pytest.raises(ValueError, match="primary failure"), extractor:
        raise ValueError("primary failure")

    assert "cleanup failed while handling another error" in caplog.text


def test_cleanup_failure_is_normalized_without_active_exception(tmp_path):
    extractor = CleanupFailureExtractor(tmp_path / "sample")

    with pytest.raises(ExtractorError, match="cleanup-test cleanup failed"), extractor:
        pass
