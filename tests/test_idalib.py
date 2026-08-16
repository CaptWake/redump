from redump.utils import idalib


def test_malformed_ida_config_is_ignored(monkeypatch, tmp_path):
    config = tmp_path / "ida-config.json"
    config.write_text("not json", encoding="utf-8")
    monkeypatch.setattr(idalib, "get_idalib_user_config_path", lambda: config)

    assert idalib.find_idalib() is None


def test_incomplete_ida_config_is_ignored(monkeypatch, tmp_path):
    config = tmp_path / "ida-config.json"
    config.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(idalib, "get_idalib_user_config_path", lambda: config)

    assert idalib.find_idalib() is None
