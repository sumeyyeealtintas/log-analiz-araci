import json
from pathlib import Path

from logan.__main__ import main

ORNEK = Path(__file__).parent.parent / "data" / "ornek_access.log"
TEMIZ = '192.0.2.1 - - [10/Oct/2025:13:55:36 +0300] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0 Chrome"\n' * 5


def test_temiz_log_cikis_kodu_0(tmp_path, capsys):
    dosya = tmp_path / "temiz.log"
    dosya.write_text(TEMIZ, encoding="utf-8")
    assert main([str(dosya)]) == 0
    assert "Şüpheli davranış tespit edilmedi" in capsys.readouterr().out


def test_supheli_log_cikis_kodu_1_ve_json(tmp_path, capsys):
    cikti = tmp_path / "rapor.json"
    assert main([str(ORNEK), "--json", str(cikti)]) == 1
    rapor = json.loads(cikti.read_text(encoding="utf-8"))
    assert rapor["toplam_istek"] > 2000 and len(rapor["supheliler"]) == 2
    assert "KABA KUVVET" in capsys.readouterr().out


def test_olmayan_dosya_cikis_kodu_2(capsys):
    assert main(["yok-boyle-dosya.log"]) == 2
    assert "okunamadı" in capsys.readouterr().err


def test_esik_yukseltilince_uyari_kalkar(tmp_path):
    assert main([str(ORNEK), "--tarama-esigi", "500", "--kaba-kuvvet-esigi", "500", "--hata-esigi", "5000"]) == 0
