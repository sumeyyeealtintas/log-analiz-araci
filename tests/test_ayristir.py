from datetime import timedelta

import pytest

from logan.ayristir import dosya_ayristir, satir_ayristir, zaman_ayristir

NORMAL = '203.0.113.7 - - [10/Oct/2025:13:55:36 +0300] "GET /index.html?a=1 HTTP/1.1" 200 2326 "https://ornek.com/" "Mozilla/5.0"'


def test_normal_satir():
    k = satir_ayristir(NORMAL)
    assert (k.ip, k.metot, k.yol, k.durum, k.bayt) == ("203.0.113.7", "GET", "/index.html?a=1", 200, 2326)
    assert k.yol_sadece == "/index.html"
    assert k.kullanici_araci == "Mozilla/5.0"
    assert (k.zaman.year, k.zaman.month, k.zaman.hour) == (2025, 10, 13)
    assert k.zaman.utcoffset() == timedelta(hours=3)


def test_bayt_tire_ise_sifir():
    assert satir_ayristir(NORMAL.replace("2326", "-")).bayt == 0


def test_ipv6_adres():
    k = satir_ayristir(NORMAL.replace("203.0.113.7", "2001:db8::1"))
    assert k.ip == "2001:db8::1"


def test_kullanici_araci_icinde_kacirilmis_tirnak():
    k = satir_ayristir(NORMAL.replace('"Mozilla/5.0"', r'"Bot \"v2\" (+http://x)"'))
    assert k is not None and 'v2' in k.kullanici_araci


def test_bozuk_istek_cop_veri_ayristirilir_ama_metot_yoktur():
    k = satir_ayristir('203.0.113.7 - - [10/Oct/2025:13:55:36 +0300] "\\x16\\x03\\x01" 400 0 "-" "-"')
    assert k is not None and k.metot == "-" and k.durum == 400


@pytest.mark.parametrize("satir", [
    "bu bir log satiri degil",
    "",
    '203.0.113.7 - - [10/Foo/2025:13:55:36 +0300] "GET / HTTP/1.1" 200 5 "-" "-"',   # geçersiz ay
    '203.0.113.7 - - [10/Oct/2025:13:55:36 +0300] "GET / HTTP/1.1" abc 5 "-" "-"',  # geçersiz durum
])
def test_gecersiz_satirlar_none_doner(satir):
    assert satir_ayristir(satir) is None


def test_zaman_eksi_saat_dilimi():
    z = zaman_ayristir("01/Jan/2025:00:00:00 -0500")
    assert z.utcoffset() == timedelta(hours=-5)


def test_dosya_ayristir_hatali_sayar_bos_satiri_atlar():
    kayitlar, hatali = dosya_ayristir([NORMAL, "cop", "", "  ", NORMAL + "\n"])
    assert len(kayitlar) == 2 and hatali == 1
