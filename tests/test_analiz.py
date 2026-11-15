from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from logan.analiz import (analiz_et, bot_mu, hassas_yol_mu, hata_patlamasi_tespit,
                          kaba_kuvvet_tespit, tarama_tespit)
from logan.ayristir import Kayit, dosya_ayristir, kayitlari_oku

TZ = timezone(timedelta(hours=3))
T0 = datetime(2025, 10, 10, 12, 0, 0, tzinfo=TZ)


def k(ip="192.0.2.1", saniye=0, metot="GET", yol="/", durum=200, bayt=100, ua="Mozilla/5.0"):
    return Kayit(ip, T0 + timedelta(seconds=saniye), metot, yol, durum, bayt, ua)


# ---- Yardımcılar ----
@pytest.mark.parametrize("yol", ["/.env", "/WP-LOGIN.php", "/a/../../etc/passwd", "/phpmyadmin/index.php"])
def test_hassas_yollar(yol):
    assert hassas_yol_mu(yol)


@pytest.mark.parametrize("yol", ["/", "/urunler/42", "/api/siparis"])
def test_normal_yollar_hassas_degil(yol):
    assert not hassas_yol_mu(yol)


def test_bot_tespiti():
    assert bot_mu("sqlmap/1.7") and bot_mu("python-requests/2.31") and bot_mu("-") and bot_mu("")
    assert not bot_mu("Mozilla/5.0 (Windows NT 10.0) Chrome/130")


# ---- Kaba kuvvet ----
def test_kaba_kuvvet_esik_ve_pencere():
    # 10 başarısız giriş, 5 dakikanın içinde -> yakalanır
    kayitlar = [k("198.51.100.1", i * 20, "POST", "/login", 401) for i in range(10)]
    bulunan = kaba_kuvvet_tespit(kayitlar, esik=10)
    assert len(bulunan) == 1 and bulunan[0].ip == "198.51.100.1" and bulunan[0].adet == 10


def test_kaba_kuvvet_sonrasi_basarili_giris_uyarisi():
    kayitlar = [k("198.51.100.1", i * 10, "POST", "/login", 401) for i in range(12)]
    kayitlar.append(k("198.51.100.1", 200, "POST", "/login", 200))
    assert "BAŞARILI GİRİŞ" in kaba_kuvvet_tespit(kayitlar, esik=10)[0].ayrinti


def test_kaba_kuvvet_basarili_giris_yoksa_uyari_yok():
    kayitlar = [k("198.51.100.1", i * 10, "POST", "/login", 401) for i in range(12)]
    assert "BAŞARILI GİRİŞ" not in kaba_kuvvet_tespit(kayitlar, esik=10)[0].ayrinti


def test_baska_ipden_basarili_giris_sayilmaz():
    kayitlar = [k("198.51.100.1", i * 10, "POST", "/login", 401) for i in range(12)]
    kayitlar.append(k("192.0.2.9", 200, "POST", "/login", 200))
    assert "BAŞARILI GİRİŞ" not in kaba_kuvvet_tespit(kayitlar, esik=10)[0].ayrinti


def test_kaba_kuvvet_esigin_altinda_yakalanmaz():
    kayitlar = [k("198.51.100.1", i * 20, "POST", "/login", 401) for i in range(9)]
    assert kaba_kuvvet_tespit(kayitlar, esik=10) == []


def test_kaba_kuvvet_yavas_deneme_pencereye_sigmaz():
    # 10 deneme ama her biri 2 dakika arayla: hiçbir 5 dakikalık pencerede 10 olmaz
    kayitlar = [k("198.51.100.1", i * 120, "POST", "/login", 401) for i in range(10)]
    assert kaba_kuvvet_tespit(kayitlar, esik=10) == []


def test_kaba_kuvvet_sadece_basarisiz_post_giris_sayilir():
    kayitlar = ([k("1.1.1.1", i, "POST", "/login", 200) for i in range(20)]       # başarılı girişler
                + [k("2.2.2.2", i, "GET", "/login", 401) for i in range(20)]      # POST değil
                + [k("3.3.3.3", i, "POST", "/api/siparis", 401) for i in range(20)])  # giriş yolu değil
    assert kaba_kuvvet_tespit(kayitlar, esik=10) == []


def test_kaba_kuvvet_ip_ayri_ayri_sayilir():
    kayitlar = [k(f"10.0.0.{i % 5}", i, "POST", "/login", 401) for i in range(40)]   # her IP'den 8 deneme
    assert kaba_kuvvet_tespit(kayitlar, esik=10) == []


# ---- Tarama ----
def test_tarama_farkli_yol_sayisina_bakar():
    taramaci = [k("203.0.113.9", i, yol=f"/gizli{i}", durum=404) for i in range(15)]
    assert [s.ip for s in tarama_tespit(taramaci, esik=15)] == ["203.0.113.9"]


def test_ayni_yola_tekrar_tarama_degildir():
    kayitlar = [k("203.0.113.9", i, yol="/eksik-sayfa", durum=404) for i in range(200)]   # aynı 404 yolu
    assert tarama_tespit(kayitlar, esik=15) == []


def test_basarili_normal_istekler_tarama_sayilmaz():
    kayitlar = [k("192.0.2.5", i, yol=f"/urunler/{i}", durum=200) for i in range(100)]
    assert tarama_tespit(kayitlar, esik=15) == []


# ---- 5xx patlaması ----
def test_hata_patlamasi_dilimi_bulur():
    kayitlar = [k(saniye=i, durum=503) for i in range(35)] + [k(saniye=i + 700, durum=200) for i in range(50)]
    patlama = hata_patlamasi_tespit(kayitlar, esik=30)
    assert len(patlama) == 1
    assert patlama[0]["baslangic"] == "2025-10-10 12:00" and patlama[0]["hata_5xx"] == 35


def test_dagilmis_5xx_patlama_sayilmaz():
    kayitlar = [k(saniye=i * 700, durum=500) for i in range(20)]    # her dilimde 1 tane
    assert hata_patlamasi_tespit(kayitlar, esik=30) == []


# ---- Genel rapor ----
def test_rapor_temel_sayilar():
    kayitlar = [k("1.1.1.1", 0, durum=200, bayt=10), k("1.1.1.1", 1, durum=404, bayt=5),
                k("2.2.2.2", 2, durum=500, bayt=0), k("2.2.2.2", 3, durum=200, bayt=1, ua="sqlmap")]
    r = analiz_et(kayitlar, ayristirilamayan=2)
    assert r.toplam_istek == 4 and r.ayristirilamayan == 2 and r.benzersiz_ip == 2
    assert r.toplam_bayt == 16
    assert r.durum_sinifi == {"2xx": 2, "4xx": 1, "5xx": 1}
    assert r.hata_orani_5xx == 0.25 and r.bot_orani == 0.25
    assert r.en_cok_ip[0] == ("1.1.1.1", 2) or r.en_cok_ip[0] == ("2.2.2.2", 2)


def test_bos_kayit_listesi_cokmez():
    r = analiz_et([])
    assert r.toplam_istek == 0 and r.supheliler == []


# ---- Uçtan uca: örnek log gömülü senaryoları bulmalı ----
ORNEK = Path(__file__).parent.parent / "data" / "ornek_access.log"


@pytest.mark.skipif(not ORNEK.exists(), reason="önce ornek_uret.py çalıştırılmalı")
def test_ornek_log_gomulu_senaryolari_bulur():
    kayitlar, hatali = dosya_ayristir(kayitlari_oku(str(ORNEK)))
    r = analiz_et(kayitlar, hatali)
    assert hatali == 1
    bulunan = {(s.ip, s.tur) for s in r.supheliler}
    assert ("203.0.113.66", "tarama") in bulunan
    assert ("198.51.100.23", "kaba_kuvvet") in bulunan
    assert len(r.supheliler) == 2, f"Beklenmeyen yanlış pozitif: {bulunan}"   # normal ziyaretçiler işaretlenmemeli
    assert r.hata_patlamalari and r.hata_patlamalari[0]["baslangic"] == "2025-10-10 14:00"
