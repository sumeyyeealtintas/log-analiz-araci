"""Gerçekçi ama TAMAMEN SENTETİK bir nginx erişim logu üretir (gerçek kullanıcı verisi içermez).

Normal trafiğin içine üç senaryo gömer; analiz aracının bunları bulup bulamadığını göstermek için:
  1) 203.0.113.66  -> zafiyet taraması (yüzlerce hassas yol dener)
  2) 198.51.100.23 -> /login'e kaba kuvvet saldırısı
  3) 14:00-14:10   -> sunucu hatası (5xx) patlaması
IP'ler, belgelerde kullanılması için ayrılmış örnek aralıklardandır (RFC 5737).

Çalıştırma:  python ornek_uret.py            ->  data/ornek_access.log
"""
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

TZ = timezone(timedelta(hours=3))
BASLANGIC = datetime(2025, 10, 10, 8, 0, 0, tzinfo=TZ)
AYLAR = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

NORMAL_YOLLAR = [("/", 30), ("/urunler", 20), ("/urunler/42", 10), ("/sepet", 8), ("/hakkimizda", 4),
                 ("/api/urunler", 14), ("/api/siparis", 6), ("/static/app.js", 12), ("/static/stil.css", 12), ("/giris", 4)]
NORMAL_UA = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0 Safari/537.36",
             "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) Safari/604.1",
             "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"]
TARAMA_YOLLARI = ["/.env", "/.git/config", "/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/phpmyadmin/", "/admin/",
                  "/config.php", "/.aws/credentials", "/actuator/env", "/cgi-bin/test.sh", "/../../etc/passwd",
                  "/shell", "/backup.zip", "/db.sql", "/admin/login", "/administrator/", "/server-status", "/.DS_Store", "/test.php"]


def satir(ip, zaman, metot, yol, durum, bayt, ua, referer="-"):
    z = f"{zaman.day:02d}/{AYLAR[zaman.month - 1]}/{zaman.year}:{zaman:%H:%M:%S} +0300"
    return f'{ip} - - [{z}] "{metot} {yol} HTTP/1.1" {durum} {bayt} "{referer}" "{ua}"'


def uret(seed: int = 7) -> list[str]:
    rng = random.Random(seed)
    olaylar: list[tuple[datetime, str]] = []

    # 1) Normal trafik: gün içinde öğleye doğru yoğunlaşan ziyaretçiler
    ziyaretciler = [f"192.0.2.{i}" for i in range(1, 120)]
    yollar, agirliklar = zip(*NORMAL_YOLLAR)
    for _ in range(2600):
        dk = int(rng.triangular(0, 12 * 60, 6 * 60))          # 08:00-20:00, tepe 14:00 civarı
        z = BASLANGIC + timedelta(minutes=dk, seconds=rng.randrange(60))
        yol = rng.choices(yollar, agirliklar)[0]
        durum = rng.choices([200, 304, 404, 301], [86, 8, 4, 2])[0]
        metot = "POST" if yol in ("/api/siparis", "/giris") and rng.random() < 0.8 else "GET"
        durum = 201 if metot == "POST" and yol == "/api/siparis" and durum == 200 else durum
        olaylar.append((z, satir(rng.choice(ziyaretciler), z, metot, yol, durum, rng.randrange(300, 60000),
                                 rng.choice(NORMAL_UA), "https://ornek.com/" if rng.random() < 0.3 else "-")))

    # 2) Zafiyet taraması
    t = BASLANGIC + timedelta(hours=3, minutes=12)
    for i, yol in enumerate(TARAMA_YOLLARI * 2):
        z = t + timedelta(seconds=i * 2)
        olaylar.append((z, satir("203.0.113.66", z, "GET", yol, 404 if rng.random() < 0.9 else 403, 162, "python-requests/2.31.0")))

    # 3) Kaba kuvvet: 4 dakikada 60 başarısız giriş
    t = BASLANGIC + timedelta(hours=7, minutes=30)
    for i in range(60):
        z = t + timedelta(seconds=i * 4)
        olaylar.append((z, satir("198.51.100.23", z, "POST", "/login", 401, 41, "curl/8.5.0")))
    z = t + timedelta(minutes=5)
    olaylar.append((z, satir("198.51.100.23", z, "POST", "/login", 200, 1280, "curl/8.5.0")))   # sonunda içeri girdi

    # 4) 5xx patlaması (14:00-14:10)
    t = BASLANGIC + timedelta(hours=6)
    for i in range(150):
        z = t + timedelta(seconds=rng.randrange(600))
        olaylar.append((z, satir(rng.choice(ziyaretciler), z, "GET", rng.choice(["/api/siparis", "/api/urunler", "/sepet"]),
                                 rng.choice([500, 502, 503]), 0, rng.choice(NORMAL_UA))))

    # 5) Bozuk satırlar (gerçek loglarda olur)
    olaylar.append((BASLANGIC + timedelta(minutes=1), "bu satir log bicimine uymuyor"))

    olaylar.sort(key=lambda x: x[0])
    return [s for _, s in olaylar]


if __name__ == "__main__":
    hedef = Path(__file__).parent / "data" / "ornek_access.log"
    hedef.parent.mkdir(exist_ok=True)
    satirlar = uret()
    hedef.write_text("\n".join(satirlar) + "\n", encoding="utf-8")
    print(f"{len(satirlar)} satır yazıldı -> {hedef}")
