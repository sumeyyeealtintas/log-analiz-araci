"""Log kayıtlarından istatistik ve şüpheli davranış tespiti."""
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import timedelta

from .ayristir import Kayit

# Saldırganların sıkça denediği hassas yollar (kısmi eşleşme, küçük harfe çevrilmiş yola bakılır)
HASSAS_YOL_IZLERI = (
    "/.env", "/.git", "/wp-login", "/wp-admin", "/xmlrpc.php", "/phpmyadmin", "/admin",
    "/etc/passwd", "../", "/cgi-bin", "/.aws", "/config.php", "/shell", "/actuator",
)
BOT_IZLERI = ("sqlmap", "nikto", "nmap", "masscan", "python-requests", "curl/", "wget/", "go-http-client", "zgrab")
GIRIS_YOL_IZLERI = ("/login", "/signin", "/auth", "/giris")


@dataclass
class Supheli:
    ip: str
    tur: str                 # "tarama" | "kaba_kuvvet"
    ayrinti: str
    adet: int


@dataclass
class Rapor:
    toplam_istek: int
    ayristirilamayan: int
    benzersiz_ip: int
    toplam_bayt: int
    durum_sinifi: dict[str, int]
    hata_orani_5xx: float
    en_cok_ip: list[tuple[str, int]]
    en_cok_yol: list[tuple[str, int]]
    en_cok_hatali_yol: list[tuple[str, int]]
    saatlik: dict[str, int]
    bot_orani: float
    supheliler: list[Supheli] = field(default_factory=list)
    hata_patlamalari: list[dict] = field(default_factory=list)
    ilk_zaman: str = ""
    son_zaman: str = ""


def _sinif(durum: int) -> str:
    return f"{durum // 100}xx"


def hassas_yol_mu(yol: str) -> bool:
    kucuk = yol.lower()
    return any(iz in kucuk for iz in HASSAS_YOL_IZLERI)


def bot_mu(kullanici_araci: str) -> bool:
    kucuk = kullanici_araci.lower()
    return not kullanici_araci.strip("-") or any(iz in kucuk for iz in BOT_IZLERI)


def giris_denemesi_mi(k: Kayit) -> bool:
    return k.metot == "POST" and any(iz in k.yol_sadece.lower() for iz in GIRIS_YOL_IZLERI)


def kaba_kuvvet_tespit(kayitlar: list[Kayit], esik: int = 10, pencere: timedelta = timedelta(minutes=5)) -> list[Supheli]:
    """Aynı IP'den kısa sürede çok sayıda BAŞARISIZ (401/403) giriş denemesi arar (kayan pencere)."""
    ip_basarisiz: dict[str, list] = defaultdict(list)
    ip_basarili: dict[str, list] = defaultdict(list)
    for k in kayitlar:
        if not giris_denemesi_mi(k):
            continue
        if k.durum in (401, 403):
            ip_basarisiz[k.ip].append(k.zaman)
        elif k.durum in (200, 302, 303):
            ip_basarili[k.ip].append(k.zaman)

    sonuc = []
    for ip, zamanlar in ip_basarisiz.items():
        zamanlar.sort()
        en_fazla, bas = 0, 0
        for son in range(len(zamanlar)):                       # iki işaretçili kayan pencere
            while zamanlar[son] - zamanlar[bas] > pencere:
                bas += 1
            en_fazla = max(en_fazla, son - bas + 1)
        if en_fazla >= esik:
            dk = int(pencere.total_seconds() // 60)
            ayrinti = f"{dk} dakikada en fazla {en_fazla} başarısız giriş (toplam {len(zamanlar)})"
            # En kritik sinyal: başarısız denemelerden SONRA başarılı giriş -> hesap ele geçirilmiş olabilir
            if any(z >= zamanlar[0] for z in ip_basarili.get(ip, [])):
                ayrinti += " | ARDINDAN BAŞARILI GİRİŞ: hesap ele geçirilmiş olabilir!"
            sonuc.append(Supheli(ip, "kaba_kuvvet", ayrinti, en_fazla))
    return sonuc


def tarama_tespit(kayitlar: list[Kayit], esik: int = 15) -> list[Supheli]:
    """Çok sayıda farklı hassas/olmayan yolu deneyen IP'leri (zafiyet taraması) bulur."""
    kesif: dict[str, set[str]] = defaultdict(set)
    for k in kayitlar:
        if k.durum >= 400 or hassas_yol_mu(k.yol):
            kesif[k.ip].add(k.yol_sadece)
    sonuc = []
    for ip, yollar in kesif.items():
        if len(yollar) >= esik:
            hassas = sum(hassas_yol_mu(y) for y in yollar)
            sonuc.append(Supheli(ip, "tarama", f"{len(yollar)} farklı hatalı/hassas yol denedi ({hassas} hassas)", len(yollar)))
    return sonuc


def hata_patlamasi_tespit(kayitlar: list[Kayit], esik: int = 30, dilim_dk: int = 10) -> list[dict]:
    """Zamanı `dilim_dk` dakikalık dilimlere böler; bir dilimde `esik` ve üzeri 5xx varsa bildirir.

    Tek bir saldırgan IP'sinden değil, sunucu/uygulama kaynaklı bir sorunun (deploy hatası,
    veritabanı kesintisi vb.) işaretidir.
    """
    kova: dict = defaultdict(lambda: [0, 0])           # dilim -> [toplam istek, 5xx sayısı]
    for k in kayitlar:
        dilim = k.zaman.replace(minute=(k.zaman.minute // dilim_dk) * dilim_dk, second=0, microsecond=0)
        kova[dilim][0] += 1
        kova[dilim][1] += k.durum >= 500
    return [
        {"baslangic": d.strftime("%Y-%m-%d %H:%M"), "dilim_dk": dilim_dk, "hata_5xx": h, "toplam": t, "oran": h / t}
        for d, (t, h) in sorted(kova.items()) if h >= esik
    ]


def analiz_et(kayitlar: list[Kayit], ayristirilamayan: int = 0, tarama_esigi: int = 15,
              kaba_kuvvet_esigi: int = 10, en_cok: int = 5, hata_esigi: int = 30) -> Rapor:
    if not kayitlar:
        return Rapor(0, ayristirilamayan, 0, 0, {}, 0.0, [], [], [], {}, 0.0)

    n = len(kayitlar)
    sinif = Counter(_sinif(k.durum) for k in kayitlar)
    ip_sayac = Counter(k.ip for k in kayitlar)
    yol_sayac = Counter(k.yol_sadece for k in kayitlar)
    hatali_yol = Counter(k.yol_sadece for k in kayitlar if k.durum >= 400)
    saatlik = Counter(k.zaman.strftime("%Y-%m-%d %H:00") for k in kayitlar)
    zamanlar = sorted(k.zaman for k in kayitlar)

    supheliler = tarama_tespit(kayitlar, tarama_esigi) + kaba_kuvvet_tespit(kayitlar, kaba_kuvvet_esigi)
    supheliler.sort(key=lambda s: (-s.adet, s.ip))

    return Rapor(
        toplam_istek=n,
        ayristirilamayan=ayristirilamayan,
        benzersiz_ip=len(ip_sayac),
        toplam_bayt=sum(k.bayt for k in kayitlar),
        durum_sinifi=dict(sorted(sinif.items())),
        hata_orani_5xx=sinif.get("5xx", 0) / n,
        en_cok_ip=ip_sayac.most_common(en_cok),
        en_cok_yol=yol_sayac.most_common(en_cok),
        en_cok_hatali_yol=hatali_yol.most_common(en_cok),
        saatlik=dict(sorted(saatlik.items())),
        bot_orani=sum(bot_mu(k.kullanici_araci) for k in kayitlar) / n,
        supheliler=supheliler,
        hata_patlamalari=hata_patlamasi_tespit(kayitlar, hata_esigi),
        ilk_zaman=zamanlar[0].isoformat(),
        son_zaman=zamanlar[-1].isoformat(),
    )
