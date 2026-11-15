"""Nginx / Apache "combined" biçimindeki erişim loglarını ayrıştırır.

Biçim:
  $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
Örnek:
  203.0.113.7 - - [10/Oct/2025:13:55:36 +0300] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"
"""
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

# Dikkat: tırnak içindeki alanlarda kaçırılmış tırnak (\") olabilir, bu yüzden (?:[^"\\]|\\.)*
_SATIR = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<kullanici>\S+) \[(?P<zaman>[^\]]+)\] '
    r'"(?P<istek>(?:[^"\\]|\\.)*)" (?P<durum>\d{3}) (?P<bayt>\d+|-) '
    r'"(?P<referer>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)"\s*$'
)
_ZAMAN = re.compile(r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$")
# strptime yerel dile bağımlı olabilir (%b); bu yüzden ay adlarını kendimiz çeviriyoruz.
_AYLAR = {a: i for i, a in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


@dataclass(frozen=True)
class Kayit:
    ip: str
    zaman: datetime
    metot: str
    yol: str
    durum: int
    bayt: int
    kullanici_araci: str

    @property
    def yol_sadece(self) -> str:
        """Sorgu dizesi (?...) olmadan yol."""
        return self.yol.split("?", 1)[0]


def zaman_ayristir(metin: str) -> datetime:
    m = _ZAMAN.match(metin)
    if not m or m.group(2) not in _AYLAR:
        raise ValueError(f"Geçersiz zaman: {metin!r}")
    gun, ay, yil, sa, dk, sn, isaret, oh, om = m.groups()
    fark = timedelta(hours=int(oh), minutes=int(om)) * (1 if isaret == "+" else -1)
    return datetime(int(yil), _AYLAR[ay], int(gun), int(sa), int(dk), int(sn), tzinfo=timezone(fark))


def satir_ayristir(satir: str) -> Kayit | None:
    """Tek satırı ayrıştırır; biçime uymuyorsa None döner."""
    m = _SATIR.match(satir.rstrip("\n"))
    if not m:
        return None
    try:
        zaman = zaman_ayristir(m["zaman"])
    except ValueError:
        return None
    parcalar = m["istek"].split(" ")
    # Bozuk/boş istekler ("-" ya da TLS el sıkışma çöpü) metot/yol içermez
    metot = parcalar[0] if len(parcalar) >= 2 else "-"
    yol = parcalar[1] if len(parcalar) >= 2 else "-"
    return Kayit(
        ip=m["ip"], zaman=zaman, metot=metot, yol=yol, durum=int(m["durum"]),
        bayt=0 if m["bayt"] == "-" else int(m["bayt"]), kullanici_araci=m["ua"],
    )


def dosya_ayristir(satirlar: Iterable[str]) -> tuple[list[Kayit], int]:
    """Tüm satırları ayrıştırır. (kayıtlar, ayrıştırılamayan satır sayısı) döndürür."""
    kayitlar, hatali = [], 0
    for satir in satirlar:
        if not satir.strip():
            continue
        k = satir_ayristir(satir)
        if k is None:
            hatali += 1
        else:
            kayitlar.append(k)
    return kayitlar, hatali


def kayitlari_oku(yol: str) -> Iterator[str]:
    with open(yol, encoding="utf-8", errors="replace") as f:
        yield from f
