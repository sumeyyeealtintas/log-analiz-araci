"""Komut satırı:  python -m logan erisim.log [--json cikti.json] [--tarama-esigi 15] [--kaba-kuvvet-esigi 10]

Şüpheli davranış ya da 5xx patlaması bulunursa çıkış kodu 1 olur; bu sayede CI/cron betiklerinde alarm üretmek için kullanılabilir.
"""
import argparse
import json
import sys
from dataclasses import asdict

from .analiz import Rapor, analiz_et
from .ayristir import dosya_ayristir, kayitlari_oku


def _bayt(n: int) -> str:
    for birim in ("B", "KB", "MB", "GB"):
        if n < 1024 or birim == "GB":
            return f"{n:.1f} {birim}" if birim != "B" else f"{n} B"
        n /= 1024
    return str(n)


def raporu_yazdir(r: Rapor) -> None:
    if r.toplam_istek == 0:
        print("Analiz edilecek geçerli kayıt bulunamadı.")
        return
    print(f"Dönem            : {r.ilk_zaman[:19]}  ->  {r.son_zaman[:19]}")
    print(f"Toplam istek     : {r.toplam_istek:,}   (ayrıştırılamayan satır: {r.ayristirilamayan})")
    print(f"Benzersiz IP     : {r.benzersiz_ip:,}")
    print(f"Aktarılan veri   : {_bayt(r.toplam_bayt)}")
    print(f"5xx hata oranı   : %{r.hata_orani_5xx * 100:.2f}")
    print(f"Bot / otomasyon  : %{r.bot_orani * 100:.1f}")
    print("\nDurum kodu sınıfları:")
    for s, adet in r.durum_sinifi.items():
        print(f"  {s}  {adet:>7,}  %{adet / r.toplam_istek * 100:5.1f}  {'█' * int(adet / r.toplam_istek * 40)}")
    for baslik, liste in (("En çok istek yapan IP'ler", r.en_cok_ip), ("En çok istenen yollar", r.en_cok_yol),
                          ("En çok hata veren yollar (4xx/5xx)", r.en_cok_hatali_yol)):
        print(f"\n{baslik}:")
        for ad, adet in liste:
            print(f"  {adet:>7,}  {ad}")
    print("\nSaatlik trafik:")
    en_buyuk = max(r.saatlik.values())
    for saat, adet in r.saatlik.items():
        print(f"  {saat}  {adet:>6,}  {'▇' * max(1, int(adet / en_buyuk * 30))}")

    print("\n⚠ Şüpheli davranışlar:" if r.supheliler else "\n✓ Şüpheli davranış tespit edilmedi.")
    for s in r.supheliler:
        etiket = "TARAMA     " if s.tur == "tarama" else "KABA KUVVET"
        print(f"  [{etiket}] {s.ip:<16} {s.ayrinti}")

    if r.hata_patlamalari:
        print("\n⚠ Sunucu hatası (5xx) patlamaları:")
        for h in r.hata_patlamalari:
            print(f"  {h['baslangic']} ({h['dilim_dk']} dk)  {h['hata_5xx']} / {h['toplam']} istek 5xx  (%{h['oran'] * 100:.0f})")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="logan", description="Nginx/Apache erişim logu analizi ve şüpheli davranış tespiti.")
    p.add_argument("dosya", help="erişim log dosyası (combined biçim)")
    p.add_argument("--json", metavar="DOSYA", help="raporu JSON olarak kaydet")
    p.add_argument("--tarama-esigi", type=int, default=15, help="bir IP kaç farklı hatalı/hassas yol denerse tarama sayılsın")
    p.add_argument("--kaba-kuvvet-esigi", type=int, default=10, help="5 dakikada kaç başarısız giriş kaba kuvvet sayılsın")
    p.add_argument("--hata-esigi", type=int, default=30, help="10 dakikalık dilimde kaç 5xx hata patlama sayılsın")
    a = p.parse_args(argv)

    try:
        kayitlar, hatali = dosya_ayristir(kayitlari_oku(a.dosya))
    except OSError as hata:
        print(f"Dosya okunamadı: {hata}", file=sys.stderr)
        return 2
    rapor = analiz_et(kayitlar, hatali, a.tarama_esigi, a.kaba_kuvvet_esigi, hata_esigi=a.hata_esigi)
    raporu_yazdir(rapor)
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump(asdict(rapor), f, ensure_ascii=False, indent=2)
        print(f"\nJSON rapor: {a.json}")
    return 1 if (rapor.supheliler or rapor.hata_patlamalari) else 0


if __name__ == "__main__":
    sys.exit(main())
