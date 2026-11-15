# 🔍 Log Analiz Aracı

Nginx / Apache **erişim loglarını** okuyup trafik istatistiği çıkaran ve **şüpheli davranışları** tespit eden bir komut satırı aracı: zafiyet taraması, kaba kuvvet (brute-force) giriş saldırısı ve sunucu hatası (5xx) patlaması. Harici kütüphane gerektirmez.

> Sunucuya bir şey olduğunda ilk bakılan yer loglardır. Bu araç, binlerce satırı okumak yerine "ne oldu?" sorusuna saniyeler içinde cevap verir.

## 🧰 Teknolojiler
Python 3.12 (yalnızca standart kütüphane) · regex · argparse · pytest · GitHub Actions

## 🎯 Ne Tespit Eder?
| Tespit | Nasıl çalışır |
|---|---|
| 🛡️ **Zafiyet taraması** | Aynı IP'nin çok sayıda **farklı** hatalı ya da hassas yolu (`/.env`, `/wp-login.php`, `/../etc/passwd`...) denemesi. Aynı 404 sayfasını tekrar tekrar istemek tarama sayılmaz |
| 🔐 **Kaba kuvvet** | Aynı IP'den **5 dakikalık kayan pencerede** çok sayıda başarısız (401/403) `POST /login`. Başarısız denemelerin ardından **başarılı giriş** varsa ayrıca "hesap ele geçirilmiş olabilir" uyarısı verir |
| 🔥 **5xx patlaması** | 10 dakikalık dilimde çok sayıda sunucu hatası; saldırgandan değil, uygulama/sunucu sorunundan (kötü deploy, veritabanı kesintisi) kaynaklanır |
| 📊 **Genel istatistik** | İstek sayısı, benzersiz IP, durum kodu sınıfları, en çok istek yapan IP'ler, en çok istenen ve en çok hata veren yollar, saatlik trafik, bot oranı |

## 🚀 Kullanım
```bash
python ornek_uret.py                     # sentetik örnek log üretir (data/ornek_access.log)
python -m logan data/ornek_access.log
python -m logan erisim.log --json rapor.json --tarama-esigi 20 --kaba-kuvvet-esigi 15
```
Çıkış kodu: `0` temiz, `1` şüpheli davranış ya da 5xx patlaması var, `2` dosya okunamadı. Bu sayede `cron` ya da CI betiğinde alarm tetiklemek için kullanılabilir.

### Örnek çıktı
```
Toplam istek     : 2,851   (ayrıştırılamayan satır: 1)
Benzersiz IP     : 121
5xx hata oranı   : %5.26

Saatlik trafik:
  2025-10-10 13:00     389  ▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇
  2025-10-10 14:00     552  ▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇▇

⚠ Şüpheli davranışlar:
  [KABA KUVVET] 198.51.100.23  5 dakikada en fazla 60 başarısız giriş (toplam 60) | ARDINDAN BAŞARILI GİRİŞ: hesap ele geçirilmiş olabilir!
  [TARAMA     ] 203.0.113.66   20 farklı hatalı/hassas yol denedi (15 hassas)

⚠ Sunucu hatası (5xx) patlamaları:
  2025-10-10 14:00 (10 dk)  150 / 226 istek 5xx  (%66)
```

## 🔬 Tasarım Kararları
- **Kayan pencere (sliding window):** Kaba kuvvet tespiti sabit saat dilimlerine değil, iki işaretçili kayan pencereye dayanır. Böylece saldırı bir dilim sınırına denk gelse bile kaçmaz. Aynı sayıda deneme yavaş yayılırsa (2 dakikada bir) yakalanmaz, çünkü bu normal kullanıcı hatalarına benzer.
- **Yanlış alarmı azaltma:** Normal ziyaretçilerin hiçbiri şüpheli işaretlenmez (testle doğrulanır). Tarama tespiti "farklı yol sayısı"na bakar, tek yola yapılan tekrarlara bakmaz.
- **Dil bağımsız tarih ayrıştırma:** `strptime` yerel dile bağlı olabileceğinden (`%b`) ay adları elle eşlenir.
- **Dayanıklı ayrıştırma:** Bozuk satırlar çökme yerine sayılıp raporlanır; tırnak içinde kaçırılmış tırnak (`\"`), IPv6 adresleri ve TLS çöpü istekler (`"\x16\x03\x01"`) işlenir.

## 🧪 Test
```bash
pytest -q        # 39 test
```
Ayrıştırma sınır durumları, eşik değerleri (tam eşikte yakalanır, bir altında yakalanmaz), kayan pencere, yavaş saldırı, başarılı giriş uyarısı, yanlış alarm yokluğu ve komut satırı çıkış kodları test edilir.

## ⚠️ Sınırlar
- Örnek log **tamamen sentetiktir** (IP'ler RFC 5737 örnek aralığındadır, gerçek kullanıcı verisi yoktur). Eşik varsayılanları bu örnek ve genel pratiklere göre seçildi; **gerçek sistemde kendi trafiğinize göre ayarlanmalıdır**.
- Yalnızca `combined` log biçimini destekler.
- IP tabanlı tespit, arkada paylaşılan NAT / proxy varsa yanıltıcı olabilir (aynı IP'den birçok kullanıcı).
- Bu bir savunma / analiz aracıdır; yalnızca kendi sistemlerinizin loglarında kullanın.

## 📁 Yapı
```
├── logan/
│   ├── ayristir.py   # log satırı ayrıştırma
│   ├── analiz.py     # istatistik ve tespit algoritmaları
│   └── __main__.py   # komut satırı arayüzü
├── ornek_uret.py     # sentetik log üretici (3 saldırı senaryosu gömer)
├── data/ornek_access.log
└── tests/
```

## 🔭 Geliştirme Fikirleri
- GeoIP ile ülke bazlı özet
- `fail2ban` benzeri otomatik IP engelleme listesi çıktısı
- Gerçek zamanlı izleme (`tail -f` modu)
- JSON log biçimi desteği
