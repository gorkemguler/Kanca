<p align="center">
  <img src="assets/banner.svg" alt="Kanca — yetkili güvenlik testleri için araya giren HTTP/HTTPS proxy" width="100%">
</p>

<p align="center">
  <a href="https://github.com/gorkemguler/Kanca/actions/workflows/ci.yml"><img src="https://github.com/gorkemguler/Kanca/actions/workflows/ci.yml/badge.svg" alt="CI durumu"></a>
  <a href="https://github.com/gorkemguler/Kanca/blob/main/go.mod"><img src="https://img.shields.io/badge/Go-1.24-00ADD8?logo=go&logoColor=white" alt="Go sürümü"></a>
  <a href="https://github.com/gorkemguler/Kanca/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="Lisans: MIT"></a>
</p>

<p align="center">
  <a href="README.md">English</a> · <strong>Türkçe</strong>
</p>

# Kanca

**Yetkili** web uygulaması güvenlik testleri için araya giren (intercepting)
bir HTTP/HTTPS proxy — Burp Suite gibi araçlara açık ve üzerinde
değişiklik yapılabilir bir alternatif. Kanca, bir tarayıcı (veya herhangi
bir HTTP istemcisi) ile konuştuğu sunucular arasına girer, her isteği/yanıtı
kaydeder ve isteklerinizi duraklatıp düzenlemenize, tekrar göndermenize ve
fuzzlamanıza olanak tanır.

> ⚠️ **Sadece yetkili kullanım içindir.** Kanca trafiği çözer ve değiştirir.
> Yalnızca sahibi olduğunuz veya test etmek için açıkça izin aldığınız
> sistemlere karşı kullanın. Geçerli tüm yasa ve sözleşmelere uymak sizin
> sorumluluğunuzdadır.

## Ekran görüntüleri

![Proxy geçmişi: Kanca üzerinden yakalanan bir tarayıcı oturumu, giriş isteği ve yanıtıyla birlikte](assets/screenshots/history.png)

<table>
  <tr>
    <td width="50%"><img src="assets/screenshots/repeater.png" alt="Repeater"><br><sub><b>Repeater</b> — ürün sorgusunu tek tırnakla yeniden göndermek SQL hatasını ortaya çıkarıyor.</sub></td>
    <td width="50%"><img src="assets/screenshots/intruder.png" alt="Intruder"><br><sub><b>Intruder</b> — 1–30 arası kullanıcı ID'leri taranıyor; grep-match iki admin hesabını işaretliyor.</sub></td>
  </tr>
  <tr>
    <td width="50%"><img src="assets/screenshots/findings.png" alt="Bulgular"><br><sub><b>Bulgular</b> — pasif header/cookie kontrolleri ve aktif tarama ipuçları (XSS, SQLi, path traversal, SSTI, open redirect, CRLF).</sub></td>
    <td width="50%"><img src="assets/screenshots/sitemap.png" alt="Site haritası"><br><sub><b>Site haritası</b> — yakalanan endpoint'ler host bazlı bir ağaç olarak.</sub></td>
  </tr>
</table>

<sub>Ekran görüntüleri, yerelde çalışan ve bilerek zayıf bırakılmış bir demo mağazaya karşı alınmıştır.</sub>

## İndirme

macOS, Windows ve Linux için derlenmiş sürümler her
[release](https://github.com/gorkemguler/Kanca/releases) içinde hazır.

| Platform | Dosya | Çalıştırma |
| --- | --- | --- |
| macOS (universal) | `kanca-macos-universal.zip` | Açın, ilk açılışta `kanca.app`'e sağ tık → **Aç** (notarize edilmediği için Gatekeeper bir kez sorar). |
| Windows (x64) | `kanca-windows-amd64.zip` | Açın ve `kanca.exe`'yi çalıştırın. |
| Linux (x64) | `kanca-linux-amd64.tar.gz` | Çıkartın ve `./kanca`'yı çalıştırın (`libgtk-3` ve `libwebkit2gtk-4.0` gerekir). |
| Tarayıcı eklentisi | `kanca-browser-extension.zip` | Aşağıdaki [Tarayıcı eklentisi](#tarayıcı-eklentisi) bölümüne bakın. |

Kendiniz derlemek isterseniz aşağıdaki [Desktop uygulaması](#desktop-uygulaması) bölümüne bakın.

## Tek tıkla tarayıcı

Başlamanın en hızlı yolu: Kanca'nın üst barındaki **Open browser** butonuna
(ya da **CA / Settings → Browser setup** altındakine) tıklayın. Kanca gerekirse
proxy'yi başlatır ve Chrome, Edge veya Brave'i, trafiği zaten Kanca'dan geçen
ayrı bir profille açar.

- **HTTPS hemen çalışır.** Tarayıcıya yalnızca Kanca'nın kendi sertifika
  anahtarlarına güvenmesi söylenir; işletim sisteminin güven deposuna hiçbir şey
  kurulmaz ve diğer tüm siteler normal sertifika kontrolünden geçmeye devam eder.
- **Günlük tarayıcınıza dokunulmaz.** Test profili kendi çerezleri ve geçmişiyle
  `~/.kanca/browser-profile` içinde durur.
- **Yerel hedefler de yakalanır**, `localhost` ve `*.localhost` dahil.

Kanca, kuruluysa Chrome'u tercih eder. Tarayıcının kendi güncelleme ve senkron
trafiği kapatılır, ancak Edge yine de Microsoft servislerine birkaç istek
gönderir; bunları geçmişten uzak tutmak için **Target scope** (CA / Settings)
ayarlayın.

CLI'da `go run ./cmd/kanca -browser` aynı işi yapar.

## Tarayıcı eklentisi

<img src="assets/screenshots/extension.png" alt="Kanca tarayıcı eklentisi" width="300" align="right">

Chrome, Edge, Brave ve Opera için yardımcı eklenti, Kanca'yı tarayıcınız için tek
tıkla açıp kapatır; proxy ayarlarıyla uğraşmanız gerekmez:

- **Tek tıkla yönlendirme** — tarayıcının HTTP ve HTTPS trafiğini Kanca'ya gönderir
  (varsayılan `127.0.0.1:8080`, ya da sizin belirlediğiniz host/port). Aktifken
  toolbar ikonu turuncu olur ve **ON** rozeti çıkar; <kbd>Alt</kbd>+<kbd>Shift</kbd>+<kbd>K</kbd> ile açılıp kapanır.
- **Canlı durum** — trafiğin gerçekten Kanca'dan geçip geçmediğini ya da Kanca'nın
  henüz çalışmadığını gösterir.
- **CA sertifikası** — *Install CA certificate…* butonu, Kanca'nın kendisinin sunduğu
  `http://kanca/` sayfasını açar; root sertifikayı işletim sistemine göre kurulum
  adımlarıyla birlikte indirirsiniz.
- **Yerel hedefler** — tarayıcıların normalde proxy'yi atlattığı `localhost`,
  `127.0.0.1` ve `*.localhost` adreslerini de isteğe bağlı olarak yakalar.
- **Bypass listesi** — Kanca'yı atlaması gereken host'lar, ör. `*.google.com` gürültüsü.
- **Çakışma uyarısı** — proxy'yi başka bir eklenti (VPN ya da proxy değiştirici)
  veya bir politika kontrol ediyorsa uyarır.

**Kurulum:** Kanca uygulamasında **CA / Settings → Browser setup** bölümüne gidip
**Get the extension**'a tıklayın; eklenti `~/.kanca/browser-extension` klasörüne
yazılır ve klasör açılır. (Ya da [son sürümden](https://github.com/gorkemguler/Kanca/releases/latest)
`kanca-browser-extension.zip` dosyasını indirip açın.) Ardından `chrome://extensions`
(Edge'de `edge://extensions`) sayfasını açın, **Geliştirici modu**nu açın,
**Paketlenmemiş öğe yükle**'ye tıklayıp klasörü seçin. Firefox henüz desteklenmiyor.

**Sertifikaya güvenin (kendi tarayıcınızda HTTPS için):** macOS'ta
**CA / Settings → Install on this Mac**'e tıklayın; macOS şifrenizi ister ve
Safari, Chrome ve Edge sertifikaya güvendiğinde durum yeşile döner.
**Remove from this Mac** geri alır. Uygulama olmadan şu komutu çalıştırın:

```bash
security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db ~/Downloads/kanca-ca.crt
```

Diğer sistemlerde adım adım talimatlar için proxy üzerinden `http://kanca/`
adresini açın. Firefox her platformda kendi sertifika listesini kullanır.

<br clear="right">


## Özellikler (MVP)

| Özellik | Ne yapar |
| --- | --- |
| **Araya giren proxy** | Yerel bir root CA tarafından imzalanmış, anlık üretilen host bazlı sertifikalarla TLS'i sonlandırır; böylece HTTPS trafiği incelenip değiştirilebilir. |
| **HTTP geçmişi** | Her isteğin/yanıtın her iki tarafının ham baytlarıyla birlikte, aranabilir ve filtrelenebilir şekilde kaydı tutulur. |
| **Interception kuyruğu** | İstekleri (isteğe bağlı olarak yanıtları da) duraklatın, ham baytları düzenleyin, ardından iletin veya düşürün. |
| **Repeater** | Herhangi bir isteği alın, özgürce değiştirin ve istediğiniz kadar tekrar gönderin — her sekme kendi gönderim geçmişini tutar ve satır bazlı diff, bir yanıtı bir önceki gönderimle karşılaştırır. |
| **Intruder / fuzzer** | Dört saldırı tipiyle (sniper, battering ram, pitchfork, cluster bomb) otomatik payload enjeksiyonu, eşzamanlılık kontrolü ve grep-eşleşme vurgulama. Payload setleri bir listeden veya üretilen sayısal bir aralıktan gelir; her set için işlemciler (URL/base64 encode, büyük/küçük harf, MD5/SHA-1/SHA-256) uygulanabilir. |
| **Hedef kapsamı (scope)** | Kaydı seçilen host'larla sınırlandırın (tam eşleşme, üst alan adı veya `*.` joker karakter); kapsam dışı trafik yine proxy'lenir ama kaydedilmez. |
| **Okunabilir gövdeler** | `gzip`, `deflate` ve `brotli` yanıtları görüntüleme için şeffaf biçimde çözülür; proxy ise değiştirilmemiş baytları iletmeye devam eder. |
| **Site haritası** | Yakalanan trafik, düz bir günlük yerine host bazlı bir URL yolu ağacı olarak sunulur; böylece hedefin yapısını görebilirsiniz. |
| **Match & replace** | Hattın üzerinde uygulanan regex değişimleri — giden isteklerin ve gelen yanıtların istek satırını, bir header'ı veya gövdesini yeniden yazın (Content-Length doğru tutulur). |
| **Gövde arama** | Sadece method/host/path değil, istek/yanıt gövdelerinde de geçmişi filtreleyin. |
| **Pasif tarayıcı** | Gözlemlenen trafikten güvenlik sorunlarını işaretler (eksik CSP/HSTS/X-Content-Type-Options, güvensiz cookie'ler, gevşek CORS, sürüm ifşası) — ek bir istek göndermeden. |
| **Aktif tarayıcı** | Talep üzerine, tek bir isteğin insertion point'lerini — query, form gövdesi ve JSON gövdesi parametreleri — yansıyan girdi/XSS, hataya dayalı SQL enjeksiyonu, path traversal, open redirect, template enjeksiyonu (SSTI) ve CRLF/header enjeksiyonu için dener; yalnızca kapsam içindeki host'larla sınırlı. Opt-in bir **agresif** mod, boolean ve time-based SQLi ile time-based komut enjeksiyonu kontrollerini ekler (bunlar hedefi gözlemlenebilir şekilde çalıştırır). Sadece tespit amaçlıdır: her kontrol bir baseline ile karşılaştırma yapar ve elle doğrulanacak bir ipucu işaretler — asla istismar (exploitation) girişiminde bulunmaz. |
| **Kaydet / içe-dışa aktar** | Tam bir oturumu (flow'lar, kurallar, bulgular, kapsam) bir proje dosyasına kaydedip sonra tekrar açın; yakalanan trafiği HAR 1.2 olarak dışa aktarın ve başka araçlardan HAR yakalamalarını içe aktarın. |
| **WebSocket desteği** | `ws://` ve `wss://` upgrade'leri şeffaf biçimde köprülenir (normal HTTP için hop-by-hop olarak `Upgrade`/`Connection` header'ları temizlendiğinden eskiden bu bağlantılar bozulurdu) — canlı, bağlantı başına frame kaydıyla birlikte; sıfırdan yazılmış RFC 6455 framing, harici bağımlılık yok. |
| **Tarayıcı kurulumu** | [Open browser](#tek-tıkla-tarayıcı), CA kurmadan HTTPS'in çalıştığı, önceden ayarlanmış izole bir Chrome/Edge/Brave profili açar; [tarayıcı eklentisi](#tarayıcı-eklentisi) kendi tarayıcınızı Kanca'ya yönlendirir; proxy'nin kendisinin sunduğu (asla dışarı iletilmeyen ya da kaydedilmeyen) `http://kanca/` sayfası root CA'yı indirmenizi sağlar. |

## Mimari

Proje iki Go modülüne ayrılmıştır; böylece engine bağımlılıksız ve tamamen
test edilebilir kalırken, desktop kabuğu GUI araç zincirini taşır.

```
kanca/                      çekirdek modül — saf Go standart kütüphanesi, bağımlılık yok
├── internal/
│   ├── cert/               anlık üretilen sertifika otoritesi (root + leaf sertifikalar)
│   ├── proxy/              araya giren proxy motoru + HTTP wire codec
│   │                       (WebSocket köprüleme/frame yakalama dahil)
│   ├── history/            aranabilir, sınırlı boyutlu flow kaydı
│   ├── repeater/           düzenle-ve-tekrar-gönder çalışma alanları
│   ├── intruder/           payload şablonlama + eşzamanlı saldırı motoru
│   ├── rules/              match-and-replace (hat üzerinde regex yeniden yazımı)
│   ├── scanner/            yakalanan flow'lar üzerinde pasif güvenlik kontrolleri
│   ├── activescan/         yıkıcı olmayan aktif problar (opt-in, kapsamla sınırlı)
│   ├── sitemap/            yakalanan flow'lardan oluşturulan host bazlı URL yolu ağacı
│   ├── diff/               satır bazlı metin diff'i (repeater yanıt karşılaştırması)
│   ├── har/                HAR 1.2 dışa/içe aktarım
│   └── project/            bir oturumu kaydet/yükle (flow'lar, kurallar, bulgular, kapsam)
├── cmd/kanca/              GUI gerektirmeyen headless CLI çalıştırıcı
└── desktop/                ayrı bir modül — Wails v2 desktop uygulaması
    ├── app.go              Go ↔ frontend bağlantıları
    ├── main.go             Wails giriş noktası
    └── frontend/           React + TypeScript arayüz (Vite)
```

Çekirdek modülün **hiçbir harici bağımlılığı olmadığından**, Go'nun kurulu
olduğu her yerde derlenir ve testleri çalışır — CI için başka hiçbir şeye
gerek yoktur.

## Hızlı başlangıç — headless CLI

CLI, GUI olmadan tüm proxy motorunu çalıştırır; sunucularda, CI'da veya
işlerin çalıştığını doğrulamak için kullanışlıdır.

```bash
go run ./cmd/kanca -addr 127.0.0.1:8080
```

Ardından tarayıcınızın HTTP/HTTPS proxy ayarını `127.0.0.1:8080` olarak
belirleyin (ya da [tarayıcı eklentisini](#tarayıcı-eklentisi) açın). HTTPS'i de
yakalamak için proxy üzerinden `http://kanca/` adresine gidip root sertifikayı
indirin veya CLI ile dışa aktarın, sonra tarayıcınızın/işletim sisteminizin güven
deposuna ekleyin:

```bash
go run ./cmd/kanca -export-ca kanca-ca.pem
```

Bayraklar (flags):

| Bayrak | Varsayılan | Anlamı |
| --- | --- | --- |
| `-addr` | `127.0.0.1:8080` | proxy dinleme adresi |
| `-cadir` | `~/.kanca` | root CA'nın saklandığı yer |
| `-export-ca PATH` | — | root sertifikayı `PATH`'e yazıp çıkar |
| `-insecure-upstream` | `true` | upstream sunucu sertifikalarının doğrulamasını atla |
| `-max-flows` | `100000` | bellekte tutulan azami işlem (transaction) sayısı |
| `-browser` | `false` | Chrome/Edge/Brave'i, trafiği zaten proxy'den geçen ayrı bir profille açar |

## Desktop uygulaması

GUI bir [Wails v2](https://wails.io) uygulamasıdır. Go, Node.js ve Wails
CLI'nin yanı sıra Wails'in belgelediği platforma özgü webview
bağımlılıklarına ihtiyacınız var (ör. Linux'ta `webkit2gtk`, Windows'ta
WebView2).

```bash
go install github.com/wailsapp/wails/v2/cmd/wails@latest

cd desktop
wails dev      # canlı yeniden yükleme ile geliştirme
wails build    # desktop/build/bin altında native bir binary üretir
```

İlk açılışta, trafiği zaten Kanca'dan geçen bir tarayıcı için **Open browser**'a
tıklayın. Kendi tarayıcınızı kullanmak isterseniz **CA / Settings → Browser setup**
bölümünden eklentiyi ekleyin ve root sertifikaya güvenin.

## Geliştirme

```bash
# çekirdek motor: derle, vet, test et (harici bağımlılık yok)
go build ./...
go vet ./...
go test ./...

# frontend tip kontrolü + build
cd desktop/frontend && npm install && npm run build

# tarayıcı eklentisi birim testleri (bağımlılık yok)
cd extension && npm test
```

Proxy motoru, gerçek HTTP ve HTTPS backend'ler ayağa kaldırıp trafiği
proxy üzerinden geçiren uçtan uca testlerle kapsanır; interception'da
düşürme/düzenleme yolları da dahildir (`internal/proxy/proxy_test.go`).

## Yol haritası

Olası gelecek çalışmalar: kimlik doğrulama/oturum yönetimi yardımcıları,
yerleşik bir wordlist yöneticisi ve bant dışı (OAST) etkileşim tespiti.

## Lisans

MIT — bkz. [LICENSE](LICENSE).
