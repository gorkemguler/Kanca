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
    <td width="50%"><img src="assets/screenshots/findings.png" alt="Scanner"><br><sub><b>Scanner</b> — hedefler, tek tıkla <b>Scan targets</b> ve bulgular: pasif kontroller, aktif tarama ipuçları (XSS, SQLi, SSTI, open redirect, CRLF) ve Claude'un doğruladığı açıklar (<b>AI</b>).</sub></td>
    <td width="50%"><img src="assets/screenshots/sitemap.png" alt="Site haritası"><br><sub><b>Site haritası</b> — yakalanan endpoint'ler host bazlı bir ağaç olarak.</sub></td>
  </tr>
</table>

<sub>Ekran görüntüleri, yerelde çalışan ve bilerek zayıf bırakılmış bir demo mağazaya karşı alınmıştır.</sub>

## Kurulum

### 1. İndirip çalıştırın

Sisteminize uygun dosyayı [son sürümden](https://github.com/gorkemguler/Kanca/releases/latest) indirin:

| Platform | Dosya | Çalıştırma |
| --- | --- | --- |
| macOS (Intel + Apple silicon) | `kanca-macos-universal.zip` | Açın, ilk seferde `kanca.app`'e sağ tık → **Aç** (notarize edilmediği için Gatekeeper bir kez sorar). |
| Windows (x64) | `kanca-windows-amd64.zip` | Açın ve `kanca.exe`'yi çalıştırın. SmartScreen uyarırsa **Ek bilgi → Yine de çalıştır**'ı seçin. |
| Linux (x64) | `kanca-linux-amd64.tar.gz` | Çıkartın ve `./kanca`'yı çalıştırın (`libgtk-3` ve `libwebkit2gtk-4.0` gerekir). |

Kendiniz derlemek isterseniz [Desktop uygulaması](#desktop-uygulaması) bölümüne bakın.

### 2. Yakalamaya başlayın

**En kolayı: Kanca tarayıcısı.** Üst bardaki **Open browser**'a tıklayın. Kanca
proxy'yi başlatır ve Chrome, Edge veya Brave'i trafiği zaten Kanca'dan geçen ayrı
bir profille açar. HTTPS hemen çalışır, yani **3. adımı atlayabilirsiniz**.
Ayrıntılar: [Tek tıkla tarayıcı](#tek-tıkla-tarayıcı).

**Ya da kendi tarayıcınız.** [Tarayıcı eklentisi](#tarayıcı-eklentisi) (Chrome,
Edge, Brave, Opera) ile Kanca'ya yönlendirin veya HTTP ve HTTPS proxy ayarını elle
`127.0.0.1:8080` yapın. Ardından 3. adıma geçin.

### 3. Kanca sertifikasına güvenin (sadece kendi tarayıcınız için)

HTTPS trafiğini okuyabilmek için tarayıcınızın Kanca'nın root sertifikasına
güvenmesi gerekir. Dosyayı proxy üzerinden `http://kanca/` adresini açarak ya da
**CA / Settings → Export to file…** ile alın; Kanca ayrıca `~/.kanca/ca-cert.pem`
konumunda saklar.

- **macOS**: HTTPS'e henüz güvenilmiyorken Kanca'nın üstte gösterdiği şeritteki
  **Trust certificate** düğmesine tıklayın (ya da **CA / Settings → Install on
  this Mac**). macOS şifrenizi veya Touch ID'nizi ister; Safari, Chrome ve Edge
  sertifikaya güvendiğinde şerit kaybolur. `kanca-ca.crt` dosyasına çift
  tıklamak tek başına yetmez: sertifikayı yalnızca ekler, ardından Anahtar
  Zinciri Erişimi'nde **Her Zaman Güven** yapmanız gerekir. Ya da Terminal'de:

  ```bash
  security add-trusted-cert -r trustRoot -p ssl -k ~/Library/Keychains/login.keychain-db ~/.kanca/ca-cert.pem
  ```

- **Windows**: `kanca-ca.crt`'ye çift tıklayın → **Sertifika Yükle** → **Geçerli
  Kullanıcı** → **Tüm sertifikaları aşağıdaki depolama alanına yerleştir** →
  **Güvenilen Kök Sertifika Yetkilileri**. Ya da bir terminalde:

  ```powershell
  certutil -user -addstore Root kanca-ca.crt
  ```

- **Linux**: Chrome, Edge ve Chromium kendi sertifika veritabanlarını kullanır:
  **Ayarlar → Gizlilik ve güvenlik → Güvenlik → Sertifikaları yönet → Yetkililer →
  İçe aktar**. Ya da `libnss3-tools` kuruluysa:

  ```bash
  certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "Kanca Root CA" -i kanca-ca.crt
  ```

- **Firefox (her işletim sistemi)** ayrı bir liste tutar: **Ayarlar → Gizlilik ve
  Güvenlik → Sertifikalar → Sertifikaları Göster → Yetkililer → İçe aktar**, ardından
  *Web sitelerini tanımlamak için bu CA'ya güven* kutusunu işaretleyin.

Tarayıcı açıksa yeniden başlatın. Kontrol etmek için proxy üzerinden
`http://kanca/` adresini açın: sayfa bu tarayıcının sertifikaya güvenip
güvenmediğini söyler; [tarayıcı eklentisi](#tarayıcı-eklentisi) de gösterir.
**Test bitince sertifikayı kaldırın**: macOS'ta
**CA / Settings → Remove from this Mac**; Windows'ta
`certutil -user -delstore Root "Kanca Root CA"`; diğerlerinde içe aktardığınız
yerden *Kanca Root CA*'yı silin.

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
gönderir; bunları geçmişten uzak tutmak için sitenizi **Scanner** sekmesinde hedef
olarak ekleyip *Only record traffic to targets* seçeneğini işaretleyin.

CLI'da `go run ./cmd/kanca -browser` aynı işi yapar.

## Tarayıcı eklentisi

<img src="assets/screenshots/extension.png" alt="Kanca tarayıcı eklentisi" width="300" align="right">

Chrome, Edge, Brave ve Opera için yardımcı eklenti, Kanca'yı tarayıcınız için tek
tıkla açıp kapatır; proxy ayarlarıyla uğraşmanız gerekmez:

- **Tek tıkla yönlendirme** — tarayıcının HTTP ve HTTPS trafiğini Kanca'ya gönderir
  (varsayılan `127.0.0.1:8080`, ya da sizin belirlediğiniz host/port). Aktifken
  toolbar ikonu turuncu olur ve **ON** rozeti çıkar; <kbd>Alt</kbd>+<kbd>Shift</kbd>+<kbd>K</kbd> ile açılıp kapanır.
- **Canlı durum** — trafiğin gerçekten Kanca'dan geçip geçmediğini ya da Kanca'nın
  henüz çalışmadığını, ayrıca bu tarayıcının Kanca sertifikasına güvenip
  güvenmediğini (yani HTTPS sitelerde uyarı çıkıp çıkmayacağını) gösterir.
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

HTTPS trafiğini görmek için ayrıca
[Kanca sertifikasına güvenin](#3-kanca-sertifikasına-güvenin-sadece-kendi-tarayıcınız-için).

<br clear="right">


## AI asistanı (MCP)

![AI Assistant sekmesi: Claude'un Kanca'daki adımları; yakalanan trafiği okumaktan bir IDOR ve bir SQL injection'ı doğrulamaya kadar](assets/screenshots/ai.png)

Kanca, Claude ile birlikte çalışabilir. Siz hedefi her zamanki gibi gezersiniz;
[Claude Code](https://claude.com/claude-code) ya da Claude Desktop'taki Claude
yakaladığınız trafiği okur, zafiyet arar, şüphelerini kendi istekleriyle sınar ve
doğruladıklarını **Findings** sekmesine kaydeder. Kanca ile
[Model Context Protocol](https://modelcontextprotocol.io) üzerinden konuşur.

**Açmak için:** siteyi **Scanner** sekmesinde hedef olarak ekleyin, **AI
Assistant** sekmesini açın ve **Allow AI assistants to use Kanca** kutusunu
işaretleyin. Ardından Claude'u bağlayın:

- **Claude Code**: **Copy command** düğmesine basın ve komutu terminalde bir kez
  çalıştırın. Şuna benzer:
  ```bash
  claude mcp add --transport http kanca http://127.0.0.1:8765/mcp --header "Authorization: Bearer <token>"
  ```
- **Claude Desktop**: **Add to Claude Desktop** düğmesine basın, sonra Claude
  Desktop'tan tamamen çıkıp yeniden açın. Kanca kendini
  `claude_desktop_config.json` dosyasına ekler; diğer sunucularınızı korur ve
  dosyanın `.bak` kopyasını bırakır. Claude Desktop, Kanca'nın programını küçük
  bir köprü olarak (`kanca mcp-stdio`) başlatır; bu yüzden Kanca açık ve AI
  erişimi açık olmalı. Kayıt programın konumunu gösterdiği için önce Kanca'yı
  kalıcı yerine (ör. Applications) taşıyın.
- **Opencode**: aynı sekmede **Connect Opencode** bölümünü açın. Remote,
  secret'ı dosyaya yazmaz (`Bearer {env:KANCA_MCP_TOKEN}`, `oauth:false`;
  önce `export KANCA_MCP_TOKEN="$(jq -r .token ~/.kanca/mcp.json)"`),
  local ise secretsiz `{"type":"local","command":["kanca","mcp-stdio"]}` kullanır
  (uygulamadaki kopyalama düğmesi Kanca'nın tam yolunu yazar; örnek, `kanca`
  komutunun `PATH`'te olduğunu varsayar).
  `opencode mcp list` / `opencode mcp debug kanca` ile doğrulayın. Örnekler:
  `opencode.json.example` (remote) ve `opencode.local.json.example` (local).

Sonra örneğin şunu sorun: *"Kanca'daki API isteklerini IDOR ve yetki kontrolü
açıkları için incele, şüphelendiğin her şeyi doğrula."*

| Araç | Claude'un onunla yapabildiği |
| --- | --- |
| `list_flows`, `get_flow` | Yakalanan istekleri listeler ve filtreler; bir isteği ve (çözülmüş) yanıtını okur. |
| `get_sitemap`, `get_scope` | Hedefin yapısını ve neyi test etmeye izinli olduğunu görür. |
| `list_findings`, `add_finding` | Kanca'nın bulgularını okur, kanıtıyla yeni bulgu kaydeder. |
| `send_request` | Hedeflerinizden birine ham istek gönderir; istek Proxy History'ye kaydedilir. |
| `active_scan` | Yakalanmış bir istek üzerinde Kanca'nın aktif tarayıcısını, istenirse ActiveScan++ kontrolleriyle birlikte çalıştırır. |

Güvenlik önlemleri:

- **Sadece yerel.** Uç nokta `127.0.0.1:8765` adresini dinler, rastgele 256 bitlik
  bir token ister (`~/.kanca/mcp.json` içinde, yalnızca sizin okuyabileceğiniz
  şekilde saklanır) ve web sayfalarından gelen istekleri reddeder. **New token**
  bağlı tüm istemcilerin erişimini keser.
- **Sadece hedefler.** Claude yakalanan her şeyi okuyabilir, ama yalnızca
  hedeflerinize istek gönderip tarama yapabilir; hedef yoksa sadece okur. **Read only**
  modu göndermeyi tamamen kapatır.
- **Bütçeli.** Oturum başına en fazla 500 istek (aktif tarama istekleri dahil).
  AI erişimini kapatıp açmak yeni bir oturum başlatır.
- **Gizli bilgiler varsayılan olarak maskeli.** Cookie, token, parola, API
  anahtarı ve JWT'ler Claude'a `[[KANCA_SECRET_1]]` gibi yer tutucular olarak
  gider; Claude istek gönderdiğinde Kanca gerçek değerleri geri koyar.
  Göstermek için **Mask secrets** işaretini kaldırın.
- **DELETE varsayılan olarak kapalı.** **Allow DELETE requests** işaretlenmeden
  `send_request` ve `active_scan` DELETE isteklerini reddeder; çünkü taramayı
  yeniden çalıştırmak silme işlemini tekrarlar ve gerçek veriyi kaldırabilir.
- **Hiçbir şey gizli değil.** **Activity** listesi Claude'un attığı her adımı
  gösterir; gönderdiği istekler Proxy History'de **AI** etiketiyle, bulguları da
  **AI** rozetiyle görünür.

> Claude'un okuduğu her şey sohbetinizin parçası olarak Anthropic'e gönderilir.
> Yalnızca test etme izniniz olan ve verisini paylaşabileceğiniz hedeflerde kullanın.

Arayüz olmadan, `kanca -scope shop.example -mcp` aynı uç noktayı
[CLI](#hızlı-başlangıç--headless-cli)'dan sunar ve bağlantı komutlarını yazdırır.

## Özellikler (MVP)

| Özellik | Ne yapar |
| --- | --- |
| **Araya giren proxy** | Yerel bir root CA tarafından imzalanmış, anlık üretilen host bazlı sertifikalarla TLS'i sonlandırır; böylece HTTPS trafiği incelenip değiştirilebilir. |
| **HTTP geçmişi** | Her isteğin/yanıtın her iki tarafının ham baytlarıyla birlikte, aranabilir ve filtrelenebilir şekilde kaydı tutulur. Method ve gizlenecek status kodlarına göre filtreleyin, filtre preset'leri kaydedin, akışlara not ve renkli highlight ekleyin. Herhangi bir akıştan CSRF proof-of-concept formu üretilebilir. |
| **Interception kuyruğu** | İstekleri (isteğe bağlı olarak yanıtları da) duraklatın, ham baytları düzenleyin, ardından iletin veya düşürün. |
| **Repeater** | Herhangi bir isteği alın, özgürce değiştirin ve istediğiniz kadar tekrar gönderin — her sekme kendi gönderim geçmişini tutar ve satır bazlı diff, bir yanıtı bir önceki gönderimle karşılaştırır. |
| **Karşılaştırıcı (Comparer)** | Herhangi iki metni yan yana karşılaştırın: iki yanıt, iki istek veya yapıştırılan payload'lar — iki taraf da geçmişteki bir akıştan tek tıkla yüklenebilir. |
| **JWT çalışma tezgâhı** | Bir token'ı çözün, payload'unu düzenleyin, yeniden imzalayın (HS256/384/512) ya da `none`'a indirgeyin ve bir secret'a karşı doğrulayın. |
| **Intruder / fuzzer** | Dört saldırı tipiyle (sniper, battering ram, pitchfork, cluster bomb) otomatik payload enjeksiyonu, eşzamanlılık ve istek-arası gecikme kontrolü, duraklat/devam ettirme, grep-eşleşme vurgulama ve grep-extract ile değer hasadı. Pozisyonlar eşleşen `§` işaretleriyle belirtilir, ör. `/user/§1§` (`FUZZ` anahtar kelimesi isteğe bağlı eski kısayol olarak hâlâ kabul edilir); payload setleri bir listeden veya üretilen sayısal bir aralıktan gelir; her set için işlemciler (URL/base64 encode, büyük/küçük harf, MD5/SHA-1/SHA-256) uygulanabilir. Kombinasyon uzayı güvenlik sınırıyla kesilir. |
| **Hedefler (Targets)** | **Scanner** sekmesinde belirlenir: test etmeye izinli olduğunuz host'lar (tam eşleşme, üst alan adı veya `*.` joker karakter; adres yapıştırmak da olur). Aktif tarama, site taraması ve AI asistanı bunların dışına dokunmaz; *Only record traffic to targets* seçilmedikçe her site yine kaydedilir. |
| **Okunabilir gövdeler** | Tarayıcılar Kanca'nın çözemediği `br` ve `zstd` sıkıştırmalarını ister; Kanca sunuculardan yalnızca `gzip` ve `deflate` ister ve bunları görüntüleme, arama, Intruder grep ve tarama için çözer. |
| **Site haritası** | Yakalanan trafik, düz bir günlük yerine host bazlı bir URL yolu ağacı olarak sunulur; böylece hedefin yapısını görebilirsiniz. |
| **Match & replace** | Hattın üzerinde uygulanan regex değişimleri — giden isteklerin ve gelen yanıtların istek satırını, bir header'ı veya gövdesini yeniden yazın (Content-Length doğru tutulur). |
| **Gövde arama** | Sadece method/host/path değil, istek/yanıt gövdelerinde de geçmişi filtreleyin. |
| **Pasif tarayıcı** | Gözlemlenen trafikten güvenlik sorunlarını işaretler (eksik CSP/HSTS/X-Content-Type-Options, güvensiz cookie'ler, gevşek CORS, sürüm ifşası) — ek bir istek göndermeden. |
| **Site taraması** | Scanner sekmesindeki **Scan targets** (ya da Site Map'te bir sitenin yanındaki **Scan site**), hedeflerinizde yakalanan parametreli tüm istekleri tek tek aktif tarayıcıdan geçirir ve ilerlemeyi canlı gösterir; bulgular hemen altında listelenir. Formlar ve durumu değiştiren diğer istekler, her prob onları yeniden gönderdiği için yalnızca siz işaretlerseniz dahil edilir; DELETE için ayrı bir opt-in gerekir, query/form/JSON insertion point'leri tek tek açılıp kapatılabilir. Bulgular triyaj durumuna sahiptir (new/confirmed/resolved/false-positive). |
| **Aktif tarayıcı** | Talep üzerine, tek bir isteğin insertion point'lerini — query, form gövdesi ve JSON gövdesi parametreleri — yansıyan girdi/XSS, hataya dayalı SQL enjeksiyonu, path traversal, open redirect, template enjeksiyonu (SSTI) ve CRLF/header enjeksiyonu için dener; yalnızca hedeflerinizle sınırlı. Opt-in bir **agresif** mod, boolean ve time-based SQLi ile time-based komut enjeksiyonu kontrollerini ekler (bunlar hedefi gözlemlenebilir şekilde çalıştırır). Sadece tespit amaçlıdır: her kontrol bir baseline ile karşılaştırma yapar ve elle doğrulanacak bir ipucu işaretler — asla istismar (exploitation) girişiminde bulunmaz. |
| **ActiveScan++ kontrolleri** | PortSwigger'ın [ActiveScan++](https://github.com/PortSwigger/active-scan-plus-plus) eklentisinin (Apache-2.0) isteğe bağlı bir uyarlaması: Proxy History'de **Active scan** düğmesinin yanındaki ya da site tarama panelindeki **ActiveScan++** kutusunu işaretleyin (AI asistanı için `plus`). Host başına açıkta kalan dosyalara (`/.git/config`, `/server-status`, OAuth/OpenID metadata…), React Server Components RCE'ye (CVE-2025-55182 / CVE-2025-66478) ve PHP2Shell'e (CVE-2026-109618 / CVE-2026-109619); istek başına Host ve X-Forwarded-Host header poisoning'e, HTTP üzerinden her Host'a cevap veren sunuculara (DNS rebinding), XML girdi işlemeye, Rails dosya ifşasına (CVE-2019-5418), PHP2Shell'den etkilenen PHP sürümlerine ve Google API anahtarlarına; parametre başına Edge Side Include'lara, şüpheli girdi dönüşümlerine (tırnak yutma, aritmetik/EL/Razor değerlendirme, Unicode normalizasyonu, kırpma ve büyük/küçük harf dönüşümü…), template ve çalışma zamanı hata mesajlarına ve parser'ı DTD kabul eden SAML mesajlarına bakar. Basic auth kimlik bilgileri de insertion point olur. **Aggressive** de açıksa, bir çökme probu ([php2shellbt](https://github.com/pentestershell/php2shellbt)'den, MIT) birkaç MiB'lık bozuk bir multipart gönderip worker'ın ölüp ölmediğine bakarak PHP2Shell'i `display_errors` kapalıyken bile yakalar. Tarayıcının geri kalanı gibi yalnızca belirti arar: bant dışı sunucu gerektiren ya da hedefte kod çalıştıran kontroller alınmamıştır. |
| **Kaydet / içe-dışa aktar** | Tam bir oturumu (flow'lar, kurallar, bulgular, kapsam) bir proje dosyasına kaydedip sonra tekrar açın; yakalanan trafiği HAR 1.2 olarak dışa aktarın ve başka araçlardan HAR yakalamalarını içe aktarın. |
| **WebSocket desteği** | `ws://` ve `wss://` upgrade'leri şeffaf biçimde köprülenir (normal HTTP için hop-by-hop olarak `Upgrade`/`Connection` header'ları temizlendiğinden eskiden bu bağlantılar bozulurdu) — canlı, bağlantı başına frame kaydıyla birlikte; sıfırdan yazılmış RFC 6455 framing, harici bağımlılık yok. |
| **AI asistanı (MCP)** | [Claude](#ai-asistanı-mcp)'un yakalanan trafiği okumasını, hedeflerinize istek gönderip tarama yapmasını ve bulgu raporlamasını sağlar; gizli bilgiler maskelenir, her adım görünür. |
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
│   ├── activescan/         yıkıcı olmayan aktif problar ve site taraması (hedeflerle sınırlı),
│   │                       ActiveScan++ uyarlaması dahil
│   ├── sitemap/            yakalanan flow'lardan oluşturulan host bazlı URL yolu ağacı
│   ├── scope/              hedef host eşleştirme
│   ├── mcp/                AI asistanları için MCP sunucusu (+ stdio köprüsü)
│   ├── diff/               satır bazlı metin diff'i (repeater yanıt karşılaştırması)
│   ├── jwt/                JWT çözme/doğrulama/imzalama (HS256/384/512 ve none)
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
belirleyin (ya da [tarayıcı eklentisini](#tarayıcı-eklentisi) açın), veya hazır
ayarlı bir tarayıcı için `-browser` bayrağını kullanın. Kendi tarayıcınızda HTTPS'i
de yakalamak için proxy üzerinden `http://kanca/` adresine gidip root sertifikayı
indirin veya CLI ile dışa aktarın, sonra
[sertifikaya güvenin](#3-kanca-sertifikasına-güvenin-sadece-kendi-tarayıcınız-için):

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
| `-scope HOSTS` | — | virgülle ayrılmış hedef host'lar; yalnızca bunlar kaydedilir ve AI asistanı yalnızca bunları test edebilir |
| `-mcp` | `false` | [AI asistanı](#ai-asistanı-mcp) uç noktasını `127.0.0.1:8765` üzerinde sunar |
| `-mcp-readonly` | `false` | `-mcp` ile: asistan trafiği okuyabilir ama istek gönderemez |
| `-mcp-no-mask` | `false` | `-mcp` ile: cookie, token ve parolaları asistana maskelemeden gösterir |

`kanca mcp-stdio`, Claude Desktop'ın çalışan bir Kanca'ya ulaşmak için başlattığı köprüdür.

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

# frontend tip kontrolü + build ve birim testleri (Node 24+, bağımlılık yok)
cd desktop/frontend && npm install && npm run build && npm test

# tarayıcı eklentisi birim testleri (bağımlılık yok)
cd extension && npm test
```

Proxy motoru, gerçek HTTP ve HTTPS backend'ler ayağa kaldırıp trafiği
proxy üzerinden geçiren uçtan uca testlerle kapsanır; interception'da
düşürme/düzenleme yolları da dahildir (`internal/proxy/proxy_test.go`).

## Yol haritası

Son eklenenler: istek karşılaştırıcı, JWT çalışma tezgâhı, bulgu triyaj akışı,
geçmiş notları ve filtre preset'leri, CSRF PoC üretimi, Intruder
duraklat/devam/gecikme/extract, `§…§` Intruder pozisyonları, site
taramalarında DELETE opt-in ve insertion-point anahtarları, zengin
HAR dışa aktarımları ve ActiveScan++ kontrolleri.

Olası gelecek çalışmalar: kimlik doğrulama/oturum yönetimi yardımcıları
(giriş makroları, çok kullanıcılı bağlamlar), yerleşik bir wordlist yöneticisi,
spider/AJAX taraması, stored/DOM XSS ve SSRF kontrolleri ile bant dışı (OAST)
etkileşim tespiti.

## Lisans

MIT — bkz. [LICENSE](LICENSE).
