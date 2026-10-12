# KnightOnLine.exe — Tersine Mühendislik Raporu (Sürüm 2)

**Dosya:** KnightOnLine.exe (10.299.392 bayt) · 32-bit x86 · MSVC ile derlenmiş · derleme tarihi 2021-10-07
**ImageBase:** 0x400000 · **Bölümler:** .text (kod), .rdata, .data, .rsrc

> **Adres okuma kılavuzu (önemli!)**
> - Bu rapordaki bütün **fonksiyon RVA'ları** gerçek RVA'dır. Cheat Engine'de adres = `KnightOnLine.exe + RVA` (yani 0x400000 + RVA).
> - **Global/değişken adresleri** zaten VA olarak verilmiştir (ör. `0xF50FD0`) — CE'ye doğrudan yazılabilir.
> - Örnek: Send fonksiyonu RVA `0xA5C40` → CE'de `KnightOnLine.exe+A5C40`.

> **İlk rapordan düzeltmeler**
> 1. `0x782250` bir "codec" değildir; CRT'nin standart **memmove** fonksiyonudur (paket yükünü taşımak için kullanılır).
> 2. Paketler yine de **şifrelenir**: gönderim hattında `0x6981D0` çağrısı + `0xED03E0` adresindeki şifreleme nesnesi (JvCryption tarzı, sabit anahtar `0x20128966 / 0x12075001`). Ayrıntısı §6'da.
> 3. "Jump table yok" sonucu yanlıştı: switch tabloları **var** (`0x4DA76C`, `0x4F0A2C`) ancak exe paketli/korumalı olduğundan disk üzerinde şifreli duruyorlar; oyun çalışırken RAM'de çözülmüş halde olurlar. Ayrıntısı §7'de.
> 4. Send wrapper'ın **496 çağrı yeri** tekrar doğrulandı (örnek: `0xA95D9`).

---

## 1. Genel mimari (kanıt: RTTI isimleri exe içinde bulundu)

Exe, Knight Online'ın klasik istemci kod ailesinden derlenmiş — RTTI kayıtlarında şu sınıf isimleri birebir okundu:
`CAPISocket`, `CGameProcedure`, `CGameProcMain`, `CGameProcCharacterSelect/Create`, `CGameProcLogIn` ailesi, `CN3FXBundleGame` vb.
Bu, açık kaynak **OpenKO** projesiyle aynı sınıf mimarisi (§8 karşılaştırma tablosu).

Ağ akışı özet:

```
GÖNDERME:
 oyun kodu (496 yerden) ─► CAPISocket::Send (0xA5C40)
   ├─ [0xEADFD4] bayrak kontrolü (log/mod)
   ├─ this ∈ { [0xF50FD0], [0xF50FD4] } kontrolü
   ├─ kritik bölüm (0xED03AC) + send bayrağı 0xED03B8
   ├─ şifreleme/paket inşası: 0x6981D0  (10 argüman; anahtar nesnesi 0xED03E0)
   ├─ başlık: htons(0xAA55) + uzunluk kelimesi  [bu kısım 0xA5F11-0xA5F25]
   ├─ el sıkışma modu [netobj+0x400DC]≠0 ise yük +4'ten, dönen sayaç baytı +5'e
   ├─ gövde kopyalama: memmove (0x782250)
   ├─ kuyruk: htons(0x55AA)
   └─ send() döngüsü [WSOCK32!ord19], hata 0x2733 (WSAEWOULDBLOCK) → PostQuitMessage

ALMA:
 WM_SOCKETMSG (WM=0x41F) pencere mesajı ─► WindowProc (0x108A1C / 0x108C1F / 0x41E47B / 0x422B64)
   └─► CAPISocket::Receive (0xA7160): ioctlsocket(FIONREAD) → recv() → halka tampona ekle
        └─► kuyruk: netobj+0x400E4 (Packet* deque), sayaç +0x40100
 oyun döngüsü ─► 0xD6950: kuyruktan paket çeker
   └─► sanal çağrı: [0xF50FF0] → vtable[+8]  (= aktif sahnenin ProcessPacket'i)
        ├─ CGameProcedure::ProcessPacket  0xDA450  (opcode 0x01–0xFE switch)
        └─ CGameProcMain::PacketProcess   0xF0870  (opcode 0x02–0x6E switch)
```

---

## 2. Tablo A — Kimliği belirlenen fonksiyonlar

| RVA | CE adresi | Kimlik / rol | Kanıt |
|---|---|---|---|
| `0xA5C40` | +A5C40 | **CAPISocket::Send** — paket gönderme (başlık AA55, şifreleme, 55AA, send döngüsü) | 496 çağrı yeri; iç yapı §1 |
| `0xA7160` | +A7160 | **CAPISocket::Receive** — recv döngüsü (FIONREAD → recv → halka tampon) | 6 çağrı yeri; IAT recv/ioctlsocket kullanımı |
| `0xD6950` | +D6950 | **Paket kuyruğu tüketici/dispatch** — kuyruktan (netobj+0x400E4) paket alır, aktif proc'un vtable[2] slotunu çağırır | 0x1B521C'den çağrılır; `[0xF50FF0]→[edx+8]` kalıbı |
| `0xDA450` | +DA450 | **CGameProcedure::ProcessPacket** — taban opcode switch (0x01–0xFE); son opcode'u `0xF51098`'e yazar | switch: index `0x4DA794`, tablo `0x4DA76C` |
| `0xF0870` | +F0870 | **CGameProcMain::PacketProcess** — oyun içi opcode switch (0x02–0x6E); önce tabanı dener | switch: index `0x4F0A50`, tablo `0x4F0A2C`; vtable `0xC6FFA4` slot[2] |
| `0xA5290` | +A5290 | **Packet ilk baytını (opcode) okuma** yardımcı | dispatch'lerin hepsinde ilk çağrı |
| `0x6981D0` | +6981D0 | **Paket şifreleme/inşa** yardımcısı (Send içinden 10 argümanla çağrılır) | 0xA5EAB çağrısı |
| `0x782250` | +782250 | CRT **memmove** | imza ve büyük-kopya dalı |
| `0xA56E0` | +A56E0 | **Connect** — inet_addr/gethostbyname → socket → WSAAsyncSelect(WM 0x41F, olay 0x1002) → connect | WSOCK32 ord zinciri |
| `0xA6560` | +A6560 | **Disconnect/Release** — closesocket, tampon sıfırlama, şifre anahtarını `0x20128966/0x12075001` ile yeniden kurma | IAT closesocket; anahtar sabitleri |
| `0xDDBC0` | +DDBC0 | **Bölge bağlantı kurucu** — şifre nesnesini başlatır, `[netobj+0x400D8]=port`, `[netobj+0x400DC]=0` yapar | 0xDDD8E'deki anahtar çağrısı |
| `0x7801A0` | +7801A0 | Şifre nesnesi **SetKey/Init** (this=0xED03E0) | 3 çağrı yeri: 0xA562F, 0xA65D2, 0xDDD8E |
| `0x780180` / `0x7801C0` | +780180/+7801C0 | Şifre nesnesi Reset / Clear | çağrı yerleri §6 |
| `0x780C76` | +780C76 | **Periyodik zamanlayıcı geri-çağrı çalıştırıcı** — 10 slotluk liste `0xF5F624`, sayaç `0xDBB4C4` | tek `call [eax*4+disp]` alanı |
| `0xD6250` | +D6250 | **Sahne/proc kaydedici** — aktif CGameProcedure'ı `[0xF50FF0]`'a yazar, `[netobj+0x178]=1` | WindowProc zinciri |
| `0x16CC50` | +16CC50 | Karakter seçimi sahnesi recv işleyici | recv çağrısı 0x16D0DB |
| `0x5902F0` | +5902F0 | Login yanıtı ayrıştırıcı | recv çağrısı 0x5907CF |
| `0x593520` / `0x593B10` | +593520 / +593B10 | Login-sonrası alt ayrıştırıcılar | recv çağrıları 0x593988 / 0x593F78 |
| `0x6990A0` | +6990A0 | Ek recv işleyici | recv çağrısı 0x699609 |
| `0x108A1C`, `0x108C1F`, `0x41E47B`, `0x422B64` | aynı | **WindowProc WM 0x41F** karşılaştırma bölgeleri | cmp 0x41F kalıpları |
| `0xA5B50` | +A5B50 | Kritik bölüm/sıra ilklendirici (Send ilk kullanımda) | 0xA5D1B çağrısı |

### Send wrapper'ın 496 çağrı yerinden örnekler
`0xA95D9, 0xAF7CE, 0xAFAD4, 0xAFC9F, 0xBEE14, 0xBEED7, 0xBF165, 0xBF4C5, 0xD07C3, 0xD3AC6, 0xE1AF6, 0x10D053, 0x11319B, 0x21C15B, 0x2254E8, 0x268A3F, 0x2B2395, 0x328180, 0x359AFE, 0x42BDDF, 0x483471, 0x4D7C47, 0x512B05, 0x59E8CD, 0x5B6A57, 0x5CC5AD …`
(Tam 496 adres çalışma betiklerinden üretilebilir; her biri bir "MsgSend_*" oyun fonksiyonudur.)

---

## 3. Tablo B — Globaller / işaretçiler

| Adres (VA) | Tür | Anlam |
|---|---|---|
| `0xF50FD0` | CAPISocket* | **Ana ağ nesnesi** (oyun sunucusu soketi); Send'in `this`'i |
| `0xF50FD4` | CAPISocket* | İkinci soket nesnesi (login/alt bağlantı) |
| `0xF50FE0` | nesne* | Oyun yöneticisi; `+0x178` = "oyunda" bayrağı |
| `0xF50FE4 / 0xF50FE8 / 0xF50FEC` | nesne* | Olay zinciri globalleri |
| `0xF50FF0` | CGameProcedure* | **Aktif sahne nesnesi** — dispatch bunun vtable'ından gider |
| `0xF50FF4` | HWND | Pencere kolu |
| `0xF51004` | nesne* | Kök uygulama nesnesi (`+0x20C` sahne, `+0x4DC` alt nesne, `+0x7EC` bayrak) |
| `0xF51098` | DWORD | **En son işlenen opcode** (0xDA49C'de yazılır) — log için altın değerinde |
| `0xF5108D` | BYTE | El sıkışma dönen sayaç baytı (1..0xFA) |
| `0xF52800` | BYTE | Tek-seferlik init bayrağı |
| `0xEADFD4` | BYTE | Send girişinde kontrol edilen mod/log bayrağı |
| `0xED03AC` | nesne | Send kritik bölümü / sıra nesnesi |
| `0xED03B4` | DWORD | Send tampon işaretçisi (başlık buraya yazılır) |
| `0xED03B8` | BYTE | Send bayrakları (bit0 = sıra kuruldu) |
| `0xED03D0/D4/D8` | sayaçlar | Şifreleme durum sayaçları |
| `0xED03E0` | nesne | **Şifreleme nesnesi** (JvCryption tarzı) |
| `0xDBB4C4` | DWORD | Zamanlayıcı geri-çağrı sayısı |
| `0xDBB524` | DWORD | CRT güvenlik çerezi (her fonksiyon girişinde görünür) |
| `0xDFCB68` | DWORD | Bağlantı durumu (1/2 kapısı) |
| `0xF5F624` | dizi | 10 slotluk periyodik geri-çağrı tablosu |
| `0x4DA76C` / `0x4DA794` | tablo | **Taban switch** case tablosu / opcode index tablosu (diskte şifreli) |
| `0x4F0A2C` / `0x4F0A50` | tablo | **Oyun-içi switch** case tablosu / opcode index tablosu (diskte şifreli) |
| `0xC6FFA4` | vtable | CGameProcMain vtable'ı (slot[2] = 0xF0870) |

### Ağ nesnesi (CAPISocket) alan haritası — `this = [0xF50FD0]`
| Ofset | Anlam |
|---|---|
| `+0x08` | SOCKET (geçersiz = -1) |
| `+0x9C` | bağlantı durumu bayrağı |
| `+0xA0` | recv tamponu (0x40000 bayt) |
| `+0x400B8` | şifre/anahtar bölgesi başlangıcı |
| `+0x400D8` | port |
| `+0x400DC` | el sıkışma/şifre modu (0 = düz, ≠0 = sayaçlı mod) |
| `+0x400E4` | gelen paket kuyruğu (Packet* deque) |
| `+0x40100` | kuyruktaki paket sayısı |
| `+0x40104` | gönderme izin bayrağı |

### WSOCK32 IAT eşlemesi (ord numarasıyla import)
| IAT (VA) | Fonksiyon |
|---|---|
| `0xC6A60C` | WSAAsyncSelect (ord101) |
| `0xC6A610` | connect (ord4) |
| `0xC6A614` | htons (ord9) |
| `0xC6A618` | **send** (ord19) |
| `0xC6A61C` | closesocket (ord3) |
| `0xC6A620` | ioctlsocket (ord12) |
| `0xC6A628` | **recv** (ord16) |
| `0xC6A600` | socket (ord23) |
| `0xC6A5F8` | inet_addr (ord10) |
| `0xC6A5FC` | gethostbyname (ord52) |
| `0xC6A608` | setsockopt (ord21) |
| `0xC6A604` | WSAGetLastError (ord111) |

---

## 4. Tablo C — Paket tel formatı

```
[ 0xAA55 (htons) ][ uzunluk (2 bayt LE) ][ YÜK ][ 0x55AA (htons) ]
YÜK (şifreli, JvCryption tarzı):
  - düz mod  : opcode + parametreler
  - el sıkışma modu ([netobj+0x400DC] != 0):
      yük+4 = şifre imza/sayaç alanı, yük+5 = dönen sayaç (0xF5108D, 1..0xFA), yük+6.. = paket
```

---

## 5. Tablo D — Opcode listesi (referans)

Opcode numaraları KO protokol ailesinde ortaktır. Tam liste `opcodes.csv` dosyasında (127 opcode, OpenKO kaynağından). Özet:

| Opcode | İsim | | Opcode | İsim |
|---|---|---|---|---|
| 0x01 | WIZ_LOGIN | | 0x2B | WIZ_VERSION_CHECK |
| 0x02 | WIZ_NEW_CHAR | | 0x2C | WIZ_CRYPTION |
| 0x03 | WIZ_DEL_CHAR | | 0x2D | WIZ_USERLOOK_CHANGE |
| 0x04 | WIZ_SEL_CHAR | | 0x2E | WIZ_NOTICE |
| 0x05 | WIZ_SEL_NATION | | 0x2F | WIZ_PARTY |
| 0x06 | WIZ_MOVE | | 0x30 | WIZ_EXCHANGE |
| 0x07 | WIZ_USER_INOUT | | 0x31 | WIZ_MAGIC_PROCESS |
| 0x08 | WIZ_ATTACK | | 0x32 | WIZ_SKILLPT_CHANGE |
| 0x09 | WIZ_ROTATE | | 0x33 | WIZ_OBJECT_EVENT |
| 0x0A | WIZ_NPC_INOUT | | 0x34 | WIZ_CLASS_CHANGE |
| 0x0B | WIZ_NPC_MOVE | | 0x3C | WIZ_KNIGHTS_PROCESS |
| 0x0C | WIZ_ALLCHAR_INFO_REQ | | 0x3E | WIZ_KNIGHTS_LIST |
| 0x0D | WIZ_GAMESTART | | 0x3F | WIZ_ITEM_REMOVE |
| 0x0E | WIZ_MYINFO | | 0x42 | WIZ_COMPRESS_PACKET |
| 0x0F | WIZ_LOGOUT | | 0x45 | WIZ_WAREHOUSE |
| 0x10 | WIZ_CHAT | | 0x4B | WIZ_WARP_LIST |
| 0x11 | WIZ_DEAD | | 0x52 | WIZ_CLIENT_EVENT |
| 0x12 | WIZ_REGENE | | 0x5B | WIZ_ITEM_UPGRADE |
| 0x13 | WIZ_TIME | | 0x64 | WIZ_QUEST |
| 0x14 | WIZ_WEATHER | | 0x68 | WIZ_MERCHANT |
| 0x17 | WIZ_HP_CHANGE | | 0x6A | WIZ_SHOPPING_MALL |
| 0x1A | WIZ_EXP_CHANGE | | 0x70 | WIZ_CAPE |
| 0x1B | WIZ_LEVEL_CHANGE | | 0x71 | WIZ_PREMIUM |
| 0x1E | WIZ_WARP | | 0x76 | WIZ_PET |
| 0x1F | WIZ_ITEM_MOVE | | 0x78 | WIZ_KING |
| 0x20 | WIZ_NPC_EVENT | | 0x7B | WIZ_BIFROST |
| 0x21 | WIZ_ITEM_TRADE | | 0x7C+ | 23xx'te eklenen yeni opcodes |
| 0x22 | WIZ_TARGET_HP | | | |
| 0x25 | WIZ_TRADE_NPC | | | |
| 0x26 | WIZ_ITEM_GET | | | |
| 0x27 | WIZ_ZONE_CHANGE | | | |
| 0x28 | WIZ_POINT_CHANGE | | | |
| 0x29 | WIZ_STATE_CHANGE | | | |
| 0x2A | WIZ_LOYALTY_CHANGE | | | |

Not: Senin exende taban switch 0x01–0xFE aralığını kapsıyor (254 slot) — yani 0x7F üstü 23xx dönemine ait yeni opcodlar da tabloya dahil.

---

## 6. Şifreleme katmanı (düzeltilmiş bulgu)

- Şifreleme nesnesi: **`0xED03E0`** (global, tek örnek).
- Anahtar sabitleri: **`0x20128966` ve `0x12075001`** — üç yerde yazılıyor: bağlantı kurulumu (`0xA562F`), koparma/sıfırlama (`0xA65D2`), bölge girişi (`0xDDD8E`). OpenKO'daki `InitCrypt(PublicKey)` ile aynı rol; fark: resmi 23xx istemcide anahtar sabit gömülü.
- Şifre fonksiyonları: `0x7801C0` (Clear), `0x780180` (Reset), `0x7801A0` (SetKey/Init).
- Send hattında yükü işleyen asıl fonksiyon: **`0x6981D0`**.
- Açık kaynak karşıtı: OpenKO `shared/JvCryption.h` — algoritma aynı aile (XOR tabanlı akış şifresi + crc32).

---

## 7. Dispatch tabloları ve paketli-exe durumu

**Durum:** Exe'nin ilk import'u `RP.softw` (koruma/paketleyici kalıntısı), giriş noktası CRT başlangıcının ortasına işaret ediyor ve switch tablolarının bulunduğu `.text` bölgeleri diskte şifreli/bozuk çıktı. Yani:

- `0x4DA76C` (254 case adresi) ve `0x4DA794` (opcode→slot index) — **diskte okunamıyor, RAM'de çözülür.**
- `0x4F0A2C` (109 case adresi) ve `0x4F0A50` (index) — aynı.

**Bu iyi haber:** Oyun çalışırken bu tablolar gerçek halleriyle RAM'de durur. CE ile tek seferde dump edilebilirler:

1. Oyuna gir, CE'de `KnightOnLine.exe+4DA794` adresinden **254 bayt** oku → her bayt bir slot numarası (opcode N için slot = bayt[N-1]).
2. `KnightOnLine.exe+4DA76C` adresinden **slotSayısı×4 bayt** oku → her dword bir handler'ın VA'sı. Handler RVA = değer − 0x400000.
3. Aynısını `+4F0A50` (109 bayt) ve `+4F0A2C` için yap.
4. Sağlama: `KnightOnLine.exe+F51098` = o anda işlenen opcode (loglayarak eşleştirme yapılabilir).
5. Alternatif izleme: `KnightOnLine.exe+DA450` fonksiyon girişine breakpoint koy; `ESP+4`/`ESP+8` = paket işaretçileri.

Dispatch'in kendisi statik olarak çözüldü (§2: 0xD6950 → 0xDA450 → 0xF0870 zinciri); eksik olan yalnızca case→fonksiyon eşlemesi ve o da RAM'den alınacak.

---

## 8. Tablo E — OpenKO karşılaştırması

OpenKO (github.com/Open-KO/KnightOnline), KO'nun **1.298** sürümünün açık kaynak yeniden inşasıdır; istemci + sunucu içerir. Senin exen resmi 2021 (23xx) istemcisi — sürüm farkı büyük ama **sınıf mimarisi ve paket formatı aynı aile** (kanıt: RTTI isimleri ve AA55/55AA formatının birebir tutması).

| OpenKO kaynağındaki sembol (1.298) | Senin exendeki karşılığı | Not |
|---|---|---|
| `CAPISocket::Send(uint8_t*,int)` | **`0xA5C40`** | Aynı tel formatı; 23xx'te kritik bölüm eklenmiş |
| `CAPISocket::Receive()` | **`0xA7160`** | Aynı FIONREAD→recv→halka tampon akışı |
| `ExpandableCircularBuffer` (halka tampon) | Receive içinde, tampon `this+0xA0` | OpenKO'da `m_CB` alanı |
| `CAPISocket::ReceiveProcess()` (AA55/55AA çerçeveleme) | Receive + `0xD6950` bölgesine dağıtılmış | kuyruk `netobj+0x400E4` |
| `CAPISocket::Connect()` | **`0xA56E0`** | Aynı socket→WSAAsyncSelect→connect sırası |
| `WM_SOCKETMSG = WM_USER+1` (0x401) | **WM = 0x41F** | 23xx farklı mesaj numarası kullanıyor |
| `CJvCryption s_JvCrypt` (statik) | **nesne `0xED03E0`** | 1.298'de anahtar sunucudan gelir (WIZ_VERSION_CHECK); 23xx'te sabit `0x20128966` |
| `PACKET_HEADER 0xAA55 / PACKET_TAIL 0x55AA` | aynı (0xA5F11 / 0xA5F4D) | birebir |
| `s_pSocket` (global soket) | **`[0xF50FD0]`** | |
| `s_pSocketSub` | **`[0xF50FD4]`** | |
| `CGameProcedure::ProcessPacket(pkt)` switch | **`0xDA450`** | OpenKO'da 5 case; 23xx'te 254 slot |
| `CGameProcMain::PacketProcess` switch | **`0xF0870`** | OpenKO'da yüzlerce `MsgRecv_*` metoduna dağıtır |
| `MsgRecv_*` handler metodları | case tablosundan çıkacak (RAM dump, §7) | |
| `MsgSend_*` çağrıları | 496 çağrı yerinin her biri (§2) | |
| `DataPack / Packet : ByteBuffer` | `Packet` (opcode okuma: `0xA5290`) | |
| `SEND_BUF_SIZE/RECV_BUF_SIZE 262144` | recv tamponu 0x40000 (262144) | birebir |

**23xx hedefli OpenKO fork'u var mı?** Araştırma sonucu: OpenKO'nun genel fork'ları (ChickenHin, tamirbr, yme1019 vb.) hepsi 1.298 tabanlı; **23xx istemci kaynak kodu yayımlamış bir OpenKO fork'u bulunamadı.** 2369/2383 sürümleriyle dolaşan repolar (ör. 2383 sunucu dosyaları) yalnızca derlenmiş binary içeriyor, kaynak/offset tablosu yok. Bu yüzden karşılaştırma tablosu OpenKO 1.298 sembolleri üzerinden yapıldı — mimari aynı olduğundan eşlemeler geçerli.

---

## 9. Tam fonksiyon listesi

`funcs.csv` — CC dolgusuna göre belirlenen **32.070 fonksiyon**: sütunlar `rva, size, cmp_sayisi, call_sayisi` (RVA'ya göre sıralı). Bilinen tüm fonksiyonlar bunun içinde (ör. `000a5c40` = Send, 1024 bayt). İsimlendirme §2 tablosuyla birleştirilebilir; kalan ~32.000 fonksiyonun adlandırılması ancak kullanım yerine bağlayarak (caller analizi) yapılabilir — bu da bir sonraki adım olarak senin talimatını bekliyor.

Ek dosyalar:
- `opcodes.csv` — 127 WIZ opcode (isim + açıklama)
- `kore/dispatch_info.json` — dispatch yapısı özeti
- `kore/openko/*` — indirilen OpenKO kaynak dosyaları (APISocket.h/.cpp, PacketDef.h, GameProcMain.h, packets.h …)

---

## 10. Özet ve sonraki adımlar

1. **Gönderme tarafı tam çözüldü:** tek giriş `0xA5C40`; 496 oyun fonksiyonu buradan paket gönderir; format ve şifreleme hattı belgelendi.
2. **Alma tarafı çözüldü:** recv → halka tampon → kuyruk → `0xD6950` → `0xDA450`/`0xF0870` switch zinciri.
3. **Eksik tek parça:** opcode→handler case adresleri (diskte şifreli). §7'deki 5 adımla oyun içinden tek seferde alınabilir; istersen onu otomatikleştiren bir CE Lua betiği hazırlayabilirim.
4. Hatırlatma: GitHub'taki `benim-oyunum` reposu hâlâ **herkese açık** — işin bitince gizliye almayı unutma.

Bir sonraki talimatını bekliyorum.
