# Windows’da haqiqiy sinov: qadamba-qadam ko‘rsatma

Bu ko‘rsatma BulutSkan’ning 3-bosqichini (xavfsiz skaner moduli, digest tekshiruvi, bazalarni yangilash, CLI) haqiqiy Docker bilan sinash uchun yozilgan. Bulutli muhitda Docker yo‘q edi, shuning uchun u yerda modul soxta ishga tushirgich bilan tekshirildi. Endi xuddi shu narsani kompyuteringizda ko‘ramiz.

Sinov ikki qismdan iborat:

1. **Eksperimentni takrorlash.** Platforma III bobdagi eksperiment bazalari va `.tar` arxivlari bilan ishga tushiriladi. Natija dissertatsiya raqamlari bilan aynan bir xil chiqishi kerak.
2. **Yangi bazalar bilan oddiy ish.** Bazalar proksi orqali yangilanadi va obraz to‘g‘ridan-to‘g‘ri nomi bilan tekshiriladi.

Taxminiy vaqt: 30–40 daqiqa (bazalarni yuklab olish internet tezligiga bog‘liq).

## 0. Boshlashdan oldin

Kompyuterda allaqachon bor:

- Windows 11, Docker Desktop (WSL 2), ishga tushirilgan;
- `aquasec/trivy:0.76.1`, `anchore/grype:v0.121.0`, `checkmarx/kics:v2.2.0` va `diss-checkov:3.3.26` obrazlari;
- proksi manzili Docker Desktop’da kiritilgan;
- `D:\Dissertatsiyaga oid\Robiyaxon\Sinov` papkasi: `cache\trivy`, `cache\grype` va `tar\*.tar` shu yerda.

Kerak bo‘ladi: Git va Python 3.11 yoki undan yangi (Anaconda).

> **Muhim.** `Sinov` papkasidagi hech narsa o‘zgartirilmaydi: bazalar va arxivlar faqat nusxalanadi yoki o‘qiladi. Proksi manzilini chatga yozmang. Sinov natijalarini yuborishda ham uni yashiring.

Barcha buyruqlar **PowerShell**’da bajariladi. Har bir bosqichdan keyin chiqish kodini ko‘rish uchun `echo $LASTEXITCODE` buyrug‘idan foydalaning.

## 1. Docker’ni tekshirish

```powershell
docker version --format "Docker server: {{.Server.Version}}"
docker images --digests --format "{{.Repository}}:{{.Tag}}  {{.Digest}}" | Select-String "trivy|grype|kics|checkov"
```

Kutilgan natija: to‘rtta obraz ko‘rinadi. Trivy, Grype va KICS digestlari `bulutskan\resources\tool_digests.txt` dagi qiymatlar bilan bir xil bo‘lishi kerak:

| Obraz | Digest boshi |
|---|---|
| `aquasec/trivy:0.76.1` | `sha256:790fd66d…` |
| `anchore/grype:v0.121.0` | `sha256:621d56d1…` |
| `checkmarx/kics:v2.2.0` | `sha256:ef29dbac…` |
| `diss-checkov:3.3.26` | mahalliy obraz, digesti yo‘q (`<none>`) |

## 2. Loyihani yuklab olish

```powershell
cd "D:\Dissertatsiyaga oid\Robiyaxon"
git clone https://github.com/Abduvokhobov5888/blutlik_texnologiya.git BulutSkan
cd BulutSkan
```

Agar `git clone` proksi xatosi bilan to‘xtasa, proksini faqat shu buyruq uchun bering (u hech qayerga saqlanmaydi):

```powershell
git -c http.proxy=http://PROKSI:PORT clone https://github.com/Abduvokhobov5888/blutlik_texnologiya.git BulutSkan
```

`PROKSI:PORT` qiymatini `docker info --format "{{.HTTPSProxy}}"` buyrug‘i ko‘rsatadi.

## 3. Python muhiti

Python versiyasini tekshiring:

```powershell
python --version
```

Agar u 3.11 dan past bo‘lsa, Anaconda’da yangi muhit oching:

```powershell
conda create -n bulutskan python=3.12 -y
conda activate bulutskan
```

So‘ng loyiha uchun virtual muhit yarating va kutubxonalarni o‘rnating:

```powershell
python -m venv .venv
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

`pip` proksi xatosini bersa: `pip install --proxy http://PROKSI:PORT -e ".[dev]"`.

Tekshirish:

```powershell
bulutskan --version
```

Kutilgan natija: `BulutSkan 0.1.0`.

> Keyingi barcha bosqichlar `BulutSkan` papkasida va faollashtirilgan `.venv` bilan bajariladi. Yangi PowerShell oynasi ochilsa, `.\.venv\Scripts\Activate.ps1` ni qayta bajaring.

## 4. Testlar (Docker’siz)

```powershell
python -m pytest -q
```

Kutilgan natija: `363 passed`. Bu testlar Docker’siz ishlaydi va Windows’da ham xuddi shunday o‘tishi kerak.

## 5. Vositalar yaxlitligi

```powershell
bulutskan tools verify
```

Kutilgan natija:

```text
Docker: …
  checkov  not_locked         Checkov obrazi qulflanmagan. Bajaring: bulutskan tools lock-checkov (diss-checkov:3.3.26)
  kics     ok                 Digest mos
  trivy    ok                 Digest mos
  grype    ok                 Digest mos
```

Chiqish kodi 2: Checkov hali qulflanmagan, shuning uchun tekshiruvlar bloklangan. Bu kutilgan holat.

Checkov’ni qulflang. Platforma obraz ichidagi `checkov --version` qiymatini tarmoqsiz konteynerda tekshiradi va obraz ID sini `data\tool_lock.json` ga yozadi:

```powershell
bulutskan tools lock-checkov
bulutskan tools verify
echo $LASTEXITCODE
```

Kutilgan natija: to‘rtala vosita `ok`, chiqish kodi `0`.

## 6. Eksperimentni takrorlash (III bob raqamlari)

### 6.1. Eksperiment bazalarini nusxalash

Platforma bazalarni `BulutSkan\data\db` dan o‘qiydi. `Sinov` dagi bazalar shu yerga **nusxalanadi**:

```powershell
Remove-Item -Recurse -Force data\db -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force data\db | Out-Null
Copy-Item -Recurse "D:\Dissertatsiyaga oid\Robiyaxon\Sinov\cache\trivy" data\db\trivy
Copy-Item -Recurse "D:\Dissertatsiyaga oid\Robiyaxon\Sinov\cache\grype" data\db\grype
bulutskan db-status
```

`db-status` Trivy bazasi sanasini `2026-11-24T07:08:30…` deb ko‘rsatishi kerak.

Grype besh kundan eski bazani qabul qilmaydi. Eksperiment bazasi 24-noyabrda yig‘ilgan, shuning uchun sana tekshiruvini **faqat shu PowerShell oynasi uchun** o‘chiramiz:

```powershell
$env:BULUTSKAN_GRYPE_VALIDATE_AGE = "false"
```

### 6.2. IaC fayllari

```powershell
bulutskan scan --iac bulutskan\resources\iac --json data\sinov_iac.json
```

Kutilgan natija (IaC tekshiruvi bazaga bog‘liq emas, shuning uchun raqamlar aynan bir xil bo‘lishi kerak):

| Ko‘rsatkich | Kutilgan qiymat |
|---|---|
| Checkov | 102 ta topilma |
| KICS | 114 ta topilma, xom yozuvlar: 116 |
| Trivy | 66 ta topilma |
| Ground truth: Checkov / KICS / Trivy | 36/40, 34/40, 32/40 |
| Jaccard (ground truth bo‘yicha) | 0,842; 0,838; 0,784 |
| Hech bir vosita topmagan | DF-03, K8S-09 |
| Konsensus: tasdiqlangan | 37 |

Konsensus bo‘limidagi Jaccard (0,821; 0,816; 0,789) III bobdagidan biroz farq qiladi. Bu xato emas: u xavfsiz fayllarni ham hisobga oladi, III bob usuli esa faqat xatoli fayllarni oladi. III bob bilan solishtirish uchun “Ground truth bo‘yicha” bo‘limidagi qiymatlarga qarang.

### 6.3. Obrazlar: eksperimentdagi `.tar` arxivlari

Arxiv konteynerga faqat o‘qish uchun ulanadi, nusxalanmaydi:

```powershell
bulutskan scan --image-tar "D:\Dissertatsiyaga oid\Robiyaxon\Sinov\tar\nginx_1.21.tar" --image-name nginx:1.21
```

Kutilgan natija (`ch3.json` bilan bir xil):

```text
Bazaviy obrazning qo‘llab-quvvatlash muddati tugagan. Skanerlar natijalari to‘liq emas, obrazni almashtiring.
…
  trivy    0.76.1      1133 ta topilma
  grype    0.121.0      792 ta topilma
…
  Tasdiqlangan: 502
  Tekshirish talab etiladi: 187
  Noyob CVE: Trivy 683, Grype 508, umumiy 502
  Jaccard trivy – grype: 0,729
  Asosiy Jaccard (CVE, CPE’siz): 0,759
```

Yana ikkita obraz, ular CPE belgisini va EOL ni tekshiradi:

```powershell
bulutskan scan --image-tar "D:\Dissertatsiyaga oid\Robiyaxon\Sinov\tar\alpine_3.18.tar" --image-name alpine:3.18
bulutskan scan --image-tar "D:\Dissertatsiyaga oid\Robiyaxon\Sinov\tar\python_3.9-slim.tar" --image-name python:3.9-slim
```

| Obraz | Kutilgan natija |
|---|---|
| `alpine:3.18` | Trivy 0, Grype 6 ta noyob CVE, 6 tasi CPE asosida, J = 0,000, EOL ogohlantirishi |
| `python:3.9-slim` | Trivy 237, Grype 276, umumiy 222, J = 0,763, CPE 54, EOL ogohlantirishi (Trivy EOSL bermaydi, platforma obraz nomi va `python 3.9.25` binar fayli orqali topadi) |

Natijada `(Trivy bazani faqat o‘qish rejimida ocha olmadi: nusxa bilan qayta urinildi)` degan izoh chiqishi mumkin. Bu xato emas: platforma bazani avval faqat o‘qish uchun ulab ko‘radi, Trivy bunga ko‘nmasa, nusxa bilan qayta urinadi. Izoh chiqsa, menga ayting: `.env` da `BULUTSKAN_TRIVY_DB_MODE=copy` ni doimiy qilib qo‘yamiz.

Eksperiment qismi tugadi. Sana tekshiruvini qayta yoqing:

```powershell
Remove-Item Env:BULUTSKAN_GRYPE_VALIDATE_AGE
```

## 7. Bazalarni yangilash (proksi orqali)

```powershell
bulutskan db-update
bulutskan db-status
```

Kutilgan natija:

```text
Proksi: aniqlandi
  trivy       yangilandi (… s) 2026-…
  trivy-java  yangilandi (… s) 2026-…
  grype       yangilandi (… s)
```

Proksi manzili ekranga ham, fayllarga ham chiqmaydi. Buni tekshirish uchun proksi IP manzilining bir qismini qidirib ko‘ring (natija bo‘sh bo‘lishi kerak):

```powershell
Select-String -Path data\db\holat.json -Pattern "PROKSI_IP_QISMI"
```

> 6-bosqichda nusxalangan eksperiment bazalari endi yangisi bilan almashdi. `Sinov\cache` dagi asl bazalar o‘zgarmaydi.

## 8. Oddiy ish rejimi

### 8.1. Obrazni nomi bo‘yicha tekshirish

Platforma obrazni yuklab oladi (`docker pull`, proksini Docker Desktop o‘zi ishlatadi), `.tar` ga saqlaydi va tarmoqsiz tekshiradi:

```powershell
bulutskan scan --image nginx:1.21 --fail-on critical --fixable-only
echo $LASTEXITCODE
```

Kutilgan natija: EOL ogohlantirishi, oxirida `KONVEYER TO‘XTATILADI (chiqish kodi 1)`, `$LASTEXITCODE` = 1. Raqamlar endi III bobdagidan farq qiladi, chunki baza yangi. Bu kutilgan holat.

### 8.2. IaC va `--fail-on`

```powershell
bulutskan scan --iac bulutskan\resources\iac --fail-on high
echo $LASTEXITCODE
```

Kutilgan natija: `1`.

### 8.3. `--unknown-severity`

Checkov ochiq versiyasi jiddiylik bermaydi. Uning xatolari `--fail-on` qarorida qanday hisoblanishini solishtiring:

```powershell
bulutskan scan --iac bulutskan\resources\iac\terraform --fail-on medium --unknown-severity ignore
bulutskan scan --iac bulutskan\resources\iac\terraform --fail-on medium
```

Ikkala holatda ham konveyer to‘xtaydi, chunki KICS va Trivy o‘rta va yuqori darajali xatolarni topgan. Farq “chegaradan oshgan guruhlar” sonida ko‘rinadi: ikkinchi buyruqda Checkov’ning noma’lum darajali topilmalari ham qo‘shiladi. Jadval tagida esa `UNKNOWN = noma’lum (CI uchun medium deb olindi)` yozuvi chiqadi.

## 9. Xavfsizlik choralarini ko‘z bilan tekshirish

### 9.1. Konteyner sozlamalari

Juice Shop tekshiruvi uzoqroq davom etadi. Uni bitta oynada ishga tushiring:

```powershell
bulutskan scan --image bkimminich/juice-shop:v15.0.0
```

Ikkinchi PowerShell oynasida, skaner ishlab turgan paytda:

```powershell
docker ps --format "{{.Names}}  {{.Image}}"
docker ps -q | ForEach-Object { docker inspect $_ --format "{{.Name}} tarmoq={{.HostConfig.NetworkMode}} readonly={{.HostConfig.ReadonlyRootfs}} capdrop={{.HostConfig.CapDrop}} secopt={{.HostConfig.SecurityOpt}} xotira={{.HostConfig.Memory}}" }
docker ps -q | ForEach-Object { docker inspect $_ --format "{{range .Mounts}}{{.Destination}} rw={{.RW}}; {{end}}" }
```

Kutilgan natija:

- obraz teg orqali emas, `aquasec/trivy@sha256:…` yoki `anchore/grype@sha256:…` orqali ishlaydi;
- `tarmoq=none readonly=true capdrop=[ALL] secopt=[no-new-privileges]`;
- `/input/image.tar` va baza `rw=false`. Grype’da faqat `/scratch` `rw=true`: bu shu tekshiruvga tegishli bo‘sh vaqtinchalik katalog.

### 9.2. Vaqtinchalik kataloglar

Tekshiruv tugagach:

```powershell
Get-ChildItem data\workdir
```

Kutilgan natija: bo‘sh. Har bir tekshiruv katalogi ish tugashi bilan o‘chiriladi. Xom hisobotlar `data\hisobotlar\{ID}\` da qoladi.

### 9.3. Digest mos kelmaganda bloklash

Qulf faylidagi Checkov ID sini ataylab buzamiz:

```powershell
Copy-Item data\tool_lock.json data\tool_lock.json.bak
(Get-Content data\tool_lock.json) -replace '"image_id": "sha256:[0-9a-f]{64}"', ('"image_id": "sha256:' + ('0' * 64) + '"') | Set-Content data\tool_lock.json
bulutskan scan --iac bulutskan\resources\iac
echo $LASTEXITCODE
```

Kutilgan natija: `Tekshiruv bloklandi — vositalar yaxlitligi tasdiqlanmadi…`, chiqish kodi `2`, birorta skaner ishga tushmaydi.

Asl holatga qaytarish:

```powershell
Move-Item -Force data\tool_lock.json.bak data\tool_lock.json
bulutskan tools verify
```

### 9.4. Zararli obraz nomi

```powershell
bulutskan scan --image "nginx:1.21; whoami"
echo $LASTEXITCODE
```

Kutilgan natija: `Obraz nomi noto‘g‘ri`, chiqish kodi `2`. Docker umuman chaqirilmaydi.

## 10. Natijani menga yuborish

Quyidagilarni matn ko‘rinishida yuboring (proksi manzili chiqqan bo‘lsa, uni o‘chiring):

1. 4-bosqich: `pytest` ning oxirgi qatori;
2. 5-bosqich: `bulutskan tools verify` chiqishi;
3. 6.2 va 6.3-bosqichlar: to‘liq chiqish;
4. 7-bosqich: `bulutskan db-update` chiqishi;
5. 9.1-bosqich: `docker inspect` qatorlari;
6. biror bosqichda xato bo‘lsa, xato matni.

## 11. Muammolar va yechimlar

| Belgi | Sabab va yechim |
|---|---|
| `bulutskan` buyrug‘i topilmadi | `.venv` faollashtirilmagan: `.\.venv\Scripts\Activate.ps1` |
| `Activate.ps1` ishga tushmaydi | `Set-ExecutionPolicy -Scope Process Bypass` |
| `pip` yoki `git` proksi xatosi | `--proxy http://PROKSI:PORT` yoki `git -c http.proxy=…` |
| `tools verify`: `missing` | `docker images --digests` bilan digestni solishtiring. Obraz yo‘q bo‘lsa: `bulutskan tools pull` |
| `tools verify`: `mismatch` | Teg boshqa obrazga ko‘rsatmoqda. Menga `docker images --digests` chiqishini yuboring |
| Grype: `the vulnerability database was built … ago` | Baza eski: `bulutskan db-update` (yoki 6.1-bosqichdagi vaqtinchalik sozlama) |
| `Xotira yetmadi (chiqish kodi 137)` | `.env` ga `BULUTSKAN_CONTAINER_MEMORY=4g` yozing. Docker Desktop → Settings → Resources’da xotira yetarli ekanini tekshiring |
| `Vaqt tugadi` | `.env` ga `BULUTSKAN_SCAN_TIMEOUT_S=1800` |
| Checkov yoki KICS `read-only file system` xatosini beradi | Xato matnini menga yuboring: vositaga qo‘shimcha `tmpfs` katalogi kerak bo‘ladi |
| `Mount yo‘lida ruxsat etilmagan belgi bor` | Papka yo‘lida vergul bor. Loyihani vergulsiz yo‘lga ko‘chiring |
| `docker save bajarilmadi` | Disk to‘lgan bo‘lishi mumkin: `data\workdir` va Docker Desktop disk hajmini tekshiring |
