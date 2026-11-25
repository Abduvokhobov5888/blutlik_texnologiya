# BulutSkan arxitekturasi

> **Holat:** 3-bosqich bajarildi: xavfsiz skaner moduli, digest tekshiruvi, bazalarni yangilash, fayl yuklash himoyasi, tekshiruv quvuri va CLI ning asosiy buyruqlari. Haqiqiy Docker bilan sinov ko‘rsatmasi: [windows_sinov.md](windows_sinov.md).
> 1-bosqichda ⚠ bilan belgilangan joylar `Sinov` materiallari (`analyze.py`, `stats3.py`, `ground_truth.csv`, `run_tests.ps1`, `tool_digests.txt`, `ahp/`) asosida aniqlashtirildi.

BulutSkan — bulutli infratuzilma kodini (IaC) va konteyner obrazlarini bir nechta ochiq kodli skaner bilan tekshiradigan mahalliy veb-platforma. U Andijon davlat universiteti magistranti Odilova Robiyaxonning “Bulutli hisoblash texnologiyalari xavfsizligini ta’minlovchi dasturiy vositalarni qiyosiy tahlil qilish va ochiq kodli vositalar samaradorligini baholash” mavzusidagi dissertatsiyasining amaliy natijasidir.

## 1. Asosiy tamoyillar

Platformaning har bir qismi dissertatsiya xulosalaridan kelib chiqadigan beshta tamoyilga bo‘ysunadi:

1. **Bitta skanerga ishonilmaydi.** Har bir obyekt kamida ikkita vosita bilan tekshiriladi. Natijalar konsensus va Jaccard koeffitsienti orqali taqqoslanadi.
2. **Skaner — ishonchsiz kod.** Har bir vosita alohida, tarmoqsiz, imtiyozsiz va resurslari cheklangan konteynerda ishlaydi.
3. **Ta’minot zanjiri qotiriladi.** Vositalar teg orqali emas, faqat sha256 digest orqali chaqiriladi. Digest mos kelmasa, tekshiruv boshlanmaydi.
4. **Internet faqat bitta bosqichda kerak.** Zaifliklar bazalari alohida “bazalarni yangilash” amali bilan yuklanadi. Tekshiruvning o‘zi internetsiz bajariladi.
5. **Ma’lumotlar mahalliy qoladi.** Telemetriya, tashqi CDN va tashqi API yo‘q. Ilova sukut bo‘yicha faqat `127.0.0.1` manzilida tinglaydi.

## 2. Umumiy ko‘rinish

```mermaid
flowchart LR
    subgraph U["Foydalanuvchi"]
        BR["Brauzer<br/>Jinja2 + HTMX + Chart.js"]
        CL["CLI: bulutskan<br/>Typer, CI/CD rejimi"]
    end

    subgraph P["BulutSkan platformasi (127.0.0.1)"]
        WEB["web<br/>FastAPI, login, CSRF, i18n"]
        SEC["security<br/>yuklash himoyasi, obraz nomi regexi"]
        JOB["services.jobs<br/>fon navbati"]
        PIPE["services.pipeline<br/>tekshiruv quvuri"]
        SCN["scanner<br/>xavfsiz docker run"]
        TLS["scanner.tools<br/>digest reestri va yaxlitlik"]
        PRS["parsers<br/>Checkov, KICS, Trivy, Grype"]
        CORE["core<br/>yagona model, dedup,<br/>konsensus, Jaccard, EOL"]
        AHP["core.ahp<br/>vosita tanlash"]
        REP["reporting<br/>DOCX, JSON"]
        DB[("SQLite")]
    end

    subgraph D["Docker Engine"]
        CK["Checkov"]
        KI["KICS"]
        TR["Trivy"]
        GR["Grype"]
    end

    BR --> WEB
    WEB --> SEC --> JOB --> PIPE
    CL --> SEC
    CL --> PIPE
    PIPE --> SCN
    SCN --> TLS
    SCN -- "tarmoqsiz, faqat o‘qish" --> D
    D -- "JSON hisobot" --> PRS
    PRS --> CORE --> DB
    PIPE --> REP
    WEB --> AHP
    WEB --> DB
```

Veb-interfeys va CLI bir xil `services.pipeline` quvurini chaqiradi. Shu sababli brauzer va CI/CD bir xil natija beradi.

## 3. Modullar

| Modul | Vazifasi | Bosqich |
|---|---|---|
| `bulutskan.config` | `.env` faylidan sozlamalarni o‘qish (pydantic-settings), kataloglar va limitlar | 2 |
| `bulutskan.core.models` | Yagona topilma modeli, jiddiylik va holat sanoqlari (enum) | 2 |
| `bulutskan.core.normalize` | Jiddiylik va holatni normallashtirish, GHSA → CVE (`stats3.py` asosida) | 2 |
| `bulutskan.core.dedup` | Bitta vosita ichidagi takroriy topilmalarni birlashtirish | 2 |
| `bulutskan.core.categories` | IaC xato toifalari: `ground_truth.csv` dagi regex qoidalari | 2 |
| `bulutskan.core.consensus` | Vositalararo guruhlash, “Tasdiqlangan” va boshqa belgilar, Jaccard | 2 |
| `bulutskan.core.eol` | Eskirgan bazaviy obrazni aniqlash | 2 |
| `bulutskan.core.ahp` | AHP vaznlari, ballar, ssenariylar, reyting | 2 |
| `bulutskan.core.gate` | `--fail-on` qarori, `--unknown-severity` siyosati | 3 |
| `bulutskan.parsers.*` | Checkov, KICS, Trivy (image va config), Grype JSON parserlari (`analyze.py` asosida) | 2 |
| `bulutskan.scanner.docker` | `docker` buyrug‘ini argumentlar ro‘yxati sifatida qurish va ishga tushirish | 3 |
| `bulutskan.scanner.runs` | Vosita natijasi, qabul qilinadigan chiqish kodlari, xato izohlari | 3 |
| `bulutskan.scanner.tools` | Vositalar reestri, digest yaxlitligini tekshirish | 3 |
| `bulutskan.scanner.iac`, `.image` | IaC va obraz tekshiruvi ssenariylari | 3 |
| `bulutskan.scanner.dbupdate` | Trivy, Trivy Java va Grype bazalarini yangilash | 3 |
| `bulutskan.security.*` | Yuklash himoyasi, vaqtinchalik katalog, obraz nomi regexi, bcrypt | 3–4 |
| `bulutskan.storage.*` | SQLAlchemy jadvallari va so‘rovlar | 4 |
| `bulutskan.services.*` | Tekshiruv quvuri, fon navbati, solishtirish, demo-import | 3–7 |
| `bulutskan.web.*` | FastAPI ilovasi, marshrutlar, shablonlar, statik fayllar | 4 |
| `bulutskan.reporting.json_export` | JSON eksport | 3 |
| `bulutskan.reporting.docx_report` | DOCX hisobot | 5 |
| `bulutskan.cli` | Typer buyruqlari: `scan`, `db-update`, `db-status`, `tools` (3), `demo-import`, `user`, `serve` (4–7) | 3–7 |

Kodda identifikatorlar ingliz tilida, izohlar va docstring’lar o‘zbek tilida yoziladi. Barcha funksiyalarda tur izohlari (type hints) bo‘ladi.

## 4. Papkalar tuzilmasi

Repozitoriy ildizi — `BulutSkan` loyihasining o‘zi. Windows’da u `D:\Dissertatsiyaga oid\Robiyaxon\BulutSkan` papkasiga klon qilinadi.

```text
BulutSkan/
├── bulutskan/
│   ├── __init__.py              # versiya
│   ├── __main__.py              # python -m bulutskan
│   ├── config.py                # Settings (.env)
│   ├── cli.py                   # Typer: scan, db-update, tools, demo-import, user, serve
│   ├── core/
│   │   ├── models.py            # Finding, Severity, FindingStatus, ToolReport, ScanResult
│   │   ├── normalize.py         # jiddiylik, holat, CVE normallashtirish
│   │   ├── dedup.py             # takrorlarni birlashtirish
│   │   ├── categories.py        # IaC toifalari (ground_truth.csv)
│   │   ├── consensus.py         # konsensus guruhlari, Jaccard
│   │   ├── eol.py               # EOL aniqlash
│   │   └── ahp.py               # AHP
│   ├── parsers/
│   │   ├── base.py              # umumiy interfeys, JSON ni xavfsiz o‘qish
│   │   ├── checkov.py
│   │   ├── kics.py
│   │   ├── trivy.py             # image (zaiflik) va config (noto‘g‘ri sozlama)
│   │   └── grype.py
│   ├── scanner/
│   │   ├── docker.py            # xavfsiz docker argumentlari, subprocess, timeout
│   │   ├── tools.py             # reestr va digest tekshiruvi
│   │   ├── iac.py
│   │   ├── image.py             # pull → save → internetsiz skan
│   │   └── dbupdate.py          # bazalarni yangilash, proksini aniqlash
│   ├── security/
│   │   ├── upload_guard.py      # hajm, zip-slip, oq ro‘yxat, tar tekshiruvi
│   │   ├── workspace.py         # tekshiruv uchun vaqtinchalik katalog
│   │   ├── validators.py        # obraz nomi regexi
│   │   └── passwords.py         # bcrypt
│   ├── storage/
│   │   ├── db.py                # engine, sessiya
│   │   ├── tables.py            # ORM jadvallari
│   │   └── repo.py              # saqlash va o‘qish
│   ├── services/
│   │   ├── pipeline.py          # parse → dedup → konsensus → EOL → saqlash
│   │   ├── jobs.py              # fon navbati
│   │   ├── compare.py           # ikki tekshiruvni solishtirish
│   │   └── demo.py              # demo-import
│   ├── reporting/
│   │   ├── docx_report.py
│   │   └── json_export.py
│   ├── resources/
│   │   ├── tool_digests.txt     # Sinov\natijalar dan nusxa
│   │   ├── checkov.Dockerfile   # Sinov dan nusxa
│   │   ├── ground_truth.csv     # Sinov dan nusxa
│   │   ├── ahp.json             # Sinov\ahp: matritsa A, xos vektor w
│   │   ├── ahp_upd.json         # Sinov\ahp: ballar S2, sezgirlik natijalari
│   │   ├── iac/                 # Sinov\iac: insecure va secure test fayllari
│   │   └── eol.json             # ichki EOL ro‘yxati
│   └── web/
│       ├── app.py               # FastAPI fabrikasi, middleware’lar
│       ├── auth.py              # login, sessiya, urinishlar cheklovi
│       ├── csrf.py
│       ├── i18n.py
│       ├── i18n/uz.json, en.json
│       ├── routes/              # dashboard, iac, image, scans, compare, ahp, tools
│       ├── templates/           # base.html, sahifalar, partials/
│       └── static/              # css/, js/, icons/, vendor/ (htmx, Chart.js)
├── demo/sinov/
│   ├── natijalar/               # Sinov\natijalar: real JSON hisobotlar (testlar va demo-import uchun)
│   │   └── tahlil/              # ch3.json, summary.json: testlar uchun kutilgan natijalar
│   └── skriptlar/               # asl skriptlar (analyze.py, stats3.py, run_tests.ps1 ...), faqat ma’lumot uchun
├── tests/
│   ├── conftest.py              # demo/sinov dagi hisobotlarni fixture sifatida yuklaydi
│   └── test_*.py
├── ci/
│   ├── github-actions.yml       # namuna
│   └── gitlab-ci.yml            # namuna
├── docs/arxitektura.md
├── pyproject.toml
├── requirements.txt
├── run.ps1
├── docker-compose.yml           # ixtiyoriy
├── .env.example
├── .gitignore
├── LICENSE                      # MIT
└── README.md
```

Ish vaqtida yaratiladigan barcha fayllar ildizdagi `data/` katalogiga tushadi va repozitoriyga kirmaydi:

```text
data/
├── bulutskan.db                 # SQLite
├── workdir/{scan_uid}/          # har tekshiruv uchun alohida, ish tugagach o‘chiriladi
│   ├── input/                   # yuklangan va ochilgan IaC fayllar yoki image.tar
│   └── out/                     # faqat KICS natija fayli uchun (7.4-bo‘limga qarang)
├── db/trivy/                    # Trivy asosiy va Java bazalari
├── db/grype/                    # Grype bazasi
└── hisobotlar/{scan_uid}/       # xom JSON hisobotlar, DOCX
```

`Sinov` papkasidagi fayllar o‘zgartirilmaydi. Kerakli fayllar repozitoriyga nusxa sifatida olinadi: platforma ishlashi uchun zarur kichik fayllar `bulutskan/resources/` ga, real hisobotlar (59 MB) `demo/sinov/natijalar/` ga. Hisobotlarning bitta nusxasi ham testlar, ham `demo-import` uchun xizmat qiladi. Har bir obraz uchun faqat `run1` olingan: uchta takror natijasi bir xil chiqqan.

## 5. Tekshiruv jarayonlari

### 5.1. IaC tekshiruvi

```mermaid
sequenceDiagram
    autonumber
    actor F as Foydalanuvchi
    participant W as Web yoki CLI
    participant G as upload_guard
    participant S as pipeline
    participant D as Docker Engine
    participant B as SQLite

    F->>W: ZIP yoki Terraform, YAML, Dockerfile fayllari
    W->>G: hajm, zip-slip, oq ro‘yxat
    G->>G: workdir/{uid}/input ga xavfsiz ochish
    G-->>W: ruxsat etilgan fayllar ro‘yxati
    W->>B: Scan (holat: navbatda)
    W->>S: navbatga qo‘yish
    S->>S: vosita digestlarini tekshirish
    S->>D: Checkov (input :ro, tarmoqsiz)
    D-->>S: JSON (stdout)
    S->>D: KICS (input :ro, tarmoqsiz)
    D-->>S: results.json (out/)
    S->>D: Trivy config (input :ro, tarmoqsiz)
    D-->>S: JSON (stdout)
    S->>S: parse, dedup, toifalash, konsensus, Jaccard
    S->>B: ToolRun, Finding, FindingGroup
    S->>S: workdir/{uid} ni o‘chirish
    W-->>F: natijalar sahifasi
```

### 5.2. Konteyner obrazi tekshiruvi

```mermaid
sequenceDiagram
    autonumber
    actor F as Foydalanuvchi
    participant W as Web yoki CLI
    participant V as validators
    participant S as pipeline
    participant D as Docker Engine
    participant B as SQLite

    F->>W: obraz nomi (nginx:1.21) yoki .tar fayl
    W->>V: qat’iy regex yoki tar tuzilmasi tekshiruvi
    V-->>W: ruxsat
    W->>B: Scan (holat: navbatda)
    W->>S: navbatga qo‘yish
    S->>S: vosita digestlarini tekshirish
    S->>D: docker pull nginx:1.21
    S->>D: docker save -o workdir/{uid}/input/image.tar
    S->>D: Trivy image --input /input/image.tar (tarmoqsiz)
    D-->>S: JSON (stdout)
    S->>D: Grype docker-archive:/input/image.tar (tarmoqsiz)
    D-->>S: JSON (stdout)
    S->>S: parse, dedup, CVE konsensus, CPE belgisi, Jaccard, EOL
    S->>B: ToolRun, Finding, FindingGroup
    S->>S: workdir/{uid} ni o‘chirish
    W-->>F: natijalar sahifasi va EOL ogohlantirishi
```

Foydalanuvchi obrazi hech qachon `docker run` bilan ishga tushirilmaydi. U faqat yuklab olinadi va `.tar` arxivga saqlanadi. `.tar` fayl yuklanganda pull va save bosqichlari o‘tkazib yuboriladi.

Vositalar ketma-ket ishlaydi. Bir vaqtda faqat bitta skaner konteyneri ishlaydi, shuning uchun CPU va xotira limitlari kompyuterni band qilib qo‘ymaydi.

### 5.3. Bazalarni yangilash

```mermaid
sequenceDiagram
    autonumber
    actor F as Foydalanuvchi
    participant W as Web yoki CLI
    participant U as dbupdate
    participant D as Docker Engine
    participant B as SQLite

    F->>W: “Bazalarni yangilash”
    W->>U: ishga tushirish
    U->>D: docker info (HTTPSProxy maydoni)
    D-->>U: proksi manzili (faqat xotirada)
    U->>D: Trivy --download-db-only (db/trivy, tarmoq va proksi bilan)
    U->>D: Trivy --download-java-db-only (db/trivy)
    U->>D: Grype db update (db/grype)
    U->>U: metadata.json va db status dan sanalarni o‘qish
    U->>B: DbUpdate (sana, versiya, holat)
    W-->>F: yangilanish sanalari
```

Proksi manzili faqat shu bosqichda ishlatiladi. U faylga, bazaga va jurnalga yozilmaydi. Jurnalda faqat “proksi aniqlandi: ha/yo‘q” ko‘rinadi, chunki manzil ichida login va parol bo‘lishi mumkin.

Obrazni `docker pull` bilan yuklashda platforma proksi bermaydi. Bu ishni Docker Desktop o‘z sozlamalari bilan bajaradi.

### 5.4. Tekshiruv holatlari

```mermaid
stateDiagram-v2
    [*] --> navbatda
    navbatda --> ishlamoqda: ishchi oldi
    ishlamoqda --> tugadi: barcha vositalar muvaffaqiyatli
    ishlamoqda --> qisman: kamida bitta vosita xato berdi
    ishlamoqda --> xato: tekshiruv bajarilmadi
    navbatda --> xato: server qayta ishga tushdi
    tugadi --> [*]
    qisman --> [*]
    xato --> [*]
```

“Qisman” holatida konsensus faqat ishlagan vositalar bo‘yicha hisoblanadi va natijalar sahifasida bu haqda ogohlantirish chiqadi.

## 6. Yagona topilma modeli

### 6.1. Maydonlar

Talab qilingan to‘qqizta maydonga konsensus, hisobot va solishtirish uchun kerakli yordamchi maydonlar qo‘shiladi.

| Maydon | Tur | Ma’nosi |
|---|---|---|
| `tool` | enum | Vosita: checkov, kics, trivy, grype |
| `target` | str | Fayl (IaC) yoki paket nomi (obraz) |
| `resource` | str \| None | Resurs (IaC) yoki paket joylashuvi (obraz) |
| `rule_id` | str | Qoida ID yoki zaiflik ID |
| `title` | str | Nomi |
| `severity` | enum | CRITICAL, HIGH, MEDIUM, LOW, INFO, UNKNOWN |
| `cve` | str \| None | Normallashtirilgan CVE |
| `fixed_version` | str \| None | Tuzatilgan versiya |
| `status` | enum | Holat (6.3-bo‘lim) |
| `kind` | enum | `vulnerability` yoki `misconfiguration` |
| `installed_version` | str \| None | O‘rnatilgan versiya |
| `package_type` | str \| None | deb, apk, npm, jar, binary va hokazo |
| `category` | str \| None | IaC xato toifasi (`ground_truth.csv`) |
| `cpe_based` | bool | Grype natijasi CPE yoki binar fayl orqali topilganmi |
| `line_start`, `line_end` | int \| None | IaC faylidagi qatorlar |
| `primary_url` | str \| None | Qoida yoki CVE havolasi |
| `fingerprint` | str | Takrorlarni aniqlash kaliti (6.4-bo‘lim) |

### 6.2. Manba maydonlari

Mantiq `analyze.py` va `stats3.py` dan ko‘chirilgan. Fayl yo‘llari vositalarda turlicha (Checkov `/iac/x.tf`, KICS `../../iac/x.tf`, Trivy `x.tf`), shuning uchun parserlar ularni tekshiruv ildiziga nisbatan bir xil yo‘lga keltiradi (`canonical_path`). Checkov uchun `file_abs_path` ishlatiladi. KICS uchun `search_key` va `resource_name` alohida saqlanadi: ground truth tokeni ikkalasida ham qidiriladi.

| Maydon | Checkov | KICS | Trivy config | Trivy image | Grype |
|---|---|---|---|---|---|
| `target` | `file_path` | `files[].file_name` | `Results[].Target` | `PkgName` | `artifact.name` |
| `resource` | `resource` | `files[].resource_name` / `search_key` | `CauseMetadata.Resource` | `PkgPath` yoki `Target` | `artifact.locations[].path` |
| `rule_id` | `check_id` | `query_id` | `ID` (AVD) | `VulnerabilityID` | `vulnerability.id` |
| `title` | `check_name` | `query_name` | `Title` | `Title` | `vulnerability.id` + tavsif |
| `severity` | `severity` (ko‘pincha `null`) | `severity` | `Severity` | `Severity` | `vulnerability.severity` |
| `cve` | — | — | — | `VulnerabilityID` | `id` yoki `relatedVulnerabilities[].id` |
| `fixed_version` | — | — | — | `FixedVersion` | `vulnerability.fix.versions[]` |
| `status` | `FAILED` | — | `Status` | `Status` | `vulnerability.fix.state` |
| qatorlar | `file_line_range` | `files[].line` | `CauseMetadata.StartLine/EndLine` | — | — |

### 6.3. Normallashtirish

Jiddiylik darajalari:

| Manba qiymati | Yagona qiymat |
|---|---|
| CRITICAL, Critical | CRITICAL |
| HIGH, High | HIGH |
| MEDIUM, Medium | MEDIUM |
| LOW, Low | LOW |
| Negligible (Grype) | LOW |
| INFO, TRACE (KICS) | INFO |
| `null`, Unknown, bo‘sh | UNKNOWN |

Grype’ning Negligible darajasi LOW ga tenglanadi. `analyze.py` ham uni LOW ustuniga qo‘shib sanaydi (`LOW + NEGLIGIBLE`).

Checkov’ning ochiq kodli versiyasi ko‘pincha `severity: null` qaytaradi. Platforma bu qiymatni to‘qib chiqarmaydi va UNKNOWN deb saqlaydi. Konsensus guruhida esa guruhning jiddiyligi a’zolarning ma’lum bo‘lgan eng yuqori darajasi bo‘ladi. Masalan, Checkov va KICS bir xatoni topsa, guruh KICS darajasini oladi. Bu daraja interfeysda “guruh bo‘yicha” deb belgilanadi.

Holat (`status`):

| Yagona qiymat | O‘zbekcha nomi | Manba |
|---|---|---|
| `fix_available` | Tuzatish mavjud | Trivy `fixed`, Grype `fixed` |
| `no_fix` | Tuzatish yo‘q | Trivy `affected`, Grype `not-fixed` |
| `wont_fix` | Tuzatilmaydi | Trivy `will_not_fix`, `fix_deferred`, Grype `wont-fix` |
| `unknown` | Noma’lum | qolgan holatlar |
| `failed` | Qoidaga zid | IaC: muvaffaqiyatsiz tekshiruvlar |

IaC bo‘yicha faqat muvaffaqiyatsiz tekshiruvlar topilma sifatida saqlanadi. O‘tgan tekshiruvlar soni `ToolRun` statistikasida qoladi.

CVE normallashtirish (`stats3.cve`): ID katta harfga keltiriladi. `CVE-` bilan boshlansa, o‘zi kalit bo‘ladi. Grype’da GHSA identifikatori `relatedVulnerabilities` ro‘yxatidagi birinchi CVE ga almashtiriladi. Trivy uchun faqat `VulnerabilityID` olinadi. CVE topilmasa, asl ID (GHSA, TEMP, DLA) kalit bo‘lib qoladi. Tuzatish mavjudligi Trivy’da `FixedVersion` bo‘sh emasligi, Grype’da `fix.state == "fixed"` bilan aniqlanadi.

### 6.4. Takrorlarni birlashtirish

Bir vosita bir topilmani bir necha marta qaytarishi mumkin. Masalan, Grype bitta paketni har bir joylashuvi uchun alohida ko‘rsatadi. Birlashtirish kaliti (`fingerprint`):

- zaiflik: `tool + cve_yoki_id + paket + o‘rnatilgan_versiya`;
- noto‘g‘ri sozlama: `tool + rule_id + fayl + resurs + boshlanish_qatori`.

Bir xil kalitli yozuvlar bitta topilmaga aylanadi, joylashuvlari esa ro‘yxat bo‘lib saqlanadi.

## 7. Konsensus mantiqi (asosiy ilmiy g‘oya)

### 7.1. Konteyner zaifliklari

1. Har bir vosita uchun normallashtirilgan CVE to‘plami tuziladi: `T` (Trivy) va `G` (Grype).
2. Har bir CVE uchun guruh (`FindingGroup`) ochiladi.
3. Belgilar:
   - CVE ikkala to‘plamda bor → **Tasdiqlangan**.
   - CVE faqat bitta to‘plamda → **Tekshirish talab etiladi**.
   - Grype topilmasida `vulnerability.namespace == "nvd:cpe"` yoki `artifact.type == "binary"` bo‘lsa → qo‘shimcha **“CPE asosida, soxta bo‘lishi mumkin”** belgisi.
4. CPE belgisi konsensus belgisini almashtirmaydi, unga qo‘shiladi. Faqat Grype CPE orqali topgan CVE ikki belgini oladi: “Tekshirish talab etiladi” va “CPE asosida, soxta bo‘lishi mumkin”.
5. Jaccard koeffitsienti:

$$J(T, G) = \frac{|T \cap G|}{|T \cup G|}$$

To‘plam elementi — obrazdagi normallashtirilgan CVE kaliti (paketsiz), `stats3.py` dagi kabi. Ikkala to‘plam bo‘sh bo‘lsa, `stats3.py` 1,0 qaytaradi; platforma ham shunday qiladi. Bir nechta obraz bo‘yicha umumiy koeffitsient `(obraz, CVE)` juftliklari to‘plamida hisoblanadi.

Qo‘shimcha ravishda **asosiy Jaccard** (`j_core`) ko‘rsatiladi. Unda Trivy’ning CVE bo‘lmagan ID lari va Grype’ning faqat CPE asosida topgan CVE lari chiqarib tashlanadi. III bobda bu ko‘rsatkich vositalar farqining qancha qismi metodologiyadan kelib chiqishini ko‘rsatadi.

Tekshirish: 15 ta obrazning barchasida `t_n`, `g_n`, `common`, `only_t`, `only_g`, `j`, `j_core`, `g_cpe`, `t_fix`, `g_fix`, kritik va yuqori darajalar `ch3.json` bilan bir xil chiqadi. Umumiy J = 0,767 (`test_consensus.py`).

### 7.2. IaC topilmalari

Turli vositalarning qoida ID lari bir-biriga to‘g‘ridan-to‘g‘ri mos kelmaydi. Checkov’da `CKV_AWS_20`, KICS’da UUID, Trivy’da `AVD-AWS-0086`. Shu sababli moslashtirish xato toifasi bo‘yicha bajariladi:

`ground_truth.csv` ning har bir qatori — bitta xato (40 ta: TF-01..TF-20, K8S-01..K8S-13, DF-01..DF-07). Qatorda xatoli va xavfsiz fayl, resurs tokeni (`tf02_bucket`), regex va istisno regexi bor. Regex `rule_id + " " + title` matniga (kichik harflarda) qo‘llanadi.

Platformada ikki rejim bor:

- **Ground truth bo‘yicha baholash** (`evaluate_ground_truth`). `analyze.py` ning IaC qismi aynan ko‘chirilgan: fayl, regex, istisno va resurs tokeni tekshiriladi, Terraform qatorlari blok nomiga bog‘lanadi. Natija — har bir vosita uchun TP, FP, recall, precision, F1 va juftliklar Jaccard’i. Namoyish fayllarida `summary.json` bilan to‘liq mos: Checkov 36/40, KICS 34/40, Trivy 32/40, Jaccard 0,842 / 0,838 / 0,784.
- **Ixtiyoriy fayllar uchun toifalash** (`categorize`). Foydalanuvchi faylida GT tokenlari yo‘q. Shu sababli fayl oilasi (Terraform, Kubernetes, Dockerfile) bo‘yicha xuddi shu regex va istisnolar qo‘llanadi. Tokenli qoidalar uchun token o‘rniga resurs turi tekshiriladi. Tur namoyish faylidan olinadi: `tf09_rds` → `aws_db_instance`, demak TF-10 (RDS shifrlash) faqat `aws_db_instance` bloklariga qo‘llanadi. Prefiks bo‘yicha solishtiriladi, shuning uchun `aws_s3_bucket` qoidasi `aws_s3_bucket_acl` ga ham tegadi. Bu rejim namoyish fayllarida ground truth bilan aynan bir xil toifalarni topadi (`test_categories.py`).

Konsensus:

1. Har bir topilmaga mos toifalar aniqlanadi. `Finding.category` ga birinchisi yoziladi.
2. Guruh kaliti: `fayl + toifa`. Bitta topilma bir nechta toifaga tushishi mumkin (`analyze.py` dagi kabi).
3. Kamida ikkita vosita topgan guruh → **Tasdiqlangan**. Bitta vosita topgani → **Tekshirish talab etiladi**.
4. Hech bir toifaga tushmagan topilma o‘z qoidasi bo‘yicha alohida guruhda qoladi va “Toifalanmagan” deb belgilanadi. U Jaccard hisobiga kirmaydi.
5. Jaccard: har bir vosita juftligi uchun (Checkov–KICS, Checkov–Trivy, KICS–Trivy) va uchala vosita uchun umumiy. Ikkala to‘plam bo‘sh bo‘lsa 0 (`analyze.py` dagi kabi):

$$J(A, B, C) = \frac{|A \cap B \cap C|}{|A \cup B \cup C|}$$

## 8. Eskirgan bazaviy obrazni aniqlash

Obraz quyidagi shartlardan biri bajarilsa eskirgan (EOL) hisoblanadi:

1. Trivy hisobotida `Metadata.OS.EOSL == true`.
2. Trivy `Metadata.OS` yoki Grype `distro` maydonidagi nom va versiya ichki ro‘yxatga tushadi.
3. Obraz nomi va tegi ichki ro‘yxatdagi runtime’ga mos keladi (masalan, `node:16-alpine`, `python:3.9-slim`).
4. Grype `binary` turidagi artefaktlarida `node` 16.x yoki `python` 3.9.x topilgan.

Ichki ro‘yxat (`resources/eol.json`):

| Nomi | Moslashtirish | Qo‘llab-quvvatlash tugagan sana |
|---|---|---|
| CentOS 7 | `centos` 7.* | 2024-06-30 |
| Ubuntu 20.04 | `ubuntu` 20.04 | 2025-05-31 (standart qo‘llab-quvvatlash) |
| Debian 11 | `debian` 11, 11.* | 2026-08-31 (LTS) |
| Alpine 3.18 | `alpine` 3.18.* | 2025-05-09 |
| Alpine 3.20 | `alpine` 3.20.* | 2026-04-01 |
| Node 16 | `node:16*`, binar `node` 16.* | 2023-09-11 |
| Python 3.9 | `python:3.9*`, binar `python` 3.9.* | 2025-10-31 |

EOL aniqlansa, natijalar sahifasining eng yuqorisida va DOCX hisobotda katta qizil ogohlantirish chiqadi:

> **Bazaviy obrazning qo‘llab-quvvatlash muddati tugagan. Skanerlar natijalari to‘liq emas, obrazni almashtiring.**

Ogohlantirish ostida qaysi manba (Trivy EOSL, Grype distro, ichki ro‘yxat) uni aniqlagani ko‘rsatiladi.

## 9. AHP vosita tanlash moduli

### 9.1. Mezonlar va vaznlar (II bob)

| Kod | Mezon | Vazn |
|---|---|---|
| K1 | Funksional qamrov | 0,1674 |
| K2 | Aniqlash sifati | 0,2888 |
| K3 | CI/CD integratsiyasi | 0,0570 |
| K4 | Moslashuvchanlik va me’yoriy xaritalash | 0,0570 |
| K5 | Iqtisodiy samaradorlik | 0,0952 |
| K6 | Ta’minot zanjiri xavfsizligi | 0,1674 |
| K7 | Normativ muvofiqlik va ma’lumotlar mahalliyligi | 0,1674 |

### 9.2. Ballar (1–5)

| Vosita | K1 | K2 | K3 | K4 | K5 | K6 | K7 |
|---|---|---|---|---|---|---|---|
| Trivy | 4 | 4 | 5 | 4 | 5 | 2 | 4 |
| Grype | 2 | 4 | 5 | 2 | 5 | 4 | 4 |
| Checkov | 3 | 4 | 5 | 5 | 5 | 3 | 4 |
| KICS | 3 | 4 | 5 | 4 | 5 | 1 | 4 |
| Prowler | 3 | 3 | 4 | 5 | 5 | 3 | 4 |
| Wiz | 5 | 3 | 4 | 5 | 1 | 3 | 2 |
| Cortex Cloud | 5 | 3 | 4 | 5 | 1 | 3 | 2 |
| MS Defender for Cloud | 4 | 3 | 3 | 4 | 3 | 3 | 2 |

### 9.3. Hisoblash

Vositaning umumiy bali:

$$S_j = \sum_{i=1}^{7} w_i \cdot a_{ij}$$

Ssenariyda har bir vazn ko‘paytiruvchiga ko‘paytiriladi va yig‘indisi 1 ga keltiriladi:

$$w_i' = \frac{w_i \cdot m_i}{\sum_k w_k \cdot m_k}$$

| Ssenariy | Ko‘paytiruvchilar |
|---|---|
| Bazaviy | hammasi 1 |
| Davlat tashkiloti | K6 × 2, K7 × 2 |
| Yirik korporativ | K1 × 2, K2 × 1,5, K5 × 0,3 |
| Kichik tashkilot | K5 × 3 |

Foydalanuvchi slayderlar bilan har bir vaznni 0 dan 1 gacha o‘zgartiradi. Vaznlar avtomatik normallashtiriladi, reyting jadval va Chart.js ustunli diagrammasida darhol yangilanadi (HTMX).

9.1-jadvaldagi vaznlar to‘rt xonagacha yaxlitlangan (yig‘indisi 1,0002). Hisobda ular emas, `resources/ahp.json` dagi `w` ishlatiladi: xos vektor usulida olingan aniq vaznlar, yig‘indisi 1,0. Ballar `resources/ahp_upd.json` dagi `S2` dan olinadi. Natija 3.9-jadvalga mos (3 xonagacha): Checkov 3,874; Trivy 3,817; Grype 3,704; Prowler 3,529; KICS 3,483; Wiz va Cortex Cloud 3,148; MS Defender for Cloud 3,057.

Modul `ahp.json` dagi juftlik taqqoslash matritsasidan (`A`) bosh xos vektorni daraja usuli bilan qayta hisoblaydi. U `w` bilan 10⁻¹⁵ aniqlikda mos keladi. Muvofiqlik: λ_max = 7,042; CI = 0,0070; CR = 0,0053 < 0,1.

Sezgirlik tahlili: har bir mezon vazni ×0,5 va ×1,5 ga o‘zgartiriladi. Yetakchilar ro‘yxati va “birinchi uchlik tarkibi o‘zgarmagan” holatlar soni (14 tadan 13 tasi) `ahp_upd.json` bilan bir xil.

## 10. Ma’lumotlar bazasi

```mermaid
erDiagram
    USER ||--o{ SCAN : "boshlaydi"
    SCAN ||--|{ TOOL_RUN : "o‘z ichiga oladi"
    TOOL_RUN ||--o{ FINDING : "topadi"
    SCAN ||--o{ FINDING_GROUP : "konsensus"
    FINDING_GROUP ||--|{ FINDING : "birlashtiradi"
    USER ||--o{ AUDIT_LOG : "harakatlari"

    USER {
        int id PK
        string username UK
        string password_hash "bcrypt"
        bool is_active
        datetime created_at
        datetime last_login_at
    }
    SCAN {
        int id PK
        string uid UK "URL uchun tasodifiy ID"
        string kind "iac yoki image"
        string target "obraz nomi yoki fayllar"
        string source "web, cli, demo"
        string status "navbatda, ishlamoqda, tugadi, qisman, xato"
        int user_id FK
        datetime created_at
        datetime finished_at
        string image_digest
        string os_name
        json summary "jiddiylik bo‘yicha sonlar"
        json jaccard
        json eol
        string error
    }
    TOOL_RUN {
        int id PK
        int scan_id FK
        string tool
        string tool_version
        string image_ref "repo@sha256:..."
        int exit_code
        int duration_ms
        json db_info "baza versiyasi va sanasi"
        int passed_count
        int failed_count
        string raw_report_path
        string error
    }
    FINDING {
        int id PK
        int scan_id FK
        int tool_run_id FK
        int group_id FK
        string tool
        string kind
        string target
        string resource
        string rule_id
        string title
        string severity
        string cve
        string installed_version
        string fixed_version
        string status
        string category
        bool cpe_based
        int line_start
        int line_end
        string primary_url
        string fingerprint
    }
    FINDING_GROUP {
        int id PK
        int scan_id FK
        string key "CVE yoki fayl+toifa"
        string kind
        string title
        string severity "guruh darajasi"
        string tools "vositalar ro‘yxati"
        int tool_count
        string consensus "tasdiqlangan yoki tekshirish"
        bool cpe_suspect
        string fixed_version
    }
    DB_UPDATE {
        int id PK
        string db_name "trivy, trivy-java, grype"
        string status
        datetime started_at
        datetime finished_at
        string db_version
        datetime db_built_at
        string error
    }
    AUDIT_LOG {
        int id PK
        datetime ts
        int user_id FK
        string action "login, scan, db-update"
        string detail
        string ip
    }
```

Xom JSON hisobotlar bazaga emas, `data/hisobotlar/{scan_uid}/` katalogiga yoziladi. `TOOL_RUN.raw_report_path` shu faylni ko‘rsatadi. Ikki tekshiruvni solishtirish `FINDING_GROUP.key` bo‘yicha bajariladi: yangi, yo‘qolgan (tuzatilgan) va o‘zgarmagan topilmalar.

### 10.1. Fon navbati

Veb-so‘rov skanerni kutmaydi. Tekshiruv `ThreadPoolExecutor(max_workers=1)` asosidagi oddiy navbatga qo‘yiladi va holati bazada saqlanadi. Natijalar sahifasi holatni HTMX bilan har 2 soniyada so‘raydi. Server qayta ishga tushganda “navbatda” va “ishlamoqda” holatidagi tekshiruvlar “xato” deb yopiladi, eski `workdir` kataloglari tozalanadi.

## 11. Xavfsizlik arxitekturasi

### 11.1. Tahdidlar va choralar

| Tahdid | Chora | Modul |
|---|---|---|
| Skaner yoki uning bazasi buzilgan (ta’minot zanjiri hujumi). Real misollar `config.ps1` da qayd etilgan: Trivy 0.69.4–0.69.6 zararli relizlari (CVE-2026-33634) va 2026-yil 22-aprelda KICS teglarining zararli obrazlarga almashtirilishi | Vosita faqat `repo@sha256:...` orqali chaqiriladi, ishga tushishda digest tekshiriladi, `--pull never` | `scanner.tools`, `scanner.docker` |
| Skaner ma’lumotni tashqariga yuboradi | `--network none`, telemetriya va yangilanish tekshiruvi bayroqlari o‘chiriladi | `scanner.docker` |
| Skaner xostni buzadi | `--read-only`, `--cap-drop ALL`, `no-new-privileges`, CPU/xotira/PID limitlari, `docker.sock` ulanmaydi | `scanner.docker` |
| Maxfiy ma’lumot konteynerga o‘tadi | Konteynerga faqat aniq qiymatli `--env` beriladi, xost muhiti uzatilmaydi, `--env-file` ishlatilmaydi | `scanner.docker` |
| Buyruq inyeksiyasi | `subprocess.run([...], shell=False)`, obraz nomi qat’iy regex, nom `-` bilan boshlanmaydi | `security.validators` |
| Zip-slip va zip-bomba | Yo‘llarni tekshirish, simvolik havolalarni rad etish, hajm va fayllar soni limiti, siqish nisbati limiti | `security.upload_guard` |
| Ruxsatsiz fayl turi | Kengaytma va fayl nomi bo‘yicha oq ro‘yxat, matn ekanini tekshirish (NUL bayt yo‘q) | `security.upload_guard` |
| Tekshiruvlararo ma’lumot sizishi | Har tekshiruvga alohida `workdir/{uid}`, `finally` blokida o‘chiriladi | `security.workspace` |
| Parol o‘g‘irlanishi | bcrypt xeshi, kirish urinishlari cheklovi (5 urinish / 5 daqiqa) | `security.passwords`, `web.auth` |
| CSRF | Sessiyaga bog‘langan token, har bir POST da `hmac.compare_digest` bilan tekshiriladi | `web.csrf` |
| XSS va clickjacking | Jinja2 autoescape, qat’iy CSP (`default-src 'self'`), `X-Frame-Options: DENY` | `web.app` |
| Tarmoqdan ruxsatsiz kirish | Sukut bo‘yicha `127.0.0.1`, boshqa manzil tanlansa ogohlantirish | `config`, `cli serve` |
| Ma’lumot O‘zbekistondan chiqishi | Tashqi CDN, shrift va telemetriya yo‘q, barcha JS/CSS `static/vendor` da | `web.static` |
| Proksi manzili oshkor bo‘lishi | Faqat xotirada, jurnalda yashiriladi, commit qilinmaydi | `scanner.dbupdate` |

### 11.2. Skaner konteynerini ishga tushirish shabloni

Quyidagi shablon `scanner.docker` modulida argumentlar ro‘yxati sifatida quriladi:

```text
docker run --rm --pull never
  --name bulutskan-{uid}-{vosita}
  --network none
  --read-only
  --tmpfs /tmp:rw,nosuid,nodev,size=512m
  --cap-drop ALL
  --security-opt no-new-privileges
  --cpus 2 --memory 2g --memory-swap 2g --pids-limit 512
  --env HOME=/tmp
  --env HTTP_PROXY= --env HTTPS_PROXY= --env NO_PROXY= (va kichik harfli nusxalari)
  --mount type=bind,source={workdir}/input,target=/scan,readonly        # IaC
  --mount type=bind,source={image.tar},target=/input/image.tar,readonly # obraz
  aquasec/trivy@sha256:{digest}
  {vosita argumentlari}
```

Izohlar:

- `--pull never` digest bo‘yicha obraz kompyuterda yo‘q bo‘lsa, Docker uni jimgina yuklab olishiga yo‘l qo‘ymaydi.
- Bo‘sh `HTTP_PROXY=` qiymatlari Docker CLI ning `config.json` dagi proksini konteynerga avtomatik uzatishini bekor qiladi. Tarmoq baribir yo‘q, lekin proksi manzili konteyner ichida ham ko‘rinmaydi.
- `-v` o‘rniga `--mount` ishlatiladi: Windows yo‘lidagi `D:` ikki nuqtasi `-v` sintaksisini buzadi. Yo‘lda vergul yoki qo‘shtirnoq bo‘lsa, tekshiruv xato bilan to‘xtaydi.
- Konteynerga muhit o‘zgaruvchisi faqat `KALIT=qiymat` ko‘rinishida beriladi. `docker` jarayonining o‘ziga ham xost muhitidan faqat zarur o‘zgaruvchilar (`PATH`, `DOCKER_HOST`, Windows tizim o‘zgaruvchilari) o‘tadi.
- Timeout tugasa, konteyner `docker kill bulutskan-{uid}-{vosita}` bilan to‘xtatiladi. 137 chiqish kodi “xotira yetmadi” deb tushuntiriladi.
- Root bo‘lmagan foydalanuvchi (`--user`) hali yoqilmagan: uni Windows’dagi haqiqiy sinovdan keyin har bir vosita bilan alohida sinab ko‘ramiz.

Vositalarga xos argumentlar eksperimentdagi `run_tests.ps1` dan aynan olinadi. Shunday qilinsa, platforma III bobdagi natijalarni takrorlaydi:

| Vosita | Argumentlar | Qo‘shimcha ulanishlar |
|---|---|---|
| Trivy image | `image --cache-dir /tmp/trivy --skip-db-update --skip-java-db-update --offline-scan --scanners vuln --format json --input /input/image.tar` | `db/` → `/tmp/trivy/db` va `java-db/` → `/tmp/trivy/java-db`, ikkalasi faqat o‘qish uchun |
| Trivy config | `config --skip-check-update --format json /scan` | — |
| Grype | `docker-archive:/input/image.tar -o json`; muhit: `GRYPE_DB_CACHE_DIR=/cache`, `GRYPE_DB_AUTO_UPDATE=false`, `GRYPE_CHECK_FOR_APP_UPDATE=false`, `GRYPE_DB_VALIDATE_AGE`, `TMPDIR=/scratch` | baza → `/cache` faqat o‘qish uchun; `scratch/grype` → `/scratch` yozish uchun |
| Checkov | `-d /scan --skip-download --quiet -o json --output-file-path /out` | `out/checkov` → `/out` yozish uchun |
| KICS | `scan -p /scan -o /out --report-formats json --no-progress` | `out/kics` → `/out` yozish uchun |

Vositalar chiqish kodi: Checkov xato topsa 1, KICS eng yuqori daraja bo‘yicha 20–60 qaytaradi (eksperimentdagi `timings.csv` da ham shunday). Bu kodlar muvaffaqiyat deb qabul qilinadi.

**Yozish uchun ulanadigan kataloglar** — talabdagi “faqat tekshiriladigan fayllar `:ro`” qoidasidan uchta asosli istisno. Har biri bo‘sh holda ochiladi, faqat shu tekshiruvga tegishli va ish tugagach o‘chiriladi:

1. Checkov va KICS uchun `out/`: ular natijani faylga yozadi (eksperimentdagi kabi).
2. Grype uchun `scratch/grype`: Grype obraz qatlamlarini vaqtinchalik katalogga ochadi. Katta obrazlarda bu yuzlab megabayt, `tmpfs` esa konteyner xotirasidan joy oladi.
3. Baza nusxasi (zaxira rejim): vosita bazani faqat o‘qish rejimida ocha olmasa (`read-only file system` xatosi), baza `scratch/` ga nusxalanadi va bir marta qayta uriniladi. Asl baza baribir o‘zgarmaydi. `BULUTSKAN_TRIVY_DB_MODE=copy` bu rejimni doimiy qiladi.

### 11.3. Bazalarni yangilash konteyneri

Yagona farqlar: tarmoq yoqilgan (`bridge`), proksi `--env HTTPS_PROXY={docker info qiymati}` sifatida beriladi, baza katalogi yozish uchun ulanadi. `--read-only`, `--cap-drop ALL`, `no-new-privileges` va limitlar saqlanadi. Tekshiriladigan fayllar bu konteynerga ulanmaydi.

Buyruqlar (`run_tests.ps1` va `rerun_trivy.ps1` dan): `trivy image --cache-dir /cache --download-db-only`, `trivy image --cache-dir /cache --download-java-db-only`, `grype db update`. Keyin `grype db status` tarmoqsiz ishga tushiriladi. Sanalar `data/db/holat.json` ga yoziladi: platformaning yangilash vaqti, Trivy `metadata.json` (`UpdatedAt`, `NextUpdate`, `DownloadedAt`), Grype bazasi yig‘ilgan sana va sxemasi. Xato matnida proksi manzili uchrasa, `<proksi>` bilan almashtiriladi.

### 11.4. Digest yaxlitligi

1. `resources/tool_digests.txt` dan vosita → digest jadvali o‘qiladi. Format: `aquasec/trivy:0.76.1  ->  aquasec/trivy@sha256:...` (UTF-8, BOM bilan).
2. Ishga tushishda har bir vosita uchun `docker image inspect` bajariladi. Registrdagi obrazlar (Trivy, Grype, KICS) uchun `RepoDigests` ichida aynan shu digest bo‘lishi kerak.
3. Checkov registrdan olinmaydi: u `checkov.Dockerfile` dan mahalliy yig‘iladi va `tool_digests.txt` da digesti yo‘q (`checkov (pip) == 3.3.26`). Mahalliy yig‘ish takrorlanuvchan emas, shuning uchun birinchi yig‘ishda obraz `Id` si `data/tool_lock.json` ga yoziladi (birinchi ishonch tamoyili, trust on first use). Keyingi har ishga tushishda shu `Id` tekshiriladi va Checkov `sha256:{Id}` orqali chaqiriladi.
4. Natija:
   - **mos** — tekshiruvlar ruxsat etiladi;
   - **mos emas** — barcha tekshiruvlar bloklanadi, har bir sahifada qizil ogohlantirish chiqadi, CLI 2 kodi bilan chiqadi;
   - **obraz yo‘q** — tekshiruvlar bloklanadi, `bulutskan tools pull` buyrug‘i taklif qilinadi;
   - **Docker ishlamayapti** — faqat ko‘rish rejimi (tarix, demo ma’lumotlar, AHP).

### 11.5. Fayl yuklash himoyasi

| Tekshiruv | Sukut qiymati |
|---|---|
| Yuklanadigan IaC fayl yoki ZIP hajmi | 20 MB (oqim bo‘yicha sanaladi, `Content-Length` ga ishonilmaydi) |
| ZIP ochilgandagi umumiy hajm | 100 MB |
| ZIP dagi yozuvlar soni | 1000 |
| Siqish nisbati | 100:1 dan oshmasin |
| Obraz `.tar` hajmi | 4096 MB |
| Ruxsat etilgan fayllar | `.tf`, `.tfvars`, `.hcl`, `.yaml`, `.yml`, `.json`, `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, `Containerfile` |

ZIP yozuvi quyidagi hollarda butun arxiv rad etiladi: absolyut yo‘l, `..` qismi, Windows disk harfi, simvolik havola, shifrlangan yozuv, ichma-ich ZIP, Windows’da to‘qnashadigan nomlar (katta-kichik harf farqi). Har bir fayl ochilgach `Path.resolve()` natijasi `workdir/{uid}/input` ichida ekani yana tekshiriladi. Oq ro‘yxatga kirmaydigan oddiy fayllar o‘tkazib yuboriladi va natijalar sahifasida ro‘yxati ko‘rsatiladi.

Obraz `.tar` fayli xostda ochilmaydi. Faqat `tarfile` bilan tuzilmasi ko‘riladi: `manifest.json` (docker-archive) yoki `index.json` (oci-archive) borligi va yozuv nomlari xavfsizligi.

Obraz nomi regexi Docker havola grammatikasiga asoslanadi: `[registr[:port]/]nom[/nom...][:teg][@sha256:64_hex]`, uzunligi 255 belgigacha, kichik harflar, birinchi belgi harf yoki raqam.

## 12. Veb-interfeys

Jinja2 shablonlari serverda tayyorlanadi, HTMX qisman yangilanishlarni bajaradi. Chap tomonda menyu, asosiy qismda kartochkalar. Jiddiylik darajalari rang va SVG ikonka bilan belgilanadi: CRITICAL — to‘q qizil, HIGH — qizil-to‘q sariq, MEDIUM — sariq, LOW — ko‘k, INFO va UNKNOWN — kulrang. Pastki qismda doimiy yozuv: **“Ma’lumotlar O‘zbekiston hududidan chiqmaydi”**.

| Sahifa | Marshrut |
|---|---|
| Kirish / chiqish | `GET/POST /login`, `POST /logout` |
| Boshqaruv paneli | `GET /` |
| IaC tekshiruvi | `GET/POST /scan/iac` |
| Obraz tekshiruvi | `GET/POST /scan/image` |
| Tekshiruvlar tarixi | `GET /scans` |
| Natijalar | `GET /scans/{uid}`, `GET /scans/{uid}/status` (HTMX), `GET /scans/{uid}/findings` (HTMX filtr) |
| Eksport | `GET /scans/{uid}/report.docx`, `GET /scans/{uid}/export.json` |
| Solishtirish | `GET /scans/compare?a={uid}&b={uid}` |
| AHP | `GET /ahp`, `POST /ahp/calc` (HTMX) |
| Vositalar va bazalar | `GET /tools`, `POST /tools/db-update` |
| Til | `POST /lang/{uz\|en}` |

Boshqaruv paneli: jami tekshiruvlar, kritik topilmalar, tasdiqlangan topilmalar ulushi, oxirgi baza yangilanishi. Diagrammalar: vositalar bo‘yicha topilmalar, jiddiylik taqsimoti, vaqt bo‘yicha tekshiruvlar, tekshiruvlar kesimida Jaccard.

Tillar: o‘zbek (lotin, asosiy) va ingliz. Matnlar `web/i18n/uz.json` va `en.json` da, tanlangan til cookie’da saqlanadi.

Cookie: `HttpOnly`, `SameSite=Strict`, imzo kaliti `.env` dagi `BULUTSKAN_SECRET_KEY`. Birinchi foydalanuvchi `bulutskan user create` buyrug‘i bilan yaratiladi. `run.ps1` foydalanuvchi yo‘qligini ko‘rsa, buni o‘zi taklif qiladi.

## 13. CLI

| Buyruq | Vazifasi |
|---|---|
| `bulutskan scan --iac ./infra --fail-on high` | IaC tekshiruvi |
| `bulutskan scan --image nginx:1.21 --fail-on critical --fixable-only` | Obraz tekshiruvi |
| `bulutskan scan --image-tar ./app.tar` | Tayyor `.tar` faylni tekshirish |
| `bulutskan db-update` | Zaifliklar bazalarini yangilash |
| `bulutskan db-status` | Bazalar sanalari |
| `bulutskan tools verify` | Digestlarni tekshirish |
| `bulutskan tools pull` | Trivy, Grype, KICS ni digest bo‘yicha yuklab olish |
| `bulutskan tools lock-checkov` | Mahalliy Checkov obrazi ID sini qulflash |
| `bulutskan tools build-checkov` | Checkov’ni `checkov.Dockerfile` dan yig‘ish |
| `bulutskan demo-import` | Namoyish ma’lumotlarini import qilish (Docker va internetsiz) |
| `bulutskan user create` | Foydalanuvchi yaratish |
| `bulutskan serve` | Veb-serverni ishga tushirish (sukut: 127.0.0.1:8000) |

Qo‘shimcha `scan` parametrlari: `--image-name` (`--image-tar` uchun obraz nomi, EOL tekshiruviga kerak), `--json natija.json`, `--unknown-severity`. `--docx` 5-bosqichda qo‘shiladi.

`--fail-on` chegarasi: jiddiyligi chegaradan past bo‘lmagan **konsensus guruhlari** sanaladi. Bir xatoni uchta vosita topgan bo‘lsa ham, u bir marta sanaladi. `--fixable-only` faqat tuzatilgan versiyasi bor zaifliklarni sanaydi. IaC uchun u e’tiborga olinmaydi va bu haqda eslatma chiqadi.

`--unknown-severity {ignore,low,medium,high}` (sukut: `medium`). Checkov’ning ochiq versiyasi jiddiylik bermaydi. Xatoni faqat Checkov topgan bo‘lsa, guruh darajasi UNKNOWN bo‘ladi va u hech qachon chegaraga yetmasdi. Namoyish fayllarida bunday xato bitta — TF-20 (HTTP listener). Unga 30 ta toifalanmagan Checkov topilmasi ham qo‘shiladi. Bu parametr faqat `--fail-on` qarorida ishlatiladi: ma’lumotda daraja `UNKNOWN` bo‘lib qoladi, hisobotda esa `noma’lum (CI uchun medium deb olindi)` deb yoziladi. JSON eksportda `severity`, `severity_ci` va `severity_label` maydonlari bor.

Chiqish kodlari: `0` — chegaradan oshmadi; `1` — chegaradan oshdi; `2` — foydalanish xatosi, vosita yaxlitligi buzilgan yoki tekshiruv bajarilmadi.

GitHub Actions va GitLab CI namunalari `ci/` katalogida turadi. Ular `.github/workflows/` ga qo‘yilmaydi, chunki repozitoriyning o‘zida ishga tushib ketmasligi kerak.

## 14. Hisobot

DOCX (python-docx, o‘zbek tilida):

1. Umumiy xulosa: obyekt, sana, holat, jami topilmalar, asosiy xavf.
2. Jiddiylik bo‘yicha jadval (vosita × daraja).
3. Konsensus: tasdiqlangan va tekshirish talab etiladigan guruhlar soni, CPE belgilari, Jaccard koeffitsientlari.
4. EOL ogohlantirishi (bo‘lsa).
5. Tuzatish tavsiyalari: zaifliklar uchun “paket → tuzatilgan versiya”, IaC uchun qoida havolasi va tavsiya.
6. Vosita versiyalari, digestlari va baza sanalari.

JSON eksport: `schema_version`, tekshiruv ma’lumotlari, vositalar (versiya, digest, baza sanasi), xulosa, konsensus guruhlari, Jaccard, EOL va barcha topilmalar.

## 15. Testlash strategiyasi

Barcha testlar Docker’siz o‘tadi. Docker chaqiruvlari `subprocess.run` ni almashtiradigan soxta ishga tushirgich (fake runner) bilan tekshiriladi.

Platforma Windows’da ishlatiladi, bulutli testlar esa Linux’da o‘tadi. Linux ochiq faylni o‘chirishga ruxsat beradi, Windows esa yo‘q (`PermissionError: [WinError 32]`). Shu farq tufayli bitta xato faqat Windows’dagi sinovda chiqqan edi. Endi `tests/winfs.py` barcha testlarda Windows qoidasini taqlid qiladi: test katalogidagi ochiq fayl ustida `unlink`, `remove`, `rmdir`, `rename` va `replace` xato beradi.

| Test fayli | Nimani tekshiradi | Ma’lumot |
|---|---|---|
| `test_parsers.py` | To‘rt vosita parserlari: yozuvlar soni, darajalar, tuzatiladiganlar `summary.json` bilan | `demo/sinov/natijalar` dagi real JSON |
| `test_normalize.py` | Jiddiylik, holat, GHSA → CVE, fayl yo‘llari | qo‘lda yozilgan misollar |
| `test_dedup.py` | Takrorlarni birlashtirish | real JSON va misollar |
| `test_consensus.py` | Belgilar, CPE belgisi, Jaccard: 15 obraz `ch3.json` bilan, IaC `summary.json` bilan | real JSON |
| `test_categories.py` | GT baholash `summary.json` bilan, ixtiyoriy fayllar uchun toifalash | `iac/run1` va `ground_truth.csv` |
| `test_eol.py` | EOL aniqlash | real Trivy/Grype JSON |
| `test_ahp.py` | 3.9-jadval, xos vektor, CR, sezgirlik tahlili | `ahp.json`, `ahp_upd.json` |
| `test_upload_guard.py` | Zip-slip, zip-bomba, simvolik havola, oq ro‘yxat, hajm, katalog o‘chirilishi | test ichida yaratiladigan arxivlar |
| `test_validators.py` | Obraz nomi regexi | to‘g‘ri va zararli nomlar |
| `test_docker_cmd.py` | Majburiy bayroqlar, `shell=False`, maxfiy muhit o‘zgaruvchilari yo‘qligi, `--mount` yo‘llari | `subprocess.run` almashtiriladi |
| `test_tools.py` | `tool_digests.txt`, digest holatlari (mos, mos emas, yo‘q, qulflanmagan), Checkov qulfi | `tests/fakes.py` (soxta docker) |
| `test_dbupdate.py` | Proksi aniqlash va yashirish, faqat shu bosqichda tarmoq, sanalar | soxta docker, eksperiment metadata fayllari |
| `test_scanner.py` | Butun quvur: buyruqlar xavfsizligi, natijalar `ch3.json`/`summary.json` bilan, zaxira rejim, xatolar, katalog o‘chirilishi | soxta docker + real JSON |
| `test_gate.py` | `--fail-on`, `--fixable-only`, `--unknown-severity`, hisobot yozuvi | real JSON |
| `test_cli.py` | Chiqish kodlari 0/1/2, `--unknown-severity`, JSON eksport, `tools`, `db-update` | soxta docker + real JSON |
| `test_windows_files.py` | Windows fayl qoidasi: ochiq faylni o‘chirish/ko‘chirish (WinError 32), qisman yozilgan fayllarni bekor qilish, katalogni qayta urinib o‘chirish | `tests/winfs.py` |
| `test_web.py` | Login, CSRF, ruxsatsiz kirish (4-bosqich) | FastAPI `TestClient` |

## 16. Texnologiyalar

| Qatlam | Tanlov |
|---|---|
| Til | Python 3.11+ |
| Backend | FastAPI, Starlette SessionMiddleware, Uvicorn |
| Ma’lumotlar | SQLAlchemy 2, SQLite |
| Model va sozlamalar | Pydantic 2, pydantic-settings |
| Shablonlar | Jinja2, HTMX 2 (loyiha ichida) |
| Diagrammalar | Chart.js 4 (loyiha ichida) |
| Xavfsizlik | bcrypt, itsdangerous |
| CLI | Typer |
| Hisobot | python-docx |
| Testlar | pytest, httpx |
| Skanerlar | Trivy 0.76.1, Grype v0.121.0, KICS v2.2.0, Checkov 3.3.26 (digest bo‘yicha) |

## 17. Qabul qilingan qarorlar

| № | Masala | Qaror |
|---|---|---|
| 1 | `ground_truth.csv` tuzilmasi va regex mantiqi | 7.2-bo‘lim: GT baholash va resurs turi bo‘yicha toifalash |
| 2 | `stats3.py`: Jaccard elementi, GHSA → CVE, bo‘sh to‘plam | 7.1-bo‘lim: CVE kaliti, `relatedVulnerabilities`, bo‘sh → 1,0 |
| 3 | Jiddiylik xaritasi (Negligible, Checkov `null`) | Negligible → LOW, `null` → UNKNOWN (6.3-bo‘lim) |
| 4 | `tool_digests.txt` va Checkov | 11.4-bo‘lim: Checkov uchun birinchi yig‘ishdagi `Id` qotiriladi |
| 5 | Vosita argumentlari | `run_tests.ps1` dagi argumentlar aynan (11.2-bo‘lim) |
| 6 | AHP vaznlari | `ahp.json` dagi aniq `w`, ballar `S2` (foydalanuvchi tasdiqlagan) |
| 7 | Digest mos kelmaganda | Tekshiruvlar bloklanadi, tarix, demo va AHP ishlaydi (foydalanuvchi tasdiqlagan) |
| 8 | KICS uchun yozish katalogi | Bo‘sh, alohida `out/` katalogi |

## 18. Bosqichlar

| Bosqich | Natija |
|---|---|
| 1 | `docs/arxitektura.md`, `.gitignore`, `.env.example` |
| 2 | Parserlar, yagona model, konsensus, AHP va ularning testlari |
| 3 | Xavfsiz skaner ishga tushirgich, digest tekshiruvi, bazalarni yangilash, yuklash himoyasi, tekshiruv quvuri, CLI (`scan`, `db-update`, `db-status`, `tools`), `--unknown-severity`, Windows sinov ko‘rsatmasi |
| 4 | SQLite (tarix), veb-interfeys: kirish, panel, IaC va obraz tekshiruvi, natijalar, AHP, tarix |
| 5 | DOCX hisobot, JSON eksport, CLI, CI namunalari |
| 6 | O‘zbekcha README, LICENSE (MIT) |
| 7 | `bulutskan demo-import` |
