# BulutSkan

[![build](https://github.com/Abduvokhobov5888/blutlik_texnologiya/actions/workflows/build.yml/badge.svg)](https://github.com/Abduvokhobov5888/blutlik_texnologiya/actions/workflows/build.yml)

BulutSkan bulutli infratuzilma kodi (IaC) va konteyner obrazlarini bir nechta ochiq kodli skaner bilan tekshiradi, natijalarni konsensus asosida baholaydi va o‘zbek tilida hisobot beradi. Platforma Andijon davlat universiteti magistrlik dissertatsiyasining (70610202 – Axborot xavfsizligi) amaliy natijasi.

| Obyekt | Vositalar |
|---|---|
| IaC: Terraform, Kubernetes YAML, Dockerfile | Checkov, KICS, Trivy (config) |
| Konteyner obrazi: nomi yoki `docker save` arxivi | Trivy, Grype |

## Imkoniyatlar

- **Yagona topilma modeli.** To‘rt vositaning har xil formatdagi hisobotlari bitta modelga keltiriladi, takrorlar birlashtiriladi.
- **Konsensus.** Kamida ikki vosita topgan muammo “tasdiqlangan” bo‘ladi, bitta vosita topgani esa “tekshirish talab etiladi” deb belgilanadi. Faqat CPE asosida topilgan, ya’ni soxta bo‘lishi mumkin bo‘lgan zaifliklarga alohida belgi qo‘yiladi. Vositalar mosligi Jaccard koeffitsiyenti bilan o‘lchanadi.
- **Eskirgan bazaviy obraz (EOL).** Qo‘llab-quvvatlanishi tugagan obrazda skanerlar ko‘p zaiflikni ko‘rmaydi. Platforma buni aniqlab, qizil ogohlantirish beradi.
- **AHP bo‘yicha vosita tanlash.** Yetti mezonli model ishlatiladi: vaznlarni o‘zgartirsangiz, reyting darhol qayta hisoblanadi. Ssenariylar va sezgirlik tahlili ham bor.
- **Hisobotlar:** DOCX (o‘zbekcha) va JSON.
- **CI/CD:** `--fail-on` chegarasi; chiqish kodlari `0`, `1`, `2`. GitHub Actions va GitLab CI namunalari `ci/` papkasida.
- **Tarix va boshqaruv paneli:** SQLite, diagrammalar, ikki tekshiruvni solishtirish, audit jurnali.
- **Namoyish rejimi.** III bob eksperimenti natijalari (15 ta obraz va IaC fayllari) dastur ichida keladi va Docker’siz ham ochiladi.

## O‘rnatish

### Windows (tavsiya etiladi)

1. [Releases](https://github.com/Abduvokhobov5888/blutlik_texnologiya/releases) sahifasidan `BulutSkan_Setup.exe` faylini yuklab oling.
2. O‘rnatuvchini ishga tushiring. Administrator huquqi, Python yoki git kerak emas.
3. Ish stolidagi **BulutSkan** belgisini bosing. Brauzer ochiladi: administrator akkauntini yarating, so‘ng sozlash ustasi Docker, vositalar va bazalarni tekshiradi.

Yangi tekshiruvlar uchun **Docker Desktop** (Linux konteynerlari) kerak. Docker bo‘lmasa, platforma namoyish rejimida ishlaydi.

Batafsil yo‘riqnoma, SmartScreen ogohlantirishi va haqiqiy sinov qadamlari: [docs/windows_ornatish.md](docs/windows_ornatish.md).

### Manba koddan

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/bulutskan serve
```

Windows’da manba koddan ishlash, eksperimentni takrorlash va ZIP orqali yangilash yo‘riqnomasi: [docs/windows_sinov.md](docs/windows_sinov.md).

## Foydalanish

### Veb-interfeys

`bulutskan serve` buyrug‘i (yoki ish stolidagi belgi) `http://127.0.0.1:8000/` manzilini ochadi. Dastur faqat shu kompyuterdan ochiladi.

| Sahifa | Vazifasi |
|---|---|
| Boshqaruv paneli | Tekshiruvlar soni, kritik topilmalar, tasdiqlangan ulush, eskirgan obrazlar, diagrammalar |
| IaC tekshiruvi / Obraz tekshiruvi | Fayl yoki ZIP yuklash; obraz nomi yoki `.tar` arxiv |
| Tekshiruv sahifasi | Jiddiylik jadvali, vositalar va digestlar, konsensus guruhlari (filtrlar bilan), JSON va DOCX |
| Solishtirish | Ikki tekshiruv orasidagi yangi va yo‘qolgan topilmalar |
| Vosita tanlash (AHP) | Vaznlar, reyting, ssenariylar, sezgirlik tahlili |
| Vositalar va bazalar | Sozlash ustasi (faqat administrator) |
| Audit jurnali, Foydalanuvchilar | Administrator uchun |

### CLI va CI/CD

```bash
bulutskan scan --iac ./infra --fail-on high --json natija.json --docx hisobot.docx
bulutskan scan --image nginx:1.21 --fail-on critical --fixable-only
bulutskan scan --image-tar ilova.tar --image-name ilova:1.0 --save
```

| Kod | Ma’nosi |
|---|---|
| `0` | Chegaradan oshgan topilma yo‘q |
| `1` | `--fail-on` darajasidagi topilma bor: konveyer to‘xtaydi |
| `2` | Biror vosita ishlamadi (qisman natija) yoki xato. Qisman natijani qabul qilish uchun `--allow-partial` qo‘shiladi |

Checkov’ning ochiq versiyasi jiddiylik darajasini bermaydi. Shu sababli faqat Checkov topgan muammolar CI qarorida `--unknown-severity` bo‘yicha baholanadi (sukut: `medium`).

Boshqa buyruqlar: `db-update`, `db-status`, `tools verify|pull|build-checkov|lock-checkov`, `user add|list|disable|enable|passwd`, `demo-import`. To‘liq ro‘yxat: `bulutskan --help`. Konveyer namunalari: [ci/github-actions.yml](ci/github-actions.yml), [ci/gitlab-ci.yml](ci/gitlab-ci.yml).

## Himoya uchun 5 daqiqalik ssenariy

Docker va internetsiz ishlaydi: barcha raqamlar III bob eksperimentining real hisobotlaridan olinadi.

| Daqiqa | Ko‘rsatiladi | Nimaga e’tibor berish kerak |
|---|---|---|
| 0:00 | Ish stolidagi belgi → boshqaruv paneli | 16 ta tekshiruv, vositalar bo‘yicha va jiddiylik bo‘yicha diagrammalar, 15 ta obraz bo‘yicha Trivy–Grype Jaccard |
| 1:00 | Tekshiruvlar tarixi → `nginx:1.21` | Qizil EOL ogohlantirishi (Debian 11); 689 ta noyob topilma, 502 tasi tasdiqlangan; Jaccard 0,729 |
| 2:00 | Konsensus guruhlari: “Tekshirish talab etiladi” va “CPE asosida” filtrlari | Bitta vosita topgan va soxta bo‘lishi mumkin bo‘lgan topilmalar ajratiladi |
| 2:45 | Namoyish IaC fayllari (III bob) | Ground truth: Checkov 36/40, KICS 34/40, Trivy 32/40; hech bir vosita topmagan xatolar: DF-03, K8S-09 |
| 3:30 | Vosita tanlash (AHP) | CR = 0,0053; Checkov 3,874, Trivy 3,818, Grype 3,707; K2 slayderini siljitib reyting o‘zgarishini ko‘rsatish; sezgirlik jadvali |
| 4:30 | `nginx:1.21` → **DOCX hisobot** | Word’da: xulosa, EOL, jiddiylik jadvali, konsensus, tuzatish tavsiyalari, metodologiya |

Docker Desktop bo‘lsa, oxirida `alpine:3.20` obrazini jonli tekshirish mumkin: bir necha daqiqa ketadi.

## Dissertatsiya bilan bog‘liqlik

| Dissertatsiyada | Platformada | Avtomatik test |
|---|---|---|
| II bob: AHP, 7 mezon, xos vektor usulidagi vaznlar, CR = 0,0053 | AHP sahifasi | `tests/test_ahp.py::test_eigenvector_reproduces_weights_and_consistency` |
| 3.9-jadval: Checkov 3,874; Trivy 3,818; Grype 3,707 | AHP reytingi | `tests/test_ahp.py::test_scores_match_table_3_9` |
| Sezgirlik tahlili (vaznlar ×0,5 va ×1,5) | AHP sahifasi | `tests/test_ahp.py::test_sensitivity_matches_dissertation` |
| III bob: 15 ta obraz, Trivy va Grype, har bir obraz bo‘yicha Jaccard | Namoyish tekshiruvlari, panel | `tests/test_consensus.py::test_image_consensus_matches_stats3` |
| Umumiy Jaccard 0,767 (CVE bo‘lmagan va faqat CPE asosidagi yozuvlarsiz: 0,837) | Har bir obraz sahifasi | `tests/test_consensus.py::test_overall_image_jaccard_matches_stats3` |
| IaC: 40 ta ataylab kiritilgan xato; Checkov 36, KICS 34, Trivy 32; precision 1,0 | Namoyish IaC tekshiruvi | `tests/test_scanner.py`, `tests/test_categories.py` |
| IaC vositalari mosligi: Jaccard 0,842 / 0,838 / 0,784 | IaC tekshiruv sahifasi | `tests/test_consensus.py::test_iac_jaccard_on_insecure_files_matches_analyze` |
| Eskirgan obrazlar (EOL) | Qizil ogohlantirish, DOCX bo‘limi | `tests/test_eol.py` |

Kutilgan qiymatlar dissertatsiya skriptlari hisoblagan `demo/sinov/natijalar/tahlil/ch3.json` va `summary.json` fayllaridan olinadi. Platforma ularni xom hisobotlardan qaytadan hisoblaydi, testlar esa natijalar bir xil ekanini tekshiradi.

## Xavfsizlik

- Har bir skaner alohida konteynerda ishlaydi: `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, CPU, xotira va jarayonlar soni cheklangan. Fayllar konteynerga faqat o‘qish uchun ulanadi.
- Vositalar faqat sha256 digest bo‘yicha chaqiriladi. Mahalliy yig‘ilgan Checkov obrazining ID si qulflanadi. Digest mos kelmasa, tekshiruvlar bloklanadi.
- Internet faqat bazalarni yangilash va vositalarni yuklab olishda kerak bo‘ladi. Proksi Docker Desktop sozlamasidan olinadi va tarmoqsiz konteynerlarga uzatilmaydi.
- Veb: CSP (inline skript yo‘q), CSRF, `X-Frame-Options`, HttpOnly va SameSite=Strict cookie, bcrypt, kirish urinishlari va so‘rovlar tezligi cheklangan, audit jurnali.
- Yuklangan fayllar tekshiruvdan keyin o‘chiriladi. Telemetriya va tashqi CDN yo‘q: ma’lumotlar O‘zbekiston hududidan chiqmaydi.

Batafsil: [docs/arxitektura.md](docs/arxitektura.md), 11- va 17-bo‘limlar.

## Loyiha tuzilmasi

```text
bulutskan/        core (model, konsensus, AHP, EOL), parsers, scanner (Docker), security,
                  services (pipeline, navbat, sozlash), storage (SQLite), reporting, web, cli.py
demo/sinov/       III bob eksperimentining real hisobotlari va skriptlari
packaging/        PyInstaller, Inno Setup, smoke test
ci/               CI/CD namunalari
docs/             arxitektura, Windows yo‘riqnomalari
tests/            pytest (Docker’siz, soxta docker va Windows fayl qoidasi bilan)
```

## Ishlab chiquvchilar uchun

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m mypy bulutskan tests
```

Testlar Docker talab qilmaydi. GitHub Actions ularni Ubuntu va Windows’da ishga tushiradi, keyin o‘rnatuvchini yig‘ib, toza Windows’da tekshiradi. Release ikki yo‘l bilan chiqadi: `v*` tegi push qilinganda yoki **Actions → build → Run workflow** (tarmoq `main`, “Release chiqarish” belgilangan) orqali. Ikkinchi holatda `v{versiya}` tegi o‘sha commit’da yaratiladi.

## Litsenziya

[MIT](LICENSE). Loyiha ichidagi uchinchi tomon kutubxonalari: htmx (0BSD) va Chart.js (MIT), ro‘yxati `bulutskan/web/static/vendor/LICENSES.txt` da. Skanerlar (Checkov, KICS, Trivy, Grype) o‘z litsenziyalari bilan alohida konteyner obrazlarida ishlaydi va o‘rnatuvchi ichiga kirmaydi.
