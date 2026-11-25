# BulutSkan’ni Windows’ga o‘rnatish (o‘rnatuvchi orqali)

Bu yo‘riqnoma tayyor o‘rnatuvchi `BulutSkan_Setup.exe` bilan ishlash uchun. Python, git va manba kod kerak emas. Manba koddan ishga tushirish va eksperimentni takrorlash `docs/windows_sinov.md` da yozilgan.

Hujjat oxirida **haqiqiy sinov qadamlari** jadvali bor (8-bo‘lim). O‘rnatuvchi toza kompyuterda shu jadval bo‘yicha tekshiriladi.

## 1. Talablar

| | |
|---|---|
| Operatsion tizim | Windows 10 yoki 11, 64-bit |
| Huquq | Oddiy foydalanuvchi. Administrator huquqi talab qilinmaydi |
| Docker Desktop | Yangi tekshiruvlar uchun kerak. U **Linux konteynerlari** rejimida (WSL 2) bo‘lishi lozim. Docker bo‘lmasa, dastur namoyish rejimida ishlaydi (5-bo‘lim) |
| Internet | Faqat birinchi sozlashda kerak: vosita obrazlari va zaifliklar bazalarini yuklab olish uchun. Proksi Docker Desktop sozlamasidan olinadi |
| Disk | Dasturning o‘zi ~150 MB. Vosita obrazlari va zaifliklar bazalari bir necha gigabayt joy egallaydi |

## 2. Yuklab olish

1. Repozitoriyning **Releases** sahifasini oching va eng so‘nggi versiyani tanlang.
2. **Assets** bo‘limidan ikkita faylni yuklab oling: `BulutSkan_Setup.exe` va `SHA256SUMS.txt`.
3. Fayl buzilmaganini tekshiring. PowerShell’da yuklab olingan papkada quyidagini bajaring:

```powershell
Get-FileHash .\BulutSkan_Setup.exe -Algorithm SHA256
Get-Content .\SHA256SUMS.txt
```

Ikkala qiymat bir xil bo‘lishi kerak. `Get-FileHash` katta harflarda chiqaradi, harf registri ahamiyatsiz.

## 3. O‘rnatish

1. `BulutSkan_Setup.exe` ni ikki marta bosing.
2. **SmartScreen ogohlantirishi.** O‘rnatuvchi raqamli imzoga ega emas, shuning uchun Windows “Windows protected your PC” oynasini ko‘rsatishi mumkin. **More info** ni, so‘ng **Run anyway** ni bosing. Faylning SHA-256 qiymati 2-bo‘limda tekshirilgan bo‘lsa, bu xavfsiz.
3. O‘rnatuvchi oynalari o‘zbek tilida:
   - **Litsenziya (MIT):** “Shartlarni qabul qilaman” → **Keyingi**.
   - **O‘rnatish papkasi:** sukut bo‘yicha `%LOCALAPPDATA%\Programs\BulutSkan`. O‘zgartirish shart emas → **Keyingi**.
   - **Qo‘shimcha vazifalar:** “Ish stolida belgi yaratish” belgilangan bo‘lsin → **Keyingi** → **O‘rnatish**.
4. Oxirgi oynada “BulutSkan’ni ishga tushirish” belgilangan bo‘ladi. **Tugatish** ni bosing.

**Jim o‘rnatish** (masalan, bir nechta kompyuterga):

```powershell
.\BulutSkan_Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
```

## 4. Birinchi ishga tushirish

1. Ish stolidagi **BulutSkan** belgisini bosing. Qora oyna ochiladi, unda quyidagiga o‘xshash yozuv chiqadi:

   ```text
   BulutSkan 1.0.0 ishlayapti: http://127.0.0.1:8000/
   Ma’lumotlar katalogi: C:\Users\...\AppData\Local\BulutSkan\data
   Dasturni to‘xtatish uchun shu oynani yoping (yoki Ctrl+C).
   ```

   **Bu oynani yopmang:** dastur shu oyna ochiq turganda ishlaydi. Oynani yopsangiz, dastur to‘xtaydi.
2. Bir necha soniyadan keyin brauzer o‘zi ochiladi. Ochilmasa, oynadagi manzilni brauzerga kiriting. Dastur faqat shu kompyuterdan ochiladi (`127.0.0.1`), tarmoqdagi boshqa kompyuterlar unga ulana olmaydi.
3. **Administrator akkaunti.** Birinchi ochilganda “Birinchi sozlash” sahifasi chiqadi. Login va parol kiriting. Parol kamida 12 belgi bo‘lishi kerak. Bu sahifa faqat bir marta, akkaunt yo‘qligida ochiladi.
4. Login va parol bilan kiring. Birinchi kirishda **sozlash ustasi** ochiladi (“Vositalar va bazalar” sahifasi).
5. Namoyish ma’lumotlari (III bob eksperimenti: 15 ta obraz va IaC fayllari) birinchi ishga tushirishda o‘zi yuklanadi. Bunga bir necha soniya ketadi, “Tekshiruvlar tarixi” sahifasida 16 ta yozuv paydo bo‘ladi.

Belgi ikkinchi marta bosilsa, yangi nusxa ochilmaydi: ishlab turgan dastur brauzerda ochiladi va oynada “BulutSkan allaqachon ishlayapti” yozuvi chiqadi.

## 5. Sozlash ustasi

Usta to‘rt qadamni tartib bilan tekshiradi. Keyingi qadam oldingisi yashil bo‘lgandan keyin ochiladi.

| № | Qadam | Yashil bo‘lsa | Qizil bo‘lsa |
|---|---|---|---|
| 1 | Docker | Docker Desktop ishlayapti, Linux konteynerlari | **O‘rnatish ko‘rsatmasi** yoki **Namoyish rejimida davom etish** |
| 2 | Vosita obrazlari | Trivy, Grype, KICS sha256 digest bo‘yicha mos | **Yuklab olish** (faqat digest bo‘yicha) |
| 3 | Checkov obrazi | Mahalliy yig‘ilgan obraz qulflangan | **Yig‘ish** yoki **Qulflash** |
| 4 | Zaifliklar bazalari | Trivy, Trivy Java va Grype bazalari bor | **Yuklab olish** yoki **Yangilash** |

- Har amalning holati va jarayoni sahifada yangilanib turadi. Sahifani yopib, keyinroq qaytish mumkin: amallarni fon jarayoni bajaradi.
- **Proksi.** Internet kerak bo‘lgan amallar (obraz va bazalarni yuklab olish, Checkov’ni yig‘ish) proksini Docker Desktop’dan oladi: **Settings → Resources → Proxies**. Ulanish xatosi chiqsa, avval shu sozlamani tekshiring. Proksi manzili BulutSkan’da saqlanmaydi.
- **Docker bo‘lmasa.** “Namoyish rejimida davom etish” tugmasi panelni ochadi. Eksperiment natijalari, konsensus, Jaccard, EOL ogohlantirishi, AHP hamda DOCX va JSON hisobotlar Docker’siz ishlaydi. Yangi tekshiruv yuborib bo‘lmaydi, buni sahifa tepasidagi ko‘k yozuv eslatadi. Docker o‘rnatilgandan keyin “Qayta tekshirish” ni bosing.
- **Docker Windows konteynerlari rejimida bo‘lsa,** 1-qadam qizil bo‘ladi. Vazifalar panelidagi Docker belgisini o‘ng tugma bilan bosing va **Switch to Linux containers** ni tanlang.

## 6. Foydalanish

- **Boshqaruv paneli:** tekshiruvlar soni, kritik topilmalar, konsensus ulushi, eskirgan obrazlar, diagrammalar.
- **IaC tekshiruvi:** Terraform, Kubernetes YAML yoki Dockerfile fayllarini (yoki ZIP arxivni) yuklang. “Namoyish fayllari” tanlansa, III bobdagi 40 ta xato bor fayllar tekshiriladi.
- **Obraz tekshiruvi:** obraz nomi (`nginx:1.21`) yoki `docker save` bilan olingan `.tar` fayl.
- **Tekshiruv sahifasi:** jiddiylik jadvali, vositalar versiyasi va digestlari, konsensus guruhlari (filtrlar bilan), **JSON** va **DOCX hisobot** tugmalari.
- **Solishtirish:** ikki tekshiruv o‘rtasida yangi va yo‘qolgan topilmalar.
- **Vosita tanlash (AHP):** vaznlarni o‘zgartiring, reyting darhol qayta hisoblanadi. Ssenariylar va sezgirlik tahlili ham shu sahifada.
- **Administrator:** foydalanuvchilar va audit jurnali (CSV yuklab olish bilan).

### CLI

O‘rnatilgan dastur buyruq qatoridan ham ishlaydi:

```powershell
$bs = "$env:LOCALAPPDATA\Programs\BulutSkan\BulutSkan.exe"
& $bs --version
& $bs scan --image nginx:1.21 --fail-on critical --json natija.json --docx hisobot.docx
& $bs scan --iac D:\loyiha\infra --fail-on high --save
& $bs user add tahlilchi --role analyst
```

`--save` natijani tarixga yozadi, shunda u veb-interfeysda ham ko‘rinadi. Chiqish kodlari: `0` — chegaradan oshmadi, `1` — `--fail-on` darajasidagi topilma bor, `2` — biror vosita ishlamadi (qisman natija). Qisman natijani qabul qilish uchun `--allow-partial` qo‘shiladi.

### Sozlamalar fayli

Odatda sozlash shart emas. Kerak bo‘lsa, `%LOCALAPPDATA%\BulutSkan\bulutskan.env` faylini yarating, masalan:

```text
BULUTSKAN_PORT=8080
BULUTSKAN_OPEN_BROWSER=false
BULUTSKAN_LANG=en
```

## 7. Yangilash va o‘chirish

**Yangilash.** Yangi `BulutSkan_Setup.exe` ni eski versiya ustidan o‘rnating. Avval dastur oynasini yoping. Foydalanuvchi ma’lumotlari `%LOCALAPPDATA%\BulutSkan\data` papkasida turadi, yangilash ularga tegmaydi: akkauntlar, tekshiruvlar tarixi, `tool_lock.json` va zaifliklar bazalari saqlanib qoladi.

**O‘chirish.** **Sozlamalar → Ilovalar → BulutSkan → O‘chirish**. Dastur papkasi o‘chiriladi, ma’lumotlar papkasi qoladi. Uni ham o‘chirmoqchi bo‘lsangiz, `%LOCALAPPDATA%\BulutSkan` papkasini qo‘lda o‘chiring. Vosita obrazlari Docker’da qoladi, ularni Docker Desktop’ning **Images** bo‘limidan o‘chirish mumkin.

## 8. Haqiqiy sinov qadamlari

Toza kompyuterda (yoki BulutSkan hech qachon o‘rnatilmagan Windows foydalanuvchisida) quyidagi qadamlarni tartib bilan bajaring. Har qadam uchun natijani yozib boring.

| № | Qadam | Kutilgan natija |
|---|---|---|
| 1 | Releases’dan `BulutSkan_Setup.exe` va `SHA256SUMS.txt` ni yuklab oling, `Get-FileHash` bilan tekshiring | Qiymatlar bir xil |
| 2 | O‘rnatuvchini ishga tushiring (SmartScreen: More info → Run anyway) | Oynalar o‘zbek tilida, administrator paroli so‘ralmaydi |
| 3 | O‘rnatishni tugating | Ish stolida va Boshlash (Start) menyusida **BulutSkan** belgisi bor |
| 4 | Belgini bosing | Qora oynada manzil chiqadi, brauzer o‘zi ochiladi |
| 5 | Administrator akkauntini yarating va kiring | Sozlash ustasi ochiladi |
| 6 | **Docker Desktop ishlamayotgan holatda** “Qayta tekshirish” ni bosing | 1-qadam qizil: “Docker Desktop o‘rnatilgan, lekin ishga tushirilmagan…” |
| 7 | “Tekshiruvlar tarixi” ni oching | 16 ta namoyish yozuvi (15 obraz + IaC) |
| 8 | `nginx:1.21` ni oching | Qizil EOL ogohlantirishi; Jaccard `0,729` |
| 9 | “Namoyish IaC fayllari (III bob)” ni oching | Ground truth: Checkov 36/40, KICS 34/40, Trivy 32/40 |
| 10 | “Vosita tanlash (AHP)” ni oching | CR = 0,0053; reyting: Checkov, Trivy, Grype; slayder siljitilsa reyting o‘zgaradi |
| 11 | `nginx:1.21` sahifasida **DOCX hisobot** ni bosing | Word’da ochiladi, bo‘limlar 1 dan ketma-ket raqamlangan |
| 12 | Docker Desktop’ni ishga tushiring, ustada “Qayta tekshirish” | 1-qadam yashil (Docker versiyasi, Linux konteynerlari) |
| 13 | 2–4-qadamlarni ustadagi tugmalar bilan bajaring | Har biri yashil bo‘ladi; proksi Docker Desktop’dan olinadi |
| 14 | “Obraz tekshiruvi”: `alpine:3.20` | Tekshiruv navbatga tushadi, bir necha daqiqada “Tugadi” |
| 15 | “IaC tekshiruvi”: namoyish fayllari | Natija 9-qadamdagi bilan bir xil (36/34/32) |
| 16 | Belgini ikkinchi marta bosing | Yangi oyna ochilib yopiladi: “allaqachon ishlayapti”, brauzer ochiladi |
| 17 | Dastur oynasini yoping, belgini qayta bosing | Dastur qayta ochiladi, tarix va akkaunt saqlangan |
| 18 | Yangi versiyani eski ustidan o‘rnating (keyingi relizda) | Tarix, akkaunt, bazalar va `tool_lock.json` saqlangan |
| 19 | Dasturni o‘chiring | Dastur papkasi yo‘q, `%LOCALAPPDATA%\BulutSkan\data` qolgan |

**Natijani yuborish.** Har bir qadam uchun “bajarildi” yoki “xato” deb yozing. Xato bo‘lsa, qora oynadagi oxirgi qatorlarni va ekran suratini yuboring. 12–13-qadamlar uchun PowerShell’dagi `docker info` natijasini ham yuboring, lekin undan proksi manzilini o‘chirib tashlang.

GitHub Actions har bir versiyada 1–4, 7–11, 16 va 19-qadamlarni avtomatik tekshiradi (`.github/workflows/build.yml`, “Windows o‘rnatuvchisi” ishi). Unda Docker Linux konteynerlari yo‘q, shuning uchun 12–15-qadamlar faqat haqiqiy kompyuterda tekshiriladi.

## 9. Muammolar va yechimlar

| Muammo | Yechim |
|---|---|
| SmartScreen o‘rnatuvchini ochmayapti | **More info → Run anyway**. Tashkilot siyosati imzosiz dasturlarni taqiqlagan bo‘lsa, administratorga murojaat qiling |
| Antivirus `BulutSkan.exe` ni bloklayapti | PyInstaller bilan yig‘ilgan imzosiz dasturlarda shunday bo‘lishi mumkin. SHA-256 ni tekshiring va dastur papkasini istisnolarga qo‘shing |
| Brauzer ochilmadi | Qora oynadagi manzilni (`http://127.0.0.1:8000/`) qo‘lda oching |
| 8000-port band | Dastur keyingi bo‘sh portni (8001, 8002, …) o‘zi tanlaydi; manzil oynada ko‘rinadi |
| Ustada “Docker Desktop topilmadi”, lekin u o‘rnatilgan | Docker Desktop’ni ishga tushiring va bir daqiqa kuting. Dastur Docker’ni `PATH` dan, topilmasa `C:\Program Files\Docker\Docker\resources\bin\docker.exe` dan oladi |
| Obraz yoki baza yuklanmayapti | Docker Desktop → Settings → Resources → Proxies sozlamasini tekshiring |
| Parolni unutdim | PowerShell: `& "$env:LOCALAPPDATA\Programs\BulutSkan\BulutSkan.exe" user passwd admin` |
