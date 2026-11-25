## BulutSkan — Windows o‘rnatuvchisi

IaC fayllari (Terraform, Kubernetes, Dockerfile) va konteyner obrazlarini Checkov, KICS, Trivy va Grype bilan tekshiruvchi mahalliy platforma. Natijalar konsensus asosida baholanadi. Platforma Andijon davlat universiteti magistrlik dissertatsiyasining amaliy natijasi.

### O‘rnatish

1. `BulutSkan_Setup.exe` faylini yuklab oling.
2. Faylni ishga tushiring. Administrator huquqi talab qilinmaydi. Dastur `%LOCALAPPDATA%\Programs\BulutSkan` papkasiga o‘rnatiladi.
3. Windows SmartScreen “Windows protected your PC” deb ogohlantirsa, **More info → Run anyway** tugmalarini bosing. O‘rnatuvchi raqamli imzoga ega emas, shuning uchun bu ogohlantirish chiqadi.
4. Ish stolidagi **BulutSkan** belgisini bosing. Brauzer ochiladi. U yerda administrator akkauntini yarating, so‘ng sozlash ustasi ochiladi.

Python, git yoki boshqa dastur o‘rnatish shart emas. Yangi tekshiruvlar uchun **Docker Desktop** (Linux konteynerlari rejimi) kerak. Docker bo‘lmasa, dastur namoyish rejimida ishlaydi: dissertatsiyaning III bobidagi eksperiment natijalari (15 ta obraz va IaC fayllari), AHP hamda DOCX/JSON hisobotlar Docker’siz ham ochiladi.

Batafsil yo‘riqnoma: [docs/windows_ornatish.md]({{REPO_URL}}/blob/main/docs/windows_ornatish.md).

### Fayl tekshiruvi

```
SHA256  {{SHA256}}  BulutSkan_Setup.exe
```

PowerShell’da tekshirish: `Get-FileHash .\BulutSkan_Setup.exe -Algorithm SHA256`.

### Ma’lumotlar

Barcha ma’lumotlar kompyuterda, `%LOCALAPPDATA%\BulutSkan\data` papkasida saqlanadi. Dastur o‘chirilsa yoki yangilansa ham bu papka saqlanib qoladi. Telemetriya va tashqi CDN ishlatilmaydi; ma’lumotlar O‘zbekiston hududidan chiqmaydi.
