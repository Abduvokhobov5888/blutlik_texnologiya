# =====================================================================
#  Magistrlik dissertatsiyasi, III bob: ochiq kodli bulut xavfsizligi
#  vositalarini (Trivy, Grype, Checkov, KICS) sinash skripti.
#
#  Ishga tushirish (PowerShell, shu papkada):
#     Set-ExecutionPolicy -Scope Process Bypass
#     .\run_tests.ps1
#
#  Skript nima qiladi:
#   1) vositalar obrazlarini yuklab oladi va ularning digestini yozib qo'yadi;
#   2) IaC test fayllarini Checkov, KICS va Trivy bilan INTERNETSIZ tekshiradi;
#   3) images.txt dagi obrazlarni yuklab, .tar faylga saqlaydi;
#   4) Trivy va Grype zaifliklar bazalarini yuklaydi;
#   5) har bir obrazni Trivy va Grype bilan INTERNETSIZ tekshiradi ($Repeats marta);
#   6) barcha natijalarni "natijalar" papkasiga yozadi.
#  Skanerlarga faqat shu "Sinov" papkasi ko'rinadi; shaxsiy fayllaringizga kirmaydi.
# =====================================================================
param([int]$Repeats = 3, [string]$Image = "nginx:1.21")

$Root = $PSScriptRoot
. (Join-Path $Root "config.ps1")
# ---- Proksi: config.ps1 dagi $PROXY yoki Windows sozlamasidan avtomatik olinadi ----
if (-not $PROXY) {
    # 1) Docker Desktop'ning ichki proksisi (Settings -> Resources -> Proxies da sozlangan bo'lsa)
    $dp = (docker info --format "{{.HTTPSProxy}}" 2>$null)
    if (-not $dp) { $dp = (docker info --format "{{.HTTPProxy}}" 2>$null) }
    if ($dp) { $dp = "$dp".Trim(); if ($dp -notmatch '^https?://') { $dp = "http://$dp" }; $PROXY = $dp }
}
if (-not $PROXY) {
    # 2) Windows proksi sozlamasi
    $ie = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if ($ie -and $ie.ProxyEnable -eq 1 -and $ie.ProxyServer) {
        $ps = $ie.ProxyServer
        if ($ps -match 'https=([^;]+)') { $ps = $Matches[1] } elseif ($ps -match 'http=([^;]+)') { $ps = $Matches[1] }
        if ($ps -notmatch '^https?://') { $ps = "http://$ps" }
        $PROXY = $ps
    }
}
$ProxyArgs = @(); $BuildProxy = @()
if ($PROXY) {
    $cp = $PROXY -replace '//(127\.0\.0\.1|localhost)', '//host.docker.internal'
    $ProxyArgs  = @('-e', "HTTP_PROXY=$cp", '-e', "HTTPS_PROXY=$cp", '-e', "http_proxy=$cp", '-e', "https_proxy=$cp", '-e', 'NO_PROXY=localhost,127.0.0.1')
    $BuildProxy = @('--build-arg', "HTTP_PROXY=$cp", '--build-arg', "HTTPS_PROXY=$cp", '--build-arg', "http_proxy=$cp", '--build-arg', "https_proxy=$cp")
    Write-Host "Proksi ishlatiladi: $cp" -ForegroundColor Yellow
}

$Res   = Join-Path $Root "natijalar"
$ResI  = Join-Path $Res "iac"
$ResV  = Join-Path $Res "images"
$Tar   = Join-Path $Root "tar"
$CacheT = Join-Path $Root "cache\trivy"
$CacheG = Join-Path $Root "cache\grype"
$Iac   = Join-Path $Root "iac"
foreach ($d in @($Res, $ResI, $ResV, $Tar, $CacheT, $CacheG)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }

Start-Transcript -Path (Join-Path $Res "log.txt") -Append | Out-Null
$timings = Join-Path $Res "timings.csv"
$ErrLog  = Join-Path $Res "stderr_log.txt"
if (-not (Test-Path $timings)) { "tool;target;run;seconds;exitcode" | Out-File -Encoding utf8 $timings }

function Step($msg) { Write-Host ""; Write-Host "==== $msg ====" -ForegroundColor Cyan }
function Timed($tool, $target, $run, [scriptblock]$block) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    & $block
    $code = $LASTEXITCODE
    $script:LastCode = $code
    $sw.Stop()
    $sec = [math]::Round($sw.Elapsed.TotalSeconds, 2).ToString([Globalization.CultureInfo]::InvariantCulture)
    "$tool;$target;$run;$sec;$code" | Out-File -Encoding utf8 -Append $timings
    Write-Host ("   {0} | {1} | run {2}: {3} s (exit {4})" -f $tool, $target, $run, $sec, $code)
}


# ---------------- Faqat bitta obraz uchun Trivy'ni qayta ishga tushirish ----------------
# nginx:1.21 obrazida Java (.jar) fayllar bor, Trivy ularni tekshirish uchun Java bazasini talab qiladi.
Step "Trivy Java bazasini yuklash"
Timed "trivy-javadb" "download" 1 { docker run --rm @ProxyArgs -v "${CacheT}:/cache" $TRIVY_IMAGE image --cache-dir /cache --download-java-db-only 2>> $ErrLog | Out-Null }
if ($script:LastCode -ne 0) { Write-Host "XATO: Java bazasi yuklanmadi. Ekranni rasmga olib Claude'ga yuboring." -ForegroundColor Red; Stop-Transcript | Out-Null; exit 2 }

Step "Trivy: $Image (internet o'chirilgan)"
$name = ($Image -replace "[/:]", "_")
for ($r = 1; $r -le $Repeats; $r++) {
    Timed "trivy" $Image $r { docker run --rm --network none -v "${CacheT}:/cache" -v "${Tar}:/tar:ro" -v "${ResV}:/out" $TRIVY_IMAGE image --cache-dir /cache --skip-db-update --skip-java-db-update --offline-scan --scanners vuln --format json --output "/out/trivy_${name}_run$r.json" --input "/tar/$name.tar" 2>> $ErrLog | Out-Null }
}
Step "TAYYOR"
Write-Host "Endi Claude'ga 'nginx tayyor' deb yozing." -ForegroundColor Green
Stop-Transcript | Out-Null
