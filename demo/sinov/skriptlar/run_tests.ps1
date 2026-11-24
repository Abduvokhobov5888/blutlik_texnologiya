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
param([int]$Repeats = 3)

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

# ---------------- 0. Docker tekshiruvi va muhit ma'lumotlari ----------------
Step "0. Docker va kompyuter ma'lumotlari"
docker version --format "Docker server: {{.Server.Version}}"
if ($LASTEXITCODE -ne 0) { Write-Host "Docker ishlamayapti. Docker Desktop'ni ishga tushiring va qayta urinib ko'ring." -ForegroundColor Red; Stop-Transcript | Out-Null; exit 1 }
$cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
$ram = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
$os  = (Get-CimInstance Win32_OperatingSystem).Caption
$dv  = (docker version --format "{{.Server.Version}}")
@("Sana: $(Get-Date -Format 'yyyy-MM-dd HH:mm')", "OT: $os", "CPU: $cpu", "RAM: $ram GB", "Docker: $dv") | Out-File -Encoding utf8 (Join-Path $Res "env.txt")

# ---------------- 1. Vositalar obrazlari ----------------
Step "1. Vositalarni yuklab olish va digestlarni yozish"
$digests = Join-Path $Res "tool_digests.txt"
"" | Out-File -Encoding utf8 $digests
foreach ($img in @($TRIVY_IMAGE, $GRYPE_IMAGE, $KICS_IMAGE)) {
    docker pull $img
    $dg = docker image inspect $img --format "{{index .RepoDigests 0}}"
    "$img  ->  $dg" | Out-File -Encoding utf8 -Append $digests
}
docker build @BuildProxy -t "diss-checkov:$CHECKOV_VERSION" --build-arg "CHECKOV_VERSION=$CHECKOV_VERSION" -f (Join-Path $Root "checkov.Dockerfile") $Root
"checkov (pip) == $CHECKOV_VERSION" | Out-File -Encoding utf8 -Append $digests

$ver = Join-Path $Res "versions.txt"
"--- trivy ---"   | Out-File -Encoding utf8 $ver;  docker run --rm $TRIVY_IMAGE --version | Out-File -Encoding utf8 -Append $ver
"--- grype ---"   | Out-File -Encoding utf8 -Append $ver; docker run --rm $GRYPE_IMAGE version | Out-File -Encoding utf8 -Append $ver
"--- kics ---"    | Out-File -Encoding utf8 -Append $ver; docker run --rm $KICS_IMAGE version | Out-File -Encoding utf8 -Append $ver
"--- checkov ---" | Out-File -Encoding utf8 -Append $ver; docker run --rm "diss-checkov:$CHECKOV_VERSION" --version | Out-File -Encoding utf8 -Append $ver
Write-Host "   Digestlar natijalar\tool_digests.txt fayliga yozildi."

# ---------------- 2. IaC skanerlash (internetsiz) ----------------
Step "2. IaC test fayllarini tekshirish (internet o'chirilgan)"
for ($r = 1; $r -le $Repeats; $r++) {
    $o = Join-Path $ResI "run$r"; New-Item -ItemType Directory -Force -Path $o | Out-Null
    Timed "checkov" "iac" $r { docker run --rm --network none -v "${Iac}:/iac:ro" -v "${o}:/out" "diss-checkov:$CHECKOV_VERSION" -d /iac --skip-download --quiet -o json --output-file-path /out/checkov 2>> $ErrLog | Out-Null }
    Timed "kics" "iac" $r { docker run --rm --network none -v "${Iac}:/iac:ro" -v "${o}:/out" $KICS_IMAGE scan -p /iac -o /out/kics --report-formats json --no-progress 2>> $ErrLog | Out-Null }
    Timed "trivy-config" "iac" $r { docker run --rm --network none -v "${Iac}:/iac:ro" -v "${o}:/out" $TRIVY_IMAGE config --skip-check-update --format json --output /out/trivy_config.json /iac 2>> $ErrLog | Out-Null }
}

# ---------------- 3. Obrazlarni yuklab, .tar ga saqlash ----------------
Step "3. Sinov obrazlarini yuklab olish"
$images = Get-Content (Join-Path $Root "images.txt") | Where-Object { $_ -and -not $_.StartsWith("#") } | ForEach-Object { $_.Trim() }
$imgDig = Join-Path $Res "image_digests.txt"
"" | Out-File -Encoding utf8 $imgDig
foreach ($img in $images) {
    $name = ($img -replace "[/:]", "_")
    $tarFile = Join-Path $Tar "$name.tar"
    docker pull $img
    if ($LASTEXITCODE -ne 0) { Write-Host "   $img yuklanmadi, o'tkazib yuboriladi" -ForegroundColor Yellow; continue }
    $dg = docker image inspect $img --format "{{index .RepoDigests 0}}"
    "$img  ->  $dg" | Out-File -Encoding utf8 -Append $imgDig
    if (-not (Test-Path $tarFile)) { docker save $img -o $tarFile }
}

# ---------------- 4. Zaifliklar bazalarini yuklash ----------------
Step "4. Trivy va Grype bazalarini yuklash"
Timed "trivy-db" "download" 1 { docker run --rm @ProxyArgs -v "${CacheT}:/cache" $TRIVY_IMAGE image --cache-dir /cache --download-db-only 2>> $ErrLog | Out-Null }
$trivyOk = ($script:LastCode -eq 0)
Timed "grype-db" "download" 1 { docker run --rm @ProxyArgs -e GRYPE_DB_CACHE_DIR=/cache -v "${CacheG}:/cache" $GRYPE_IMAGE db update 2>> $ErrLog | Out-Null }
$grypeOk = ($script:LastCode -eq 0)
if (-not ($trivyOk -and $grypeOk)) {
    Write-Host ""
    Write-Host "XATO: zaifliklar bazasi yuklanmadi (Trivy: $trivyOk, Grype: $grypeOk)." -ForegroundColor Red
    Write-Host "Sabab odatda proksi. Ekranni rasmga olib Claude'ga yuboring." -ForegroundColor Red
    Stop-Transcript | Out-Null
    exit 2
}
docker run --rm -e GRYPE_DB_CACHE_DIR=/cache -v "${CacheG}:/cache" $GRYPE_IMAGE db status | Out-File -Encoding utf8 (Join-Path $Res "grype_db_status.txt")
Get-ChildItem -Path $CacheT -Recurse -Filter "metadata.json" | Where-Object { $_.DirectoryName -like "*db" } | Select-Object -First 1 | ForEach-Object { Copy-Item $_.FullName (Join-Path $Res "trivy_db_metadata.json") }

# ---------------- 5. Obrazlarni skanerlash (internetsiz) ----------------
Step "5. Obrazlarni Trivy va Grype bilan tekshirish (internet o'chirilgan)"
foreach ($img in $images) {
    $name = ($img -replace "[/:]", "_")
    if (-not (Test-Path (Join-Path $Tar "$name.tar"))) { continue }
    for ($r = 1; $r -le $Repeats; $r++) {
        Timed "trivy" $img $r { docker run --rm --network none -v "${CacheT}:/cache" -v "${Tar}:/tar:ro" -v "${ResV}:/out" $TRIVY_IMAGE image --cache-dir /cache --skip-db-update --skip-java-db-update --offline-scan --scanners vuln --format json --output "/out/trivy_${name}_run$r.json" --input "/tar/$name.tar" 2>> $ErrLog | Out-Null }
        Timed "grype" $img $r { docker run --rm --network none -e GRYPE_DB_CACHE_DIR=/cache -e GRYPE_DB_AUTO_UPDATE=false -e GRYPE_CHECK_FOR_APP_UPDATE=false -v "${CacheG}:/cache" -v "${Tar}:/tar:ro" -v "${ResV}:/out" $GRYPE_IMAGE "docker-archive:/tar/$name.tar" -o json --file "/out/grype_${name}_run$r.json" 2>> $ErrLog | Out-Null }
    }
}

Step "TAYYOR"
Write-Host "Barcha natijalar shu papkada: $Res" -ForegroundColor Green
Write-Host "Endi Claude'ga 'sinov tugadi' deb yozing." -ForegroundColor Green
Stop-Transcript | Out-Null
