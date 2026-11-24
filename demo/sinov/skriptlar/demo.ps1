# =====================================================================
#  HIMOYA UCHUN NAMOYISH SKRIPTI (taxminan 1 daqiqa)
#  Ishga tushirish:  powershell -ExecutionPolicy Bypass -File .\demo.ps1
#  Talab: Docker Desktop yoqilgan bo'lsin. Internet kerak emas.
# =====================================================================
$Root = $PSScriptRoot
. (Join-Path $Root "config.ps1")
$Iac = Join-Path $Root "iac"
function Step($msg) { Write-Host ""; Write-Host "==== $msg ====" -ForegroundColor Cyan }
function Pause-Demo { Write-Host ""; Read-Host "Davom etish uchun Enter ni bosing" | Out-Null }

Step "1. Vositalar versiyalari"
docker run --rm "diss-checkov:$CHECKOV_VERSION" --version
docker run --rm $TRIVY_IMAGE --version
Pause-Demo

Step "2. Zaif Terraform faylini Checkov bilan tekshirish (internet o'chirilgan)"
docker run --rm --network none -v "${Iac}:/iac:ro" "diss-checkov:$CHECKOV_VERSION" -f /iac/terraform/insecure/main.tf --framework terraform --compact --skip-download
Pause-Demo

Step "3. Kubernetes manifestini Trivy bilan tekshirish"
docker run --rm --network none -v "${Iac}:/iac:ro" $TRIVY_IMAGE config --skip-check-update --quiet /iac/kubernetes/insecure
Pause-Demo

Step "4. Eksperimentning yakuniy natijalari (analyze.py)"
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { $py = Get-Command py -ErrorAction SilentlyContinue }
if ($py) { & $py.Source (Join-Path $Root "analyze.py") $Root | Select-Object -First 12 }
else { Get-Content (Join-Path $Root "natijalar\tahlil\analyze_log.txt") -TotalCount 12 }

Step "TAYYOR"
