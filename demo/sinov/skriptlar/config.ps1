# Vosita versiyalari (2026-yil 24-noyabr holatiga rasmiy GitHub relizlari bo'yicha tekshirilgan).
# DIQQAT: Trivy 0.69.4, 0.69.5, 0.69.6 versiyalari ZARARLI (CVE-2026-33634) - ulardan foydalanmang.
# DIQQAT: KICS uchun "latest", "alpine", "debian", "v2.1.20" teglarini ishlatmang - ular 2026-yil
#         22-aprelda vaqtincha zararli obrazlar bilan almashtirilgan edi. Hodisadan keyin chiqqan
#         v2.2.0 relizi tanlandi.
$TRIVY_IMAGE     = "aquasec/trivy:0.76.1"
$GRYPE_IMAGE     = "anchore/grype:v0.121.0"
$KICS_IMAGE      = "checkmarx/kics:v2.2.0"
$CHECKOV_VERSION = "3.3.26"

# Proksi. Bo'sh qoldirilsa, Windows sozlamasidan avtomatik olinadi.
# Masalan: $PROXY = "http://10.0.0.1:3128"
$PROXY = ""
