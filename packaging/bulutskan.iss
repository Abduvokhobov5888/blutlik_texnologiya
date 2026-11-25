; BulutSkan o‘rnatuvchisi (Inno Setup 6). Fayl UTF-8 (BOM bilan) saqlanadi.
;
; Yig‘ish (avval PyInstaller: dist\BulutSkan\BulutSkan.exe):
;   iscc /DAppVersion=1.0.0 packaging\bulutskan.iss
; Natija: dist\BulutSkan_Setup.exe
;
; O‘rnatish administrator huquqisiz, joriy foydalanuvchi uchun:
;   %LOCALAPPDATA%\Programs\BulutSkan
; Foydalanuvchi ma’lumotlari (baza, hisobotlar, zaifliklar bazalari) alohida:
;   %LOCALAPPDATA%\BulutSkan\data — yangilash va o‘chirishda saqlanib qoladi.
;
; Jim o‘rnatish: BulutSkan_Setup.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{0E00705E-A2D1-4EA8-A5C5-3279909FBC54}
AppName=BulutSkan
AppVersion={#AppVersion}
AppVerName=BulutSkan {#AppVersion}
AppPublisher=Andijon davlat universiteti (magistrlik dissertatsiyasi)
AppComments=IaC fayllari va konteyner obrazlarini ochiq kodli skanerlar bilan tekshirish
VersionInfoVersion={#AppVersion}
DefaultDirName={localappdata}\Programs\BulutSkan
DefaultGroupName=BulutSkan
DisableProgramGroupPage=yes
DisableDirPage=auto
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=BulutSkan_Setup
SetupIconFile=bulutskan.ico
UninstallDisplayIcon={app}\BulutSkan.exe
UninstallDisplayName=BulutSkan
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=no
LicenseFile=..\LICENSE

[Languages]
Name: "uz"; MessagesFile: "compiler:Default.isl"

[Messages]
SetupAppTitle=BulutSkan o‘rnatuvchisi
SetupWindowTitle=BulutSkan %1 o‘rnatuvchisi
WelcomeLabel1=BulutSkan o‘rnatuvchisiga xush kelibsiz
WelcomeLabel2=Kompyuteringizga [name/ver] o‘rnatiladi.%n%nDastur IaC fayllari va konteyner obrazlarini Checkov, KICS, Trivy va Grype bilan tekshiradi. Tekshiruvlar uchun Docker Desktop kerak; u bo‘lmasa, III bob eksperimenti natijalari namoyish rejimida ko‘rsatiladi.
ButtonBack=< &Orqaga
ButtonNext=&Keyingi >
ButtonInstall=&O‘rnatish
ButtonCancel=Bekor qilish
ButtonFinish=&Tugatish
ButtonBrowse=&Tanlash...
LicenseLabel=Litsenziya shartlari bilan tanishib chiqing.
LicenseLabel3=Litsenziya (MIT) matni:
LicenseAccepted=Shartlarni &qabul qilaman
LicenseNotAccepted=Shartlarni qabul &qilmayman
WizardSelectDir=O‘rnatish papkasi
SelectDirDesc=[name] qayerga o‘rnatilsin?
SelectDirLabel3=[name] quyidagi papkaga o‘rnatiladi.
SelectDirBrowseLabel=Davom etish uchun "Keyingi" ni bosing. Boshqa papka tanlash uchun "Tanlash" ni bosing.
WizardSelectTasks=Qo‘shimcha vazifalar
SelectTasksDesc=Qo‘shimcha amallarni tanlang.
SelectTasksLabel2=[name] o‘rnatilayotganda bajariladigan amallarni belgilang va "Keyingi" ni bosing.
WizardReady=O‘rnatishga tayyor
ReadyLabel1=[name] o‘rnatishga tayyor.
ReadyLabel2a=O‘rnatishni boshlash uchun "O‘rnatish" ni bosing.
ReadyLabel2b=O‘rnatishni boshlash uchun "O‘rnatish" ni bosing.
WizardInstalling=O‘rnatilmoqda
InstallingLabel=[name] o‘rnatilmoqda, kuting...
FinishedHeadingLabel=O‘rnatish tugadi
FinishedLabelNoIcons=[name] o‘rnatildi.
FinishedLabel=[name] o‘rnatildi. Uni ish stolidagi belgi orqali ishga tushirishingiz mumkin.
ClickFinish="Tugatish" ni bosing.
ExitSetupTitle=O‘rnatishdan chiqish
ExitSetupMessage=O‘rnatish tugamadi. Chiqsangiz, dastur o‘rnatilmaydi.%n%nChiqilsinmi?
ConfirmUninstall=%1 va uning barcha qismlari o‘chirilsinmi? Ma’lumotlaringiz (AppData\Local\BulutSkan) saqlanib qoladi.
UninstalledAll=%1 kompyuterdan o‘chirildi.

[CustomMessages]
uz.CreateDesktopIcon=Ish stolida belgi yaratish
uz.AdditionalIcons=Qo‘shimcha belgilar:
uz.LaunchProgram=BulutSkan’ni ishga tushirish

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[InstallDelete]
; Eski versiyaning kutubxonalari qolmasin (foydalanuvchi ma’lumotlari boshqa papkada).
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "..\dist\BulutSkan\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\BulutSkan"; Filename: "{app}\BulutSkan.exe"; WorkingDir: "{app}"; Comment: "IaC va konteyner obrazlarini tekshirish"
Name: "{autodesktop}\BulutSkan"; Filename: "{app}\BulutSkan.exe"; WorkingDir: "{app}"; Tasks: desktopicon; Comment: "IaC va konteyner obrazlarini tekshirish"

[Run]
Filename: "{app}\BulutSkan.exe"; Description: "{cm:LaunchProgram}"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent
