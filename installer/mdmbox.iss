#define MyAppName "MDMBOX"
#ifndef MyAppVersion
  #define MyAppVersion "0.1.0"
#endif
#ifndef SourceDir
  #error "SourceDir is required"
#endif
#ifndef OutputDir
  #error "OutputDir is required"
#endif
#ifndef RepoRoot
  #error "RepoRoot is required"
#endif

[Setup]
AppId={{8D62A7C9-5E4B-4C61-8A3F-6BEE2D2D4B91}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher=mdmbox
AppPublisherURL=https://github.com/
DefaultDirName={autopf}\MDMBOX
DefaultGroupName=MDMBOX
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=mdmbox-setup-{#MyAppVersion}
SetupIconFile={#RepoRoot}\res\nekobox.ico
UninstallDisplayIcon={app}\mdmbox.exe
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
VersionInfoCompany=mdmbox
VersionInfoDescription=MDMBOX Installer
VersionInfoProductName=MDMBOX
VersionInfoProductVersion={#MyAppVersion}
VersionInfoTextVersion={#MyAppVersion}

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\MDMBOX"; Filename: "{app}\mdmbox.exe"
Name: "{autodesktop}\MDMBOX"; Filename: "{app}\mdmbox.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\mdmbox.exe"; Description: "Запустить MDMBOX"; Flags: nowait postinstall skipifsilent
