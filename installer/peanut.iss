#ifndef Version
  #define Version "0.1.0"
#endif

[Setup]
AppName=Peanut
AppVersion={#Version}
AppPublisher=Peanut
DefaultDirName={autopf}\peanut
DisableProgramGroupPage=yes
PrivilegesRequired=admin
OutputDir=..\dist
OutputBaseFilename=PeanutSetup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=Peanut

[Files]
Source: "..\peanut.exe"; DestDir: "{app}"; Flags: ignoreversion

[Run]
Filename: "{app}\peanut.exe"; Parameters: "install --pause"; Flags: waituntilterminated; Description: "Set up Peanut"

[UninstallRun]
Filename: "{app}\peanut.exe"; Parameters: "uninstall --pause"; RunOnceId: "PeanutRemove"; Flags: waituntilterminated
