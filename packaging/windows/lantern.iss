; Inno Setup script for the Lantern Windows installer.
;
; Build (after PyInstaller has written a one-folder build, dist\lantern\):
;   iscc /DAppVersion=1.1.0 /DAppDir=<folder with lantern.exe and _internal> /DOutDir=<output folder> packaging\windows\lantern.iss
;
; The installer ships PyInstaller's one-folder form, not the one-file
; lantern.exe: a one-file exe unpacks itself into a temp folder on every
; run, which antivirus heuristics often flag, and it starts slower.
;
; Installs for the current user only: no admin prompt, files go to
; %LOCALAPPDATA%\Programs\Lantern, and that folder is added to the user's
; PATH. Scan history lives in %LOCALAPPDATA%\Lantern\lantern.db, which the
; uninstaller leaves in place.

#ifndef AppVersion
  #error Pass /DAppVersion=x.y.z
#endif
#ifndef AppDir
  #define AppDir "..\..\dist\lantern"
#endif
#ifndef OutDir
  #define OutDir "..\..\dist"
#endif

[Setup]
; Never change AppId: upgrades and uninstall find the install by it.
AppId={{162EF9D4-55F7-448D-B80C-BB937061F570}
AppName=Lantern
AppVersion={#AppVersion}
AppVerName=Lantern {#AppVersion}
AppPublisher=DarthBitBeard
AppPublisherURL=https://github.com/DarthBitBeard/Lantern
AppSupportURL=https://github.com/DarthBitBeard/Lantern/issues
AppUpdatesURL=https://github.com/DarthBitBeard/Lantern/releases
DefaultDirName={autopf}\Lantern
DefaultGroupName=Lantern
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ChangesEnvironment=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutDir}
OutputBaseFilename=lantern-{#AppVersion}-windows-x64-setup
SetupIconFile=lantern.ico
UninstallDisplayIcon={app}\lantern.exe
UninstallDisplayName=Lantern {#AppVersion}
LicenseFile=..\..\LICENSE
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "addtopath"; Description: "Add lantern to my PATH, so it runs from any terminal"; GroupDescription: "Command line:"
Name: "desktopicon"; Description: "Create a desktop shortcut for the dashboard"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Dirs]
; Per-user data folder shared by the shortcuts and the command prompt.
Name: "{localappdata}\Lantern"

[InstallDelete]
; Clear the previous build's runtime files so an upgrade never mixes two
; PyInstaller builds. Scan data is in {localappdata}\Lantern, not here.
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "{#AppDir}\lantern.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#AppDir}\_internal\*"; DestDir: "{app}\_internal"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "lantern.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Icons]
; The dashboard runs in a console window: closing it stops the server.
; `|| pause` keeps the window open only when Lantern exits with an error
; (for example, port 8068 is already in use), so the message can be read.
Name: "{group}\Lantern Dashboard"; Filename: "{cmd}"; \
  Parameters: "/c """"{app}\lantern.exe"" web --open --db ""{localappdata}\Lantern\lantern.db"" || pause"""; \
  WorkingDir: "{localappdata}\Lantern"; IconFilename: "{app}\lantern.ico"; \
  Comment: "Start the Lantern dashboard and open it in your browser"
Name: "{group}\Lantern Command Prompt"; Filename: "{cmd}"; \
  Parameters: "/k ""set ""PATH={app};%PATH%"" && lantern --help"""; \
  WorkingDir: "{localappdata}\Lantern"; IconFilename: "{app}\lantern.ico"; \
  Comment: "A command prompt where lantern scan, history, and report work"
Name: "{group}\Uninstall Lantern"; Filename: "{uninstallexe}"
Name: "{userdesktop}\Lantern Dashboard"; Filename: "{cmd}"; \
  Parameters: "/c """"{app}\lantern.exe"" web --open --db ""{localappdata}\Lantern\lantern.db"" || pause"""; \
  WorkingDir: "{localappdata}\Lantern"; IconFilename: "{app}\lantern.ico"; Tasks: desktopicon

[Run]
Filename: "{cmd}"; \
  Parameters: "/c """"{app}\lantern.exe"" web --open --db ""{localappdata}\Lantern\lantern.db"" || pause"""; \
  WorkingDir: "{localappdata}\Lantern"; Description: "Open the Lantern dashboard now"; \
  Flags: postinstall nowait skipifsilent unchecked

[Code]
const
  EnvKey = 'Environment';

function PathHasDir(const Path, Dir: string): Boolean;
begin
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Path) + ';') > 0;
end;

procedure AddToUserPath(const Dir: string);
var
  Path: string;
begin
  if not RegQueryStringValue(HKCU, EnvKey, 'Path', Path) then
    Path := '';
  if PathHasDir(Path, Dir) then
    exit;
  if (Path <> '') and (Copy(Path, Length(Path), 1) <> ';') then
    Path := Path + ';';
  RegWriteExpandStringValue(HKCU, EnvKey, 'Path', Path + Dir);
end;

procedure RemoveFromUserPath(const Dir: string);
var
  Path, Rest, Item, Kept: string;
  P: Integer;
begin
  if not RegQueryStringValue(HKCU, EnvKey, 'Path', Path) then
    exit;
  Rest := Path;
  Kept := '';
  while Rest <> '' do
  begin
    P := Pos(';', Rest);
    if P = 0 then
    begin
      Item := Rest;
      Rest := '';
    end
    else
    begin
      Item := Copy(Rest, 1, P - 1);
      Delete(Rest, 1, P);
    end;
    if (Item <> '') and (CompareText(Item, Dir) <> 0) then
    begin
      if Kept <> '' then
        Kept := Kept + ';';
      Kept := Kept + Item;
    end;
  end;
  if Kept <> Path then
    RegWriteExpandStringValue(HKCU, EnvKey, 'Path', Kept);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('addtopath') then
    AddToUserPath(ExpandConstant('{app}'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromUserPath(ExpandConstant('{app}'));
end;
