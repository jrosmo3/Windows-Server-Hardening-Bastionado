@echo off
:: ===========================================================================
:: Windows Server 2019-2022 Hardening Script (Enhanced) — Con RDP habilitado
:: ===========================================================================

setlocal enabledelayedexpansion

:: — Formatear fecha y hora para el log —
for /f "tokens=1-3 delims=/ " %%a in ('date /t') do (
  set Day=%%a & set Month=%%b & set Year=%%c
)
for /f "tokens=1-3 delims=:." %%a in ("%time%") do (
  set hh=%%a & set mm=%%b & set ss=%%c
)
set hh=!hh: =0!
set "LOGFILE=%~dp0hardening-%Year%-%Month%-%Day%_!hh!-!mm!-!ss!.log"

:: — Encabezado —
echo ===========================================================================
echo Starting Windows Server Hardening (RDP Enabled): %date% %time%
echo Log: %LOGFILE%
echo ===========================================================================

:: — Comprobar privilegios de admin —
net session >nul 2>&1 || (
  echo [ERROR] Este script requiere permisos de administrador.
  pause
  exit /b 1
)

goto :Main

:: =============================================================================
:: Funciones
:: =============================================================================

:WriteLog
  echo [%date% %time%] %*
  echo [%date% %time%] %*>>"%LOGFILE%"
  goto :EOF

:ApplyReg
  set "Key=%~1" & set "Name=%~2" & set "Type=%~3" & set "Data=%~4"
  for /f "tokens=3" %%A in ('reg query "%Key%" /v "%Name%" 2^>nul ^| findstr /i "%Name%"') do set "Current=%%A"
  if /i "!Current!" NEQ "%Data%" (
    reg add "%Key%" /v "%Name%" /t "%Type%" /d "%Data%" /f >>"%LOGFILE%" 2>&1 && call :WriteLog OK "%Key%\\%Name% → %Data%" || call :WriteLog ERR "%Key%\\%Name%"
  ) else (
    call :WriteLog SKIP "%Key%\\%Name% already %Data%"
  )
  goto :EOF

:DisableService
  set "Svc=%~1"
  sc query "%Svc%" >nul 2>&1
  if errorlevel 1 (
    call :WriteLog SKIP "Service %Svc% not found"
  ) else (
    sc config "%Svc%" start=disabled >>"%LOGFILE%" 2>&1 && call :WriteLog OK "Disabled %Svc%" || call :WriteLog ERR "Disable %Svc%"
  )
  goto :EOF

:: =============================================================================
:: Main
:: =============================================================================

:Main

call :WriteLog "1. Disable SMBv1 & require signing"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" SMB1                    REG_DWORD 0
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10"            Start                   REG_DWORD 4
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" RequireSecuritySignature REG_DWORD 1
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" EnableSecuritySignature  REG_DWORD 1
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" RequireSecuritySignature REG_DWORD 1

call :WriteLog "2. Harden TLS/SSL protocols"
for %%P in ("SSL 2.0" "SSL 3.0" "TLS 1.0" "TLS 1.1") do (
  call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\%%~P\Server" Enabled   REG_DWORD 0
  call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\%%~P\Client" Enabled   REG_DWORD 0
)
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" Enabled   REG_DWORD 1
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" Enabled   REG_DWORD 1

call :WriteLog "3. Disable unused services"
for %%S in (Fax XblGameSave XboxGipSvc WSearch TNMon Toolhelp RemoteRegistry Telnet SCardSvr TftpServer) do (
  call :DisableService %%S
)

call :WriteLog "4. Enforce password/lockout policies"
net accounts /minpwlen:14 /maxpwage:90 /uniquepw:5
net accounts /lockoutthreshold:5 /lockoutwindow:30 /lockoutduration:30

call :WriteLog "5. Configure Windows Firewall"
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound

call :WriteLog "6. Disable LLMNR"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" EnableMulticast REG_DWORD 0

call :WriteLog "7. Enforce UAC settings"
call :ApplyReg "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" EnableLUA                 REG_DWORD 1
call :ApplyReg "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" ConsentPromptBehaviorAdmin REG_DWORD 2

call :WriteLog "8. Disable WDigest & LMHash caching"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" UseLogonCredential  REG_DWORD 0
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"                       LmCompatibilityLevel REG_DWORD 5

call :WriteLog "9. AuditPol skipped (localización)"

call :WriteLog "10. Configure Event Log sizes & retention"
for %%L in (Application Security System Setup) do (
  wevtutil sl %%L /ms:2097152 /rt:false >>"%LOGFILE%" 2>&1 && call :WriteLog OK "LogSize %%L" || call :WriteLog ERR "LogSize %%L"
)

call :WriteLog "11. Configure Windows Update service"
sc config wuauserv start=auto >>"%LOGFILE%" 2>&1 && call :WriteLog OK "wuauserv=auto" || call :WriteLog ERR "wuauserv"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f >>"%LOGFILE%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions       /t REG_DWORD /d 4 /f >>"%LOGFILE%" 2>&1

call :WriteLog "12. Enable PowerShell logging"
call :ApplyReg "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" EnableScriptBlockLogging REG_DWORD 1
call :ApplyReg "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"     EnableTranscripting     REG_DWORD 1
call :ApplyReg "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"     OutputDirectory         REG_SZ    "%SystemRoot%\Temp\PS-Transcripts"

call :WriteLog "13. Configure Defender Antivirus"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Set-MpPreference -DisableRealtimeMonitoring $false -MAPSReporting Advanced -SubmitSamplesConsent SendAllSamples -EnableNetworkProtection Enabled; Start-MpScan -ScanType QuickScan" >>"%LOGFILE%" 2>&1

rem — Determinar ruta de manage-bde.exe —
set "BDE1=%SystemRoot%\System32\manage-bde.exe"
set "BDE2=%SystemRoot%\Sysnative\manage-bde.exe"
if exist "%BDE1%" ( set "BDE=%BDE1%" ) else if exist "%BDE2%" ( set "BDE=%BDE2%" ) else ( set "BDE=" )

call :WriteLog "14. Enable BitLocker on OS drive"
if defined BDE (
  "%BDE%" -status C: | findstr /i "Percentage Encrypted.*100%%" >nul || (
    "%BDE%" -on C: -RecoveryPassword >>"%LOGFILE%" 2>&1 && call :WriteLog OK "BitLocker initiated" || call :WriteLog ERR "BitLocker initiation"
  )
) else (
  call :WriteLog ERR "manage-bde.exe not found"
)

call :WriteLog "15. Apply AppLocker template rules"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "New-AppLockerPolicy -RuleType All -AsTemplate -XML > '%~dp0AppLockerPolicy.xml'; Set-AppLockerPolicy -XMLPolicy '%~dp0AppLockerPolicy.xml' -Merge" >>"%LOGFILE%" 2>&1 && call :WriteLog OK "AppLocker rules applied" || call :WriteLog ERR "AppLocker rules"

call :WriteLog "16. Enable Remote Desktop"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" fDenyTSConnections REG_DWORD 0
sc config TermService start=auto >>"%LOGFILE%" 2>&1 && call :WriteLog OK "TermService=auto"
sc start TermService >>"%LOGFILE%" 2>&1 && call :WriteLog OK "TermService started"
netsh advfirewall firewall set rule group="remote desktop" new enable=yes >>"%LOGFILE%" 2>&1 && call :WriteLog OK "Firewall RDP enabled"

call :WriteLog "17. Install & configure LAPS"
powershell -NoProfile -ExecutionPolicy Bypass -Command "if(-not(Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)){Register-PSRepository -Default -ErrorAction Stop}; Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop; if(-not(Get-Module -ListAvailable -Name LAPS)){Install-Module -Name LAPS -Force -AllowClobber -Scope AllUsers -ErrorAction Stop}; Import-Module LAPS -ErrorAction Stop; if(Get-Command Set-AdmPwdPasswordSettings -ErrorAction SilentlyContinue){Set-AdmPwdPasswordSettings -PasswordLength 14 -PasswordComplexity 4 -PasswordAgeDays 30 -ErrorAction Stop}" >>"%LOGFILE%" 2>&1 && call :WriteLog OK "LAPS installed/configured" || call :WriteLog ERR "LAPS installation"

call :WriteLog "18. Enable Credential Guard"
bcdedit /set hypervisorlaunchtype auto >>"%LOGFILE%" 2>&1 && call :WriteLog OK "hypervisorlaunchtype=auto"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" EnableVirtualizationBasedSecurity   REG_DWORD 1
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" RequirePlatformSecurityFeatures    REG_DWORD 1

call :WriteLog "19. Install & apply Windows Updates"
powershell -NoProfile -ExecutionPolicy Bypass -Command "if(-not(Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)){Register-PSRepository -Default -ErrorAction Stop}; Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop; if(-not(Get-Module -ListAvailable -Name PSWindowsUpdate)){Install-Module -Name PSWindowsUpdate -Force -AllowClobber -Scope AllUsers -ErrorAction Stop}; Import-Module PSWindowsUpdate -ErrorAction Stop; Get-WindowsUpdate -AcceptAll -Install -AutoReboot | Out-Null" >>"%LOGFILE%" 2>&1 && call :WriteLog OK "Updates installed" || call :WriteLog ERR "Windows Update"

echo ===========================================================================
echo Hardening completed (with RDP): %date% %time%
echo Logfile: %LOGFILE%
echo ===========================================================================

endlocal & exit /b 0
