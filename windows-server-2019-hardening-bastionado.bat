@echo off
:: ===========================================================================
:: Windows Server 2019 Hardening Script (Enhanced)
:: - Registro de acciones
:: - Funciones parametrizadas
:: - Detección de errores
:: - Idempotencia
:: - Controles STIG/CIS y avanzados adicionales
:: - Añade LAPS, Credential Guard y remediación de parches
:: ===========================================================================

:: Variables globales
setlocal enabledelayedexpansion
set "LOGFILE=%~dp0hardening-%date:~4,2%-%date:~7,2%-%date:~10,4%_%time:~0,2%-%time:~3,2%-%time:~6,2%.log"
(
  echo ===========================================================================
  echo Starting Windows Server Hardening: %date% %time%
  echo ===========================================================================
) >> "%LOGFILE%"

:: ---------------------------------------------------------------------------
:: Función: Write-Log
:: Param: %* = mensaje
:: ---------------------------------------------------------------------------
:WriteLog
  echo [%date% %time%] %* >> "%LOGFILE%"
  goto :eof

:: ---------------------------------------------------------------------------
:: Función: Apply-Registry (idempotente)
:: Params: %1=Key, %2=ValueName, %3=Type, %4=Data
:: ---------------------------------------------------------------------------
:ApplyReg
  set "Key=%~1"
  set "Name=%~2"
  set "Type=%~3"
  set "Data=%~4"
  for /f "tokens=3" %%A in ('reg query "%Key%" /v "%Name%" 2^>nul ^| findstr /i "%Name%"') do set "Current=%%A"
  if /i "!Current!" NEQ "%Data%" (
    reg add "%Key%" /v "%Name%" /t "%Type%" /d "%Data%" /f >> "%LOGFILE%" 2>&1 && call :WriteLog "[OK] Set %Key%\\%Name% to %Data%" || call :WriteLog "[ERR] Failed %Key%\\%Name%"
  ) else (
    call :WriteLog "[SKIP] %Key%\\%Name% already %Data%"
  )
  goto :eof

:: ---------------------------------------------------------------------------
:: Función: Disable-Service
:: Param: %1 = ServiceName
:: ---------------------------------------------------------------------------
:DisableService
  set "Svc=%~1"
  sc query "%Svc%" >nul 2>&1
  if !errorlevel! EQU 0 (
    sc config "%Svc%" start= disabled >> "%LOGFILE%" 2>&1 && call :WriteLog "[OK] Disabled service %Svc%" || call :WriteLog "[ERR] Disable service %Svc%"
  ) else (
    call :WriteLog "[SKIP] Service %Svc% not found"
  )
  goto :eof

:: ==========================================================================
:: Secciones de Hardening
:: ==========================================================================

:: 1. Deshabilitar SMBv1 y forzar SMB Signing
call :WriteLog "-- Disable SMBv1 & Require Signing --"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1" "REG_DWORD" "0"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" "Start" "REG_DWORD" "4"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature" "REG_DWORD" "1"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableSecuritySignature" "REG_DWORD" "1"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" "REG_DWORD" "1"

:: 2. Endurecer protocolos TLS/SSL
call :WriteLog "-- Harden TLS/SSL protocols --"
for %%P in ("SSL 2.0" "SSL 3.0" "TLS 1.0" "TLS 1.1") do (
  call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\%%~P\Server" "Enabled" "REG_DWORD" "0"
  call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\%%~P\Client" "Enabled" "REG_DWORD" "0"
)
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" "Enabled" "REG_DWORD" "1"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" "Enabled" "REG_DWORD" "1"

:: 3. Servicios innecesarios
call :WriteLog "-- Disable unused services --"
for %%S in (Fax XblGameSave XboxGipSvc WSearch TNMon Toolhelp RemoteRegistry Telnet SCardSvr TftpServer) do call :DisableService "%%S"

:: 4. Políticas de contraseña y bloqueo
call :WriteLog "-- Enforce password/lockout policies --"
net accounts /minpwlen:14 /maxpwage:90 /uniquepw:5 >> "%LOGFILE%" 2>&1
net accounts /lockoutthreshold:5 /lockoutwindow:30 /lockoutduration:30 >> "%LOGFILE%" 2>&1

:: 5. Windows Firewall
call :WriteLog "-- Configure Windows Firewall --"
netsh advfirewall set allprofiles state on >> "%LOGFILE%" 2>&1
netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound >> "%LOGFILE%" 2>&1

:: 6. Deshabilitar LLMNR
call :WriteLog "-- Disable LLMNR --"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" "EnableMulticast" "REG_DWORD" "0"

:: 7. UAC reforzado
call :WriteLog "-- Enforce UAC settings --"
call :ApplyReg "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" "REG_DWORD" "1"
call :ApplyReg "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" "REG_DWORD" "2"

:: 8. WDigest & LMHash
call :WriteLog "-- Disable WDigest & LMHash caching --"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" "UseLogonCredential" "REG_DWORD" "0"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel" "REG_DWORD" "5"

:: 9. Políticas de auditoría
call :WriteLog "-- Configure Audit Policies --"
for %%C in ("Account Logon" "Account Management" "Logon/Logoff" "Policy Change" "Privilege Use" "System" "Object Access") do auditpol /set /category:"%%~C" /success:enable /failure:enable >> "%LOGFILE%" 2>&1

:: 10. Tamaño y retención de Event Logs
call :WriteLog "-- Configure Event Log sizes & retention --"
for %%L in (Application Security System Setup) do wevtutil sl %%L /ms:2097152 /rt:false >> "%LOGFILE%" 2>&1

:: 11. Windows Update automática
call :WriteLog "-- Configure Windows Update --"
sc config wuauserv start= auto >> "%LOGFILE%" 2>&1
powershell -Command "(Get-WindowsUpdateSettings).AutomaticInstallEnabled = $true" >> "%LOGFILE%" 2>&1

:: 12. PowerShell logging
call :WriteLog "-- Enable PowerShell logging --"
call :ApplyReg "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging" "REG_DWORD" "1"
call :ApplyReg "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" "REG_DWORD" "1"
call :ApplyReg "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "OutputDirectory" "REG_SZ" "%SystemRoot%\\Temp\\PS-Transcripts"

:: 13. Microsoft Defender Antivirus
call :WriteLog "-- Configure Defender Antivirus --"
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $false -MAPSReporting Advanced -SubmitSamplesConsent SendAllSamples -EnableNetworkProtection Enabled" >> "%LOGFILE%" 2>&1
powershell -Command "Start-MpScan -ScanType QuickScan" >> "%LOGFILE%" 2>&1

:: 14. BitLocker
call :WriteLog "-- Enable BitLocker on OS drive --"
manage-bde -status C: | findstr /i "Percentage Encrypted" | findstr /i "100%" >nul
if errorlevel 1 ( manage-bde -on C: -RecoveryPassword >> "%LOGFILE%" 2>&1 && call :WriteLog "[OK] BitLocker initiated" ) else call :WriteLog "[SKIP] BitLocker already enabled"

:: 15. AppLocker
call :WriteLog "-- Apply default AppLocker rules --"
powershell -Command "New-AppLockerPolicy -Default -XML" > "%~dp0AppLockerPolicy.xml" 2>> "%LOGFILE%"
powershell -Command "Set-AppLockerPolicy -XMLPolicy (%~dp0AppLockerPolicy.xml) -Merge" >> "%LOGFILE%" 2>&1 && call :WriteLog "[OK] AppLocker default rules applied"

:: 16. RDP
call :WriteLog "-- Disable Remote Desktop --"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" "REG_DWORD" "1"
sc config TermService start= disabled >> "%LOGFILE%" 2>&1

:: 17. LAPS
call :WriteLog "-- Install & configure LAPS --"
powershell -Command "Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force" >> "%LOGFILE%" 2>&1
powershell -Command "Install-Module -Name LAPS -Force -Confirm:`$false" >> "%LOGFILE%" 2>&1
powershell -Command "Import-Module LAPS; Set-AdmPwdPasswordSettings -PasswordComplexity 4 -PasswordLength 14 -PasswordAgeDays 30" >> "%LOGFILE%" 2>&1

:: 18. Credential Guard
call :WriteLog "-- Enable Credential Guard --"
bcdedit /set hypervisorlaunchtype auto >> "%LOGFILE%" 2>&1 && call :WriteLog "[OK] hypervisorlaunchtype set to auto" || call :WriteLog "[ERR] bcdedit hypervisorlaunchtype"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity" "REG_DWORD" "1"
call :ApplyReg "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" "RequirePlatformSecurityFeatures" "REG_DWORD" "1"

:: 19. Remediación de parches
call :WriteLog "-- Install & apply Windows Updates --"
powershell -Command "Install-Module -Name PSWindowsUpdate -Force -Confirm:`$false; Import-Module PSWindowsUpdate; Get-WindowsUpdate -AcceptAll; Install-WindowsUpdate -AcceptAll -AutoReboot" >> "%LOGFILE%" 2>&1

:: ---------------------------------------------------------------------------
:: Finalización
:: ---------------------------------------------------------------------------
(
  echo ===========================================================================
  echo Hardening completed: %date% %time%
  echo Logfile: %LOGFILE%
  echo ===========================================================================
) >> "%LOGFILE%"
endlocal
exit /b 0
