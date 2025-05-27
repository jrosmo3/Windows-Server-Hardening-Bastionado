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

:: ========================================================================== ...
(rest of the script continues exactly as defined in canvas)
