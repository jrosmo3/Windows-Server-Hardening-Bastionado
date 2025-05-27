# Windows-Server-Hardening-Bastionado
Script para bastionar Windows Server

Este proyecto contiene un script de hardening para Windows Server 2019-2022 que automatiza más de 20 controles de seguridad basados en STIG, CIS y buenas prácticas adicionales, incluyendo:

- Deshabilitar SMBv1 y forzar SMB Signing
- Endurecer protocolos TLS/SSL
- Deshabilitar servicios innecesarios
- Políticas de contraseñas y bloqueo de cuenta
- Configuración de Windows Firewall y políticas por defecto
- Deshabilitar LLMNR
- Refuerzo de UAC
- Deshabilitar WDigest y LMHash
- Políticas de auditoría avanzadas
- Configuración de tamaños y retención de registros de eventos
- Actualizaciones automáticas de Windows
- Logging y transcripción de PowerShell
- Configuración de Microsoft Defender Antivirus
- Encriptación de disco con BitLocker
- Reglas predeterminadas de AppLocker
- Deshabilitar RDP
- Instalación y configuración de LAPS
- Habilitar Credential Guard
- Remediación de parches con PSWindowsUpdate

## Requisitos

- Windows Server 2019 con PowerShell instalado
- Ejecución como administrador
- Conectividad a Internet para descargar módulos de PowerShell (LAPS, PSWindowsUpdate)

## Uso

1. Clonar o descargar este repositorio.
2. Colocar el script en una ruta accesible.
3. Abrir CMD como administrador y ejecutar el script
4. Revisar el log generado en la misma carpeta.

## Contribuciones

Se aceptan pull requests para mejoras, nuevos controles o actualizaciones de versiones futuras de Windows.
