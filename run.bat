@echo off
set /p target="Digite a URL do site (ex: https://exemplo.com): "
set /p token="Digite seu Token da API do WPScan (ou deixe em branco para pular): "

if "%token%"=="" (
    python wp_scanner.py %target%
) else (
    python wp_scanner.py %target% --api-token %token%
)

pause
