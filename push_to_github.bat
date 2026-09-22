@echo off
setlocal enabledelayedexpansion

:: ============================================================
:: CONFIGURAR AQUI ANTES DE RODAR
:: ============================================================
set GITHUB_USER=souzaprivrs
set GITHUB_REPO=ipa
set GITHUB_TOKEN=SEU_TOKEN_AQUI
set COMMIT_MSG=ZeroM$ branding update + new logo
:: ============================================================

set ROOT=%~dp0
set GIT_DIR=%ROOT%.git_portable
set GIT_EXE=%GIT_DIR%\bin\git.exe

echo.
echo [1/4] Verificando Git...

if exist "%GIT_EXE%" goto :git_ready

echo Git nao encontrado. Baixando Git portatil...
set GIT_ZIP=%TEMP%\PortableGit.7z.exe
"C:\Windows\System32\curl.exe" -L -o "%GIT_ZIP%" "https://github.com/git-for-windows/git/releases/download/v2.46.0.windows.1/PortableGit-2.46.0-64-bit.7z.exe"
if errorlevel 1 (
    echo ERRO: Falha ao baixar Git. Verifique sua conexao.
    pause
    exit /b 1
)
echo Extraindo Git portatil...
"%GIT_ZIP%" -o"%GIT_DIR%" -y
if errorlevel 1 (
    echo ERRO: Falha ao extrair Git.
    pause
    exit /b 1
)
echo Git instalado com sucesso!

:git_ready
echo.
echo [2/4] Configurando repositorio...
set PATH=%GIT_DIR%\bin;%PATH%

cd /d "%ROOT%"

if not exist ".git\" (
    "%GIT_EXE%" init
    "%GIT_EXE%" branch -M main
) else (
    echo Repositorio git ja existe.
)

"%GIT_EXE%" config user.email "zerom@build.local"
"%GIT_EXE%" config user.name "ZeroM$"

set REMOTE_URL=https://%GITHUB_TOKEN%@github.com/%GITHUB_USER%/%GITHUB_REPO%.git
"%GIT_EXE%" remote remove origin 2>nul
"%GIT_EXE%" remote add origin "%REMOTE_URL%"

echo.
echo [3/4] Fazendo commit de tudo...
"%GIT_EXE%" add -A
"%GIT_EXE%" commit -m "%COMMIT_MSG%" || echo (Nada novo para commitar)

echo.
echo [4/4] Enviando para GitHub...
"%GIT_EXE%" push -u origin main --force
if errorlevel 1 (
    echo.
    echo ERRO no push! Verifique:
    echo  - GITHUB_USER, GITHUB_REPO e GITHUB_TOKEN corretos
    echo  - O repositorio existe no GitHub
    echo  - O token tem permissao de escrita (repo)
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  SUCESSO! Codigo enviado para:
echo  https://github.com/%GITHUB_USER%/%GITHUB_REPO%
echo.
echo  O GitHub Actions vai compilar o IPA automaticamente.
echo  Acesse: https://github.com/%GITHUB_USER%/%GITHUB_REPO%/actions
echo ============================================================
echo.
pause
