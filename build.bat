@echo off
setlocal enabledelayedexpansion

set root=%~dp0
set src=%root%src
set bin=%root%bin
set inter=%bin%\intermediates
set out=%bin%\novm.exe
set cc=gcc
set cflags=-Wall -Wextra -O2 -std=c11 -municode -D_UNICODE -DUNICODE -DWIN32_LEAN_AND_MEAN -DCOBJMACROS -D_WIN32_WINNT=0x0601 -Wno-array-bounds -Wno-unused-parameter
set ldflags=-static -mwindows -luser32 -ladvapi32 -lole32 -loleaut32 -lwbemuuid -lpsapi -lshlwapi

if not exist "%bin%" mkdir "%bin%"
if not exist "%inter%" mkdir "%inter%"

set objs=
for /r "%src%" %%f in (*.c) do (
    set name=%%~nf
    set obj=%inter%\!name!.o
    echo [cc] %%f
    %cc% %cflags% -c "%%f" -o "!obj!"
    if errorlevel 1 goto fail
    set objs=!objs! "!obj!"
)

echo [link] %out%
%cc% !objs! -o "%out%" %ldflags%
if errorlevel 1 goto fail

echo [done] %out%
endlocal
exit /b 0

:fail
echo [fail] build aborted
endlocal
exit /b 1
