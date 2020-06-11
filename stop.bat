@echo off & setlocal
set batchPath=%~dp0

Powershell.exe -windowstyle hidden -file "%batchPath%stop_appd_collector.ps1
