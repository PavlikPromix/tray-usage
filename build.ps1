param([switch]$SkipTests)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$output = Join-Path $root 'out'
New-Item -ItemType Directory -Force -Path $output | Out-Null
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Install Visual Studio Build Tools with Desktop development with C++ and Windows SDK.' }
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'MSVC C++ toolset not found.' }
$devCmd = Join-Path $vs 'Common7\Tools\VsDevCmd.bat'
$commands = @(
    '@echo off',
    ('call "{0}" -arch=x64 -host_arch=x64 >nul' -f $devCmd),
    'if errorlevel 1 exit /b 1',
    ('cd /d "{0}"' -f $output),
    ('rc /nologo /i "{0}\src" /fo app.res "{0}\src\app.rc"' -f $root),
    'if errorlevel 1 exit /b 1',
    ('cl /nologo /std:c++17 /O1 /GL /MT /EHsc /W4 /WX /permissive- /utf-8 /GS /guard:cf /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /D_WIN32_WINNT=0x0A00 "{0}\src\main.cpp" app.res /Fe:TrayUsage.exe /link /SUBSYSTEM:WINDOWS /LTCG /OPT:REF,ICF /DYNAMICBASE /NXCOMPAT /guard:cf winhttp.lib ws2_32.lib crypt32.lib shell32.lib user32.lib gdi32.lib advapi32.lib' -f $root),
    'if errorlevel 1 exit /b 1'
)
if (-not $SkipTests) {
    $commands += @(
        ('cl /nologo /std:c++17 /O2 /MT /EHsc /W4 /WX /permissive- /utf-8 "{0}\tests\usage_tests.cpp" /Fe:usage_tests.exe' -f $root),
        'if errorlevel 1 exit /b 1',
        'usage_tests.exe',
        'if errorlevel 1 exit /b 1',
        ('cl /nologo /std:c++17 /O2 /MT /EHsc /W4 /WX /permissive- /utf-8 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /D_WIN32_WINNT=0x0A00 "{0}\tests\native_tests.cpp" /Fe:native_tests.exe /link /SUBSYSTEM:CONSOLE winhttp.lib ws2_32.lib crypt32.lib shell32.lib user32.lib gdi32.lib advapi32.lib' -f $root),
        'if errorlevel 1 exit /b 1',
        'native_tests.exe',
        'if errorlevel 1 exit /b 1',
        ('cl /nologo /std:c++17 /O2 /MT /EHsc /W4 /WX /permissive- /utf-8 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX /D_WIN32_WINNT=0x0A00 "{0}\tests\proxy_tests.cpp" /Fe:proxy_tests.exe /link /SUBSYSTEM:CONSOLE winhttp.lib ws2_32.lib crypt32.lib shell32.lib user32.lib gdi32.lib advapi32.lib' -f $root),
        'if errorlevel 1 exit /b 1',
        'proxy_tests.exe',
        'if errorlevel 1 exit /b 1'
    )
}
$commands += 'exit /b 0'
$batchFile = Join-Path $output 'compile.cmd'
[IO.File]::WriteAllLines($batchFile, $commands, [Text.Encoding]::Default)
& $env:ComSpec /d /c "`"$batchFile`""
if ($LASTEXITCODE -ne 0) { throw "Build failed with exit code $LASTEXITCODE" }
$binary = Get-Item -LiteralPath (Join-Path $output 'TrayUsage.exe')
Write-Host ('Ready: {0} ({1:N0} bytes)' -f $binary.FullName, $binary.Length)
