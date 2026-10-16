param([string]$Binary = (Join-Path $PSScriptRoot '..\out\TrayUsage.exe'))
$ErrorActionPreference = 'Stop'
$binaryPath = (Resolve-Path -LiteralPath $Binary).Path
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class TrayUsageSmoke {
    [StructLayout(LayoutKind.Sequential)] public struct IconId {
        public uint cbSize; public IntPtr hwnd; public uint id; public Guid guid;
    }
    [StructLayout(LayoutKind.Sequential)] public struct Rect { public int left, top, right, bottom; }
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindow(string name, string title);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern IntPtr SendMessageTimeout(IntPtr hwnd, uint msg, UIntPtr wp, IntPtr lp, uint flags, uint timeout, out UIntPtr result);
    [DllImport("shell32.dll")] public static extern int Shell_NotifyIconGetRect(ref IconId id, out Rect rect);
}
'@
function Assert-True($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Get-IconWindow {
    $until = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $window = [TrayUsageSmoke]::FindWindow('TrayUsage.NotificationWindow', 'TrayUsage')
        if ($window -ne [IntPtr]::Zero) { return $window }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $until)
    throw 'Notification window not created'
}
function Send-Command([IntPtr]$Window, [uint32]$Command) {
    $messageResult = [UIntPtr]::Zero
    $sent = [TrayUsageSmoke]::SendMessageTimeout($Window, 0x111, [UIntPtr]$Command, [IntPtr]::Zero, 2, 5000, [ref]$messageResult)
    Assert-True ($sent -ne [IntPtr]::Zero) 'UI thread stopped responding'
}
$existing = [TrayUsageSmoke]::FindWindow('TrayUsage.NotificationWindow', 'TrayUsage')
Assert-True ($existing -eq [IntPtr]::Zero) 'Close the running TrayUsage before this test'
$key = 'HKCU:\Software\TrayUsage'
$keyExisted = Test-Path -LiteralPath $key
$oldValue = Get-ItemPropertyValue -LiteralPath $key -Name WindowSeconds -ErrorAction SilentlyContinue
$app = $null
try {
    $app = Start-Process -FilePath $binaryPath -WindowStyle Hidden -PassThru
    $window = Get-IconWindow
    Assert-True (-not [TrayUsageSmoke]::IsWindowVisible($window)) 'The app must not display a normal window'
    $icon = New-Object TrayUsageSmoke+IconId
    $icon.cbSize = [Runtime.InteropServices.Marshal]::SizeOf($icon)
    $icon.hwnd = $window; $icon.id = 1
    $rectangle = New-Object TrayUsageSmoke+Rect
    $until = [DateTime]::UtcNow.AddSeconds(10)
    do {
        $iconStatus = [TrayUsageSmoke]::Shell_NotifyIconGetRect([ref]$icon, [ref]$rectangle)
        if ($iconStatus -eq 0) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $until)
    Assert-True ($iconStatus -eq 0) ('Explorer did not return icon geometry (HRESULT={0:X8}, struct size={1}, window={2})' -f $iconStatus, $icon.cbSize, $window)
    $duplicate = Start-Process -FilePath $binaryPath -WindowStyle Hidden -PassThru
    Assert-True ($duplicate.WaitForExit(5000)) 'A second instance should exit immediately'
    Assert-True ($duplicate.ExitCode -eq 0) 'Second instance returned an error'
    Send-Command $window 1002
    Assert-True ((Get-ItemPropertyValue -LiteralPath $key -Name WindowSeconds) -eq 604800) 'Weekly choice not saved'
    Send-Command $window 1001
    Assert-True ((Get-ItemPropertyValue -LiteralPath $key -Name WindowSeconds) -eq 18000) '5-hour choice not saved'
    Send-Command $window 1004
    Assert-True ($app.WaitForExit(30000)) 'App failed to exit cleanly'
    Assert-True ($app.ExitCode -eq 0) 'App exited with an error'
    Write-Host 'Smoke tests passed: real tray icon, no visible window, single instance, both menu choices, clean exit.'
} finally {
    if ($app -and -not $app.HasExited) {
        $quit = Start-Process -FilePath $binaryPath -ArgumentList '--quit' -WindowStyle Hidden -PassThru
        $quit.WaitForExit(5000) | Out-Null
        $app.WaitForExit(30000) | Out-Null
    }
    if ($null -ne $oldValue) {
        Set-ItemProperty -LiteralPath $key -Name WindowSeconds -Value $oldValue
    } elseif (Test-Path -LiteralPath $key) {
        Remove-ItemProperty -LiteralPath $key -Name WindowSeconds -ErrorAction SilentlyContinue
        if (-not $keyExisted) { Remove-Item -LiteralPath $key }
    }
}
