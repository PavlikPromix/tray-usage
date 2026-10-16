param([string]$Binary = (Join-Path $PSScriptRoot '..\out\TrayUsage.exe'), [switch]$Preview)
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
    [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr hwnd);
    [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr hwnd, int id);
    [DllImport("user32.dll", EntryPoint="SendMessageW", CharSet=CharSet.Unicode)] public static extern IntPtr SetText(IntPtr hwnd, uint msg, UIntPtr wp, string text);
    [DllImport("user32.dll", EntryPoint="SendMessageW", CharSet=CharSet.Unicode)] public static extern IntPtr GetText(IntPtr hwnd, uint msg, UIntPtr wp, System.Text.StringBuilder text);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessage(IntPtr hwnd, uint msg, UIntPtr wp, IntPtr lp);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr hwnd, uint msg, UIntPtr wp, IntPtr lp);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hwnd, out Rect rect);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hwnd, IntPtr dc, uint flags);
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
function Start-TestApp {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $binaryPath; $info.UseShellExecute = $false; $info.CreateNoWindow = $true
    # Deliberately absent credentials: UI tests never use the user's account or network token.
    $info.EnvironmentVariables['CODEX_HOME'] = Join-Path $PSScriptRoot '..\out\smoke-no-auth'
    return [Diagnostics.Process]::Start($info)
}
function Open-Proxy([IntPtr]$Window) {
    [TrayUsageSmoke]::PostMessage($Window, 0x111, [UIntPtr]1005, [IntPtr]::Zero) | Out-Null
    $until = [DateTime]::UtcNow.AddSeconds(5)
    do {
        $dialog = [TrayUsageSmoke]::FindWindow('#32770', 'Прокси — TrayUsage')
        if ($dialog -ne [IntPtr]::Zero) { return $dialog }
        Start-Sleep -Milliseconds 50
    } while ([DateTime]::UtcNow -lt $until)
    throw 'Proxy dialog not created'
}
function Set-ProxyMode([IntPtr]$Dialog, [int]$Mode) {
    [TrayUsageSmoke]::SendMessage([TrayUsageSmoke]::GetDlgItem($Dialog, 1101), 0x14e, [UIntPtr]$Mode, [IntPtr]::Zero) | Out-Null
    Send-Command $Dialog ((1 -shl 16) -bor 1101)
}
function Set-Field([IntPtr]$Dialog, [int]$Id, [string]$Value) {
    Assert-True ([TrayUsageSmoke]::SetText([TrayUsageSmoke]::GetDlgItem($Dialog, $Id), 0xc, [UIntPtr]::Zero, $Value) -ne [IntPtr]::Zero) 'Cannot edit dialog field'
}
function Get-Field([IntPtr]$Dialog, [int]$Id) {
    $text = New-Object Text.StringBuilder 1024
    [TrayUsageSmoke]::GetText([TrayUsageSmoke]::GetDlgItem($Dialog, $Id), 0xd, [UIntPtr]$text.Capacity, $text) | Out-Null
    return $text.ToString()
}
function Set-Auth([IntPtr]$Dialog, [bool]$Enabled) {
    [TrayUsageSmoke]::SendMessage([TrayUsageSmoke]::GetDlgItem($Dialog, 1104), 0xf1, [UIntPtr]([int]$Enabled), [IntPtr]::Zero) | Out-Null
    Send-Command $Dialog 1104
}
function Get-DialogHeight([IntPtr]$Dialog) {
    $area = New-Object TrayUsageSmoke+Rect
    [TrayUsageSmoke]::GetWindowRect($Dialog, [ref]$area) | Out-Null
    return $area.bottom - $area.top
}
function Save-DialogPreview([IntPtr]$Dialog, [string]$Name) {
    if (-not $Preview) { return }
    Add-Type -AssemblyName System.Drawing
    $area = New-Object TrayUsageSmoke+Rect
    [TrayUsageSmoke]::GetWindowRect($Dialog, [ref]$area) | Out-Null
    $bitmap = New-Object Drawing.Bitmap ($area.right - $area.left), ($area.bottom - $area.top)
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    $dc = $graphics.GetHdc()
    try { Assert-True ([TrayUsageSmoke]::PrintWindow($Dialog, $dc, 0)) 'Cannot render dialog preview' } finally { $graphics.ReleaseHdc($dc); $graphics.Dispose() }
    try { $bitmap.Save((Join-Path (Split-Path $binaryPath) $Name)) } finally { $bitmap.Dispose() }
}
function Wait-DialogClosed([IntPtr]$Dialog) {
    $until = [DateTime]::UtcNow.AddSeconds(5)
    while ([TrayUsageSmoke]::IsWindowVisible($Dialog) -and [DateTime]::UtcNow -lt $until) { Start-Sleep -Milliseconds 50 }
    Assert-True (-not [TrayUsageSmoke]::IsWindowVisible($Dialog)) ('Proxy dialog did not close: ' + (Get-Field $Dialog 1107))
}
function Assert-TestPassword([IntPtr]$Dialog) {
    $mask = [TrayUsageSmoke]::SendMessage([TrayUsageSmoke]::GetDlgItem($Dialog, 1106), 0xd2, [UIntPtr]::Zero, [IntPtr]::Zero)
    Assert-True ($mask -ne [IntPtr]::Zero) 'Password field must be masked'
    $protected = (Get-Item -LiteralPath $key).GetValue('ProxyConfig')
    $plain = [Security.Cryptography.ProtectedData]::Unprotect($protected, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    try { Assert-True ([Text.Encoding]::Unicode.GetString($plain).Contains('smoke-password')) 'Password not preserved in protected settings' }
    finally { [Array]::Clear($plain, 0, $plain.Length) }
}
$existing = [TrayUsageSmoke]::FindWindow('TrayUsage.NotificationWindow', 'TrayUsage')
Assert-True ($existing -eq [IntPtr]::Zero) 'Close the running TrayUsage before this test'
$key = 'HKCU:\Software\TrayUsage'
$keyExisted = Test-Path -LiteralPath $key
$oldValue = $null; $oldProxy = $null
if ($keyExisted) {
    $registryKey = Get-Item -LiteralPath $key
    $oldValue = $registryKey.GetValue('WindowSeconds')
    $oldProxy = $registryKey.GetValue('ProxyConfig')
}
$oldProxyKind = if ($null -ne $oldProxy) { (Get-Item -LiteralPath $key).GetValueKind('ProxyConfig') } else { $null }
$app = $null
try {
    $app = Start-TestApp
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
    $dialog = Open-Proxy $window
    Assert-True (-not [TrayUsageSmoke]::IsWindowEnabled($window)) 'Proxy dialog must be modal'
    Set-ProxyMode $dialog 2
    Set-Auth $dialog $false
    $compactHeight = Get-DialogHeight $dialog
    Set-Field $dialog 1102 '127.0.0.1'
    Set-Field $dialog 1103 '70000'
    Send-Command $dialog 1
    Assert-True ([TrayUsageSmoke]::IsWindowVisible($dialog)) 'Invalid port closed the dialog'
    Assert-True ((Get-Field $dialog 1107).Length -gt 0) 'Validation message missing'
    Assert-True ((Get-DialogHeight $dialog) -gt $compactHeight) 'Validation message must expand the compact dialog'
    Set-Field $dialog 1103 '8080'
    Set-Auth $dialog $true
    Assert-True ([TrayUsageSmoke]::IsWindowEnabled([TrayUsageSmoke]::GetDlgItem($dialog, 1106))) 'Password field not enabled'
    Set-Field $dialog 1105 'smoke-user'
    Set-Field $dialog 1106 'smoke-password'
    Send-Command $dialog 1
    Wait-DialogClosed $dialog
    Assert-True (-not [TrayUsageSmoke]::IsWindowVisible($dialog)) ('Save did not close proxy dialog: ' + (Get-Field $dialog 1107) + '; host=' + (Get-Field $dialog 1102) + '; port=' + (Get-Field $dialog 1103))
    $savedProxy = [Convert]::ToBase64String((Get-ItemPropertyValue -LiteralPath $key -Name ProxyConfig))
    $dialog = Open-Proxy $window
    Assert-True ((Get-Field $dialog 1102) -eq '127.0.0.1') ('HTTP host did not reload: ' + (Get-Field $dialog 1102))
    Assert-True ((Get-Field $dialog 1105) -eq 'smoke-user') 'HTTP username did not reload'
    Assert-TestPassword $dialog
    $authHeight = Get-DialogHeight $dialog
    Save-DialogPreview $dialog 'proxy-dialog.png'
    Set-Auth $dialog $false
    Assert-True ([TrayUsageSmoke]::IsWindowVisible([TrayUsageSmoke]::GetDlgItem($dialog, 1106))) 'Password field must keep its place when auth is disabled'
    Assert-True (-not [TrayUsageSmoke]::IsWindowEnabled([TrayUsageSmoke]::GetDlgItem($dialog, 1106))) 'Unused password field must be disabled'
    Assert-True ((Get-DialogHeight $dialog) -eq $authHeight) 'Auth toggle must keep the form layout'
    Save-DialogPreview $dialog 'proxy-dialog-no-auth.png'
    Set-Auth $dialog $true
    Assert-True ((Get-DialogHeight $dialog) -eq $authHeight) 'Repeated auth toggles must restore dialog size'
    Assert-True ((Get-Field $dialog 1105) -eq 'smoke-user') 'Auth toggle lost the username'
    Set-Field $dialog 1102 'cancelled.example'
    Send-Command $dialog 2
    Wait-DialogClosed $dialog
    Assert-True ([Convert]::ToBase64String((Get-ItemPropertyValue -LiteralPath $key -Name ProxyConfig)) -eq $savedProxy) 'Cancel changed saved settings'
    $dialog = Open-Proxy $window
    Set-ProxyMode $dialog 3
    Assert-True ((Get-Field $dialog 1103) -eq '1080') 'SOCKS5 default port missing'
    Send-Command $dialog 1
    Wait-DialogClosed $dialog
    Send-Command $window 1004
    Assert-True ($app.WaitForExit(30000)) 'App failed to exit before restart'
    $app = Start-TestApp
    $window = Get-IconWindow
    $dialog = Open-Proxy $window
    $mode = [TrayUsageSmoke]::SendMessage([TrayUsageSmoke]::GetDlgItem($dialog, 1101), 0x147, [UIntPtr]::Zero, [IntPtr]::Zero)
    Assert-True ($mode.ToInt32() -eq 3 -and (Get-Field $dialog 1103) -eq '1080') 'SOCKS5 settings did not survive restart'
    Assert-TestPassword $dialog
    Set-ProxyMode $dialog 1
    Assert-True (-not [TrayUsageSmoke]::IsWindowEnabled([TrayUsageSmoke]::GetDlgItem($dialog, 1102))) 'Direct mode must disable proxy fields'
    Assert-True ([TrayUsageSmoke]::IsWindowVisible([TrayUsageSmoke]::GetDlgItem($dialog, 1102))) 'Direct mode must keep proxy fields in place'
    Assert-True ((Get-DialogHeight $dialog) -eq $compactHeight) 'Mode change must keep the form layout'
    Send-Command $dialog 1
    Wait-DialogClosed $dialog
    $dialog = Open-Proxy $window
    Set-ProxyMode $dialog 0
    Save-DialogPreview $dialog 'proxy-dialog-system.png'
    Send-Command $dialog 1
    Wait-DialogClosed $dialog
    Assert-True ($null -eq (Get-Item -LiteralPath $key).GetValue('ProxyConfig')) 'System mode did not clear saved proxy'
    Send-Command $window 1004
    Assert-True ($app.WaitForExit(30000)) 'App failed to exit cleanly'
    Assert-True ($app.ExitCode -eq 0) 'App exited with an error'
    Write-Host 'Smoke tests passed: tray icon, single instance, modal proxy dialog, validation, HTTP/SOCKS5/auth save, cancel, restart persistence, direct/system modes, clean exit.'
} finally {
    if ($app -and -not $app.HasExited) {
        $quit = Start-Process -FilePath $binaryPath -ArgumentList '--quit' -WindowStyle Hidden -PassThru
        $quit.WaitForExit(5000) | Out-Null
        $app.WaitForExit(30000) | Out-Null
    }
    if ($null -ne $oldProxy) {
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -LiteralPath $key -Name ProxyConfig -Value $oldProxy -PropertyType $oldProxyKind -Force | Out-Null
    } elseif (Test-Path -LiteralPath $key) {
        Remove-ItemProperty -LiteralPath $key -Name ProxyConfig -ErrorAction SilentlyContinue
    }
    if ($null -ne $oldValue) {
        Set-ItemProperty -LiteralPath $key -Name WindowSeconds -Value $oldValue
    } elseif (Test-Path -LiteralPath $key) {
        Remove-ItemProperty -LiteralPath $key -Name WindowSeconds -ErrorAction SilentlyContinue
        if (-not $keyExisted) { Remove-Item -LiteralPath $key }
    }
}
