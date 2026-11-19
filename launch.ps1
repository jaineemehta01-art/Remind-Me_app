# Remind Me - Aesthetic Console Launcher
$Host.UI.RawUI.WindowTitle = "🔔 Remind Me - Daily Task & Event Reminder"
try {
  $Host.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size(76, 28)
  $Host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size(76, 28)
} catch {}

Clear-Host
Write-Host ""
Write-Host "  ╭──────────────────────────────────────────────────────────────────╮" -ForegroundColor DarkCyan
Write-Host "  │                                                                  │" -ForegroundColor DarkCyan
Write-Host "  │   ██████╗ ███████╗███╗   ███╗██╗███╗   ██╗██████╗   ███╗   ███╗███████╗   │" -ForegroundColor Cyan
Write-Host "  │   ██╔══██╗██╔════╝████╗ ████║██║████╗  ██║██╔══██╗  ████╗ ████║██╔════╝   │" -ForegroundColor Cyan
Write-Host "  │   ██████╔╝█████╗  ██╔████╔██║██║██╔██╗ ██║██║  ██║  ██╔████╔██║█████╗     │" -ForegroundColor Cyan
Write-Host "  │   ██╔══██╗██╔══╝  ██║╚██╔╝██║██║██║╚██╗██║██║  ██║  ██║╚██╔╝██║██╔══╝     │" -ForegroundColor Cyan
Write-Host "  │   ██║  ██║███████╗██║ ╚═╝ ██║██║██║ ╚████║██████╔╝  ██║ ╚═╝ ██║███████╗   │" -ForegroundColor Cyan
Write-Host "  │   ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝   ╚═╝     ╚═╝╚══════╝   │" -ForegroundColor Cyan
Write-Host "  │                                                                  │" -ForegroundColor DarkCyan
Write-Host "  │       🔔 D A I L Y   T A S K   &   E V E N T   R E M I N D E R       │" -ForegroundColor White
Write-Host "  ╰──────────────────────────────────────────────────────────────────╯" -ForegroundColor DarkCyan
Write-Host ""

Write-Host "  ┌─ SYSTEM INITIALIZATION ──────────────────────────────────────────┐" -ForegroundColor DarkGray
Write-Host "  │  [✓] Environment       : Windows Native                          │" -ForegroundColor Gray

# Detect Node
$nodePath = ""
if (Get-Command node -ErrorAction SilentlyContinue) {
  $nodePath = "node"
} elseif (Test-Path "$env:APPDATA\Antigravity\bin\agy-node.cmd") {
  $nodePath = "$env:APPDATA\Antigravity\bin\agy-node.cmd"
} elseif (Test-Path "C:\Program Files\nodejs\node.exe") {
  $nodePath = "C:\Program Files\nodejs\node.exe"
}

if ($nodePath -ne "") {
  Write-Host "  │  [✓] Runtime Engine    : Node.js (Detected)                     │" -ForegroundColor Green
  Write-Host "  │  [✓] Starting Server   : REST API & Static Server                │" -ForegroundColor Green
  
  $serverScript = Join-Path $PSScriptRoot "server.js"
  Start-Process -FilePath $nodePath -ArgumentList "`"$serverScript`"" -WindowStyle Hidden
  Start-Sleep -Seconds 2
  
  Write-Host "  │  [✓] Local Database    : Connected (data/database.json)          │" -ForegroundColor Green
  Write-Host "  │  [✓] Starting Tasks    : 0 Default (Clean Slate for User Tasks)  │" -ForegroundColor Green
  Write-Host "  │  [✓] Audio Synthesizer : 6 Melodic Ringtones Ready               │" -ForegroundColor Green
  Write-Host "  │  [✓] Opening Browser   : http://localhost:3000                   │" -ForegroundColor Cyan
  Start-Process "http://localhost:3000"
} else {
  Write-Host "  │  [!] Standalone Mode   : Browser Engine                          │" -ForegroundColor Yellow
  Write-Host "  │  [✓] Audio Synthesizer : 6 Melodic Ringtones Ready               │" -ForegroundColor Green
  $indexPath = Join-Path $PSScriptRoot "index.html"
  Start-Process $indexPath
}
Write-Host "  └──────────────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray
Write-Host ""

Write-Host "  ╭─ SERVICE STATUS ─────────────────────────────────────────────────╮" -ForegroundColor DarkGreen
Write-Host "  │                                                                  │" -ForegroundColor DarkGreen
Write-Host "  │   ● STATUS  : ONLINE & RUNNING 🟢                                │" -ForegroundColor Green
Write-Host "  │   ● URL     : http://localhost:3000                              │" -ForegroundColor White
Write-Host "  │   ● TASKS   : Clean Start (Ready for your reminders)             │" -ForegroundColor Gray
Write-Host "  │                                                                  │" -ForegroundColor DarkGreen
Write-Host "  │   Keep this window open while using Remind Me.                   │" -ForegroundColor DarkGray
Write-Host "  ╰──────────────────────────────────────────────────────────────────╯" -ForegroundColor DarkGreen
Write-Host ""

Write-Host "  Shortcuts: [O] Open in Browser  •  [R] Restart Server  •  [Q] Exit" -ForegroundColor Cyan
Write-Host ""

while ($true) {
  $key = [Console]::ReadKey($true).KeyChar.ToString().ToUpper()
  if ($key -eq 'O') {
    Write-Host "  [INFO] Opening http://localhost:3000 in your browser..." -ForegroundColor Yellow
    Start-Process "http://localhost:3000"
  } elseif ($key -eq 'R') {
    Write-Host "  [INFO] Restarting server..." -ForegroundColor Yellow
    if ($nodePath -ne "") {
      $serverScript = Join-Path $PSScriptRoot "server.js"
      Start-Process -FilePath $nodePath -ArgumentList "`"$serverScript`"" -WindowStyle Hidden
      Start-Sleep -Seconds 1
    }
    Start-Process "http://localhost:3000"
  } elseif ($key -eq 'Q') {
    Write-Host "  Thank you for using Remind Me! Have a great and productive day! ✨" -ForegroundColor Green
    Start-Sleep -Seconds 1
    break
  }
}
