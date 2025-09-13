Clear-Host
# Header
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "             ACTIVATION TOOLKIT MENU           " -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
function Show-Menu {
    Write-Host ""
    Write-Host "Available Options:" -ForegroundColor Green
    Write-Host "  1 - MassGrave Activation"
    Write-Host "  2 - WinRAR Activation"
    Write-Host "  3 - Spicetify Install"
    Write-Host "  4 - Cursor Pro Install"
    Write-Host "  5 - Exit"
}
do {
    Show-Menu
    $choice = Read-Host "`nEnter your choice (1-5)"
    switch ($choice) {
        "1" {
            Write-Host "`nRunning MassGrave Activation..." -ForegroundColor Yellow
            try {
                irm https://get.activated.win | iex
            } catch {
                Write-Host "`n[!] Failed to run MassGrave Activation." -ForegroundColor Red
            }
        }
        "2" {
            Write-Host "`nRunning WinRAR Activation..." -ForegroundColor Yellow
            try {
                irm https://naeembolchhi.github.io/WinRAR-Activator/WRA.ps1 | iex
            } catch {
                Write-Host "`n[!] Failed to run WinRAR Activation." -ForegroundColor Red
            }
        }
        "3" {
            Write-Host "`nRunning Spicetify Install..." -ForegroundColor Yellow
            try {
                iwr -useb https://raw.githubusercontent.com/spicetify/cli/main/install.ps1 | iex
            } catch {
                Write-Host "`n[!] Failed to run Spicetify Install." -ForegroundColor Red
            }
        }
        "4" {
            Write-Host "`nRunning Cursor Pro Install..." -ForegroundColor Yellow
            try {
                irm https://raw.githubusercontent.com/yeongpin/cursor-free-vip/main/scripts/install.ps1 | iex
            } catch {
                Write-Host "`n[!] Failed to run Cursor Pro Install." -ForegroundColor Red
            }
        }
        "5" {
            Write-Host "`nExiting... Closing PowerShell." -ForegroundColor Green
            Start-Sleep -Seconds 1
            Stop-Process -Id $PID
        }
        default {
            Write-Host "`n[!] Invalid option. Please enter 1, 2, 3, 4, or 5." -ForegroundColor Red
        }
    }
    Write-Host "`nReturning to menu..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 2
    Clear-Host
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "             ACTIVATION TOOLKIT MENU           " -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
} while ($true)
