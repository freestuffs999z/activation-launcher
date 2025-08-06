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
    Write-Host "  3 - Exit"
}

do {
    Show-Menu
    $choice = Read-Host "`nEnter your choice (1-3)"

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
            Write-Host "`nExiting... Closing PowerShell." -ForegroundColor Green
            Start-Sleep -Seconds 1
            Stop-Process -Id $PID  # <- This forcefully ends the script and PowerShell
        }

        default {
            Write-Host "`n[!] Invalid option. Please enter 1, 2, or 3." -ForegroundColor Red
        }
    }

    Write-Host "`nReturning to menu..." -ForegroundColor DarkGray
    Start-Sleep -Seconds 2
    Clear-Host
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "             ACTIVATION TOOLKIT MENU           " -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan

} while ($true)