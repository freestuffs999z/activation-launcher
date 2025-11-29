Clear-Host

# Enhanced Password Protection System
# Features: SHA-256 hashing, secure memory handling, timing attack resistance, lockout protection

function ConvertTo-PlainText([Security.SecureString]$secureString) {
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
    try {
        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

function Get-PasswordHash([SecureString]$securePassword) {
    $password = ConvertTo-PlainText $securePassword
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($password))
        return [System.BitConverter]::ToString($hash).Replace("-", "").ToLower()
    }
    finally {
        $hasher.Dispose()
        Clear-Variable password -ErrorAction SilentlyContinue
    }
}

function Get-LockoutFilePath {
    return [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "activator_lockout.tmp")
}

function Get-LockoutState {
    $lockoutFile = Get-LockoutFilePath
    if (Test-Path $lockoutFile) {
        try {
            $data = Get-Content $lockoutFile -Raw | ConvertFrom-Json
            $lockoutExpiry = [DateTime]::ParseExact($data.LockoutExpiry, "yyyy-MM-dd HH:mm:ss", $null)
            
            if ([DateTime]::Now -lt $lockoutExpiry) {
                $remaining = ($lockoutExpiry - [DateTime]::Now).TotalSeconds
                if ($remaining -gt 0) {
                    return @{
                        IsLocked       = $true
                        RemainingTime  = $remaining
                        FailedAttempts = $data.FailedAttempts
                    }
                }
                else {
                    # Lockout expired (edge case), remove file
                    Remove-Item $lockoutFile -ErrorAction SilentlyContinue
                }
            }
            else {
                # Lockout expired, remove file
                Remove-Item $lockoutFile -ErrorAction SilentlyContinue
            }
        }
        catch {
            # Invalid file, remove it
            Remove-Item $lockoutFile -ErrorAction SilentlyContinue
        }
    }
    
    return @{
        IsLocked       = $false
        RemainingTime  = 0
        FailedAttempts = 0
    }
}

function Set-LockoutState {
    param(
        [int]$FailedAttempts,
        [int]$LockoutDuration = 30
    )
    
    $lockoutFile = Get-LockoutFilePath
    $lockoutExpiry = [DateTime]::Now.AddSeconds($LockoutDuration)
    
    $data = @{
        FailedAttempts = $FailedAttempts
        LockoutExpiry  = $lockoutExpiry.ToString("yyyy-MM-dd HH:mm:ss")
    }
    
    $data | ConvertTo-Json | Set-Content $lockoutFile -ErrorAction SilentlyContinue
}

function Clear-LockoutState {
    $lockoutFile = Get-LockoutFilePath
    Remove-Item $lockoutFile -ErrorAction SilentlyContinue
}

function Test-SecurePassword {
    # Default password: Activation@123 (change the hash below to update password)
    # To generate new hash: Get-PasswordHash (ConvertTo-SecureString "YourNewPassword" -AsPlainText -Force)
    $passwordHash = "833e4157b0baa14a72ce831bc4e7b84b26c4eec878c4c35cff2767d5581e06db"
    $maxAttempts = 3
    $lockoutTime = 30  # seconds
    $attempt = 0

    # Check for existing lockout
    $lockoutState = Get-LockoutState
    if ($lockoutState.IsLocked) {
        Write-Host "===============================================" -ForegroundColor Cyan
        Write-Host "           SECURE ACCESS REQUIRED             " -ForegroundColor Cyan
        Write-Host "===============================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "[!] System is currently locked due to previous failed attempts!" -ForegroundColor Red
        Write-Host "[!] Lockout remaining: $([Math]::Ceiling($lockoutState.RemainingTime)) seconds" -ForegroundColor Red
        Write-Host "[!] Previous failed attempts: $($lockoutState.FailedAttempts)" -ForegroundColor Yellow
        
        # Countdown based on actual remaining time, not a simple counter
        do {
            $currentState = Get-LockoutState
            if (-not $currentState.IsLocked) {
                break
            }
            $remainingSeconds = [Math]::Ceiling($currentState.RemainingTime)
            if ($remainingSeconds -le 0) {
                break
            }
            Write-Host "`rLockout remaining: $remainingSeconds seconds " -NoNewline -ForegroundColor DarkRed
            Start-Sleep -Seconds 1
        } while ($true)
        
        Write-Host "`n[✓] Lockout period expired. You may now try again." -ForegroundColor Green
        Clear-LockoutState
        Start-Sleep -Seconds 2
        Clear-Host
    }

    $attempt = $lockoutState.FailedAttempts

    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "           SECURE ACCESS REQUIRED             " -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""

    while ($attempt -lt $maxAttempts) {
        $currentAttempt = $attempt + 1
        Write-Host "Authentication required ($currentAttempt/$maxAttempts)" -ForegroundColor Yellow

        try {
            $secureInput = Read-Host "Enter password" -AsSecureString

            Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 300)

            $enteredHash = Get-PasswordHash $secureInput

            if ($enteredHash -eq $passwordHash) {
                Write-Host "`n[✓] Authentication successful!" -ForegroundColor Green
                Clear-LockoutState  # Clear any existing lockout on successful auth
                Clear-Variable enteredHash, secureInput -ErrorAction SilentlyContinue
                [System.GC]::Collect()
                Start-Sleep -Seconds 1
                return $true
            }
            else {
                $attempt++
                Write-Host "`n[✗] Authentication failed!" -ForegroundColor Red
                Clear-Variable enteredHash -ErrorAction SilentlyContinue
                
                if ($attempt -lt $maxAttempts) {
                    $remaining = $maxAttempts - $attempt
                    Write-Host "Remaining attempts: $remaining" -ForegroundColor Yellow
                    Write-Host ""
                    # Save current failed attempts to persistent storage
                    Set-LockoutState -FailedAttempts $attempt -LockoutDuration 0
                    Start-Sleep -Seconds 2
                }
                else {
                    # Maximum attempts reached, activate lockout
                    Set-LockoutState -FailedAttempts $attempt -LockoutDuration $lockoutTime
                    break
                }
            }
        }
        catch {
            Write-Host "`n[!] Authentication error occurred." -ForegroundColor Red
            $attempt = $maxAttempts
            Set-LockoutState -FailedAttempts $maxAttempts -LockoutDuration $lockoutTime
        }
    }

    Write-Host "`n[!] Maximum authentication attempts exceeded!" -ForegroundColor Red
    Write-Host "[!] System locked for security. Waiting $lockoutTime seconds..." -ForegroundColor Red
    Write-Host "[!] This lockout will persist even if you close and restart the script!" -ForegroundColor Yellow

    # Countdown based on actual remaining time, not a simple counter  
    do {
        $currentState = Get-LockoutState
        if (-not $currentState.IsLocked) {
            break
        }
        $remainingSeconds = [Math]::Ceiling($currentState.RemainingTime)
        if ($remainingSeconds -le 0) {
            break
        }
        Write-Host "`rLockout remaining: $remainingSeconds seconds " -NoNewline -ForegroundColor DarkRed
        Start-Sleep -Seconds 1
    } while ($true)

    Write-Host "`n[!] Access denied. Exiting for security." -ForegroundColor Red
    Write-Host "`nPress Enter to close this window..." -ForegroundColor Yellow
    [void][System.Console]::ReadLine()
    exit
}

function Show-SecurityBanner {
    Write-Host ""
    Write-Host "SECURITY NOTICE:" -ForegroundColor Red
    Write-Host "   • This toolkit contains sensitive operations" -ForegroundColor Yellow
    Write-Host "   • Unauthorized access is prohibited" -ForegroundColor Yellow
    Write-Host "   • All activities may be logged" -ForegroundColor Yellow
    Write-Host ""
}

# Password Authentication
Show-SecurityBanner
if (-not (Test-SecurePassword)) {
    Write-Host "Security breach detected. Terminating..." -ForegroundColor Red
    Write-Host "`nPress Enter to close this window..." -ForegroundColor Yellow
    [void][System.Console]::ReadLine()
    exit
}

Clear-Host

# Main Application Header
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "             ACTIVATION TOOLKIT MENU           " -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "Authenticated User Session Active" -ForegroundColor Green

function Show-Menu {
    Write-Host ""
    Write-Host "Available Options:" -ForegroundColor Green
    Write-Host "  1 - MassGrave Activation" -ForegroundColor Green
    Write-Host "  2 - WinRAR Activation" -ForegroundColor Green
    Write-Host "  3 - Spicetify Install" -ForegroundColor Green
    Write-Host "  4 - Cursor Pro Install" -ForegroundColor Green
    Write-Host "  5 - Change Password" -ForegroundColor Green
    Write-Host "  6 - Exit" -ForegroundColor Green
}

function Set-NewPassword {
    Write-Host "`nPassword Change Utility" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan

    $newPassword1 = Read-Host "Enter new password" -AsSecureString
    $newPassword2 = Read-Host "Confirm new password" -AsSecureString

    $plain1 = ConvertTo-PlainText $newPassword1
    $plain2 = ConvertTo-PlainText $newPassword2

    if ($plain1 -eq $plain2) {
        $newHash = Get-PasswordHash $newPassword1
        Write-Host "`n[✓] New password hash generated:" -ForegroundColor Green
        Write-Host "$newHash" -ForegroundColor Yellow
        
        Write-Host "`nUpdating script with new password..." -ForegroundColor Cyan
        
        try {
            # Get the current script path
            $scriptPath = $MyInvocation.ScriptName
            if (-not $scriptPath) {
                $scriptPath = $PSCommandPath
            }
            
            if ($scriptPath) {
                # Read the current script content
                $scriptContent = Get-Content $scriptPath -Raw
                
                # Find and replace the password hash line
                $pattern = '(\$passwordHash = ")[^"]+(")'
                $replacement = "`${1}$newHash`${2}"
                
                if ($scriptContent -match $pattern) {
                    $updatedContent = $scriptContent -replace $pattern, $replacement
                    
                    # Write the updated content back to the script
                    Set-Content -Path $scriptPath -Value $updatedContent -Encoding UTF8
                    
                    Write-Host "[✓] Password updated successfully in script!" -ForegroundColor Green
                    Write-Host "[!] The new password will take effect on next script run." -ForegroundColor Yellow
                    
                    # Offer to restart the script
                    $restart = Read-Host "`nWould you like to restart the script now to use the new password? (y/N)"
                    if ($restart -eq "y" -or $restart -eq "Y") {
                        Write-Host "`nRestarting script with new password..." -ForegroundColor Green
                        Start-Sleep -Seconds 2
                        & $scriptPath
                        exit
                    }
                }
                else {
                    Write-Host "[!] Could not find password hash line in script." -ForegroundColor Red
                    Write-Host "Manual update required:" -ForegroundColor Yellow
                    Write-Host "Replace the `$passwordHash value with: $newHash" -ForegroundColor White
                }
            }
            else {
                Write-Host "[!] Could not determine script path for automatic update." -ForegroundColor Red
                Write-Host "Manual update required:" -ForegroundColor Yellow
                Write-Host "Replace the `$passwordHash value with: $newHash" -ForegroundColor White
            }
        }
        catch {
            Write-Host "[✗] Error updating script: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Manual update required:" -ForegroundColor Yellow
            Write-Host "Replace the `$passwordHash value with: $newHash" -ForegroundColor White
        }
    }
    else {
        Write-Host "`n[✗] Passwords do not match!" -ForegroundColor Red
    }

    Clear-Variable plain1, plain2, newPassword1, newPassword2, newHash, scriptContent, updatedContent -ErrorAction SilentlyContinue
    Read-Host "`nPress Enter to continue"
}

function Invoke-RemoteScript {
    param(
        [string]$Url,
        [string]$Description,
        [int]$MaxRetries = 3,
        [int]$InitialDelayMs = 1000
    )
    
    # Browser-like headers to bypass Cloudflare bot detection
    $headers = @{
        'User-Agent'                = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        'Accept'                    = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        'Accept-Language'           = 'en-US,en;q=0.9'
        'Accept-Encoding'           = 'gzip, deflate, br'
        'DNT'                       = '1'
        'Connection'                = 'keep-alive'
        'Upgrade-Insecure-Requests' = '1'
    }
    
    $attempt = 0
    $delay = $InitialDelayMs
    
    while ($attempt -lt $MaxRetries) {
        $attempt++
        
        try {
            Write-Host "[Attempt $attempt/$MaxRetries] Downloading $Description..." -ForegroundColor Cyan
            
            # Create web session for cookie handling
            $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            
            # Download the script
            $scriptContent = Invoke-RestMethod -Uri $Url -Headers $headers -WebSession $session -TimeoutSec 30 -ErrorAction Stop
            
            # Verify we got actual script content, not HTML
            if ($scriptContent -match '<html|<!DOCTYPE|<head|<body') {
                throw "Received HTML page instead of script (possible Cloudflare challenge)"
            }
            
            Write-Host "[✓] Successfully downloaded $Description" -ForegroundColor Green
            
            # Execute the script
            Write-Host "[Executing] Running $Description..." -ForegroundColor Yellow
            Invoke-Expression $scriptContent
            
            return $true
            
        }
        catch {
            $errorMsg = $_.Exception.Message
            Write-Host "[✗] Attempt $attempt failed: $errorMsg" -ForegroundColor Red
            
            if ($attempt -lt $MaxRetries) {
                Write-Host "[Retry] Waiting $($delay/1000) seconds before retry..." -ForegroundColor Yellow
                Start-Sleep -Milliseconds $delay
                $delay = $delay * 2  # Exponential backoff
            }
            else {
                Write-Host "[✗] All attempts failed for $Description" -ForegroundColor Red
                Write-Host "Error details: $errorMsg" -ForegroundColor DarkRed
                Write-Host "URL: $Url" -ForegroundColor DarkGray
                return $false
            }
        }
    }
    
    return $false
}

do {
    Show-Menu
    $choice = Read-Host "`nEnter your choice (1-6)"

    switch ($choice) {
        "1" {
            Write-Host "`nRunning MassGrave Activation..." -ForegroundColor Yellow
            $success = Invoke-RemoteScript -Url 'https://get.activated.win' -Description 'MassGrave Activation'
            if ($success) {
                Write-Host "[✓] MassGrave Activation completed." -ForegroundColor Green
            }
            else {
                Write-Host "[!] MassGrave Activation failed. Please check your internet connection or try again later." -ForegroundColor Yellow
            }
        }
        "2" {
            Write-Host "`nRunning WinRAR Activation..." -ForegroundColor Yellow
            $success = Invoke-RemoteScript -Url 'https://naeembolchhi.github.io/WinRAR-Activator/WRA.ps1' -Description 'WinRAR Activation'
            if ($success) {
                Write-Host "[✓] WinRAR Activation completed." -ForegroundColor Green
            }
            else {
                Write-Host "[!] WinRAR Activation failed. Please check your internet connection or try again later." -ForegroundColor Yellow
            }
        }
        "3" {
            Write-Host "`nRunning Spicetify Install..." -ForegroundColor Yellow
            $success = Invoke-RemoteScript -Url 'https://raw.githubusercontent.com/spicetify/cli/main/install.ps1' -Description 'Spicetify Install'
            if ($success) {
                Write-Host "[✓] Spicetify installation completed." -ForegroundColor Green
            }
            else {
                Write-Host "[!] Spicetify installation failed. Please check your internet connection or try again later." -ForegroundColor Yellow
            }
        }
        "4" {
            Write-Host "`nRunning Cursor Pro Install..." -ForegroundColor Yellow
            $success = Invoke-RemoteScript -Url 'https://raw.githubusercontent.com/yeongpin/cursor-free-vip/main/scripts/install.ps1' -Description 'Cursor Pro Install'
            if ($success) {
                Write-Host "[✓] Cursor Pro installation completed." -ForegroundColor Green
            }
            else {
                Write-Host "[!] Cursor Pro installation failed. Please check your internet connection or try again later." -ForegroundColor Yellow
            }
        }
        "5" {
            Set-NewPassword
        }
        "6" {
            Write-Host "`nClosing secure session..." -ForegroundColor Green
            Write-Host "Thank you for using the Activation Toolkit!" -ForegroundColor Cyan
            Write-Host "`nPress Enter to close this window..." -ForegroundColor Yellow
            [void][System.Console]::ReadLine()
            exit
        }
        default {
            Write-Host "`nInvalid option. Please enter 1-6." -ForegroundColor Red
        }
    }

    if ($choice -ne "5") {
        Write-Host "`nReturning to menu..." -ForegroundColor DarkGray
        Start-Sleep -Seconds 3
    }

    Clear-Host
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "             ACTIVATION TOOLKIT MENU           " -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "Authenticated User Session Active" -ForegroundColor Green

} while ($true)

