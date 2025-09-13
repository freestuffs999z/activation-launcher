Clear-Host

# Enhanced Password Protection System with Multi-User Support
# Features: SHA-256 hashing, secure memory handling, timing attack resistance, lockout protection
# Admin/Temporary user roles with single-use expiration

function ConvertTo-PlainText([Security.SecureString]$secureString) {
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
    try {
        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

function Get-PasswordHash([SecureString]$securePassword) {
    $password = ConvertTo-PlainText $securePassword
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($password))
        return [System.BitConverter]::ToString($hash).Replace("-", "").ToLower()
    } finally {
        $hasher.Dispose()
        Clear-Variable password -ErrorAction SilentlyContinue
    }
}

function Get-LockoutFilePath {
    return [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "activator_lockout.tmp")
}

function Get-TempUsersFilePath {
    return [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "activator_tempusers.json")
}

function Get-TempUsers {
    $tempUsersFile = Get-TempUsersFilePath
    if (Test-Path $tempUsersFile) {
        try {
            $content = Get-Content $tempUsersFile -Raw
            if ($content) {
                return $content | ConvertFrom-Json
            }
        } catch {
            # Invalid file, remove it
            Remove-Item $tempUsersFile -ErrorAction SilentlyContinue
        }
    }
    return @()
}

function Save-TempUsers {
    param([array]$users)
    $tempUsersFile = Get-TempUsersFilePath
    try {
        $users | ConvertTo-Json -Depth 3 | Set-Content $tempUsersFile -ErrorAction SilentlyContinue
    } catch {
        Write-Host "[!] Warning: Could not save temporary users data." -ForegroundColor Yellow
    }
}

function New-TempUser {
    param(
        [string]$Username,
        [string]$Password,
        [int]$AllowedTool
    )
    
    $passwordHash = Get-PasswordHash (ConvertTo-SecureString $Password -AsPlainText -Force)
    $existingUsers = Get-TempUsers
    $tempUsers = @()
    
    # Convert existing users to consistent hashtable format and filter out duplicate username
    foreach ($user in $existingUsers) {
        if ($user.Username -ne $Username) {
            $tempUsers += @{
                Username = $user.Username
                PasswordHash = $user.PasswordHash
                AllowedTool = $user.AllowedTool
                CreatedDate = $user.CreatedDate
                IsUsed = $user.IsUsed
                UsedDate = if ($user.PSObject.Properties['UsedDate']) { $user.UsedDate } else { $null }
            }
        }
    }
    
    # Add new temp user
    $newUser = @{
        Username = $Username
        PasswordHash = $passwordHash
        AllowedTool = $AllowedTool
        CreatedDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        IsUsed = $false
        UsedDate = $null
    }
    
    $tempUsers += $newUser
    Save-TempUsers $tempUsers
    
    Clear-Variable passwordHash, Password -ErrorAction SilentlyContinue
    return $true
}

function Test-TempUserCredentials {
    param(
        [string]$Username,
        [SecureString]$Password
    )
    
    $tempUsers = Get-TempUsers
    $user = $tempUsers | Where-Object { $_.Username -eq $Username -and -not $_.IsUsed }
    
    if ($user) {
        $enteredHash = Get-PasswordHash $Password
        if ($enteredHash -eq $user.PasswordHash) {
            return @{
                IsValid = $true
                AllowedTool = $user.AllowedTool
                Username = $user.Username
            }
        }
    }
    
    Clear-Variable enteredHash -ErrorAction SilentlyContinue
    return @{ IsValid = $false }
}

function Remove-TempUser {
    param([string]$Username)
    
    $existingUsers = Get-TempUsers
    $tempUsers = @()
    
    # Convert to consistent hashtable format and filter out target username
    foreach ($user in $existingUsers) {
        if ($user.Username -ne $Username) {
            $tempUsers += @{
                Username = $user.Username
                PasswordHash = $user.PasswordHash
                AllowedTool = $user.AllowedTool
                CreatedDate = $user.CreatedDate
                IsUsed = $user.IsUsed
                UsedDate = if ($user.PSObject.Properties['UsedDate']) { $user.UsedDate } else { $null }
            }
        }
    }
    
    Save-TempUsers $tempUsers
}

function Set-TempUserAsUsed {
    param([string]$Username)
    
    $existingUsers = Get-TempUsers
    $updatedUsers = @()
    
    foreach ($user in $existingUsers) {
        if ($user.Username -eq $Username) {
            # Create new object with updated properties
            $updatedUsers += @{
                Username = $user.Username
                PasswordHash = $user.PasswordHash
                AllowedTool = $user.AllowedTool
                CreatedDate = $user.CreatedDate
                IsUsed = $true
                UsedDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            }
        } else {
            # Keep existing user as-is, but ensure it has UsedDate property
            $updatedUsers += @{
                Username = $user.Username
                PasswordHash = $user.PasswordHash
                AllowedTool = $user.AllowedTool
                CreatedDate = $user.CreatedDate
                IsUsed = $user.IsUsed
                UsedDate = if ($user.PSObject.Properties['UsedDate']) { $user.UsedDate } else { $null }
            }
        }
    }
    
    Save-TempUsers $updatedUsers
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
                        IsLocked = $true
                        RemainingTime = $remaining
                        FailedAttempts = $data.FailedAttempts
                    }
                } else {
                    # Lockout expired (edge case), remove file
                    Remove-Item $lockoutFile -ErrorAction SilentlyContinue
                }
            } else {
                # Lockout expired, remove file
                Remove-Item $lockoutFile -ErrorAction SilentlyContinue
            }
        } catch {
            # Invalid file, remove it
            Remove-Item $lockoutFile -ErrorAction SilentlyContinue
        }
    }
    
    return @{
        IsLocked = $false
        RemainingTime = 0
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
        LockoutExpiry = $lockoutExpiry.ToString("yyyy-MM-dd HH:mm:ss")
    }
    
    $data | ConvertTo-Json | Set-Content $lockoutFile -ErrorAction SilentlyContinue
}

function Clear-LockoutState {
    $lockoutFile = Get-LockoutFilePath
    Remove-Item $lockoutFile -ErrorAction SilentlyContinue
}

function Test-UserAuthentication {
    # Admin password: Activation@123
    $adminPasswordHash = "833e4157b0baa14a72ce831bc4e7b84b26c4eec878c4c35cff2767d5581e06db"
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
        
        Write-Host "`n[+] Lockout period expired. You may now try again." -ForegroundColor Green
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
            $username = Read-Host "Username (or press Enter for admin)"
            if ([string]::IsNullOrWhiteSpace($username)) {
                $username = "admin"
            }
            
            $secureInput = Read-Host "Enter password" -AsSecureString

            Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 300)

            # Check if admin user
            if ($username -eq "admin") {
                $enteredHash = Get-PasswordHash $secureInput
                if ($enteredHash -eq $adminPasswordHash) {
                    Write-Host "`n[+] Admin authentication successful!" -ForegroundColor Green
                    Clear-LockoutState
                    Clear-Variable enteredHash, secureInput -ErrorAction SilentlyContinue
                    [System.GC]::Collect()
                    Start-Sleep -Seconds 1
                    return @{
                        IsAuthenticated = $true
                        UserRole = "Admin"
                        Username = "admin"
                        AllowedTool = 0  # 0 means all tools
                    }
                }
            }
            else {
                # Check temporary user
                $tempUserResult = Test-TempUserCredentials -Username $username -Password $secureInput
                if ($tempUserResult.IsValid) {
                    Write-Host "`n[+] Temporary user authentication successful!" -ForegroundColor Green
                    Write-Host "[!] Single-use access granted for Tool #$($tempUserResult.AllowedTool)" -ForegroundColor Yellow
                    Clear-LockoutState
                    Clear-Variable secureInput -ErrorAction SilentlyContinue
                    [System.GC]::Collect()
                    Start-Sleep -Seconds 1
                    return @{
                        IsAuthenticated = $true
                        UserRole = "TempUser"
                        Username = $tempUserResult.Username
                        AllowedTool = $tempUserResult.AllowedTool
                    }
                }
            }

            $attempt++
            Write-Host "`n[-] Authentication failed!" -ForegroundColor Red
            Clear-Variable enteredHash, secureInput -ErrorAction SilentlyContinue
            
            if ($attempt -lt $maxAttempts) {
                $remaining = $maxAttempts - $attempt
                Write-Host "Remaining attempts: $remaining" -ForegroundColor Yellow
                Write-Host ""
                Set-LockoutState -FailedAttempts $attempt -LockoutDuration 0
                Start-Sleep -Seconds 2
            } else {
                Set-LockoutState -FailedAttempts $attempt -LockoutDuration $lockoutTime
                break
            }
        } catch {
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

function Get-ToolName {
    param([int]$toolNumber)
    switch ($toolNumber) {
        1 { return "MassGrave Activation" }
        2 { return "WinRAR Activation" }
        3 { return "Spicetify Install" }
        4 { return "Cursor Pro Install" }
        default { return "Unknown Tool" }
    }
}

function Show-Menu {
    param([hashtable]$user)
    
    Write-Host ""
    
    if ($user.UserRole -eq "Admin") {
        Write-Host "Available Options:" -ForegroundColor Green
        Write-Host "  1 - MassGrave Activation" -ForegroundColor Green
        Write-Host "  2 - WinRAR Activation" -ForegroundColor Green
        Write-Host "  3 - Spicetify Install" -ForegroundColor Green
        Write-Host "  4 - Cursor Pro Install" -ForegroundColor Green
        Write-Host "  5 - Change Admin Password" -ForegroundColor Green
        Write-Host "  6 - Create Temporary User" -ForegroundColor Cyan
        Write-Host "  7 - Manage Temporary Users" -ForegroundColor Cyan
        Write-Host "  8 - Exit" -ForegroundColor Green
    } else {
        Write-Host "Available Options:" -ForegroundColor Yellow
        Write-Host "  $(Get-ToolName $user.AllowedTool) - Single Use Only" -ForegroundColor Green
        Write-Host "  Exit after using the tool" -ForegroundColor Yellow
    }
}

function Set-NewPassword {
    Write-Host "`nAdmin Password Change Utility" -ForegroundColor Cyan
    Write-Host "============================" -ForegroundColor Cyan

    $newPassword1 = Read-Host "Enter new admin password" -AsSecureString
    $newPassword2 = Read-Host "Confirm new admin password" -AsSecureString

    $plain1 = ConvertTo-PlainText $newPassword1
    $plain2 = ConvertTo-PlainText $newPassword2

    if ($plain1 -eq $plain2) {
        $newHash = Get-PasswordHash $newPassword1
        Write-Host "`n[+] New admin password hash generated:" -ForegroundColor Green
        Write-Host "$newHash" -ForegroundColor Yellow
        
        Write-Host "`nUpdating script with new admin password..." -ForegroundColor Cyan
        
        try {
            # Get the current script path
            $scriptPath = $MyInvocation.ScriptName
            if (-not $scriptPath) {
                $scriptPath = $PSCommandPath
            }
            
            if ($scriptPath) {
                # Read the current script content
                $scriptContent = Get-Content $scriptPath -Raw
                
                # Find and replace the admin password hash line
                $pattern = '(\$adminPasswordHash = ")([a-f0-9]+)(")'
                $replacement = "`${1}$newHash`${3}"
                
                if ($scriptContent -match $pattern) {
                    $updatedContent = $scriptContent -replace $pattern, $replacement
                    
                    # Write the updated content back to the script
                    Set-Content -Path $scriptPath -Value $updatedContent -Encoding UTF8
                    
                    Write-Host "[+] Admin password updated successfully in script!" -ForegroundColor Green
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
                    Write-Host "[!] Could not find admin password hash line in script." -ForegroundColor Red
                    Write-Host "Manual update required:" -ForegroundColor Yellow
                    Write-Host "Replace the `$adminPasswordHash value with: $newHash" -ForegroundColor White
                }
            }
            else {
                Write-Host "[!] Could not determine script path for automatic update." -ForegroundColor Red
                Write-Host "Manual update required:" -ForegroundColor Yellow
                Write-Host "Replace the `$adminPasswordHash value with: $newHash" -ForegroundColor White
            }
        }
        catch {
            Write-Host "[-] Error updating script: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "Manual update required:" -ForegroundColor Yellow
            Write-Host "Replace the `$adminPasswordHash value with: $newHash" -ForegroundColor White
        }
    }
    else {
        Write-Host "`n[-] Passwords do not match!" -ForegroundColor Red
    }

    Clear-Variable plain1, plain2, newPassword1, newPassword2, newHash, scriptContent, updatedContent -ErrorAction SilentlyContinue
    Read-Host "`nPress Enter to continue"
}

function New-TempUserInterface {
    Write-Host "`nCreate Temporary User" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    
    Write-Host "`nAvailable Tools:" -ForegroundColor Yellow
    Write-Host "  1 - MassGrave Activation" -ForegroundColor White
    Write-Host "  2 - WinRAR Activation" -ForegroundColor White
    Write-Host "  3 - Spicetify Install" -ForegroundColor White
    Write-Host "  4 - Cursor Pro Install" -ForegroundColor White
    
    $username = Read-Host "`nEnter username for temporary user"
    if ([string]::IsNullOrWhiteSpace($username)) {
        Write-Host "[-] Username cannot be empty!" -ForegroundColor Red
        Read-Host "`nPress Enter to continue"
        return
    }
    
    $password = Read-Host "Enter password for temporary user"
    if ([string]::IsNullOrWhiteSpace($password)) {
        Write-Host "[-] Password cannot be empty!" -ForegroundColor Red
        Read-Host "`nPress Enter to continue"
        return
    }
    
    $toolChoice = Read-Host "Select tool number (1-4) for this user"
    $toolNumber = 0
    if ([int]::TryParse($toolChoice, [ref]$toolNumber) -and $toolNumber -ge 1 -and $toolNumber -le 4) {
        try {
            if (New-TempUser -Username $username -Password $password -AllowedTool $toolNumber) {
                Write-Host "`n[+] Temporary user '$username' created successfully!" -ForegroundColor Green
                Write-Host "[!] User can access: $(Get-ToolName $toolNumber)" -ForegroundColor Yellow
                Write-Host "[!] This is a single-use account and will expire after tool usage." -ForegroundColor Yellow
            } else {
                Write-Host "`n[-] Failed to create temporary user!" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "`n[-] Error creating user: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    else {
        Write-Host "`n[-] Invalid tool selection! Please choose 1-4." -ForegroundColor Red
    }
    
    Clear-Variable password -ErrorAction SilentlyContinue
    Read-Host "`nPress Enter to continue"
}

function Show-TempUsersInterface {
    Write-Host "`nManage Temporary Users" -ForegroundColor Cyan
    Write-Host "======================" -ForegroundColor Cyan
    
    $tempUsers = Get-TempUsers
    
    if ($tempUsers.Count -eq 0) {
        Write-Host "`nNo temporary users found." -ForegroundColor Yellow
        Read-Host "`nPress Enter to continue"
        return
    }
    
    Write-Host "`nCurrent Temporary Users:" -ForegroundColor Yellow
    Write-Host "========================" -ForegroundColor Yellow
    
    for ($i = 0; $i -lt $tempUsers.Count; $i++) {
        $user = $tempUsers[$i]
        $status = if ($user.IsUsed) { "USED" } else { "ACTIVE" }
        $statusColor = if ($user.IsUsed) { "Red" } else { "Green" }
        
        Write-Host "`n[$($i + 1)] Username: $($user.Username)" -ForegroundColor White
        Write-Host "    Tool: $(Get-ToolName $user.AllowedTool)" -ForegroundColor White
        Write-Host "    Status: $status" -ForegroundColor $statusColor
        Write-Host "    Created: $($user.CreatedDate)" -ForegroundColor Gray
        if ($user.IsUsed -and $user.UsedDate) {
            Write-Host "    Used: $($user.UsedDate)" -ForegroundColor Gray
        }
    }
    
    Write-Host "`nOptions:" -ForegroundColor Yellow
    Write-Host "  D - Delete a user" -ForegroundColor White
    Write-Host "  C - Clean up used accounts" -ForegroundColor White
    Write-Host "  Enter - Return to main menu" -ForegroundColor White
    
    $choice = Read-Host "`nEnter your choice"
    
    switch ($choice.ToUpper()) {
        "D" {
            $userNum = Read-Host "Enter user number to delete (1-$($tempUsers.Count))"
            $index = 0
            if ([int]::TryParse($userNum, [ref]$index) -and $index -ge 1 -and $index -le $tempUsers.Count) {
                $userToDelete = $tempUsers[$index - 1]
                $confirm = Read-Host "Delete user '$($userToDelete.Username)'? (y/N)"
                if ($confirm -eq "y" -or $confirm -eq "Y") {
                    Remove-TempUser -Username $userToDelete.Username
                    Write-Host "[+] User '$($userToDelete.Username)' deleted successfully!" -ForegroundColor Green
                    Start-Sleep -Seconds 2
                }
            } else {
                Write-Host "[-] Invalid user number!" -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
        "C" {
            $usedUsers = $tempUsers | Where-Object { $_.IsUsed }
            if ($usedUsers.Count -gt 0) {
                $confirm = Read-Host "Delete all $($usedUsers.Count) used accounts? (y/N)"
                if ($confirm -eq "y" -or $confirm -eq "Y") {
                    foreach ($user in $usedUsers) {
                        Remove-TempUser -Username $user.Username
                    }
                    Write-Host "[+] Cleaned up $($usedUsers.Count) used accounts!" -ForegroundColor Green
                    Start-Sleep -Seconds 2
                }
            } else {
                Write-Host "[!] No used accounts to clean up." -ForegroundColor Yellow
                Start-Sleep -Seconds 2
            }
        }
    }
}

function Execute-Tool {
    param([int]$toolNumber, [hashtable]$user)
    
    $toolName = Get-ToolName $toolNumber
    Write-Host "`nRunning $toolName..." -ForegroundColor Yellow
    
    try {
        switch ($toolNumber) {
            1 {
                Invoke-RestMethod https://get.activated.win | Invoke-Expression
                Write-Host "[+] MassGrave Activation completed." -ForegroundColor Green
            }
            2 {
                Invoke-RestMethod https://naeembolchhi.github.io/WinRAR-Activator/WRA.ps1 | Invoke-Expression
                Write-Host "[+] WinRAR Activation completed." -ForegroundColor Green
            }
            3 {
                Invoke-WebRequest -UseBasicParsing https://raw.githubusercontent.com/spicetify/cli/main/install.ps1 | Invoke-Expression
                Write-Host "[+] Spicetify installation completed." -ForegroundColor Green
            }
            4 {
                Invoke-RestMethod https://raw.githubusercontent.com/yeongpin/cursor-free-vip/main/scripts/install.ps1 | Invoke-Expression
                Write-Host "[+] Cursor Pro installation completed." -ForegroundColor Green
            }
        }
        
        # Mark temporary user as used (single-use expiration)
        if ($user.UserRole -eq "TempUser") {
            Set-TempUserAsUsed -Username $user.Username
            Write-Host "`n[!] Your temporary account has been used and is now expired." -ForegroundColor Yellow
            Write-Host "[!] Contact administrator for new access if needed." -ForegroundColor Yellow
            Write-Host "`nPress Enter to exit..." -ForegroundColor Yellow
            [void][System.Console]::ReadLine()
            exit
        }
    }
    catch {
        Write-Host "[-] Failed to run $toolName`: $($_.Exception.Message)" -ForegroundColor Red
        
        # Even on failure, mark temp user as used to prevent retry abuse
        if ($user.UserRole -eq "TempUser") {
            Set-TempUserAsUsed -Username $user.Username
            Write-Host "`n[!] Your temporary account has been used and is now expired." -ForegroundColor Yellow
            Write-Host "`nPress Enter to exit..." -ForegroundColor Yellow
            [void][System.Console]::ReadLine()
            exit
        }
    }
}

# User Authentication
Show-SecurityBanner
$currentUser = Test-UserAuthentication
if (-not $currentUser.IsAuthenticated) {
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
if ($currentUser.UserRole -eq "Admin") {
    Write-Host "Admin User Session Active - Full Access" -ForegroundColor Green
} else {
    Write-Host "Temporary User Session Active - Limited Access" -ForegroundColor Yellow
    Write-Host "Authorized Tool: $(Get-ToolName $currentUser.AllowedTool)" -ForegroundColor Yellow
}

# Main application loop
do {
    Show-Menu $currentUser
    
    if ($currentUser.UserRole -eq "Admin") {
        $choice = Read-Host "`nEnter your choice (1-8)"
        
        switch ($choice) {
            "1" { Execute-Tool 1 $currentUser }
            "2" { Execute-Tool 2 $currentUser }
            "3" { Execute-Tool 3 $currentUser }
            "4" { Execute-Tool 4 $currentUser }
            "5" { Set-NewPassword }
            "6" { New-TempUserInterface }
            "7" { Show-TempUsersInterface }
            "8" {
                Write-Host "`nClosing admin session..." -ForegroundColor Green
                Write-Host "Thank you for using the Activation Toolkit!" -ForegroundColor Cyan
                Write-Host "`nPress Enter to close this window..." -ForegroundColor Yellow
                [void][System.Console]::ReadLine()
                exit
            }
            default {
                Write-Host "`nInvalid option. Please enter 1-8." -ForegroundColor Red
            }
        }
        
        if ($choice -notin @("5", "6", "7", "8")) {
            Write-Host "`nReturning to menu..." -ForegroundColor DarkGray
            Start-Sleep -Seconds 3
        }
    }
    else {
        # Temporary user - single tool access only
        Write-Host "`nPress Enter to use your authorized tool, or type 'exit' to quit..." -ForegroundColor Yellow
        $choice = Read-Host
        
        if ($choice.ToLower() -eq "exit") {
            Write-Host "`nExiting without using tool..." -ForegroundColor Yellow
            Write-Host "`nPress Enter to close this window..." -ForegroundColor Yellow
            [void][System.Console]::ReadLine()
            exit
        }
        else {
            Execute-Tool $currentUser.AllowedTool $currentUser
            # Function will exit after tool execution for temp users
        }
    }

    if ($currentUser.UserRole -eq "Admin") {
        Clear-Host
        Write-Host "===============================================" -ForegroundColor Cyan
        Write-Host "             ACTIVATION TOOLKIT MENU           " -ForegroundColor Cyan
        Write-Host "===============================================" -ForegroundColor Cyan
        Write-Host "Admin User Session Active - Full Access" -ForegroundColor Green
    }

} while ($true)
