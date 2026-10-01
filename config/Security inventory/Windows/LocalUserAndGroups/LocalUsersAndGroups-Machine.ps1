#Requires -Version 3.0
. $PSScriptRoot\..\Shared\Helper.ps1 -Force

$WinBioStatus = @{
   MULTIPLE           = 0x00000001
   FACIAL_FEATURES    = 0x00000002
   VOICE              = 0x00000004
   FINGERPRINT        = 0x00000008
   IRIS               = 0x00000010
   RETINA             = 0x00000020
   HAND_GEOMETRY      = 0x00000040
   SIGNATURE_DYNAMICS = 0x00000080
   KEYSTROKE_DYNAMICS = 0x00000100
   LIP_MOVEMENT       = 0x00000200
   THERMAL_FACE_IMAGE = 0x00000400
   THERMAL_HAND_IMAGE = 0x00000800
   GAIT               = 0x00001000
   SCENT              = 0x00002000
   DNA                = 0x00004000
   EAR_SHAPE          = 0x00008000
   FINGER_GEOMETRY    = 0x00010000
   PALM_PRINT         = 0x00020000
   VEIN_PATTERN       = 0x00040000
   FOOT_PRINT         = 0x00080000
   OTHER              = 0x40000000
   PASSWORD           = 0x80000000
}

function Get-vlUACState {
   <#
    .SYNOPSIS
        Function that checks if the UAC is enabled.
    .DESCRIPTION
        Function that checks if the UAC is enabled.
        This check is using the registry key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA
    .LINK
        https://uberagent.com
    .OUTPUTS
        If the UAC is enabled, the script will return a vlResultObject with the UACEnabled property set to true.
        If the UAC is disabled, the script will return a vlResultObject with the UACEnabled property set to false.
    .EXAMPLE
        Get-vlUACState
    #>

   $riskScore = 60

   try {
      $uac = Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Value "EnableLUA"
      if ($uac -eq 1) {
         $result = [PSCustomObject]@{
            UACEnabled = $true
         }

         return New-vlResultObject -result $result -score 10 -riskScore $riskScore
      }
      else {
         $result = [PSCustomObject]@{
            UACEnabled = $false
         }

         return New-vlResultObject -result $result -score 4 -riskScore $riskScore
      }
   }
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-vlLAPSEventLog {
   <#
    .SYNOPSIS
        Retrieves LAPS (Local Administrator Password Solution) event logs from the Microsoft-Windows-LAPS/Operational log.

    .DESCRIPTION
        This function searches for LAPS events in the Microsoft-Windows-LAPS/Operational event log. It retrieves events with level 2 (error) and 3 (warning) that occurred within the given time range.

    .LINK
        https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/windows-laps-troubleshooting-guidance

    .OUTPUTS
        Returns a custom object with two properties:
        - Errors: An array containing LAPS events with Event ID 2 (error).
        - Warnings: An array containing LAPS events with Event ID 3 (warning).

    .EXAMPLE
         #Retrieves LAPS events from the Microsoft-Windows-LAPS/Operational log that occurred within the last 24 hours.
        Get-vlLAPSEventLog -StartTime (Get-Date).AddHours(-24)
   #>

   [CmdletBinding()]
   param (
      [DateTime]$StartTime = (Get-Date).AddHours(-24),
      [DateTime]$EndTime = (Get-Date)
   )

   $errors = @()
   $warnings = @()

   try {
      # Define the log name (for LAPS)
      $logName = 'Microsoft-Windows-LAPS/Operational'

      # Check if $Start time is before $End time if not swap them
      if ($StartTime -gt $EndTime) {
         $temp = $StartTime
         $StartTime = $EndTime
         $EndTime = $temp
      }

      try {
         # Search the Event Logs for each Event ID
         Get-WinEvent -LogName $logName -ErrorAction Stop | Where-Object { ($_.Level -eq 2 -or $_.Level -eq 3) -and $_.TimeCreated -ge $StartTime -and $_.TimeCreated -le $EndTime } | ForEach-Object {
            # only keep: TimeCreated, Id, Message
            $winEvent = [PSCustomObject]@{
               TimeCreated = Get-vlTimeString -time $_.TimeCreated
               Id          = $_.Id
               Message     = $_.Message
               Level       = if ($_.Level -eq 2) { "Error" } elseif ($_.Level -eq 3) { "Warning" } else { "" }
            }

            # add the event to the errors array if the event id is 2 (error)
            if ($_.Level -eq 2) {
               $errors += $winEvent
            }

            # add the event to the warnings array if the event id is 3 (warning)
            if ($_.Level -eq 3) {
               $warnings += $winEvent
            }
         }

         # filter $errors and $warnings for unique events. Only keep latest event for each event id
         $errors = $errors | Group-Object -Property Id | ForEach-Object { $_.Group | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1 }
         $warnings = $warnings | Group-Object -Property Id | ForEach-Object { $_.Group | Sort-Object -Property TimeCreated -Descending | Select-Object -First 1 }
      }
      catch {
         # if the log does not exist, return an empty result
         $result = [PSCustomObject]@{
            Errors   = $errors
            Warnings = $warnings
         }

         return $result
      }

      $result = [PSCustomObject]@{
         Errors   = $errors
         Warnings = $warnings
      }

      return $result
   }
   catch {
      $result = [PSCustomObject]@{
         Errors   = $errors
         Warnings = $warnings
      }

      return $result
   }
}

function Get-vlLAPSTestEventLog {
   <#
    .SYNOPSIS
        Function that checks the Windows event log for LAPS errors and warnings.
    .DESCRIPTION
        Function that checks the Windows event log for LAPS errors and warnings.
    .OUTPUTS
        If the Windows event log contains LAPS errors, the script will return a vlResultObject with the EventLog errors and warnings.
    .EXAMPLE
        Get-vlLAPSTestEventLog
    #>
   try {
      $riskScore = 30
      $eventLog = Get-vlLAPSEventLog -StartTime (Get-Date).AddHours(-24) -EndTime (Get-Date)

      # merge lists to one output list
      $lapsLog = @()

      if ($eventLog.Warnings) {
         $lapsLog += $eventLog.Warnings
      }

      if ($eventLog.Errors) {
         $lapsLog += $eventLog.Errors
      }

      if ($eventLog.Errors.Count -gt 0) {
         return New-vlResultObject -result $lapsLog -score 8 -riskScore $riskScore
      }
      elseif ($eventLog.Warnings.Count -gt 0) {
         return New-vlResultObject -result $lapsLog -score 9 -riskScore $riskScore
      }

      return New-vlResultObject -result $lapsLog -score 10 -riskScore $riskScore
   }
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-vlLAPSSettings {
   <#
    .SYNOPSIS
        Function that returns the LAPS settings.
    .DESCRIPTION
        Function that returns the LAPS settings.
    .LINK
        https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings
    .OUTPUTS
        If the LAPS is enabled, the script will return a vlResultObject indicating the LAPS settings.
    .EXAMPLE
        Get-vlLAPSSettings
    #>

   $riskScore = 40

   try {
      <#
      https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings

      LAPS CSP	HKLM\Software\Microsoft\Policies\LAPS
      LAPS Group Policy	HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS
      LAPS Local Configuration	HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config
      Legacy Microsoft LAPS	HKLM\Software\Policies\Microsoft Services\AdmPwd

      Windows LAPS queries all known registry key policy roots, starting at the top and moving down.
      If no settings are found under a root, that root is skipped and the query proceeds to the next root.
      When a root that has at least one explicitly defined setting is found, that root is used as the active policy.
      If the chosen root is missing any settings, the settings are assigned their default values.
      #>

      $hkeys = @{
         'LAPS CSP'                 = 'Software\Microsoft\Policies\LAPS'
         'LAPS Group Policy'        = 'Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
         'LAPS Local Configuration' = 'Software\Microsoft\Windows\CurrentVersion\LAPS\Config'
         'Legacy Microsoft LAPS'    = 'Software\Policies\Microsoft Services\AdmPwd'
      }

      $complexityArray = @(
         'A-Z',
         'A-Z + a-z',
         'A-Z + a-z + 0-9',
         'A-Z + a-z + 0-9 + special chars'
      )

      foreach ($hkey in $hkeys.GetEnumerator()) {

         # check if $hkey exists and contains any values
         $lapsRegSettings = Get-vlRegistryKeyValues -Hive "HKLM" -Path $hkey.Value

         if ($null -ne $lapsRegSettings -and $lapsRegSettings.PSObject.Properties.Count -ge 0) {
            $lapsSettings = [PSCustomObject]@{
               Mode               = $hkey.Key
               Enabled            = $true
               PasswordComplexity = if ( $lapsRegSettings.PSObject.Properties.Name -contains "PasswordComplexity" -and $lapsRegSettings.PasswordComplexity -ge 1 -and $lapsRegSettings.PasswordComplexity -le 4) { $complexityArray[$lapsRegSettings.PasswordComplexity - 1] } else { $null }
               PasswordLength     = if ( $lapsRegSettings.PSObject.Properties.Name -contains "PasswordLength") { $lapsRegSettings.PasswordLength } else { $null }
            }

            if ($hkey.Key -eq "Legacy Microsoft LAPS") {
               $lapsSettings.Enabled = if ( $lapsRegSettings.PSObject.Properties.Name -contains "AdmPwdEnabled") { $lapsRegSettings.AdmPwdEnabled -eq 1 } else { $false }

               if ($lapsSettings.Enabled -eq $true) {
                  return New-vlResultObject -result $lapsSettings -score 10 -riskScore $riskScore
               }
               else {
                  return New-vlResultObject -result $lapsSettings -score 6 -riskScore $riskScore
               }
            }

            return New-vlResultObject -result $lapsSettings -score 10 -riskScore $riskScore
         }
      }

      $lapsSettings =
      [PSCustomObject]@{
         Enabled = $false
      }
      return New-vlResultObject -result $lapsSettings -score 6 -riskScore $riskScore
   }
   catch {
      return New-vlErrorObject-context $_
   }
}

function Get-vlMachineAvailableFactors () {
   <#
    .SYNOPSIS
        Function that returns the Machine Factors, that can be used.
    .DESCRIPTION
        Function that returns the Machine Factors, that can be used.
    .LINK
        https://uberagent.com
    .OUTPUTS
        Retruns if the Machine Factors are available and the name of the factors
    .NOTES
        Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\SensorInfo
    .EXAMPLE
        Get-vlMachineAvailableFactors
    #>

   $winBioUsed = $false
   $winBioAccountInfoPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\AccountInfo"
   $winBioSensorInfoBasePath = "SOFTWARE\Microsoft\Windows\CurrentVersion\WinBio\SensorInfo"

   if (-not (Test-Path -Path ("HKLM:\" + $winBioSensorInfoBasePath ))) {
      return [PSCustomObject]@{
         WinBioAvailable        = $false
         WinBioUsed             = $false
         WinBioAvailableFactors = @()
      }
   }

   $bioUsers = Get-vlRegSubkeys -Hive "HKLM" -Path $winBioAccountInfoPath

   foreach ($bioUser in $bioUsers) {
      $bioUserValues = Get-vlRegValue -Hive "HKLM" -Path ($winBioAccountInfoPath + "\" + $bioUser.PSChildName) -Value "EnrolledFactors"

      if ($bioUserValues -and $bioUserValues -gt 0) {
         $winBioUsed = $true
      }
   }

   $availableFactors = Get-vlRegValue -Hive "HKLM" -Path $winBioSensorInfoBasePath -Value "AvailableFactors"

   $availableFac = @()
   foreach ($factor in $WinBioStatus.GetEnumerator()) {
      if ($availableFactors -and $availableFactors -band $factor.value) {
         $availableFac += $factor.key
      }
   }

   return [PSCustomObject]@{
      WinBioAvailable        = $true
      WinBioUsed             = $winBioUsed
      WinBioAvailableFactors = $availableFac
   }
}

function Get-vlWindowsHelloStatusLocalMachine () {
   <#
    .SYNOPSIS
        Function that checks if Windows Hello is enabled.
    .DESCRIPTION
        Function that checks if Windows Hello is enabled.
    .LINK
        https://uberagent.com
    .OUTPUTS
        If the Windows Hello is enabled, the script will return a vlResultObject with the WindowsHelloEnabled property set to true.
        If the Windows Hello is disabled, the script will return a vlResultObject with the WindowsHelloEnabled property set to false.
    .EXAMPLE
        Get-vlWindowsHelloStatusLocalMachine
    #>

   $riskScore = 40

   try {
      $factors = Get-vlMachineAvailableFactors

      if ($factors.WinBioAvailable -and $factors.WinBioUsed) {
         return New-vlResultObject -result $factors -score 10 -riskScore $riskScore
      }
      else {
         return New-vlResultObject -result $factors -score 7 -riskScore $riskScore
      }
   }
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-vlLocalUsersAndGroupsCheck {
   <#
    .SYNOPSIS
        Function that performs the LocalUsersAndGroups check and returns the result to Citrix Experience Insights.
    .DESCRIPTION
        Function that performs the LocalUsersAndGroups check and returns the result to Citrix Experience Insights.
    .NOTES
        The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
        Specific tests can be called by passing the test name as a parameter to the script args.
        Passing no parameters or -all to the script will run all tests.
    .LINK
        https://uberagent.com
    .OUTPUTS
        A list with vlResultObject | vlErrorObject [psobject] containing the test results
    .EXAMPLE
        Get-vlLocalUsersAndGroupsCheck -uacState -lapsState -secrets
    #>

   $params = if ($global:args) { $global:args } else { "all" }
   $params = $params | ForEach-Object { $_.ToLower() }

   $Output = @()

   if ($params.Contains("all") -or $params.Contains("LUMUac")) {
      $uac = Get-vlUACState
      $Output += [PSCustomObject]@{
         Name         = "LUMUac"
         DisplayName  = "User account control"
         Description  = "This test examines the status of User Account Control (UAC). User Account Control prevents unauthorized installation of new software, changes to system settings, or system files by requiring administrator-level privileges."
         Score        = $uac.Score
         ResultData   = $uac.Result
         RiskScore    = $uac.RiskScore
         ErrorCode    = $uac.ErrorCode
         ErrorMessage = $uac.ErrorMessage
      }
   }
   if ($params.Contains("all") -or $params.Contains("LUMLaps")) {
      $laps = Get-vlLAPSSettings
      $Output += [PSCustomObject]@{
         Name         = "LUMLaps"
         DisplayName  = "Local administrator password solution - Settings"
         Description  = "This test verifies that the Local Administrator Password Solution (LAPS) is set up and enabled. LAPS is a Windows feature that automatically manages and backs up the password of a local administrator account on devices connected to Azure Active Directory or Windows Server Active Directory."
         Score        = $laps.Score
         ResultData   = $laps.Result
         RiskScore    = $laps.RiskScore
         ErrorCode    = $laps.ErrorCode
         ErrorMessage = $laps.ErrorMessage
      }

      $lapsJSon = $laps.Result | ConvertFrom-Json

      if ( $lapsJSon.Enabled -eq $true -and ($params.Contains("all") -or $params.Contains("LUMLapsEventLog"))) {
         $lapsLog = Get-vlLAPSTestEventLog

         $Output += [PSCustomObject]@{
            Name         = "LUMLapsEventLog"
            DisplayName  = "Local administrator password solution - Event log"
            Description  = "This test scans the event log for any Local Administrator Password Solution (LAPS) related errors and warnings. LAPS is a Windows feature that automatically manages and backs up the password of a local administrator account on devices connected to Azure Active Directory or Windows Server Active Directory."
            Score        = $lapsLog.Score
            ResultData   = $lapsLog.Result
            RiskScore    = $lapsLog.RiskScore
            ErrorCode    = $lapsLog.ErrorCode
            ErrorMessage = $lapsLog.ErrorMessage
         }
      }
   }
   if ($params.Contains("all") -or $params.Contains("LUMWinBio")) {
      $windowsHelloStatus = Get-vlWindowsHelloStatusLocalMachine
      $Output += [PSCustomObject]@{
         Name         = "LUMWinBio"
         DisplayName  = "Windows Hello/biometrics - Machine"
         Description  = "This test determines if Windows Hello is enabled and which factors are available. Windows Hello enables authentication using biometric factors such as fingerprint, facial or iris recognition additionally to PIN codes."
         Score        = $windowsHelloStatus.Score
         ResultData   = $windowsHelloStatus.Result
         RiskScore    = $windowsHelloStatus.RiskScore
         ErrorCode    = $windowsHelloStatus.ErrorCode
         ErrorMessage = $windowsHelloStatus.ErrorMessage
      }
   }
   return $output
}

try {
   [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}
catch {
   $OutputEncoding = [System.Text.Encoding]::UTF8
}


# Entrypoint of the script call the check function and convert the result to JSON
Write-Output (Get-vlLocalUsersAndGroupsCheck | ConvertTo-Json -Compress)

# SIG # Begin signature block
# MIIoxgYJKoZIhvcNAQcCoIIotzCCKLMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB+tzl1UBLbUTnv
# zi5gwkkfG4Ct/diO6z6mVOANisA7GaCCDbkwggawMIIEmKADAgECAhAIrUCyYNKc
# TJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0z
# NjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0
# JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJr
# Q5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhF
# LqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+F
# LEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh
# 3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJ
# wZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQay
# g9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbI
# YViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchAp
# QfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRro
# OBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IB
# WTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+
# YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAED
# MAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql
# +Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFF
# UP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1h
# mYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3Ryw
# YFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5Ubdld
# AhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw
# 8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnP
# LqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatE
# QOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bn
# KD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQji
# WQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbq
# yK+p/pQd52MbOoZWeE4wggcBMIIE6aADAgECAhAP47Ki0imEqa3MI1tkbzHeMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjYwNTE0MDAwMDAwWhcNMjcwNTEz
# MjM1OTU5WjCBiDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0Zsb3JpZGExGDAWBgNV
# BAcTD0ZvcnQgTGF1ZGVyZGFsZTEdMBsGA1UEChMUQ2l0cml4IFN5c3RlbXMsIElu
# Yy4xDzANBgNVBAsTBkNpdHJpeDEdMBsGA1UEAxMUQ2l0cml4IFN5c3RlbXMsIElu
# Yy4wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDWvV/OH9/sYPfeiQAh
# eDNU6vKMQlp+6UDbpI629yfSkJFN8YHaKLwTBL7o8njOMKdbFOSC1LwWh04pGV0Z
# DoCwXTOmzvXm10J2D6a6FKt6mZSKpwzI9RHbU8r26rhU0YU3ikAVDjTwHj44QHeL
# 0znzOlAAxzglEvpCOjHmluKMmaGqFtMdshrC4JPHjSS3Ksy2CSt5zNV88eEoU51v
# MsV/mN7wwnS8pfvFX+1J0dbHxcizG8HAeP66DG9Sedi1Tzm9beBcgYR4IMLXEe6B
# ac2y1AhOc+qFAWhj7ayMy3Mhxk4EZbXVGDP3n+GjiBUnWEfFu3DSucBi6uID+d/r
# 1mkT00hADT/aC2eT/Q/DEm+zVEuOQduX0YmBSe3anfTVLcDieVw/pI60U/e/4L8p
# JDgDwDziLIFKogXRtQYnV9fn3PqMisEigo22HCU6ieJq2lkPb6AZhdSjgFEz242t
# uDwfstvbn6tiZUXa6HggVbPZVZXTUFKhBsC8WE7VdNVd2HECAwEAAaOCAgMwggH/
# MB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBRbcl4N
# sqHrugpyuVoA9I4eak86SjA+BgNVHSAENzA1MDMGBmeBDAEEATApMCcGCCsGAQUF
# BwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0PAQH/BAQDAgeA
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+GTWh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5n
# UlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3JsNC5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEz
# ODQyMDIxQ0ExLmNybDCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0
# MDk2U0hBMzg0MjAyMUNBMS5jcnQwCQYDVR0TBAIwADANBgkqhkiG9w0BAQsFAAOC
# AgEAba1In5WIqLU6LE1uLOVwCllMLOAVeWUb1wPJ2fugaH891Oy42VUvND/cxd2L
# Fl8aIBEn9snnxJpFlyoLG3eNZYPLvSHgFuWlBlHkp4cwL4hihgjXQvRdhKFINE87
# 7RCLg9aNh8LzxNs9ciMM/sho/+dv2cojZPBqCZBxL9Fk+irRkZNUwgtR6/F2ijMu
# BnbGI9M24J6QqGj81wOSIrldQ/6hFGhDG0h58VZ+s8W0Bl4gf6P7lxZb8t0biBD5
# uijZxf9Ny4grACnIY9YQQRAH9k4QcBofNvro4U20OQIjRP7i7acQ5+SyFBzIn5Ko
# MkspCGz8VkvefMDgj91dXJSBBZlWIPRkRRETTbZhq83zjZNeupLCDMGJg1hUvtOu
# Is+Wn3+1/K5jrBK9dW3BukExwO/HpumRJ5T3gCPeCz8015XXsvixZSJPW91U1zwt
# +srK0tvNKBIPGSaVfJkLsf5iKeTQVCZtR8Y17ZNX0rLU3DeBytc3d3jfafqeVlih
# YrCTmQp9FiL9gzlr4OxVghgP6mCki7B/0SJXGg+tR1AOp12T5h/FSelSoPgECFhn
# aWQct57F/q6gSrTxVxwm1/xjb2EehEriH0H+TSJ+Jhu+z4y/Slc3qzt3haC8GjEU
# zgOyna7wokqBLvdrSiTF2of1k3HQUFUymRr0h3qjKOXx2cUxghpjMIIaXwIBATB9
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTECEA/jsqLSKYSprcwjW2RvMd4wDQYJYIZIAWUDBAIBBQCggb4w
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKnx2NFKfdi3k33FxCMKIpMBLrPtyn/E
# 2A9Z5zeWYZc8MFIGCisGAQQBgjcCAQwxRDBCoECAPgBMAG8AYwBhAGwAVQBzAGUA
# cgBzAEEAbgBkAEcAcgBvAHUAcABzAC0ATQBhAGMAaABpAG4AZQAuAHAAcwAxMA0G
# CSqGSIb3DQEBAQUABIIBgF7jBXlt33j233LHP1SXFMEOMkaPgvtdmIyAHxv1dDCL
# shLJRNVLw5n9x2UdFPpqgr7oYvAWseCHYYQRo9RHAjjGHaCwFqlDriSx1NH0Ftkg
# HwfLOrnFb97xx6sTezYY8EYNkN019j2G+OItIaNh6XrNy4aZ5sCCmB3vmSTWo7en
# 2Xu87k+UIszNZu0YGxvDCVjir24Ti25xcj6ALdgzasQZ79aD33/fQnPdN03ZcGW/
# 6EFHhpiY2NJ+Cosa3AeD2f8DHdylgV+nMFYemzYgpHO5osrv0CuuE5wGj+cpBWg5
# l7vu0lDpc3oIXRre5Kp/P4uHbZm3C1geZGJ7ZGAxGxQ4uKWoPMeoG+cN+fqv5NwF
# fu6d2SABHhEUfnCgYsQuSd6016oXOcij/NeZFIS2bSt11RDLW6ECB5UYGVMXYtWq
# rxOlfbmilx/THFIR8IJHgfA3UEZ2XsloGY/gYqHS05fb2FHG71TRNoU6YDYxHMlf
# P1g0oa4b/dvtLdLnoD6Xs6GCF3YwghdyBgorBgEEAYI3AwMBMYIXYjCCF14GCSqG
# SIb3DQEHAqCCF08wghdLAgEDMQ8wDQYJYIZIAWUDBAIBBQAwdwYLKoZIhvcNAQkQ
# AQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCCOXeiyuDiZ
# pmEsucTg96s3qH5rHH1P1IYVhD1hoKWZ2AIQMHaXX044LET2/tTNbLEFQBgPMjAy
# NjEwMDExMDM5MzJaoIITOjCCBu0wggTVoAMCAQICEAhP3DNPfkVO28MPj/mSGDUw
# DQYJKoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0
# LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGlu
# ZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTAeFw0yNjA4MDUwMDAwMDBaFw0zNzEx
# MDQyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjE7MDkGA1UEAxMyRGlnaUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJl
# c3BvbmRlciAyMDI2IDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2
# e6byyf7NSvjUm0xls/04xjD4fAkOkbnGQi7+Wpx81iYxfzViaxSIctuH3KSl5YEY
# pMuFgGsA31N2D9ATMbfZdw5uaAhuWevQKhDdZIB4NnqcfpfpWQXJiQnDdAElETC+
# bhSEvNLGbA8DtwUpFMQ4yyYQSPqomT92osQAv6hBi47ATZS6JfVWe6XxhF4jJZ3i
# SAuf2Cros1czRSmWRHqMv9AfGZvp8ygYElhudpQjtcPpwoOl6QrZJUyV3iINvN4c
# O05prGV0fkjG426xDr2d3z9lcSIHkdvGPdGUrXdxfVbgOUVcp2/8ISEzwKPW++Wa
# +E2ujI91EZtukGWDJ/xZ27k3oHKEXBRGfRTqjOU+jE3ba/5++JSE/7oNHnjs5mek
# ExYN96LV/mxUbCKJb8pBNY4r3uD7hEmk/M81XhVgwDA7aMzYC3LZBg9WY5BMmbSa
# y5ecmtJuXaB/0nKWmQmVZeqTVDgsmzHP5MQuhAJkiWNuC9MmCg9TZHXbJ2/yLVSo
# v9p16UDTLtT0+aa1vN71fHeu1qMLlLNB3WOB/ADCxr3S/1hxI92Z6jKgEED/btwI
# vbfuXkNNhg8MtDg43c4tMZae9FvqMOt/9PvmAxF9TNIsIFB8G6yb36ZJZGUL8N/p
# L971DyLXcK6HM5PYnH5X+eVtczhCgHCVQCF6XDAlPQIDAQABo4IBlTCCAZEwDAYD
# VR0TAQH/BAIwADAdBgNVHQ4EFgQUFMljijAu1Er7bpTz5uNAfvXszeIwHwYDVR0j
# BBgwFoAU729TSunkBnx6yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1Ud
# JQEB/wQMMAoGCCsGAQUFBwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcw
# AYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8v
# Y2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBp
# bmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0
# cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1w
# aW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQC
# MAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAjcU6YR6dUgrfmawJgH59
# KECxa9Ji8sEi2g10CBDaMiqsaxWyW5cwlT/6ZF5sFznazqVsoC85U9dqLOYqQwst
# +UQQoNlDHgKRLa3xoc+OReFreFhnTXSG0Vrd2E2CZqUfm+5a+He1MJ/h+tNLuA+0
# Zzhn/Fo+FDYAHWZHx4R79ZsfRFYe9UiXpXBDf6DkUo183Y38NYmR/XfDYf7YZ+oR
# 9t3flbDwK+hgGMs0gNNp1w9Z2CyOyI5or/sSwomAuNQ0hWC9xoU4stD8aWsD7Rkc
# mgVRs6vlIk3zPKQ+ylcheWkMlj+CoVRlFE55pv0ZWCaFt04lwP/rdGHE9qEVQZty
# RE42ox7oNgC/r+Y4bSlZ3dw9K2x1xLtu6PkPKeLBFjzKigwfqm3Hm+k/+lnME8F5
# kPZTgiy2HLEHklpryqs6QHnPXrRNeIzkAMyylnRN8P0wmirS0WkU+ywpEWFZ4QNg
# +9xS43tTuW9x0eXh7NDc1P/sV+zWxHXKH8tFt1ncHdVzqrZaYPyYMLSn2TOXajve
# JW1L3joiQSPsWRGxkbDDW15jERFE4LvjnGu2O9zD1nLJSMdlYZEikl4w2w+q4IN/
# R+TIe0H4ngCI1moJCTbevGH4punIxM1Uoi0nmX3ZK+XbRT01uowE5ViXWHng0Rgs
# mrX/EdYUo80r3TfMlkD0/YMwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmG
# MA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5
# NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8G
# A1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBT
# SEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0
# eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+Ruw
# OnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4B
# t0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1U
# kxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTca
# arps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zb
# CclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnG
# pTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/
# AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v
# 5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoi
# wOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm
# 2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYD
# VR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04w
# HwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGG
# MBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcw
# AYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8v
# Y2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBD
# BgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgB
# hv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Q
# h8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3
# YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQ
# wr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/
# wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81
# hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00
# TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNj
# qFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0
# cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9
# sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0
# LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2
# tszWkPZPubdcMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG
# 9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkw
# FwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1
# cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBi
# MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
# d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3Qg
# RzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAi
# MGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnny
# yhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE
# 5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm
# 7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5
# w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsD
# dV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1Z
# XUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS0
# 0mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hk
# pjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m8
# 00ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+i
# sX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB
# /zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReui
# r/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0w
# azAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUF
# BzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVk
# SURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAG
# BgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9
# mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxS
# A8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/
# 6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSM
# b++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt
# 9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMYIDfDCC
# A3gCAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4x
# QTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQw
# OTYgU0hBMjU2IDIwMjUgQ0ExAhAIT9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQC
# AQUAoIHRMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUx
# DxcNMjYxMDAxMTAzOTMyWjArBgsqhkiG9w0BCRACDDEcMBowGDAWBBRR2avaA0lz
# 2E9CZqykgkjms2nEOTAvBgkqhkiG9w0BCQQxIgQg3/4AuVUDQ4tsH9krRfGewgrG
# 4NTcEqsC4PRx1toCCLgwNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgLaCdp/QTH5/n
# LbbF5unJZWdVrwQ/HqdCzA0hIOFB6/wwDQYJKoZIhvcNAQEBBQAEggIAE2S8YT+b
# HlVmr5bUyGPC2QjIkRRvs+Z9qkoVdyszOCJ5S+zIZ8nl+2zDhg3SsVHtCJR4ZUqq
# aDcdn/FhUF1t4B/tovaCWw97JuA9BSmLy0GVvRgO5Eajd/ZDiMmGLorg/5JvzPwA
# d0pcYE/r4u0mclC3xNvnQ0eLJIj3rRBYZ5yj/YQW/c/HaFK94BCuNl+HpBCSbd+6
# QTrtf7CMAOUT43ZOzrMEEMLhdWOaxlnzFV8QQTIT8os82xbRkp/PaAzeY58OHnO7
# Cc3W2UgDvQBwEZ6Hd8zeQx4SJmfjJLuudCH46SuzPzJwhPrXP0Jn7L+J/013vd+w
# rQR1kvmjzUuBPvRVydnI1ByOSS2TYMuiiArT8lfGBC2i7jXoTvaKpPE7ZVAPr+g0
# cinPp8oF11OPiX4hk/nufEVwEClF4cRetC9hcmJZJJqPANdJas9duXJtTqZYPxUI
# Rmttjxr9mmr7Q0emZH/dmgIj8jHstcyAp4tcRWUg2Att8aEkg00dajKvEFJpM9wB
# A8Ko8k8b7uGuQml28zzofgx+F39jJtCHQ4yWPU95OM3CjamMEWIMtJdkCCqqWs/3
# mDa2OrucJu5Gv/aqgX/JJkGwBrQwVKd5CaaBXL8aCyMr+fMwQVVFGqdFbrYtKDDu
# F2ObiNUeUAn33SL0T1gtHMI/LOEhfqAkc2I=
# SIG # End signature block
