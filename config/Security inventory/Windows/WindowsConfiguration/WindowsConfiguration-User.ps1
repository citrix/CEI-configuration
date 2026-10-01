
. $PSScriptRoot\..\Shared\Helper.ps1 -Force
. $PSScriptRoot\..\Shared\AppLinkHelper.ps1 -Force

function Get-CheckHTAEnabled {
   <#
    .SYNOPSIS
        Checks whether mshta.exe can be executed or is blocked by a tool such as AppLocker.
    .DESCRIPTION
        Checks whether mshta.exe can be executed or is blocked by a tool such as AppLocker.
    .LINK
        https://uberagent.com
    .OUTPUTS
        PSCustomObject
        enabled: true if enabled, false if not
    .EXAMPLE
        Get-CheckHTAEnabled
    #>

   try {
      $startProc = ""
      $score = 10
      $riskScore = 80

      # Get Windows System directory
      $systemDirectory = [System.Environment]::SystemDirectory

      # Join the path to mshta.exe
      $mshtaPath = Join-Path -Path $systemDirectory -ChildPath "mshta.exe"

      # Check if mshta.exe exists and is blocked
      $htaRunBlocked = Test-vlBlockedProgram -ProgramPath $mshtaPath

      $defaultLink = $true
      $startCmd = [AppLinkHelper]::AssocQueryString(".hta")

      if ($null -ne $startCmd -and $startCmd -ne "") {
         $startProc = (Split-Path $startCmd -Leaf)

         # check if $startProc contains space and if so, get the first part
         if ($startProc.Contains(" ")) {
            $startProc = $startProc.Split(" ")[0]
         }
      }
      else {
         $startProc = $null
      }

      # check if $status contains "mshta.exe"

      if ($startCmd.Contains("mshta.exe")) {
         $defaultLink = $true
      }
      else {
         $defaultLink = $false
      }

      if ($htaRunBlocked.FileExists -and $htaRunBlocked.IsBlocked -ne $true) {
         $score -= 7
      }

      if ($defaultLink -eq $true) {
         $score -= 3
      }

      $result = [PSCustomObject]@{
         MshtaExists = $htaRunBlocked.FileExists
         RunBlocked  = $htaRunBlocked.IsBlocked
         OpenWith    = $startProc
         DefaultLink = $defaultLink
      }

      return New-vlResultObject -result $result -score $score -riskScore $riskScore
   }
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-vlCheckWindowsRecallStatusCU {
   <#
    .SYNOPSIS
        Checks if Windows Recall is enabled for the current user.
    .DESCRIPTION
        Windows Recall is a feature for Copilot+ PCs that creates a timeline of user activity by taking snapshots of the desktop and processing them using AI.

        https://support.microsoft.com/en-us/windows/retrace-your-steps-with-recall-aa03f8a0-a78b-4b3e-b0a1-2eb8ac48701c
        https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-windowsai#disableaidataanalysis
    .OUTPUTS
         PSCustomObject
         enabled: true if enabled, false if not
    .EXAMPLE
         Get-vlCheckWindowsRecallStatusCU
    #>

   try {
      <#
         0 (Default)	Enable saving Snapshots for Windows.
         1	Disable saving Snapshots for Windows
      #>
      $riskScore = 50

      if (Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI") {
         $value = Get-vlRegValue -Hive "HKCU" -Path "SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Value "DisableAIDataAnalysis"

         if ($null -eq $value -or $value -eq 0) {
            $result = [PSCustomObject]@{
               Enabled = $true
            }

            return New-vlResultObject -result $result -score 0 -riskScore $riskScore
         }
         else {
            $result = [PSCustomObject]@{
               Enabled = $false
            }
            return New-vlResultObject -result $result -score 10 -riskScore $riskScore
         }
      }

      if (Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\WindowsAI") {
         $value = Get-vlRegValue -Hive "HKCU" -Path "SOFTWARE\Microsoft\Windows\WindowsAI" -Value "DisableAIDataAnalysis"

         if ($null -eq $value -or $value -eq 0) {
            $result = [PSCustomObject]@{
               Enabled = $true
            }

            return New-vlResultObject -result $result -score 0 -riskScore $riskScore
         }
         else {
            $result = [PSCustomObject]@{
               Enabled = $false
            }
            return New-vlResultObject -result $result -score 10 -riskScore $riskScore
         }
      }

      $result = [PSCustomObject]@{
         Enabled = $false
      }

      return New-vlResultObject -result $result -score 10 -riskScore $riskScore
   }
   catch {
      return New-vlErrorObject -context $_
   }
}

function Get-WindowsConfigurationCheck {
   #set $params to $global:args or if empty default "all"
   $params = if ($global:args) { $global:args } else { "all" }
   $Output = @()


   # disabled for now - since we would trigger a lot of false positives
   if ($params.Contains("all") -or $params.Contains("WCHta")) {
      $checkHtaEnabled = Get-CheckHTAEnabled
      $Output += [PSCustomObject]@{
         Name         = "WCHta"
         DisplayName  = "WindowsConfiguration HTA"
         Description  = "This test validates whether HTA (HTML Application) execution is enabled for the current user. HTA files can be used to execute malicious scripts or actions if not properly controlled."
         Score        = $checkHtaEnabled.Score
         ResultData   = $checkHtaEnabled.Result
         RiskScore    = $checkHtaEnabled.RiskScore
         ErrorCode    = $checkHtaEnabled.ErrorCode
         ErrorMessage = $checkHtaEnabled.ErrorMessage
      }
   }

   if ($params.Contains("all") -or $params.Contains("WCCURecallStatus")) {
      $checkWindowsRecallStatus = Get-vlCheckWindowsRecallStatusCU
      $Output += [PSCustomObject]@{
         Name         = "WCCURecallStatus"
         DisplayName  = "WindowsConfiguration Recall status - User"
         Description  = "[Experimental] This test determines the status of Windows Recall, a feature introduced with Windows 11 24H2 that creates a timeline of user activity by capturing desktop screenshots. Attackers could potentially exploit the collected data by extracting sensitive information."
         Score        = $checkWindowsRecallStatus.Score
         ResultData   = $checkWindowsRecallStatus.Result
         RiskScore    = $checkWindowsRecallStatus.RiskScore
         ErrorCode    = $checkWindowsRecallStatus.ErrorCode
         ErrorMessage = $checkWindowsRecallStatus.ErrorMessage
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


Write-Output (Get-WindowsConfigurationCheck | ConvertTo-Json -Compress)

# SIG # Begin signature block
# MIIowwYJKoZIhvcNAQcCoIIotDCCKLACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDbnVBSeHAUfDTh
# 2fqSKB4Tih7kH8OPdL12PY/d3t2Do6CCDbkwggawMIIEmKADAgECAhAIrUCyYNKc
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
# zgOyna7wokqBLvdrSiTF2of1k3HQUFUymRr0h3qjKOXx2cUxghpgMIIaXAIBATB9
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTECEA/jsqLSKYSprcwjW2RvMd4wDQYJYIZIAWUDBAIBBQCggbow
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIKtCBqCHA9dSj7PbzYdRkhjxOL19rptY
# 5Sn4nfkCdYQIME4GCisGAQQBgjcCAQwxQDA+oDyAOgBXAGkAbgBkAG8AdwBzAEMA
# bwBuAGYAaQBnAHUAcgBhAHQAaQBvAG4ALQBVAHMAZQByAC4AcABzADEwDQYJKoZI
# hvcNAQEBBQAEggGAoYQv+LHQExaN4Nm/SqCPfxEsXHPcNn1Ls1viRuhlq0TsfZ4y
# qpocllLEpIDA5l3KbdNZtqt77PsGuhNRHyJ3ubP901JgHB03ZmeqYE6eDCAipevq
# Lmq//oryNYVHr7kzfBGU5WQq+lDJN30TxkINaroDdkHmU+aVeGfqrLeJy3TOrv2t
# hpixQEon0kzP3ipZM9VNPBHhXBk03HDL20dhLw+tqc6/DsT6CpEw+QdcpVj7f3f9
# 06oB/dQjn49OD8QGcv1WxMtRNPsP/g1IeDLXe9KS9u9cGZou2WkJdTJA87fSD2Q1
# OAa0laTBne2imTMBCBjc7bx16KdD8Gg0e8ofgtMvsN45Do+YVU6lYEjU6b5IL1r2
# JLts2cLJ7ofNQBrl1EkvknsKYv6aGvXVKdb83Uyletc1UZYKvvzDPOAAhjXIBVdZ
# jfRHmNPP+77bcVAfcC0Ny/f2Bmw6dFRDzi/9dFaO9jh/UQ0WbaNN0K1qKn+Xw7EG
# XpwvvIPb4miFddjroYIXdzCCF3MGCisGAQQBgjcDAwExghdjMIIXXwYJKoZIhvcN
# AQcCoIIXUDCCF0wCAQMxDzANBglghkgBZQMEAgEFADB4BgsqhkiG9w0BCRABBKBp
# BGcwZQIBAQYJYIZIAYb9bAcBMDEwDQYJYIZIAWUDBAIBBQAEIBLOsDm7vhr3D25x
# CDLuyNRf12e5ZtuI3mvMJOvpbAsQAhEAhwRqcCbwQngox3gmxN0hNBgPMjAyNjEw
# MDExMDM5NTFaoIITOjCCBu0wggTVoAMCAQICEAhP3DNPfkVO28MPj/mSGDUwDQYJ
# KoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBS
# U0E0MDk2IFNIQTI1NiAyMDI1IENBMTAeFw0yNjA4MDUwMDAwMDBaFw0zNzExMDQy
# MzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7
# MDkGA1UEAxMyRGlnaUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3Bv
# bmRlciAyMDI2IDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC2e6by
# yf7NSvjUm0xls/04xjD4fAkOkbnGQi7+Wpx81iYxfzViaxSIctuH3KSl5YEYpMuF
# gGsA31N2D9ATMbfZdw5uaAhuWevQKhDdZIB4NnqcfpfpWQXJiQnDdAElETC+bhSE
# vNLGbA8DtwUpFMQ4yyYQSPqomT92osQAv6hBi47ATZS6JfVWe6XxhF4jJZ3iSAuf
# 2Cros1czRSmWRHqMv9AfGZvp8ygYElhudpQjtcPpwoOl6QrZJUyV3iINvN4cO05p
# rGV0fkjG426xDr2d3z9lcSIHkdvGPdGUrXdxfVbgOUVcp2/8ISEzwKPW++Wa+E2u
# jI91EZtukGWDJ/xZ27k3oHKEXBRGfRTqjOU+jE3ba/5++JSE/7oNHnjs5mekExYN
# 96LV/mxUbCKJb8pBNY4r3uD7hEmk/M81XhVgwDA7aMzYC3LZBg9WY5BMmbSay5ec
# mtJuXaB/0nKWmQmVZeqTVDgsmzHP5MQuhAJkiWNuC9MmCg9TZHXbJ2/yLVSov9p1
# 6UDTLtT0+aa1vN71fHeu1qMLlLNB3WOB/ADCxr3S/1hxI92Z6jKgEED/btwIvbfu
# XkNNhg8MtDg43c4tMZae9FvqMOt/9PvmAxF9TNIsIFB8G6yb36ZJZGUL8N/pL971
# DyLXcK6HM5PYnH5X+eVtczhCgHCVQCF6XDAlPQIDAQABo4IBlTCCAZEwDAYDVR0T
# AQH/BAIwADAdBgNVHQ4EFgQUFMljijAu1Er7bpTz5uNAfvXszeIwHwYDVR0jBBgw
# FoAU729TSunkBnx6yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB
# /wQMMAoGCCsGAQUFBwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdS
# U0E0MDk2U0hBMjU2MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDov
# L2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5n
# UlNBNDA5NlNIQTI1NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsG
# CWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAjcU6YR6dUgrfmawJgH59KECx
# a9Ji8sEi2g10CBDaMiqsaxWyW5cwlT/6ZF5sFznazqVsoC85U9dqLOYqQwst+UQQ
# oNlDHgKRLa3xoc+OReFreFhnTXSG0Vrd2E2CZqUfm+5a+He1MJ/h+tNLuA+0Zzhn
# /Fo+FDYAHWZHx4R79ZsfRFYe9UiXpXBDf6DkUo183Y38NYmR/XfDYf7YZ+oR9t3f
# lbDwK+hgGMs0gNNp1w9Z2CyOyI5or/sSwomAuNQ0hWC9xoU4stD8aWsD7RkcmgVR
# s6vlIk3zPKQ+ylcheWkMlj+CoVRlFE55pv0ZWCaFt04lwP/rdGHE9qEVQZtyRE42
# ox7oNgC/r+Y4bSlZ3dw9K2x1xLtu6PkPKeLBFjzKigwfqm3Hm+k/+lnME8F5kPZT
# giy2HLEHklpryqs6QHnPXrRNeIzkAMyylnRN8P0wmirS0WkU+ywpEWFZ4QNg+9xS
# 43tTuW9x0eXh7NDc1P/sV+zWxHXKH8tFt1ncHdVzqrZaYPyYMLSn2TOXajveJW1L
# 3joiQSPsWRGxkbDDW15jERFE4LvjnGu2O9zD1nLJSMdlYZEikl4w2w+q4IN/R+TI
# e0H4ngCI1moJCTbevGH4punIxM1Uoi0nmX3ZK+XbRT01uowE5ViXWHng0RgsmrX/
# EdYUo80r3TfMlkD0/YMwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0G
# CSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJ
# bmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0
# IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTla
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEy
# NTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHT
# CphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPh
# of6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mA
# xAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBv
# MgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps
# 0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF
# 83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXi
# UOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOM
# CZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydP
# pOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrU
# G2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+
# sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0T
# AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYD
# VR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMG
# A1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNV
# HR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1s
# BwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WI
# GjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+
# IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8M
# yb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2
# th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjaj
# V/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2
# Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFze
# GxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG
# 7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+N
# Jpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckT
# etiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszW
# kPZPubdcMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0B
# AQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz
# 7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS
# 5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7
# bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfI
# SKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jH
# trHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14
# Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2
# h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt
# 6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPR
# iQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ER
# ElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4K
# Jpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAd
# BgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SS
# y4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAC
# hjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRV
# HSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyh
# hyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO
# 0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo
# 8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++h
# UD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5x
# aiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMYIDfDCCA3gC
# AQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/
# BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYg
# U0hBMjU2IDIwMjUgQ0ExAhAIT9wzT35FTtvDD4/5khg1MA0GCWCGSAFlAwQCAQUA
# oIHRMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAcBgkqhkiG9w0BCQUxDxcN
# MjYxMDAxMTAzOTUxWjArBgsqhkiG9w0BCRACDDEcMBowGDAWBBRR2avaA0lz2E9C
# Zqykgkjms2nEOTAvBgkqhkiG9w0BCQQxIgQgm17af9btMsagiVJCFQZrV73WEddC
# 9YCYrCg3aV5bkMkwNwYLKoZIhvcNAQkQAi8xKDAmMCQwIgQgLaCdp/QTH5/nLbbF
# 5unJZWdVrwQ/HqdCzA0hIOFB6/wwDQYJKoZIhvcNAQEBBQAEggIANWfk3VEMTG8J
# xIJPEAPm/JHYg/4UqwuloIacrhTuYxsV40dFgcZLd6jioUBIXRRsBOjWHunVC326
# c3xSVKAIqrcdXtEQrDyufvmPGES1tMQ82ZNfTfbRP9SLXKUSEgMcJKuxjdAwbnTL
# mg8KpWqlPbeauaHhCXEHZe04s7XJxqqjjlALPGX7AX0T/R5gKbzqhUE9nLFMCUo+
# WOq1CJKfdr//kJPPSMml14Fs0rBItXahKzm+iUfzqk9ZIY2GPx4xFx1AQTpLx84k
# K0zhAK94hiGKGWhAiuesywvFRLmnEvMFLqUOtLqLy8MD+Beo6HjbSZm04D/pgjdi
# OPaxAWE3LT14TE1eKT+hS+eysTanWkIze6JTWV2OvycfhPGV24g8V5OnCY74eMxx
# X1a8Gbs0cePjfPRPQAPmcUTyRfbMr/W86iY8lFP8zD4H/Z0FtSamJ479M/4yWtzE
# hG+WuzthsQ8D+1kUowJPRxFb4geigCMlMQDwknRpo42amWIxj/aP3n0IIINJW645
# SrPJlVzVYx2x4542LDmK3hCk/m5j7qpNYoRX7d5XZ3c8IRL9X2iKFh6Gj/FmM+nP
# UtD4WV1d6As/r+su2HTyzoxBHkvLFF1szU4Q0VkxGSaE+vsxqjv3TfElzvgVzta6
# Wt2AJY1aYh2N1CwZ5LB3uEgzjalxRfQ=
# SIG # End signature block
