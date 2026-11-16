#Requires -RunAsAdministrator
#Requires -Version 3.0

. $PSScriptRoot\..\Shared\Helper.ps1 -Force

#https://mcpforlife.com/2020/04/14/how-to-resolve-this-state-value-of-av-providers/
$AV_ProductState = @{
   Off     = 0x0000
   On      = 0x1000
   Snoozed = 0x2000
   Expired = 0x3000
}

$AV_SignatureStatus = @{
   UpToDate  = 0x00
   OutOfDate = 0x10
}

$AV_ProductFlags = @{
   SignatureStatus = 0x000000F0
   ProductOwner    = 0x00000F00
   ProductState    = 0x0000F000
}


function Get-vlAntivirusStatus {
   <#
    .SYNOPSIS
        Get the status of the antivirus software
    .DESCRIPTION
        Get the status of the antivirus software
        This cmdlet is only available on the Windows platform.
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the status of the antivirus software
    .EXAMPLE
        Get-vlAntivirusStatus
    #>

   process {
      try {
         $result = @()
         $score = 0
         $riskScore = 100

         $osVersion = Get-vlOsVersion -ErrorAction Stop
         $isWindows7 = $osVersion -match "^6\.1"

         $isWindowsServer = Get-vlIsWindowsServer -ErrorAction Stop
         $isMpComputerStatusAvailable = Get-vlIsCmdletAvailable "Get-MpComputerStatus"
         $defenderStatus = [PSCustomObject]@{}

         if ($isMpComputerStatusAvailable -eq $true) {
            $instances = Get-MpComputerStatus -ErrorAction Stop

            $defenderStatus = [PSCustomObject]@{
               AMEngineVersion                 = if ($instances.AMEngineVersion) { $instances.AMEngineVersion } else { "" }
               AMServiceEnabled                = if ($instances.AMServiceEnabled) { $instances.AMServiceEnabled } else { "" }
               AMServiceVersion                = if ($instances.AMServiceVersion) { $instances.AMServiceVersion } else { "" }
               AntispywareEnabled              = if ($instances.AntispywareEnabled) { $instances.AntispywareEnabled } else { "" }
               AntivirusEnabled                = if ($instances.AntivirusEnabled) { $instances.AntivirusEnabled } else { "" }
               AntispywareSignatureLastUpdated = if ($instances.AntispywareSignatureLastUpdated) { $instances.AntispywareSignatureLastUpdated.ToString("yyyy-MM-ddTHH:mm:ss") } else { "" }
               AntispywareSignatureVersion     = if ($instances.AntispywareSignatureVersion) { $instances.AntispywareSignatureVersion } else { "" }
               AntivirusSignatureLastUpdated   = if ($instances.AntivirusSignatureLastUpdated) { $instances.AntivirusSignatureLastUpdated.ToString("yyyy-MM-ddTHH:mm:ss") } else { "" }
               QuickScanSignatureVersion       = if ($instances.QuickScanSignatureVersion) { $instances.QuickScanSignatureVersion } else { "" }
            }
         }

         if ($isWindowsServer -eq $false) {
            if ($isWindows7 -eq $true) {
               $instances = Get-CimInstance -ClassName AntiSpywareProduct -Namespace "root\SecurityCenter2" -ErrorAction Stop
            }
            else {
               $instances = Get-CimInstance -ClassName AntiVirusProduct -Namespace "root\SecurityCenter2" -ErrorAction Stop
            }

            $avEnabledFound = $false

            foreach ($instance in $instances) {
               $avEnabled = $($AV_ProductState["On"] -eq $($instance.productState -band $AV_ProductFlags["ProductState"]) )
               $avUp2Date = $($AV_SignatureStatus["UpToDate"] -eq $($instance.productState -band $AV_ProductFlags["SignatureStatus"]) )

               if ($avEnabled) {
                  $avEnabledFound = $true
                  if ($avUp2Date) {
                     $score = 10
                  }
                  else {
                     $score = 5
                  }
               }

               if ($instance.displayName -eq "Windows Defender" -or "{D68DDC3A-831F-4fae-9E44-DA132C1ACF46}" -eq $instance.instanceGuid) {

                  if ($avEnabled -eq $false -or $isWindows7 -eq $true) {
                     $result += [PSCustomObject]@{
                        Enabled  = $avEnabled
                        Name     = $instance.displayName
                        UpToDate = $avUp2Date
                     }
                  }
                  else {
                     $result += [PSCustomObject]@{
                        Enabled  = $avEnabled
                        Name     = $instance.displayName
                        UpToDate = $avUp2Date
                        Defender = $defenderStatus
                     }

                     $score += Get-vlTimeScore($defenderStatus.AntispywareSignatureLastUpdated)
                     $score += Get-vlTimeScore($defenderStatus.AntivirusSignatureLastUpdated)
                  }
               }
               else {
                  $result += [PSCustomObject]@{
                     Enabled  = $avEnabled
                     Name     = $instance.displayName
                     UpToDate = $avUp2Date
                  }
               }
            }

            if (-not $avEnabledFound) {
               $score = 0
            }
         }
         else {
            $result = @()
            $score = 0

            if ($defenderStatus -and $defenderStatus.AMServiceEnabled -and $defenderStatus.AntispywareEnabled -and $defenderStatus.AntivirusEnabled) {
               $score = 10

               $score += Get-vlTimeScore($defenderStatus.AntispywareSignatureLastUpdated)
               $score += Get-vlTimeScore($defenderStatus.AntivirusSignatureLastUpdated)

               $result += [PSCustomObject]@{
                  Enabled  = $true
                  Name     = "Windows Defender"
                  UpToDate = if ($score -eq 10) { $true } else { $false }
                  Defender = $defenderStatus
               }
            }
            elseif ($defenderStatus) {
               $result += [PSCustomObject]@{
                  Enabled  = $false
                  Name     = "Windows Defender"
                  UpToDate = if ($score -eq 10) { $true } else { $false }
                  Defender = $defenderStatus
               }
            }
            else {
               return New-vlErrorObject -message "Status could not be determined because SecurityCenter2 is not available on Windows Server." -errorCode 1 -context $null
            }
         }

         return New-vlResultObject -result $result -score $score -riskScore $riskScore
      }
      catch {
         return New-vlErrorObject -context $_
      }
   }
}

function Get-vlAntivirusCheck {
   <#
    .SYNOPSIS
        Function that performs the antivirus check and returns the result to Citrix Experience Insights.
    .DESCRIPTION
        Function that performs the antivirus check and returns the result to Citrix Experience Insights.
    .NOTES
        The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
        Specific tests can be called by passing the test name as a parameter to the script args.
        Passing no parameters or -all to the script will run all tests.
    .LINK
        https://uberagent.com
    .OUTPUTS
        A list with vlResultObject | vlErrorObject [psobject] containing the test results
    .EXAMPLE
        Get-vlAntivirusCheck -amsi -avStatus
    #>

   #set $params to $global:args or if empty default "all"
   $params = if ($global:args) { $global:args } else { "all" }
   $params = $params | ForEach-Object { $_.ToLower() }

   $Output = @()

   if ($params.Contains("all") -or $params.Contains("AVState")) {
      $avStatus = Get-vlAntivirusStatus
      $Output += [PSCustomObject]@{
         Name         = "AVState"
         DisplayName  = "Antivirus status"
         Description  = "This test determines whether an antivirus product is installed and its current status. If the test is performed on a Windows server operating system, due to technical limitations, only the Defender status is evaluated. If Windows Defender is enabled and your operating system is Windows 10, Windows Server 2016 or later, the test will provide additional information, such as the status of the last signature update and the current signature version."
         Score        = $avStatus.Score
         ResultData   = $avStatus.Result
         RiskScore    = $avStatus.RiskScore
         ErrorCode    = $avStatus.ErrorCode
         ErrorMessage = $avStatus.ErrorMessage
      }
   }

   Write-Output $output
}

try {
   [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}
catch {
   $OutputEncoding = [System.Text.Encoding]::UTF8
}

# Entrypoint of the script call the check function and convert the result to JSON
Write-Output (Get-vlAntivirusCheck | ConvertTo-Json -Compress)

# SIG # Begin signature block
# MIIoowYJKoZIhvcNAQcCoIIolDCCKJACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAczXy8BtCWxQTs
# dRUHU/Z9ivwXVc7LJL75+9JPU8I+a6CCDbkwggawMIIEmKADAgECAhAIrUCyYNKc
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
# zgOyna7wokqBLvdrSiTF2of1k3HQUFUymRr0h3qjKOXx2cUxghpAMIIaPAIBATB9
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTECEA/jsqLSKYSprcwjW2RvMd4wDQYJYIZIAWUDBAIBBQCggZow
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLgYKKwYBBAGCNwIBDDEgMB6gHIAaAEEAbgB0AGkAdgBpAHIAdQBz
# AC4AcABzADEwLwYJKoZIhvcNAQkEMSIEILcSMg0tA+jrGTQRRwrKg6qx/cIoC6UM
# RwtqZfN47O04MA0GCSqGSIb3DQEBAQUABIIBgK0xn5Q5SuclSoKh5IuQ+tKSarQP
# oL00QOpPORlIejeCtqXrPpgdwbCeb6TzBiXxHZJD31e+8i4aknFKyLFjOkLqW3WF
# vMhyqAuC/SKMpn0Qv/Iilgs7/wPrUq2L3bkA6OnuskjSvvzU6ZhQ13VVDxEob52T
# wxT7CW5bXqBmNf623cY6LTN86qIQlDf53FeZSj0kdeMSprO0WO5KaJfn30bYrmnE
# RZmwNhWOiEKluZ9HZw62d6xH+67aZP5bRUTr1K1Ixfi2MuqZ9aoIuftL2iaZlaL6
# qeed9asgnzS/0+x4T2wVwfmDRHwtQjR2NlqGiV0ps8G5WGt3l7VKFyXZu7Spi2xv
# 1Gqmt8+cWsf32hwcX6XeIqjJ8f34sZu8vbd0aYVoBdN1MYi4vLDcU/xUzODYhpUN
# m3s3dYxNeS4fZhuDk6N/+eB26tK5G7t18pLY1uvqblUCYRWGvt0x24SjO3Uz724D
# WAtzVT/n9naGVUZOkuD2QB7U3FgaeAvN6mEigqGCF3cwghdzBgorBgEEAYI3AwMB
# MYIXYzCCF18GCSqGSIb3DQEHAqCCF1AwghdMAgEDMQ8wDQYJYIZIAWUDBAIBBQAw
# eAYLKoZIhvcNAQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQC
# AQUABCALfUqaf0Rsp64id6upumwy930LoabSMNIcRslFPRF0CgIRAMJeB7aHn990
# s23P+d+pJWsYDzIwMjYxMTE2MDY1NjU3WqCCEzowggbtMIIE1aADAgECAhAIT9wz
# T35FTtvDD4/5khg1MA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYD
# VQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBH
# NCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwHhcNMjYwODA1
# MDAwMDAwWhcNMzcxMTA0MjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMO
# RGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2
# IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAyNiAxMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAtnum8sn+zUr41JtMZbP9OMYw+HwJDpG5xkIu/lqcfNYmMX81
# YmsUiHLbh9ykpeWBGKTLhYBrAN9Tdg/QEzG32XcObmgIblnr0CoQ3WSAeDZ6nH6X
# 6VkFyYkJw3QBJREwvm4UhLzSxmwPA7cFKRTEOMsmEEj6qJk/dqLEAL+oQYuOwE2U
# uiX1Vnul8YReIyWd4kgLn9gq6LNXM0UplkR6jL/QHxmb6fMoGBJYbnaUI7XD6cKD
# pekK2SVMld4iDbzeHDtOaaxldH5IxuNusQ69nd8/ZXEiB5Hbxj3RlK13cX1W4DlF
# XKdv/CEhM8Cj1vvlmvhNroyPdRGbbpBlgyf8Wdu5N6ByhFwURn0U6ozlPoxN22v+
# fviUhP+6DR547OZnpBMWDfei1f5sVGwiiW/KQTWOK97g+4RJpPzPNV4VYMAwO2jM
# 2Aty2QYPVmOQTJm0msuXnJrSbl2gf9JylpkJlWXqk1Q4LJsxz+TELoQCZIljbgvT
# JgoPU2R12ydv8i1UqL/adelA0y7U9Pmmtbze9Xx3rtajC5SzQd1jgfwAwsa90v9Y
# cSPdmeoyoBBA/27cCL237l5DTYYPDLQ4ON3OLTGWnvRb6jDrf/T75gMRfUzSLCBQ
# fBusm9+mSWRlC/Df6S/e9Q8i13CuhzOT2Jx+V/nlbXM4QoBwlUAhelwwJT0CAwEA
# AaOCAZUwggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFBTJY4owLtRK+26U8+bj
# QH717M3iMB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB
# /wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgw
# gYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEF
# BQcwAoZRaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3Rl
# ZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRY
# MFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0
# ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAE
# GTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAI3F
# OmEenVIK35msCYB+fShAsWvSYvLBItoNdAgQ2jIqrGsVsluXMJU/+mRebBc52s6l
# bKAvOVPXaizmKkMLLflEEKDZQx4CkS2t8aHPjkXha3hYZ010htFa3dhNgmalH5vu
# Wvh3tTCf4frTS7gPtGc4Z/xaPhQ2AB1mR8eEe/WbH0RWHvVIl6VwQ3+g5FKNfN2N
# /DWJkf13w2H+2GfqEfbd35Ww8CvoYBjLNIDTadcPWdgsjsiOaK/7EsKJgLjUNIVg
# vcaFOLLQ/GlrA+0ZHJoFUbOr5SJN8zykPspXIXlpDJY/gqFUZRROeab9GVgmhbdO
# JcD/63RhxPahFUGbckRONqMe6DYAv6/mOG0pWd3cPStsdcS7buj5DyniwRY8yooM
# H6ptx5vpP/pZzBPBeZD2U4IsthyxB5Jaa8qrOkB5z160TXiM5ADMspZ0TfD9MJoq
# 0tFpFPssKRFhWeEDYPvcUuN7U7lvcdHl4ezQ3NT/7Ffs1sR1yh/LRbdZ3B3Vc6q2
# WmD8mDC0p9kzl2o73iVtS946IkEj7FkRsZGww1teYxERROC745xrtjvcw9ZyyUjH
# ZWGRIpJeMNsPquCDf0fkyHtB+J4AiNZqCQk23rxh+KbpyMTNVKItJ5l92Svl20U9
# NbqMBOVYl1h54NEYLJq1/xHWFKPNK903zJZA9P2DMIIGtDCCBJygAwIBAgIQDces
# VwX/IZkuQEMiDDpJhjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMG
# A1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEw
# HwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAw
# WhcNMzgwMTE0MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNl
# cnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1w
# aW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAtHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTt
# Q2oRjzUXMmxCqvkbsDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7
# Z+QdSKWM06qchUP+AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7
# sQRuQL37QXbDhAktVJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrN
# yHw0Xm+nt5pnYJU3Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8Bbfn
# FRQVESYOszFI2Wv82wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0W
# kE/2qHxJ0ucS638ZxqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG
# 8pbF0LJAQQZxst7VvwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6
# ylgxCZSKi17yVp2NL+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8
# es9Xr/u6bDTnYCTKIsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ
# 3j7OgWmnhFr4yUozZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEA
# AaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8
# esrikFb2L9RJ7MtOMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4G
# A1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRr
# MGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEF
# BQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3Rl
# ZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZn
# gQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0R
# dnEwvb4LyLU0pn/N0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3
# t+s8G0iP5kvN2n7Jd2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZT
# Az40y8S4F3/a+Z1jEMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY
# 9gCDA/JYsq7pGdogP8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+N
# dADVZKON/gnZruMvNYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOO
# zr4EWj7PtspIHBldNE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN
# /TpVfHIqQ6Ku/qjTY6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8P
# bzg0c1ugMZyZZd/BdHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4
# N7OigizwJWeukcyIPbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZ
# eUz2rtY/9TCA6TD8dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yF
# ylIz0scmbKvFoW2jNrbM1pD2T7m3XDCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ
# 4ghAGFowDQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERp
# Z2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMb
# RGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMx
# MTEwOTIzNTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IElu
# YzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQg
# VHJ1c3RlZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# v+aQc2jeu+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2uexuEDcQwH/Mb
# pDgW61bGl20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlq
# czKU0RBEEC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxb
# Grzryc/NrDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcva
# k17cjo+A2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sE
# cypukQF8IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ck
# XEaPZPfBaYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA
# 5EUlibaaRBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFj
# GESVGnZifvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+
# Jqy2QXXeeqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotP
# wtZFX50g/KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8G
# A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8G
# A1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5
# BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0
# LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0Rp
# Z2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRw
# Oi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3Js
# MBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhf
# oKN0Gz22Ftf3v1cHvZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv
# 9P+Aufih9/Jy3iS8UgPITtAq3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZ
# y51PpwYDE3cnRNTnf+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTV
# Peix3P0c2PR3WlxUjG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGy
# WfVVa88nq2x2zm8jLfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3Aamf
# V6peKOK5lDGCA3wwggN4AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVT
# dGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCE/cM09+RU7bww+P+ZIY
# NTANBglghkgBZQMEAgEFAKCB0TAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQw
# HAYJKoZIhvcNAQkFMQ8XDTI2MTExNjA2NTY1N1owKwYLKoZIhvcNAQkQAgwxHDAa
# MBgwFgQUUdmr2gNJc9hPQmaspIJI5rNpxDkwLwYJKoZIhvcNAQkEMSIEIHqAjDqf
# YQVWyMonNhmPrjcli50zbPFx5LT5oh2iaw3VMDcGCyqGSIb3DQEJEAIvMSgwJjAk
# MCIEIC2gnaf0Ex+f5y22xebpyWVnVa8EPx6nQswNISDhQev8MA0GCSqGSIb3DQEB
# AQUABIICALOWK9Z5qk/vKrCtCnT4x7Pft9UfSxlFnljXFDiC/1m1fa9IpFp+i1Js
# y2FZOPUGeMdiGyFThxyis2OAISuIeO1hNxcmgtDU54HiIl8vCi5I328RWTm5i2Ss
# kLx8rkcd2LUW4FXVeuWCiH5CNrKGpGzDw76EeFyNoO+Nfy0+zYDaBFNANC+Zncb2
# QVQy8P4iIRQsrSHxItso4SzwZ8X/5Y2NCqGzUJOZORrrNadn2Ni4eXSE07moQnyu
# 0Xd4znIR1Vb2e9mZzRT9GXNeDia5iqiXO7Yx0b0nvWxqTeuh33TsR3SnaAwk+/lO
# sGDv/uByc2nig5yS6o6gpKDngbCU6/fkRkHa7mDb7VqYl60aZA9BXqKVAN9L5WQU
# lesq7GAxGWB5n8mF1cj+gAAuGcw9kRkiQ78ypEIvFm4i2gS5UTIHvQG8nCZ5767/
# r1wp5VlZPWixMRqP/WBAf9+Ijey1x3Pn90GsuhcEh/o8O1G2aFHOgox/m+aRNQzO
# mARlnvuAgGobSmJlFC06nMPOeCEzzIji6YGWVbJe69nIk4VBGWfaLQArEFioIvmZ
# A1atAzLZHZp479BV4/Bd1Vr8bLRZMdTQbcQWPc1O/O7nVdfGFi/Nb1I8vfmqw+gg
# 0ejzyGnP0+NRrSvDzImOJFUoyR5hrCEM+1cXwct0USWV9HFPF5si
# SIG # End signature block
