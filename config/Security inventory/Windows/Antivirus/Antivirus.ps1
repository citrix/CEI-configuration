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
# MIIoogYJKoZIhvcNAQcCoIIokzCCKI8CAQExDzANBglghkgBZQMEAgEFADB5Bgor
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
# zgOyna7wokqBLvdrSiTF2of1k3HQUFUymRr0h3qjKOXx2cUxgho/MIIaOwIBATB9
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
# WAtzVT/n9naGVUZOkuD2QB7U3FgaeAvN6mEigqGCF3YwghdyBgorBgEEAYI3AwMB
# MYIXYjCCF14GCSqGSIb3DQEHAqCCF08wghdLAgEDMQ8wDQYJYIZIAWUDBAIBBQAw
# dwYLKoZIhvcNAQkQAQSgaARmMGQCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQC
# AQUABCALfUqaf0Rsp64id6upumwy930LoabSMNIcRslFPRF0CgIQSlfYZYPOFCFM
# Pw7GHp1wyxgPMjAyNjEwMDExMDM5MjNaoIITOjCCBu0wggTVoAMCAQICEAhP3DNP
# fkVO28MPj/mSGDUwDQYJKoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNV
# BAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0
# IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTAeFw0yNjA4MDUw
# MDAwMDBaFw0zNzExMDQyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgU0hBMjU2IFJTQTQwOTYg
# VGltZXN0YW1wIFJlc3BvbmRlciAyMDI2IDEwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQC2e6byyf7NSvjUm0xls/04xjD4fAkOkbnGQi7+Wpx81iYxfzVi
# axSIctuH3KSl5YEYpMuFgGsA31N2D9ATMbfZdw5uaAhuWevQKhDdZIB4Nnqcfpfp
# WQXJiQnDdAElETC+bhSEvNLGbA8DtwUpFMQ4yyYQSPqomT92osQAv6hBi47ATZS6
# JfVWe6XxhF4jJZ3iSAuf2Cros1czRSmWRHqMv9AfGZvp8ygYElhudpQjtcPpwoOl
# 6QrZJUyV3iINvN4cO05prGV0fkjG426xDr2d3z9lcSIHkdvGPdGUrXdxfVbgOUVc
# p2/8ISEzwKPW++Wa+E2ujI91EZtukGWDJ/xZ27k3oHKEXBRGfRTqjOU+jE3ba/5+
# +JSE/7oNHnjs5mekExYN96LV/mxUbCKJb8pBNY4r3uD7hEmk/M81XhVgwDA7aMzY
# C3LZBg9WY5BMmbSay5ecmtJuXaB/0nKWmQmVZeqTVDgsmzHP5MQuhAJkiWNuC9Mm
# Cg9TZHXbJ2/yLVSov9p16UDTLtT0+aa1vN71fHeu1qMLlLNB3WOB/ADCxr3S/1hx
# I92Z6jKgEED/btwIvbfuXkNNhg8MtDg43c4tMZae9FvqMOt/9PvmAxF9TNIsIFB8
# G6yb36ZJZGUL8N/pL971DyLXcK6HM5PYnH5X+eVtczhCgHCVQCF6XDAlPQIDAQAB
# o4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUFMljijAu1Er7bpTz5uNA
# fvXszeIwHwYDVR0jBBgwFoAU729TSunkBnx6yuKQVvYv1Ensy04wDgYDVR0PAQH/
# BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMIGVBggrBgEFBQcBAQSBiDCB
# hTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMF0GCCsGAQUF
# BzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcnQwXwYDVR0fBFgw
# VjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3Rl
# ZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3JsMCAGA1UdIAQZ
# MBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAjcU6
# YR6dUgrfmawJgH59KECxa9Ji8sEi2g10CBDaMiqsaxWyW5cwlT/6ZF5sFznazqVs
# oC85U9dqLOYqQwst+UQQoNlDHgKRLa3xoc+OReFreFhnTXSG0Vrd2E2CZqUfm+5a
# +He1MJ/h+tNLuA+0Zzhn/Fo+FDYAHWZHx4R79ZsfRFYe9UiXpXBDf6DkUo183Y38
# NYmR/XfDYf7YZ+oR9t3flbDwK+hgGMs0gNNp1w9Z2CyOyI5or/sSwomAuNQ0hWC9
# xoU4stD8aWsD7RkcmgVRs6vlIk3zPKQ+ylcheWkMlj+CoVRlFE55pv0ZWCaFt04l
# wP/rdGHE9qEVQZtyRE42ox7oNgC/r+Y4bSlZ3dw9K2x1xLtu6PkPKeLBFjzKigwf
# qm3Hm+k/+lnME8F5kPZTgiy2HLEHklpryqs6QHnPXrRNeIzkAMyylnRN8P0wmirS
# 0WkU+ywpEWFZ4QNg+9xS43tTuW9x0eXh7NDc1P/sV+zWxHXKH8tFt1ncHdVzqrZa
# YPyYMLSn2TOXajveJW1L3joiQSPsWRGxkbDDW15jERFE4LvjnGu2O9zD1nLJSMdl
# YZEikl4w2w+q4IN/R+TIe0H4ngCI1moJCTbevGH4punIxM1Uoi0nmX3ZK+XbRT01
# uowE5ViXWHng0RgsmrX/EdYUo80r3TfMlkD0/YMwgga0MIIEnKADAgECAhANx6xX
# Bf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAf
# BgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBa
# Fw0zODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBp
# bmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1D
# ahGPNRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn
# 5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLux
# BG5AvftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3I
# fDReb6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cV
# FBURJg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQ
# T/aofEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gby
# lsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rK
# WDEJlIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6
# z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9Vne
# Ps6BaaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQAB
# o4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6
# yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYD
# VR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGsw
# aTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUF
# BzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# Um9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeB
# DAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2
# cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe3
# 6zwbSI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMD
# PjTLxLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2
# AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410
# ANVko43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47O
# vgRaPs+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39
# OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9v
# ODRzW6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3
# s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5
# TPau1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXK
# UjPSxyZsq8WhbaM2tszWkPZPubdcMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21Di
# CEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGln
# aUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtE
# aWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzEx
# MTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBU
# cnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/
# 5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xuk
# OBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpz
# MpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7Fsa
# vOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qT
# XtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRz
# Km6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRc
# Ro9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADk
# RSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMY
# RJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4m
# rLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C
# 1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYD
# VR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYD
# VR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkG
# CCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQu
# Y29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGln
# aUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmww
# EQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+g
# o3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0
# /4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnL
# nU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU9
# 6LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ
# 9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9X
# ql4o4rmUMYIDfDCCA3gCAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0
# YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExAhAIT9wzT35FTtvDD4/5khg1
# MA0GCWCGSAFlAwQCAQUAoIHRMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAc
# BgkqhkiG9w0BCQUxDxcNMjYxMDAxMTAzOTIzWjArBgsqhkiG9w0BCRACDDEcMBow
# GDAWBBRR2avaA0lz2E9CZqykgkjms2nEOTAvBgkqhkiG9w0BCQQxIgQgpmDBjlzU
# 7F1Hk1CWBsRv2hUqOKnDipZ5QmCaOSAcybQwNwYLKoZIhvcNAQkQAi8xKDAmMCQw
# IgQgLaCdp/QTH5/nLbbF5unJZWdVrwQ/HqdCzA0hIOFB6/wwDQYJKoZIhvcNAQEB
# BQAEggIAYifKCCONkMzfJ3IvLxOvBf0NZDylGxyEHixXKH6bRWq0NajT+RVca3Os
# FvEJ8+jA/Dp1R2MrgRk813XnpVeoBpk7180GQHlYO+/b7Fl76TfosFLc2wyVFWOo
# C2zGoTPzOMHGRunN9jGlIAANmQ7GAohwduSuXYbf721Q+uIPHIY+v2X/4hdTSHUD
# 1NVWmDux1C6yfiBwve8CaH9RaURDWFhXnVsKOIzClIhi7OSmEUrYfUp7lQt0BCNz
# R0cHK3KVNdwX6rjdISOg3VB7eFkIBtazvjdxSFOlhnBJ9P8A9nlFx/1MlCrGWxtv
# /4aFszierDQQbL1JvaaK9qjIqDdtXG1yykFYOSeJbInmJEFPauvu971OwedCC7Og
# YfByOs5eCNJavVIiqHAmJhI3lO9NIyqPVEmJmmUgA4yhsXay5Dk9CRG1hFwWKuk/
# +ORf73XjFOXymc7E5VGpsuyxVXqiUYjLieyG0FflVIILEILkrpLEZuBsJbUGw5y9
# DRh2wFWYtPQ1IuExZgGL5M2Qe9LRYADe7VrN/2tM9UOaQKCRq1YA7RA6uC713Ism
# HKQdVoDU8yxYgvHSTi8gFjD9w12tJ5H7fJSPF9DtCVmVskErlleYohLD+pQOM2vT
# jK+eWA3Ss16OnWuxsFEbIB3WaC745x2TU2XMSX/juiM+kPhY2Rc=
# SIG # End signature block
