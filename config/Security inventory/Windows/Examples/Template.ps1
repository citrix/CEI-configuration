# This file should help you to get started with writing SCI tests for Windows.

### Requires elevated privileges? Then add the following line to the top of the script
# #Requires -RunAsAdministrator

### We support PowerShell 3.0 and later, so we need to add the following line to the top of the script
#Requires -Version 3.0

# Include helper functions like return handling, error handling, and for working with the registry more easily
. $PSScriptRoot\..\Shared\Helper.ps1 -Force

#
# To ensure that data is displayed accurately in the Security Score Splunk dashboard, it's important to follow certain best practices.
#
# 1)  A key practice is to aggregate related values within a test and return the result as a single object.
#     This approach simplifies the analysis and visualization of data, especially when examining related metrics or statuses.
#
#     This allows you to handle dependencies, such as only getting the SSID and encryption method when WIFI is enabled and connected.
#     If you separated these values into separate tests (WIFI enabled, current SSID, encryption method), it would be more difficult to calculate the risk score and merge the data.
#
#     Example: Get-vlGroupSimilarValues.
#
# 2)  Splunk has a default limit of 10,000 characters for a single event; data is truncated if it exceeds this limit.
#     If you expect a result to exceed this limit, consider breaking it into smaller, more manageable pieces.
#
# 3)  The Security Score Splunk dashboard currently does not support every json structure.
#
#     Example: Get-vlSupportMatrixExample.
#

function Get-vlSimpleExample() {
   <#
   .SYNOPSIS
         This test returns a simple result.
   .DESCRIPTION
         This test returns a simple result.
   .NOTES
         The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
   .LINK
         https://uberagent.com
   .OUTPUTS
         vlResultObject | vlErrorObject [psobject] containing the test result
   .EXAMPLE
       Get-vlSimpleExample
   #>

   # Define risk score ranges from 0 to 100 (100 is the highest risk). This should be static and not change during the test.
   $riskScore = 90

   # Define the score for this test. Score ranges from 0 to 10 (10 is the highest score = best result).
   $score = 0 # Initialize the score variable

   # Add your test logic here, we just set a variable to true
   $result = $true

   # In this case, we set the score to 10, since the result is true.
   if ($result) {
      $score = 10
   }
   else {
      $score = 0
   }

   # Create the result object
   return New-vlResultObject -result $result -score $score -riskScore $riskScore
}

function Get-vlGroupSimilarValues() {
   <#
   .SYNOPSIS
         This test returns a grouped result.
   .DESCRIPTION
         This test returns a grouped result.
   .NOTES
         The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
   .LINK
         https://uberagent.com
   .OUTPUTS
         vlResultObject | vlErrorObject [psobject] containing the test result
   .EXAMPLE
         Get-vlGroupSimilarValues
   #>

   # Define risk score ranges from 0 to 100 (100 is the highest risk). This should be static and not change during the test.
   $riskScore = 100

   # Initialize the score variable
   $score = 10

   ### Case WIFI is enabled and connected
   $wifiStatus = "enabled"
   $wifiConnectionStatus = "connected"
   $wifiSSID = "MyWifi"
   $wifiEncryption = "WPA3"

   if ($wifiStatus -eq "enabled") {
      # Case WIFI is enabled
      # check if wifiEncryption is WPA3 else give it a lower testScore
      if ($wifiEncryption -eq "WPA3") {
         $score = 10
      }
      else {
         $score = 5
      }

      # Initialize new result object and add the values to it
      $result = @{
         wifiStatus           = $wifiStatus
         wifiConnectionStatus = $wifiConnectionStatus
         wifiSSID             = $wifiSSID
         wifiEncryption       = $wifiEncryption
      }
   }
   else {
      # Case WIFI is disabled
      # We do not need to add $wifiSSID and $wifiEncryption here, since they are not available if WIFI is disabled.
      # The dashboard will show n/a for these values if they are not present.

      $result = @{
         wifiStatus           = $wifiStatus
         wifiConnectionStatus = $wifiConnectionStatus
      }
   }

   # Create the result object
   return New-vlResultObject -result $result -score $score -riskScore $riskScore
}

function Get-vlSimpleArrayExample() {
   <#
   .SYNOPSIS
         This test returns a simple result array.
   .DESCRIPTION
         This test returns a simple result array.
   .NOTES
         The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
   .LINK
         https://uberagent.com
   .OUTPUTS
         vlResultObject | vlErrorObject [psobject] containing the test result
   .EXAMPLE
         Get-vlSimpleArrayExample
   #>

   # Arrays can be used for tests. It is important to note that the dashboard currently does only support arrays as a top-level object.

   # Define risk score ranges from 0 to 100 (100 is the highest risk). This should be static and not change during the test.
   $riskScore = 90

   # Define the score for this test. Score ranges from 0 to 10 (10 is the highest score = best result).
   $score = 0 # Initialize the score variable

   # Add your test logic here, we just create two objects and add them to the result array

   $resultObj1 = @{
      Name = "John"
      Age  = 30
   }

   $resultObj2 = @{
      Name = "Doe"
      Age  = 43
   }

   $result = @()
   $result += $resultObj1
   $result += $resultObj2

   # Create the result object
   return New-vlResultObject -result $result -score $score -riskScore $riskScore
}

function Get-vlNestedExample() {
   <#
   .SYNOPSIS
         This test returns a nested result.
   .DESCRIPTION
         This test returns a nested result.
   .NOTES
         The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
   .LINK
         https://uberagent.com
   .OUTPUTS
         vlResultObject | vlErrorObject [psobject] containing the test result
   .EXAMPLE
         Get-vlNestedExample
   #>

   $score = 3 # define the score for this test. Score ranges from 0 to 10 (10 is the highest score).
   $riskScore = 70 # define the risk score for this test. Risk score ranges from 0 to 100 (100 is the highest risk).

   # Add your test logic here
   # ...

   # Create result object, pass on $resultData to add values to the result
   $result = @{
      Enabled = $true
      CmdLine = "/bin/zsh -c 'if (2 -eq 2) { echo equals; }'"
   }

   $nestedObj = @{
      Name = "John"
      Age  = 30
   }

   # Add a nested object within the result object using key "Person"
   $result.Add("Person", $nestedObj)

   # While it is technically possible to add arrays to an nested object, the dashboard cannot display them correctly, so please avoid doing so.
   # Don't use code like: $result.Add("Members", @($nestedObj, $nestedObj2, $nestedObj3, $nestedObj4,...))

   # Create the result object
   return New-vlResultObject -result $result -score $score -riskScore $riskScore
}


function Get-vlSupportMatrixExample() {
   # JSON - Dashboard Support Matrix
   # The dashboard supports the following structures. Please use this example to check if your result can be displayed correctly.

   # Legend:
   # [+] Supported
   # [-] Not Supported

   # Structure                                                                         | Status
   # ----------------------------------------------------------------------------------|--------
   # Simple Object                                                                     | [+]
   #   {"Enabled": true, "Mode": "Auto"}
   # Code:

   # Create result object, pass on $resultData to add values to the result.
   $result = @{
      Enabled = $true
      Mode    = "Auto"
   }

   # ----------------------------------------------------------------------------------|--------
   # Array of Objects                                                                  | [+]
   #   [{"Name":"John","Age":30, "City":"New York"},
   #    {"Name":"Alice","Age":25, "City":"Los Angeles"}]
   # Code:

   $result = @(
      @{
         Name = "John"
         Age  = 30
         City = "New York"
      }
      @{
         Name = "Alice"
         Age  = 25
         City = "Los Angeles"
      }
   )

   # ----------------------------------------------------------------------------------|--------
   # Object with simple Array (Strings, Numbers)                                       | [+]
   #   {"Applications":["App1", "App2", "App3"], "Status": "Active"}
   # Code:

   $result = @{
      Applications = @("App1", "App2", "App3")
      Status       = "Active"
   }

   # ----------------------------------------------------------------------------------|--------
   # Complex Object                                                                    | [+]
   #   {"Enabled":true, "Config": {"Path":"/usr/bin", "Timeout":30},
   #    "User":{"Name":"John", "Role":"Admin"}}
   # Code:

   $result = @{
      Enabled = $true
      Config  = @{
         Path    = "/usr/bin"
         Timeout = 30
      }
      User    = @{
         Name = "John"
         Role = "Admin"
      }
   }

   # ----------------------------------------------------------------------------------|--------
   # Object with Array of Objects                                                      | [-]
   #   {"Team": "Developers",
   #    "Members": [{"Name":"John","Skill":"Java"},
   #                {"Name":"Alice","Skill":"Python"}
   #               ]}

   # While it is technically possible to add arrays to an nested object, the dashboard cannot display them correctly, so please avoid doing so.
   # Code to create such a result, that is not supported by the dashboard:

   $result = @{
      Team    = "Developers"
      Members = @(
         @{
            Name  = "John"
            Skill = "Java"
         }
         @{
            Name  = "Alice"
            Skill = "Python"
         }
      )
   }

   # ----------------------------------------------------------------------------------|--------

   $score = 10 # define the score for this test. Score ranges from 0 to 10 (10 is the highest score).
   $riskScore = 90 # define the risk score for this test. Risk score ranges from 0 to 100 (100 is the highest risk).

   # Create the result object
   return New-vlResultObject -result $result -score $score -riskScore $riskScore
}

function Get-vlErrorExample() {
   <#
   .SYNOPSIS
         This test is made to fail to demonstrate how to handle errors.
   .DESCRIPTION
         This test is made to fail to demonstrate how to handle errors.
   .NOTES
         The result will be converted to JSON. Each test returns a vlResultObject or vlErrorObject.
   .LINK
         https://uberagent.com
   .OUTPUTS
         vlResultObject | vlErrorObject [psobject] containing the test result
   .EXAMPLE
         Get-vlErrorExample
   #>

   # Add your test logic here
   # ...

   $score = 0
   $riskScore = 90

   # Try to run a command that does not exist
   try {
      $result = Invoke-Expression "Get-NonExistingCommand"

      # We should never reach this point, since the command does not exist
      return New-vlResultObject -result $result -score $score -riskScore $riskScore
   }
   catch {
      # Send empty result object, since the test failed.

      # Handle the error and return an error object.
      return New-vlErrorObject -context $_
   }
}


# Replace "Template" with the name of your module.
function Get-vlTemplateCheck {
   <#
    .SYNOPSIS
         Write a quick summary of what the function does here.
    .DESCRIPTION
         Write a description of the function here.
    .NOTES
         Additional information about the function.
    .LINK
         Provide a link to more information about the function or some related resource.
    .OUTPUTS
         A list with vlResultObject | vlErrorObject [psobject] containing the test results
    .EXAMPLE
        Get-vlTemplateCheck
    #>

   #set $params to $global:args or if empty default "all"
   $params = if ($global:args) { $global:args } else { "all" }
   $params = $params | ForEach-Object { $_.ToLower() }

   $Output = @()

   if ($params.Contains("all") -or $params.Contains("vlSimpleExample")) {
      $vlSimpleExample = Get-vlSimpleExample

      # Please always use this block, which consists atleast of Name, DisplayName, and Description.
      # Important for the pipeline, these values are parsed and displayed on the dashboard.

      $Output += [PSCustomObject]@{
         Name         = "vlSimpleExample"
         DisplayName  = "Simple example"
         Description  = "This test returns a simple result."
         Score        = $vlSimpleExample.Score # Returned from the Test
         ResultData   = $vlSimpleExample.Result # Returned from the Test
         RiskScore    = $vlSimpleExample.RiskScore # Returned from the Test
         ErrorCode    = $vlSimpleExample.ErrorCode # Returned from the Test
         ErrorMessage = $vlSimpleExample.ErrorMessage # Returned from the Test
      }
   }

   if ($params.Contains("all") -or $params.Contains("vlGroupSimilarValues")) {
      $vlGroupSimilarValues = Get-vlGroupSimilarValues

      # Please always use this block, which consists atleast of Name, DisplayName, and Description.
      # Important for the pipeline, these values are parsed and displayed on the dashboard.

      $Output += [PSCustomObject]@{
         Name         = "vlGroupSimilarValues"
         DisplayName  = "Group values example"
         Description  = "This test returns a grouped result."
         Score        = $vlGroupSimilarValues.Score # Returned from the Test
         ResultData   = $vlGroupSimilarValues.Result # Returned from the Test
         RiskScore    = $vlGroupSimilarValues.RiskScore # Returned from the Test
         ErrorCode    = $vlGroupSimilarValues.ErrorCode # Returned from the Test
         ErrorMessage = $vlGroupSimilarValues.ErrorMessage # Returned from the Test
      }
   }

   if ($params.Contains("all") -or $params.Contains("vlSimpleArrayExample")) {
      $vlSimpleArrayExample = Get-vlSimpleArrayExample

      # Please always use this block, which consists atleast of Name, DisplayName, and Description.
      # Important for the pipeline, these values are parsed and displayed on the dashboard.

      $Output += [PSCustomObject]@{
         Name         = "vlSimpleArrayExample"
         DisplayName  = "Simple array example"
         Description  = "This test returns a simple result array."
         Score        = $vlSimpleArrayExample.Score # Returned from the Test
         ResultData   = $vlSimpleArrayExample.Result # Returned from the Test
         RiskScore    = $vlSimpleArrayExample.RiskScore # Returned from the Test
         ErrorCode    = $vlSimpleArrayExample.ErrorCode # Returned from the Test
         ErrorMessage = $vlSimpleArrayExample.ErrorMessage # Returned from the Test
      }
   }

   if ($params.Contains("all") -or $params.Contains("vlNestedExample")) {
      $vlNestedExample = Get-vlNestedExample

      # Please always use this block, which consists atleast of Name, DisplayName, and Description.
      # Important for the pipeline, these values are parsed and displayed on the dashboard.

      $Output += [PSCustomObject]@{
         Name         = "vlNestedExample"
         DisplayName  = "Nested result"
         Description  = "This test returns a nested result."
         Score        = $vlNestedExample.Score # Returned from the Test
         ResultData   = $vlNestedExample.Result # Returned from the Test
         RiskScore    = $vlNestedExample.RiskScore # Returned from the Test
         ErrorCode    = $vlNestedExample.ErrorCode # Returned from the Test
         ErrorMessage = $vlNestedExample.ErrorMessage # Returned from the Test
      }
   }

   if ($params.Contains("all") -or $params.Contains("vlSupportMatrixExample")) {
      $vlSupportMatrixExample = Get-vlSupportMatrixExample

      # Please always use this block, which consists atleast of Name, DisplayName, and Description.
      # Important for the pipeline, these values are parsed and displayed on the dashboard.

      $Output += [PSCustomObject]@{
         Name         = "vlSupportMatrixExample"
         DisplayName  = "Matrix example"
         Description  = "This test returns a Matrix example."
         Score        = $vlSupportMatrixExample.Score # Returned from the Test
         ResultData   = $vlSupportMatrixExample.Result # Returned from the Test
         RiskScore    = $vlSupportMatrixExample.RiskScore # Returned from the Test
         ErrorCode    = $vlSupportMatrixExample.ErrorCode # Returned from the Test
         ErrorMessage = $vlSupportMatrixExample.ErrorMessage # Returned from the Test
      }
   }

   if ($params.Contains("all") -or $params.Contains("vlSupportMatrixExample")) {
      $vlErrorExample = Get-vlErrorExample

      # Please always use this block, which consists atleast of Name, DisplayName, and Description.
      # Important for the pipeline, these values are parsed and displayed on the dashboard.

      $Output += [PSCustomObject]@{
         Name         = "vlErrorExample"
         DisplayName  = "Error result"
         Description  = "This test is made to fail to demonstrate how to handle errors."
         Score        = $vlErrorExample.Score # Returned from the Test
         ResultData   = $vlErrorExample.Result # Returned from the Test
         RiskScore    = $vlErrorExample.RiskScore # Returned from the Test
         ErrorCode    = $vlErrorExample.ErrorCode # Returned from the Test
         ErrorMessage = $vlErrorExample.ErrorMessage # Returned from the Test
      }
   }

   Write-Output $output
}


# Ensure that the output is in UTF-8 format, hacky way to handle older PowerShell versions.
try {
   [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}
catch {
   $OutputEncoding = [System.Text.Encoding]::UTF8
}

# Entrypoint of the script call the check function and convert the result to JSON
Write-Output (Get-vlTemplateCheck | ConvertTo-Json -Compress)

# SIG # Begin signature block
# MIIooAYJKoZIhvcNAQcCoIIokTCCKI0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDzb1t+BnWETBW0
# 8ZbmmveKjcvYwBs+4IwyZ4TNOobY6KCCDbkwggawMIIEmKADAgECAhAIrUCyYNKc
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
# zgOyna7wokqBLvdrSiTF2of1k3HQUFUymRr0h3qjKOXx2cUxgho9MIIaOQIBATB9
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTECEA/jsqLSKYSprcwjW2RvMd4wDQYJYIZIAWUDBAIBBQCggZgw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwLAYKKwYBBAGCNwIBDDEeMBygGoAYAFQAZQBtAHAAbABhAHQAZQAu
# AHAAcwAxMC8GCSqGSIb3DQEJBDEiBCAFuDm6cXIyUnrt8GE2VfIB8QudI0SJw+k6
# 4RA1rV+W2DANBgkqhkiG9w0BAQEFAASCAYCJwJNSFaZa+9FUXgEcI0hnSLfEwoWK
# YFZVUqsk9hnVR8Qdbm4g036OqIP7WayFMInynEmN2SxHzEAcj7T+Xpy1se3OC+qq
# xPvBugfqxdOwrM3UtJHC0IjbJjqZRJG+df9nA2jdOkhFcEt3tU4iBnUxLD4p3yql
# zDmXb8UEmpmkPpd6kT6Ehk8H7eNkgj+GPD9AqTXYFZ5jdWI16BZjoUghkR3sIpc2
# akwyi8nymQZd5WIqKOmxvSBN7W1ivc7halt1+l6YBbu2xWgdNXbJJ/hGOqUMGINN
# pIluOjFZYBz5x8aSj1AwIkvjsSlMgyL58YJIlsn8GxK/lkPmTI1wRFl43J0lila0
# aMyvPUIe1Cjcb8BuZ9FeLCE6bc9e/SZq8ZrSKQCZkDRxq5acooheL1BheQwhuu5R
# Y6n/Ku+SeKLqi5tzV5ChGf9j8cD/jc292Eviy15bjEvI4pPsXN/ZDOD4HbAOPRCe
# BB9mwZF2gJ0rkahk3x5TWc8v5JPlx/NFtB2hghd2MIIXcgYKKwYBBAGCNwMDATGC
# F2IwghdeBgkqhkiG9w0BBwKgghdPMIIXSwIBAzEPMA0GCWCGSAFlAwQCAQUAMHcG
# CyqGSIb3DQEJEAEEoGgEZjBkAgEBBglghkgBhv1sBwEwMTANBglghkgBZQMEAgEF
# AAQgvaD1sHJx6vNMFoIljJznKspygYG7ObZWS5y7dsRLSIUCEDxVZ116rVp3a3gg
# ZlTUu94YDzIwMjYxMDAxMTAzOTI4WqCCEzowggbtMIIE1aADAgECAhAIT9wzT35F
# TtvDD4/5khg1MA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBU
# aW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwHhcNMjYwODA1MDAw
# MDAwWhcNMzcxMTA0MjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGln
# aUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2IFRp
# bWVzdGFtcCBSZXNwb25kZXIgMjAyNiAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAtnum8sn+zUr41JtMZbP9OMYw+HwJDpG5xkIu/lqcfNYmMX81YmsU
# iHLbh9ykpeWBGKTLhYBrAN9Tdg/QEzG32XcObmgIblnr0CoQ3WSAeDZ6nH6X6VkF
# yYkJw3QBJREwvm4UhLzSxmwPA7cFKRTEOMsmEEj6qJk/dqLEAL+oQYuOwE2UuiX1
# Vnul8YReIyWd4kgLn9gq6LNXM0UplkR6jL/QHxmb6fMoGBJYbnaUI7XD6cKDpekK
# 2SVMld4iDbzeHDtOaaxldH5IxuNusQ69nd8/ZXEiB5Hbxj3RlK13cX1W4DlFXKdv
# /CEhM8Cj1vvlmvhNroyPdRGbbpBlgyf8Wdu5N6ByhFwURn0U6ozlPoxN22v+fviU
# hP+6DR547OZnpBMWDfei1f5sVGwiiW/KQTWOK97g+4RJpPzPNV4VYMAwO2jM2Aty
# 2QYPVmOQTJm0msuXnJrSbl2gf9JylpkJlWXqk1Q4LJsxz+TELoQCZIljbgvTJgoP
# U2R12ydv8i1UqL/adelA0y7U9Pmmtbze9Xx3rtajC5SzQd1jgfwAwsa90v9YcSPd
# meoyoBBA/27cCL237l5DTYYPDLQ4ON3OLTGWnvRb6jDrf/T75gMRfUzSLCBQfBus
# m9+mSWRlC/Df6S/e9Q8i13CuhzOT2Jx+V/nlbXM4QoBwlUAhelwwJT0CAwEAAaOC
# AZUwggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFBTJY4owLtRK+26U8+bjQH71
# 7M3iMB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB/wQE
# AwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgwgYUw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcw
# AoZRaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0
# VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRYMFYw
# VKBSoFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAEGTAX
# MAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAI3FOmEe
# nVIK35msCYB+fShAsWvSYvLBItoNdAgQ2jIqrGsVsluXMJU/+mRebBc52s6lbKAv
# OVPXaizmKkMLLflEEKDZQx4CkS2t8aHPjkXha3hYZ010htFa3dhNgmalH5vuWvh3
# tTCf4frTS7gPtGc4Z/xaPhQ2AB1mR8eEe/WbH0RWHvVIl6VwQ3+g5FKNfN2N/DWJ
# kf13w2H+2GfqEfbd35Ww8CvoYBjLNIDTadcPWdgsjsiOaK/7EsKJgLjUNIVgvcaF
# OLLQ/GlrA+0ZHJoFUbOr5SJN8zykPspXIXlpDJY/gqFUZRROeab9GVgmhbdOJcD/
# 63RhxPahFUGbckRONqMe6DYAv6/mOG0pWd3cPStsdcS7buj5DyniwRY8yooMH6pt
# x5vpP/pZzBPBeZD2U4IsthyxB5Jaa8qrOkB5z160TXiM5ADMspZ0TfD9MJoq0tFp
# FPssKRFhWeEDYPvcUuN7U7lvcdHl4ezQ3NT/7Ffs1sR1yh/LRbdZ3B3Vc6q2WmD8
# mDC0p9kzl2o73iVtS946IkEj7FkRsZGww1teYxERROC745xrtjvcw9ZyyUjHZWGR
# IpJeMNsPquCDf0fkyHtB+J4AiNZqCQk23rxh+KbpyMTNVKItJ5l92Svl20U9NbqM
# BOVYl1h54NEYLJq1/xHWFKPNK903zJZA9P2DMIIGtDCCBJygAwIBAgIQDcesVwX/
# IZkuQEMiDDpJhjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UE
# ChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYD
# VQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcN
# MzgwMTE0MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQs
# IEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5n
# IFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAtHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oR
# jzUXMmxCqvkbsDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+Qd
# SKWM06qchUP+AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRu
# QL37QXbDhAktVJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0
# Xm+nt5pnYJU3Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQV
# ESYOszFI2Wv82wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2
# qHxJ0ucS638ZxqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF
# 0LJAQQZxst7VvwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgx
# CZSKi17yVp2NL+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9X
# r/u6bDTnYCTKIsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7O
# gWmnhFr4yUozZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOC
# AV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esri
# kFb2L9RJ7MtOMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcw
# AoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJv
# b3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQu
# Y29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwB
# BAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEw
# vb4LyLU0pn/N0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8
# G0iP5kvN2n7Jd2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40
# y8S4F3/a+Z1jEMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCD
# A/JYsq7pGdogP8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADV
# ZKON/gnZruMvNYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4E
# Wj7PtspIHBldNE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpV
# fHIqQ6Ku/qjTY6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0
# c1ugMZyZZd/BdHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7Oi
# gizwJWeukcyIPbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2
# rtY/9TCA6TD8dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz
# 0scmbKvFoW2jNrbM1pD2T7m3XDCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghA
# GFowDQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lD
# ZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGln
# aUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEw
# OTIzNTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZ
# MBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1
# c3RlZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQ
# c2jeu+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW
# 61bGl20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU
# 0RBEEC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzr
# yc/NrDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17c
# jo+A2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypu
# kQF8IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaP
# ZPfBaYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUl
# ibaaRBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESV
# GnZifvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2
# QXXeeqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZF
# X50g/KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1Ud
# EwEB/wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1Ud
# IwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5Bggr
# BgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
# bTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8v
# Y3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEG
# A1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0
# Gz22Ftf3v1cHvZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+A
# ufih9/Jy3iS8UgPITtAq3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51P
# pwYDE3cnRNTnf+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix
# 3P0c2PR3WlxUjG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVV
# a88nq2x2zm8jLfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6pe
# KOK5lDGCA3wwggN4AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lD
# ZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFt
# cGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCE/cM09+RU7bww+P+ZIYNTAN
# BglghkgBZQMEAgEFAKCB0TAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJ
# KoZIhvcNAQkFMQ8XDTI2MTAwMTEwMzkyOFowKwYLKoZIhvcNAQkQAgwxHDAaMBgw
# FgQUUdmr2gNJc9hPQmaspIJI5rNpxDkwLwYJKoZIhvcNAQkEMSIEIKgyO6bCfnfV
# O0GTG60DLd7tThxNeN4v9JKXVcOku4isMDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIE
# IC2gnaf0Ex+f5y22xebpyWVnVa8EPx6nQswNISDhQev8MA0GCSqGSIb3DQEBAQUA
# BIICAGRy8jAGJMtGrN6iSNksZruRlKvayF+z6baILpGuSpE7oAZSeKpQVIPXl23q
# wzAJRSW7ukjVRsiiVncBindTbGGajruZtBIkhMmbJG8PnFP2CZVdQQcTsU83tjXY
# A5ZEIDIxRnVPzoUrann24dwzQ4plq/HjnVZHMDhcu78cYUbl/SrQKH/Kdq6wtjl0
# xDdBntR7sHpetapKs6RldJ6c6gn2u19+iH47zPHP2qU4HPTs0Eo/LZxzmxREB+8i
# pYr+QCiWqtHi0XBtyvoupF3hobUdtiLqXfZ4gIxM/8ZGzO4qtgCYiQd08OCBdZVI
# rmg16kxOX/xP6S9EiLAFh3WrisuuFXDZKnatEJvz5sj2jo2oXphVlwkRKpXMHA4L
# 3rqPFwOf3MpteJxDr0YGhgHykxQ+OVNRpz0LHD80Nklm2QrRATy/Ip+nYFL4zoj7
# exwVOyWrmg4ZldRNpbRxK0viGGiZUYXWUhsjdRk56/wB6bOHC4yOrKcLR8ntvdMG
# lLN9aXIT64IBKnUx4v9NBmJcManvy4PhoeXW3u7qxapdQhPpzLiYjool3rXA232X
# hE5dXdpTGXBb4vyt4JUiizvo9iB1lYCyYrb4VKGUwo8Qs70QXyjRqA4TW5rWQFoY
# QH/CT9IpSeObQH4x0tkdufVDzNFxyN5mbeLjo9frMgS9xhXb
# SIG # End signature block
