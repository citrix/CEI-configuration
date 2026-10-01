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
# MIIooQYJKoZIhvcNAQcCoIIokjCCKI4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
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
# zgOyna7wokqBLvdrSiTF2of1k3HQUFUymRr0h3qjKOXx2cUxgho+MIIaOgIBATB9
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
# BB9mwZF2gJ0rkahk3x5TWc8v5JPlx/NFtB2hghd3MIIXcwYKKwYBBAGCNwMDATGC
# F2MwghdfBgkqhkiG9w0BBwKgghdQMIIXTAIBAzEPMA0GCWCGSAFlAwQCAQUAMHgG
# CyqGSIb3DQEJEAEEoGkEZzBlAgEBBglghkgBhv1sBwEwMTANBglghkgBZQMEAgEF
# AAQgvaD1sHJx6vNMFoIljJznKspygYG7ObZWS5y7dsRLSIUCEQCCH3bmIrn5jl04
# 123D6U/jGA8yMDI2MTAwMTExNTkwNlqgghM6MIIG7TCCBNWgAwIBAgIQCE/cM09+
# RU7bww+P+ZIYNTANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# VGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI2MDgwNTAw
# MDAwMFoXDTM3MTEwNDIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRp
# Z2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBU
# aW1lc3RhbXAgUmVzcG9uZGVyIDIwMjYgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBALZ7pvLJ/s1K+NSbTGWz/TjGMPh8CQ6RucZCLv5anHzWJjF/NWJr
# FIhy24fcpKXlgRiky4WAawDfU3YP0BMxt9l3Dm5oCG5Z69AqEN1kgHg2epx+l+lZ
# BcmJCcN0ASURML5uFIS80sZsDwO3BSkUxDjLJhBI+qiZP3aixAC/qEGLjsBNlLol
# 9VZ7pfGEXiMlneJIC5/YKuizVzNFKZZEeoy/0B8Zm+nzKBgSWG52lCO1w+nCg6Xp
# CtklTJXeIg283hw7TmmsZXR+SMbjbrEOvZ3fP2VxIgeR28Y90ZStd3F9VuA5RVyn
# b/whITPAo9b75Zr4Ta6Mj3URm26QZYMn/FnbuTegcoRcFEZ9FOqM5T6MTdtr/n74
# lIT/ug0eeOzmZ6QTFg33otX+bFRsIolvykE1jive4PuESaT8zzVeFWDAMDtozNgL
# ctkGD1ZjkEyZtJrLl5ya0m5doH/ScpaZCZVl6pNUOCybMc/kxC6EAmSJY24L0yYK
# D1Nkddsnb/ItVKi/2nXpQNMu1PT5prW83vV8d67WowuUs0HdY4H8AMLGvdL/WHEj
# 3ZnqMqAQQP9u3Ai9t+5eQ02GDwy0ODjdzi0xlp70W+ow63/0++YDEX1M0iwgUHwb
# rJvfpklkZQvw3+kv3vUPItdwroczk9icflf55W1zOEKAcJVAIXpcMCU9AgMBAAGj
# ggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQUyWOKMC7USvtulPPm40B+
# 9ezN4jAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8E
# BAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGF
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUH
# MAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRH
# NFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBW
# MFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# RzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkw
# FzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQCNxTph
# Hp1SCt+ZrAmAfn0oQLFr0mLywSLaDXQIENoyKqxrFbJblzCVP/pkXmwXOdrOpWyg
# LzlT12os5ipDCy35RBCg2UMeApEtrfGhz45F4Wt4WGdNdIbRWt3YTYJmpR+b7lr4
# d7Uwn+H600u4D7RnOGf8Wj4UNgAdZkfHhHv1mx9EVh71SJelcEN/oORSjXzdjfw1
# iZH9d8Nh/thn6hH23d+VsPAr6GAYyzSA02nXD1nYLI7Ijmiv+xLCiYC41DSFYL3G
# hTiy0PxpawPtGRyaBVGzq+UiTfM8pD7KVyF5aQyWP4KhVGUUTnmm/RlYJoW3TiXA
# /+t0YcT2oRVBm3JETjajHug2AL+v5jhtKVnd3D0rbHXEu27o+Q8p4sEWPMqKDB+q
# bceb6T/6WcwTwXmQ9lOCLLYcsQeSWmvKqzpAec9etE14jOQAzLKWdE3w/TCaKtLR
# aRT7LCkRYVnhA2D73FLje1O5b3HR5eHs0NzU/+xX7NbEdcofy0W3Wdwd1XOqtlpg
# /JgwtKfZM5dqO94lbUveOiJBI+xZEbGRsMNbXmMREUTgu+Oca7Y73MPWcslIx2Vh
# kSKSXjDbD6rgg39H5Mh7QfieAIjWagkJNt68Yfim6cjEzVSiLSeZfdkr5dtFPTW6
# jATlWJdYeeDRGCyatf8R1hSjzSvdN8yWQPT9gzCCBrQwggScoAMCAQICEA3HrFcF
# /yGZLkBDIgw6SYYwDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCVVMxFTATBgNV
# BAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8G
# A1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MB4XDTI1MDUwNzAwMDAwMFoX
# DTM4MDExNDIzNTk1OVowaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0
# LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGlu
# ZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBALR4MdMKmEFyvjxGwBysddujRmh0tFEXnU2tjQ2UtZmWgyxU7UNq
# EY81FzJsQqr5G7A6c+Gh/qm8Xi4aPCOo2N8S9SLrC6Kbltqn7SWCWgzbNfiR+2fk
# HUiljNOqnIVD/gG3SYDEAd4dg2dDGpeZGKe+42DFUF0mR/vtLa4+gKPsYfwEu7EE
# bkC9+0F2w4QJLVSTEG8yAR2CQWIM1iI5PHg62IVwxKSpO0XaF9DPfNBKS7Zazch8
# NF5vp7eaZ2CVNxpqumzTCNSOxm+SAWSuIr21Qomb+zzQWKhxKTVVgtmUPAW35xUU
# FREmDrMxSNlr/NsJyUXzdtFUUt4aS4CEeIY8y9IaaGBpPNXKFifinT7zL2gdFpBP
# 9qh8SdLnEut/GcalNeJQ55IuwnKCgs+nrpuQNfVmUB5KlCX3ZA4x5HHKS+rqBvKW
# xdCyQEEGcbLe1b8Aw4wJkhU1JrPsFfxW1gaou30yZ46t4Y9F20HHfIY4/6vHespY
# MQmUiote8ladjS/nJ0+k6MvqzfpzPDOy5y6gqztiT96Fv/9bH7mQyogxG9QEPHrP
# V6/7umw052AkyiLA6tQbZl1KhBtTasySkuJDpsZGKdlsjg4u70EwgWbVRSX1Wd4+
# zoFpp4Ra+MlKM2baoD6x0VR4RjSpWM8o5a6D8bpfm4CLKczsG7ZrIGNTAgMBAAGj
# ggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBTvb1NK6eQGfHrK
# 4pBW9i/USezLTjAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/57qYrhwPTzAOBgNV
# HQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYIKwYBBQUHAQEEazBp
# MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUH
# MAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRS
# b290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1UdIAQZMBcwCAYGZ4EM
# AQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAF877FoAc/gc9EXZx
# ML2+C8i1NKZ/zdCHxYgaMH9Pw5tcBnPw6O6FTGNpoV2V4wzSUGvI9NAzaoQk97fr
# PBtIj+ZLzdp+yXdhOP4hCFATuNT+ReOPK0mCefSG+tXqGpYZ3essBS3q8nL2UwM+
# NMvEuBd/2vmdYxDCvwzJv2sRUoKEfJ+nN57mQfQXwcAEGCvRR2qKtntujB71WPYA
# gwPyWLKu6RnaID/B0ba2H3LUiwDRAXx1Neq9ydOal95CHfmTnM4I+ZI2rVQfjXQA
# 1WSjjf4J2a7jLzWGNqNX+DF0SQzHU0pTi4dBwp9nEC8EAqoxW6q17r0z0noDjs6+
# BFo+z7bKSBwZXTRNivYuve3L2oiKNqetRHdqfMTCW/NmKLJ9M+MtucVGyOxiDf06
# VXxyKkOirv6o02OoXN4bFzK0vlNMsvhlqgF2puE6FndlENSmE+9JGYxOGLS/D284
# NHNboDGcmWXfwXRy4kbu4QFhOm0xJuF2EZAOk5eCkhSxZON3rGlHqhpB/8MluDez
# ooIs8CVnrpHMiD2wL40mm53+/j7tFaxYKIqL0Q4ssd8xHZnIn/7GELH3IdvG2XlM
# 9q7WP/UwgOkw/HQtyRN62JK4S1C8uw3PdBunvAZapsiI5YKdvlarEvf8EA+8hcpS
# M9LHJmyrxaFtoza2zNaQ9k+5t1wwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOII
# QBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0Rp
# Z2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTEx
# MDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/m
# kHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4
# FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMy
# lNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq8
# 68nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe
# 3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMq
# bpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxG
# j2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORF
# JYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhE
# lRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0vias
# tkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LW
# RV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNV
# HRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNV
# HSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYI
# KwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
# b20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDov
# L2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDAR
# BgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6Cj
# dBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/
# gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcud
# T6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3o
# sdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1
# VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eq
# XijiuZQxggN8MIIDeAIBATB9MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3Rh
# bXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTECEAhP3DNPfkVO28MPj/mSGDUw
# DQYJYIZIAWUDBAIBBQCggdEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMBwG
# CSqGSIb3DQEJBTEPFw0yNjEwMDExMTU5MDZaMCsGCyqGSIb3DQEJEAIMMRwwGjAY
# MBYEFFHZq9oDSXPYT0JmrKSCSOazacQ5MC8GCSqGSIb3DQEJBDEiBCAGK16dgsbE
# WyiXu827Hr+PdtPvQhvt3pLqC9PSZXz6ODA3BgsqhkiG9w0BCRACLzEoMCYwJDAi
# BCAtoJ2n9BMfn+cttsXm6cllZ1WvBD8ep0LMDSEg4UHr/DANBgkqhkiG9w0BAQEF
# AASCAgCXFefuClYhDppxuBo2aS72Vik301e1WEizjfr0IFDCrBTW5FImYx8BURNO
# TV+Now6Bk64s4OB80aTnpJV9Ro3I5BVeP4DDwHaFh2K3aolYPufdZV/1oQGOzHeL
# I58Oq5FUp/V69zXlsgT/G2KP5pCGoVzc0CKbDosmv9I3pkMoWKIcmvtVlMvpy4i7
# 76yVGJR19PRozegsj5rSwon8Ak2yiwnKmUrB/1MQHiacZ+8vcs1vP/x1OnAN9eRZ
# 1r8IIAhthny8MZrZSzI/AhkeKbTrp8lV/wX3OVdKqLnCLjEUtgytHuzb0kqFkCh0
# zHKFK6ZS5IXohqdVTLnNT+izhwRaoi94OAqHDLipBnldBx7rTnmrjwaA6T2y5hnp
# CDJclrQGb0hyByS2DkEimG4pf23qIorrUf9axgvvivkJxpIB1PiC0bRiASqglZxJ
# XpyAVY93+5O63fpB1jp4OSwZslnh3Xszd6GcBiIFad3z6OC9XC2Qu0VO1EsEPh8B
# OJWzNaGhlzXf0zQ1Z3yAatLmr6TK8YGSveTdm1Wak7ob359DAB7Dl9eER4zPK79a
# 05xPETdkWGwLehnZPuGI3Quu4r3OCOKrlZjN465l9zf1MprSw0H2LJqqK/6oqzjP
# XUW16guLOnTcLig5gB5KexXicLbEXeW9nVmT6Nkv/3DAQ9rMWA==
# SIG # End signature block
