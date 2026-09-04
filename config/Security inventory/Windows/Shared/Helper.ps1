#Requires -Version 3.0

#define global variable that contains a list of timers.
$global:debug_timers = @()

function Get-vlOsVersion {
   <#
    .SYNOPSIS
        Retruns the OS version
    .DESCRIPTION
        Retruns the OS version
    .OUTPUTS
        A string containing the OS version
    .EXAMPLE
        return Get-vlOsVersion
   #>

   $osVersion = (Get-CimInstance -ClassName Win32_OperatingSystem).Version

   return $osVersion
}

function  Get-vlIsWindowsServer {
   <#
    .SYNOPSIS
        Check if the OS is a Windows Server
    .DESCRIPTION
        Check if the OS is a Windows Server
    .OUTPUTS
        A boolean indicating if the OS is a Windows Server
    .EXAMPLE
        return Get-vlIsWindowsServer
    #>

   try {
      $os = Get-CimInstance -ClassName Win32_OperatingSystem
      if ($os.Caption -like "*Server*") {
         return $true
      }
      else {
         return $false
      }
   }
   catch {
      Write-Output $_.Exception.Message
      return $null
   }
}

function Convert-vlEnumToString ($object) {
   <#
    .SYNOPSIS
        Checks if the input object is an enum and converts it to a string
    .DESCRIPTION
        Checks if the input object is an enum and converts it to a string
    .OUTPUTS
         an object with all enums converted to strings
    .EXAMPLE
        Convert-vlEnumToString
    #>

   $outputObj = $object | ForEach-Object {
      if ($null -eq $_) {
         return ""
      }

      if ($_ -is [Enum]) {
         $_.ToString()
      }
      elseif ($_ -is [Array]) {
         $_ | ForEach-Object { Convert-vlEnumToString $_ }
      }
      elseif ($_ -is [PSCustomObject] -and $_.GetType().Name -eq 'PSCustomObject') {
         $properties = $_ | Get-Member -MemberType Properties
         $newObj = New-Object -TypeName PSCustomObject
         foreach ($prop in $properties) {
            $propValue = $_.($prop.Name)
            $newObj | Add-Member -MemberType NoteProperty -Name $prop.Name -Value (Convert-vlEnumToString $propValue)
         }
         return $newObj
      }
      else {
         return $_
      }
   }
   return $outputObj
}

function New-vlErrorObject {
   <#
    .SYNOPSIS
        Generate an error object for the result of a function
    .DESCRIPTION
        Generate an error object for the result of a function that can be returned to the caller
    .PARAMETER Context
        The context of the error/exception
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the error code and error message
    .EXAMPLE
        catch {
            return New-vlErrorObject -context $_
        }
    #>

   [CmdletBinding()]
   param (
      $context,
      $message = $null,
      $errorCode = $null
   )

   if ( $null -ne $context) {
      $finalCode = if ($context.Exception.HResult) { $context.Exception.HResult } else { 1 }
   }
   else {
      $finalCode = 1
   }

   if ( $null -ne $errorCode) {
      $finalCode = $errorCode
   }

   return [PSCustomObject]@{
      Result       = $null
      ErrorCode    = $finalCode
      ErrorMessage = if ( $null -ne $message) { $message } else { $context.Exception.Message }
      Score        = $null
      RiskScore    = $null
   }
}

function New-vlResultObject {
   <#
    .SYNOPSIS
        Generate a result object for the result of a function
    .DESCRIPTION
        Generate a result object for the result of a function that can be returned to the caller
    .PARAMETER result
        The result that should be returned
    .NOTES
        The result will be converted to JSON
        ConvertTo-Json was added in PowerShell 3.0
    .LINK
        https://uberagent.com
    .OUTPUTS
        A [psobject] containing the result, error code and error message will be set to empty
    .EXAMPLE
        New-vlResultObject($result)
    #>

   [CmdletBinding()]
   param (
      $result,
      $score,
      $riskScore
   )

   # check if top level attribues values of $result are empty or null and remove them
   if ($null -ne $result -and $result -is [psobject]) {
      $attributesToRemove = @()

      $result | Get-Member -MemberType NoteProperty | ForEach-Object {
         $value = $result.($_.Name)

         if ($null -eq $value -or
           ($value -is [string] -and [string]::IsNullOrEmpty($value)) -or
           ($value -is [array] -and $value.Count -eq 0) -or
           ($value -is [System.Collections.Generic.List[object]] -and $value.Count -eq 0)) {

            # The value is empty (null, empty string, empty array/list), exclude this property
            $attributesToRemove += $_.Name
         }
      }

      # check if $attributesToRemove contains any attributes and remove them
      if ($attributesToRemove.Count -gt 0) {
         foreach ($attribute in $attributesToRemove) {
            # remove the attribute from the result object
            $result.PSObject.Properties.Remove($attribute)
         }
      }
   }

   return [PSCustomObject]@{
      Result       = ConvertTo-Json $result -Compress -Depth 3
      ErrorCode    = 0
      ErrorMessage = ""
      Score        = $score
      RiskScore    = $riskScore
   }
}

function Get-vlRegValue {
   <#
    .SYNOPSIS
        Get the value of a registry key
    .DESCRIPTION
        Get the value of a registry key
    .PARAMETER Hive
        The hive of the registry key. Valid values are "HKLM", "HKU", "HKCU" and "HKCR"
    .PARAMETER Path
        The path to the registry key
    .PARAMETER Value
        The name of the value to read
    .PARAMETER IncludePolicies
        Checks also the GPO policies path
    .OUTPUTS
        The value of the registry key or $null if the key was not found
    .EXAMPLE
        Get-vlRegValue -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Value "ProductName"
    #>

   [CmdletBinding()]
   [OutputType([Object])]
   param (
      [Parameter(Mandatory = $true)]
      [ValidateSet("HKLM", "HKU", "HKCU", "HKCR")]
      [string]$Hive,
      [Parameter(Mandatory = $true)]
      [string]$Path,
      [Parameter(Mandatory = $false)]
      [string]$Value,
      [Parameter(Mandatory = $false)]
      [bool]$IncludePolicies = $false
   )

   process {
      try {
         #check if $Path starts with \ then remove it
         if ($Path.StartsWith("\")) {
            $Path = $Path.Substring(1)
         }

         $regKey = $null
         $regKeyValue = $null;
         if ($Hive -eq "HKCU") {
            # Get the registry key for the current user
            $regKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($Path);
         }
         elseif ($hive -eq "HKU") {
            # Get the registry key for all users
            $regKey = [Microsoft.Win32.Registry]::Users.OpenSubKey($Path);
         }
         elseif ($hive -eq "HKCR") {
            # Get the registry key for the classes root
            $regKey = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey($Path);
         }
         else {
            # Get the registry key for the local machine
            $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Path);
         }

         if ($IncludePolicies -eq $true) {
            # check if $path contains "SOFTWARE" if true then replace with "SOFTWARE\Policies\"
            $gpo_store32_path = $Path -replace "^SOFTWARE\\", "SOFTWARE\Policies\"
            $gpo_store32 = Get-vlRegValue -Hive $Hive -Path $gpo_store32_path -Value $Value

            $gpo_store64_path = $Path -replace "^SOFTWARE\\", "SOFTWARE\WOW6432Node\Policies\"
            $gpo_store64 = Get-vlRegValue -Hive $Hive -Path $gpo_store64_path -Value $Value

         }

         if ($null -ne $regKey) {
            $regKeyValue = $regKey.GetValue($Value);
         }

         if ($gpo_store32) {
            $regKeyValue = $gpo_store32
         }
         elseif ($gpo_store64) {
            $regKeyValue = $gpo_store64
         }

         return $regKeyValue;
      }
      catch {
         Write-Verbose "Registry $Hive\$Path was not found"
         return $null
      }
      finally {
         if ($null -ne $regKey) {
            Write-Verbose "Closing registry key $Hive\$Path"
            $regKey.Dispose()
         }
      }
   }

   end {
   }
}


function Get-vlRegSubkeys {
   <#
    .SYNOPSIS
        Read all the subkeys from a registry path
    .DESCRIPTION
        Read all the subkeys from a registry path
    .PARAMETER Hive
        The hive to read from. Valid values are "HKLM", "HKU" and "HKCU"
    .PARAMETER Path
        The path to the registry key
    .LINK
        https://uberagent.com
    .OUTPUTS

    .EXAMPLE
        return Get-vlRegSubkeys -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    #>

   [CmdletBinding()]
   [OutputType([Object])]
   param (
      [Parameter(Mandatory = $true)]
      [ValidateSet("HKLM", "HKU", "HKCU")]
      [string]$Hive,
      [Parameter(Mandatory = $true)]
      [string]$Path
   )
   begin {

   }

   process {
      try {
         $registryItems = @()

         #check if $Path starts with \ then remove it
         if ($Path.StartsWith("\")) {
            $Path = $Path.Substring(1)
         }

         $path = $Hive + ":\" + $Path
         if (Test-Path -Path $path) {
            $keys = Get-ChildItem -Path $path
            $registryItems = $keys | Foreach-Object {
               try {
                  #if Property length is > 0 then Get-ItemProperty else add the key to the array
                  if ($null -ne $_.Property) {
                     Get-ItemProperty $_.PsPath
                  }
                  else {
                     $_
                  }
               }
               catch {
                  $_
               }
            }
         }
         return $registryItems
      }
      catch {
         Write-Verbose "Error reading registry $Hive\$Path"
         Write-Verbose $_.Exception.Message

         return [Object]@()
      }
      finally {
      }
   }

   end {

   }
}

function Get-vlRegistryKeyValues {
   <#
    .SYNOPSIS
        Retrieves all value names and their associated values from a specified registry key.
    .DESCRIPTION
        This function fetches all value names and their corresponding values from a provided registry path. It allows querying different hives like HKLM, HKU, and HKCU.
    .PARAMETER Hive
        The registry hive to query from. Acceptable values are "HKLM", "HKU", and "HKCU".
    .PARAMETER Path
        Specifies the path to the desired registry key.
    .OUTPUTS
        System.Object. Outputs a custom object for each Value in the specified registry key which contains the ValueName and its associated Value.
    .EXAMPLE
        Get-vlRegistryKeyValues -Hive "HKLM" -Path "SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        This example queries the "SOFTWARE\Microsoft\Windows NT\CurrentVersion" key in the HKLM hive and returns all its value names and values.
#>

   param (
      [Parameter(Mandatory = $true)]
      [ValidateSet('HKLM', 'HKU', 'HKCU')]
      [string]$Hive,

      [Parameter(Mandatory = $true)]
      [ValidateNotNullOrEmpty()]
      [string]$Path
   )

   try {
      if ($Path.StartsWith("\")) {
         $Path = $Path.Substring(1)
      }

      $RegistryPath = $Hive + ":\" + $Path

      # Check if the Registry Key exists
      if (-not (Test-Path $RegistryPath)) {
         return [Object]@()
      }

      # Get value names and values from the Registry Key
      $key = Get-Item -Path $RegistryPath
      $outputObject = @{}
      $key.GetValueNames() | ForEach-Object {
         $outputObject[$_] = $key.GetValue($_)
      }

      return [PSCustomObject]$outputObject
   }
   catch {
      return [Object]@()
   }
}

function Get-vlHashTableKey {
   <#
    .SYNOPSIS
        Retrieves the key from a hashtable corresponding to a specified value.
    .DESCRIPTION
        This function takes as input a hashtable and a value. It searches the hashtable for entries where the value matches the provided value.
        It returns the key(s) of matching entries.
    .PARAMETERS
        - hashTable: The hashtable to search.
        - value: The value to search for in the hashtable.
    .OUTPUTS
        Returns the key(s) from the hashtable where the value matches the input value. If no match is found, returns $null. If multiple matches are found, returns all matching keys.
    .EXAMPLE
        $parsedProfile = Get-vlHashTableKey -hashTable $FW_PROFILES -value $rule.Profiles
    #>

   param(
      [Hashtable]$hashTable,
      [Object]$value
   )

   if ($null -ne $hashTable) {
      $hashTable.GetEnumerator() | Where-Object { $_.Value -eq $value } | ForEach-Object { $_.Name }
   }
   else {
      return $null
   }
}


function Get-vlHashTableKeys {
   <#
    .SYNOPSIS
        Returns the key names from a hashtable that correspond to the bits set in a given flag value.
    .DESCRIPTION
        This function takes a hashtable and a flag value as input. It uses bitwise operations to check which bits are set in the flag value.
        For each set bit, it finds the corresponding key in the hashtable and returns these keys.
    .PARAMETERS
        - hashTable: A hashtable where each value is a power of 2, corresponding to a bit position in a flag.
        - value: The flag value to check. This should be an integer where each set bit corresponds to a key in the hashtable.
    .OUTPUTS
        Returns a list of key names from the hashtable that correspond to the bits set in the flag value.
    .EXAMPLE
        $parsedProfile = Get-vlHashTableKeys -hashTable $FW_PROFILES -value $rule.Profiles
    #>

   param(
      [Hashtable]$hashTable,
      [Object]$value
   )

   if ($null -ne $hashTable) {
      $hashTable.GetEnumerator() | Where-Object { ($value -band $_.Value) -ne 0 } | ForEach-Object { $_.Name }
   }
   else {
      return $null
   }
}


function Get-vlTimeScore($time) {
   <#
    .SYNOPSIS
        Function that calculates the last sync score based on the time.
    .DESCRIPTION
        Function that calculates the last sync score based on the time.
    .OUTPUTS
        Returns the score based on the time.
    .EXAMPLE
        Get-vlTimeScore
    #>

   if ($null -eq $time) {
      return -3
   }

   #check if time has type DateTime if not then convert it
   if ($time.GetType().Name -ne "DateTime") {
      $time = [DateTime]$time
   }

   #check if time is less than 14 days
   if ($time -lt (Get-Date).AddDays(-14)) {
      return -3
   }

   #check if time is less than 7 days
   if ($time -lt (Get-Date).AddDays(-7)) {
      return -2
   }

   #check if time is less than 2 days
   if ($time -lt (Get-Date).AddDays(-2)) {
      return -1
   }

   return 0
}

function Get-vlTimeString {
   <#
   .SYNOPSIS
      Converts a timestamp to a formatted string representing the date and time.

   .DESCRIPTION
      The Get-vlTimeString function takes a timestamp as input and returns a formatted string representation of the date and time. It uses the "yyyy-MM-ddTHH:mm:ss" format.

   .PARAMETER timeStamp
      Specifies the timestamp to convert to a string representation. This parameter is mandatory.

   .OUTPUTS
      The function outputs a string representing the formatted date and time.

   .EXAMPLE
      Get-vlTimeString time (Get-Date)
      Returns the current date and time in the "yyyy-MM-ddTHH:mm:ss" format.

   .EXAMPLE
      Get-vlTimeString time $null
      Returns an empty string.
   #>

   [CmdletBinding()]
   [OutputType([string])]
   param (
      $time
   )

   try {
      if ($null -ne $time) {
         return $time.ToString("yyyy-MM-ddTHH:mm:ss")
      }
      else {
         return ""
      }
   }
   catch {
      return ""
   }
}

function Get-vlIsCmdletAvailable {
   [CmdletBinding()]
   [OutputType([bool])]
   param (
      [Parameter(Mandatory = $true)]
      [string]$CmdletName
   )

   try {
      $cmdlet = Get-Command $CmdletName -ErrorAction Stop
      if ($null -ne $cmdlet) {
         return $true
      }
      else {
         return $false
      }
   }
   catch {
      return $false
   }

}

function Test-vlBlockedProgram {
   <#
    .SYNOPSIS
        Tests if a program is blocked by tools like AppLocker or Windows Defender Application Control.
    .DESCRIPTION
        Tests if a program is blocked by tools like AppLocker or Windows Defender Application Control.
        Make sure to use the full path to the program to avoid potential security risks.
    .OUTPUTS
        A [bool] indicating if the program is blocked or not
    .EXAMPLE
        Test-vlBlockedProgram
    #>

   Param(
      [string]$ProgramPath
   )

   $result = [PSCustomObject]@{
      FileExists = $false
      IsBlocked  = $null
   }

   # Check if the program exists at the specified path
   if (-not (Test-Path $ProgramPath)) {
      return $result
   }
   else {
      $result.FileExists = $true
   }

   $processStartInfo = New-Object System.Diagnostics.ProcessStartInfo

   $processStartInfo.FileName = $ProgramPath
   $processStartInfo.RedirectStandardError = $true
   $processStartInfo.RedirectStandardOutput = $true
   $processStartInfo.UseShellExecute = $false
   $processStartInfo.CreateNoWindow = $true

   $process = New-Object System.Diagnostics.Process
   $process.StartInfo = $processStartInfo

   try {
      $process.Start() | Out-Null
      $process.WaitForExit()

      # the program is not blocked
      $result.IsBlocked = $false
      return $result
   }
   catch {
      # an exception occurred, indicating the program is blocked
      $result.IsBlocked = $true
      return $result
   }
}

##### Debugging utilities #####

function Add-vlTimer {
   <#
    .SYNOPSIS
        Start a timer
    .DESCRIPTION
        Start a timer
    .PARAMETER Name
        The name of the timer
    .LINK
        https://uberagent.com
    .OUTPUTS

    .EXAMPLE
        Add-vlTimer -Name "timer1"
    #>

   [CmdletBinding()]
   param (
      [Parameter(Mandatory = $true)]
      [string]$Name
   )
   begin {

   }

   process {
      $timer = New-Object -TypeName psobject -Property @{
         Name  = $Name
         Start = (Get-Date)
      }
      $global:debug_timers += $timer
   }

   end {

   }
}

function Restart-vlTimer {
   <#
    .SYNOPSIS
        Restart a timer
    .DESCRIPTION
        Restart a timer
    .PARAMETER Name
        The name of the timer
    .LINK
        https://uberagent.com
    .OUTPUTS

    .EXAMPLE
        Restart-vlTimer -Name "timer1"
    #>

   [CmdletBinding()]
   param (
      [Parameter(Mandatory = $true)]
      [string]$Name
   )
   begin {

   }

   process {
      # check if $Name is not null or empty
      if ([string]::IsNullOrEmpty($Name)) {
         return
      }

      $timer = $global:debug_timers | Where-Object { $_.Name -eq $Name }
      if ($null -ne $timer) {
         $timer.Start = (Get-Date)
      }
   }

   end {

   }
}

function Get-vlTimerElapsedTime {
   <#
    .SYNOPSIS
        Get the elapsed time for a timer by name and give the option to select between seconds and milliseconds. The default is milliseconds.
    .DESCRIPTION
        Get the elapsed time for a timer by name and give the option to select between seconds and milliseconds. The default is milliseconds.
    .PARAMETER Name
        The name of the timer
    .PARAMETER Unit
        The unit of time to return. Valid values are "sec" and "ms"
    .LINK
        https://uberagent.com
    .OUTPUTS

    .EXAMPLE
        Get-vlTimerElapsedTime -Name "timer1"
    #>

   [CmdletBinding()]
   [OutputType([System.Int64])]
   param (
      [Parameter(Mandatory = $true)]
      [string]$Name,
      [ValidateSet("sec", "ms")]
      [string]$Unit = "ms"
   )
   begin {

   }

   process {
      # check if $Name is not null or empty
      if ([string]::IsNullOrEmpty($Name)) {
         return
      }

      $timer = $global:debug_timers | Where-Object { $_.Name -eq $Name }
      if ($null -ne $timer) {
         $elapsed = (Get-Date) - $timer.Start
         if ($Unit -eq "sec") {
            return $elapsed.TotalSeconds
         }
         else {
            return $elapsed.TotalMilliseconds
         }
      }
      else {
         return [System.Int64]0
      }
   }

   end {

   }
}

function Write-vlDebugLog {
   <#
    .SYNOPSIS
        Write the elapsed time for a timer by name and give the option to select between seconds and milliseconds. The default is milliseconds.
    .DESCRIPTION
        Write the elapsed time for a timer by name and give the option to select between seconds and milliseconds. The default is milliseconds.
    .PARAMETER Name
        The name of the timer
    .PARAMETER Unit
        The unit of time to return. Valid values are "sec" and "ms"
    .PARAMETER UseFile
        Write the elapsed time to a file
    .LINK
        https://uberagent.com
    .OUTPUTS

    .EXAMPLE
        Write-vlTimerElapsedTime -Name "timer1"
    #>

   [CmdletBinding()]
   param (
      [Parameter(Mandatory = $true)]
      [string]$Data,
      [Parameter(Mandatory = $false)]
      [bool]$UseFile = $false
   )

   process {
      # get current time and format it for the log with milliseconds like 2019-01-01 12:00:00.000
      $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"

      if ($UseFile) {
         # use C:\Windows\Temp as default log path
         $logPath = "C:\\Windows\\Temp\\ua_script_debug.log"

         Add-Content -Path $logPath -Value "[$time] - ${data}"
      }
      else {
         Write-Debug "${Name}: $elapsed $Unit"
      }
   }

   end {

   }
}

function Write-vlTimerElapsedTime {
   <#
    .SYNOPSIS
        Write the elapsed time for a timer by name and give the option to select between seconds and milliseconds. The default is milliseconds.
    .DESCRIPTION
        Write the elapsed time for a timer by name and give the option to select between seconds and milliseconds. The default is milliseconds.
    .PARAMETER Name
        The name of the timer
    .PARAMETER Unit
        The unit of time to return. Valid values are "sec" and "ms"
    .PARAMETER UseFile
        Write the elapsed time to a file
    .LINK
        https://uberagent.com
    .OUTPUTS

    .EXAMPLE
        Write-vlTimerElapsedTime -Name "timer1"
    #>

   [CmdletBinding()]
   param (
      [Parameter(Mandatory = $true)]
      [string]$Name,
      [Parameter(Mandatory = $false)]
      [bool]$UseFile = $false,
      [Parameter(Mandatory = $false)]
      [ValidateSet("sec", "ms")]
      [string]$Unit = "ms"
   )

   process {
      $elapsed = Get-vlTimerElapsedTime -Name $Name -Unit $Unit
      Write-vlDebugLog -Data "${Name}: $elapsed $Unit" -UseFile $UseFile
   }

}
# SIG # Begin signature block
# MIIonQYJKoZIhvcNAQcCoIIojjCCKIoCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCnHWILwS/o5mAw
# +qkba2aHhHEyKP9k5yPslcZkOwtXdKCCDbkwggawMIIEmKADAgECAhAIrUCyYNKc
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
# zgOyna7wokqBLvdrSiTF2of1k3HQUFUymRr0h3qjKOXx2cUxgho6MIIaNgIBATB9
# MGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UE
# AxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNBNDA5NiBTSEEz
# ODQgMjAyMSBDQTECEA/jsqLSKYSprcwjW2RvMd4wDQYJYIZIAWUDBAIBBQCggZQw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwKAYKKwYBBAGCNwIBDDEaMBigFoAUAEgAZQBsAHAAZQByAC4AcABz
# ADEwLwYJKoZIhvcNAQkEMSIEIHVX6dNnqDPRKPQI02fUjFvPj7gfBaFBbkpITE6r
# QL5/MA0GCSqGSIb3DQEBAQUABIIBgDQWzsOgAE8TS5Jb0xtOyurD4GKY7NMrtgcj
# H36Hq/z+1jBgmzg9nII58ijefJ2hJ1D2hBBRLwX98Heavlz7qyIVzn1anXCZzEIX
# GE0o3sluqTVt+p+eBuBjWUc9dg4SnXwZ9IbFSdcTRpAPXp8fb6M7vvfYUnGeGvt8
# gJ/hO7JonGYZiFXuW9Oz9KckEcDqkuFKoTbsGwG+pJTlxaKT+X/GHNrj+OflXtp1
# DOnVC2uDhyLP+pcGLeFBtYDzZYmuRsQzYPf7GlLSYGvHLOqDnwprUTqz1Ibz3qFY
# l9Ql/HfAQKDcb1ez7iT/5yMUV0S1WDDN+JdBcKmopu1FTth+w2fsdItx16nW4ZfA
# RRStBMbM6+obnnZf06RKxpQN2iYKy3c+gt7zGjlNHmJvNppjnf4zOplXygtwiF3M
# eXQKTn15td6KvL5DElpdXyWvR8rNlYJi9sMVZmSkz/3hkEDqwPsifphJBm6O8Z1d
# MhZkHJBrzakS9XOICYrK0cpUrKd8nqGCF3cwghdzBgorBgEEAYI3AwMBMYIXYzCC
# F18GCSqGSIb3DQEHAqCCF1AwghdMAgEDMQ8wDQYJYIZIAWUDBAIBBQAweAYLKoZI
# hvcNAQkQAQSgaQRnMGUCAQEGCWCGSAGG/WwHATAxMA0GCWCGSAFlAwQCAQUABCBJ
# trsSs0dpC7SxxPl9l1r+Ld/O7Zydad9BslvsNphI1QIRAITfmtW0neRadM1j+Xio
# kyIYDzIwMjYwOTA0MTQxMTMxWqCCEzowggbtMIIE1aADAgECAhAIT9wzT35FTtvD
# D4/5khg1MA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1l
# U3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwHhcNMjYwODA1MDAwMDAw
# WhcNMzcxMTA0MjM1OTU5WjBjMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNl
# cnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNIQTI1NiBSU0E0MDk2IFRpbWVz
# dGFtcCBSZXNwb25kZXIgMjAyNiAxMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAtnum8sn+zUr41JtMZbP9OMYw+HwJDpG5xkIu/lqcfNYmMX81YmsUiHLb
# h9ykpeWBGKTLhYBrAN9Tdg/QEzG32XcObmgIblnr0CoQ3WSAeDZ6nH6X6VkFyYkJ
# w3QBJREwvm4UhLzSxmwPA7cFKRTEOMsmEEj6qJk/dqLEAL+oQYuOwE2UuiX1Vnul
# 8YReIyWd4kgLn9gq6LNXM0UplkR6jL/QHxmb6fMoGBJYbnaUI7XD6cKDpekK2SVM
# ld4iDbzeHDtOaaxldH5IxuNusQ69nd8/ZXEiB5Hbxj3RlK13cX1W4DlFXKdv/CEh
# M8Cj1vvlmvhNroyPdRGbbpBlgyf8Wdu5N6ByhFwURn0U6ozlPoxN22v+fviUhP+6
# DR547OZnpBMWDfei1f5sVGwiiW/KQTWOK97g+4RJpPzPNV4VYMAwO2jM2Aty2QYP
# VmOQTJm0msuXnJrSbl2gf9JylpkJlWXqk1Q4LJsxz+TELoQCZIljbgvTJgoPU2R1
# 2ydv8i1UqL/adelA0y7U9Pmmtbze9Xx3rtajC5SzQd1jgfwAwsa90v9YcSPdmeoy
# oBBA/27cCL237l5DTYYPDLQ4ON3OLTGWnvRb6jDrf/T75gMRfUzSLCBQfBusm9+m
# SWRlC/Df6S/e9Q8i13CuhzOT2Jx+V/nlbXM4QoBwlUAhelwwJT0CAwEAAaOCAZUw
# ggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFBTJY4owLtRK+26U8+bjQH717M3i
# MB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ7MtOMA4GA1UdDwEB/wQEAwIH
# gDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCBlQYIKwYBBQUHAQEEgYgwgYUwJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBdBggrBgEFBQcwAoZR
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGlt
# ZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3J0MF8GA1UdHwRYMFYwVKBS
# oFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRp
# bWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNybDAgBgNVHSAEGTAXMAgG
# BmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBAI3FOmEenVIK
# 35msCYB+fShAsWvSYvLBItoNdAgQ2jIqrGsVsluXMJU/+mRebBc52s6lbKAvOVPX
# aizmKkMLLflEEKDZQx4CkS2t8aHPjkXha3hYZ010htFa3dhNgmalH5vuWvh3tTCf
# 4frTS7gPtGc4Z/xaPhQ2AB1mR8eEe/WbH0RWHvVIl6VwQ3+g5FKNfN2N/DWJkf13
# w2H+2GfqEfbd35Ww8CvoYBjLNIDTadcPWdgsjsiOaK/7EsKJgLjUNIVgvcaFOLLQ
# /GlrA+0ZHJoFUbOr5SJN8zykPspXIXlpDJY/gqFUZRROeab9GVgmhbdOJcD/63Rh
# xPahFUGbckRONqMe6DYAv6/mOG0pWd3cPStsdcS7buj5DyniwRY8yooMH6ptx5vp
# P/pZzBPBeZD2U4IsthyxB5Jaa8qrOkB5z160TXiM5ADMspZ0TfD9MJoq0tFpFPss
# KRFhWeEDYPvcUuN7U7lvcdHl4ezQ3NT/7Ffs1sR1yh/LRbdZ3B3Vc6q2WmD8mDC0
# p9kzl2o73iVtS946IkEj7FkRsZGww1teYxERROC745xrtjvcw9ZyyUjHZWGRIpJe
# MNsPquCDf0fkyHtB+J4AiNZqCQk23rxh+KbpyMTNVKItJ5l92Svl20U9NbqMBOVY
# l1h54NEYLJq1/xHWFKPNK903zJZA9P2DMIIGtDCCBJygAwIBAgIQDcesVwX/IZku
# QEMiDDpJhjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQD
# ExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgw
# MTE0MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIElu
# Yy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJT
# QTQwOTYgU0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAtHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUX
# MmxCqvkbsDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM
# 06qchUP+AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37
# QXbDhAktVJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+n
# t5pnYJU3Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYO
# szFI2Wv82wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ
# 0ucS638ZxqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJA
# QQZxst7VvwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSK
# i17yVp2NL+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6
# bDTnYCTKIsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmn
# hFr4yUozZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0w
# ggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2
# L9RJ7MtOMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB
# /wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYI
# KwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1
# aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RH
# NC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29t
# L0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIw
# CwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4L
# yLU0pn/N0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP
# 5kvN2n7Jd2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4
# F3/a+Z1jEMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JY
# sq7pGdogP8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON
# /gnZruMvNYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7P
# tspIHBldNE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIq
# Q6Ku/qjTY6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ug
# MZyZZd/BdHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7Oigizw
# JWeukcyIPbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/
# 9TCA6TD8dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scm
# bKvFoW2jNrbM1pD2T7m3XDCCBY0wggR1oAMCAQICEA6bGI750C3n79tQ4ghAGFow
# DQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0
# IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNl
# cnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAwMDAwMFoXDTMxMTEwOTIz
# NTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcG
# A1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3Rl
# ZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv+aQc2je
# u+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2uexuEDcQwH/MbpDgW61bG
# l20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKvaJNwwrK6dZlqczKU0RBE
# EC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/ghYZs06wXGXuxbGrzryc/N
# rDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOtyU9e5TXnMcvak17cjo+A
# 2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCRcKtVgkEy19sEcypukQF8
# IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8oU85tRFYF/ckXEaPZPfB
# aYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m1O+SkjqePdwA5EUlibaa
# RBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y1YxwLEFgqrFjGESVGnZi
# fvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkliWzlDlJRR3S+Jqy2QXXe
# eqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/EIFFrb7GrhotPwtZFX50g
# /KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOCATowggE2MA8GA1UdEwEB
# /wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/nupiuHA9PMB8GA1UdIwQY
# MBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB/wQEAwIBhjB5BggrBgEF
# BQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBD
# BggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqgOKA2hjRodHRwOi8vY3Js
# My5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3JsMBEGA1Ud
# IAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEAcKC/Q1xV5zhfoKN0Gz22
# Ftf3v1cHvZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU9BNKei8ttzjv9P+Aufih
# 9/Jy3iS8UgPITtAq3votVs/59PesMHqai7Je1M/RQ0SbQyHrlnKhSLSZy51PpwYD
# E3cnRNTnf+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1RmppVLC4oVaO7KTVPeix3P0c
# 2PR3WlxUjG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxYoA5AY8WYIsGyWfVVa88n
# q2x2zm8jLfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0VysGMNNn3O3AamfV6peKOK5
# lDGCA3wwggN4AgEBMH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0
# LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGlu
# ZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCE/cM09+RU7bww+P+ZIYNTANBglg
# hkgBZQMEAgEFAKCB0TAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZI
# hvcNAQkFMQ8XDTI2MDkwNDE0MTEzMVowKwYLKoZIhvcNAQkQAgwxHDAaMBgwFgQU
# Udmr2gNJc9hPQmaspIJI5rNpxDkwLwYJKoZIhvcNAQkEMSIEII+7DqGTsmy7NvQE
# SebF0c97KMlkRmteXwcP3dbaG0twMDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIEIC2g
# naf0Ex+f5y22xebpyWVnVa8EPx6nQswNISDhQev8MA0GCSqGSIb3DQEBAQUABIIC
# AF9Yc2i5Lotu9cDtKHoiYh0x3DhlE1nFDX5F0G2uucIw2vm2d3eAMmvKgsnA3EA/
# M6decAapUmjNhAz0jEPORjtAcaqxYVxMeM1CLGlISUHG8orZYEhJPnXYN772mXQM
# +cFdJAIe6J8BQIIjT1mIaNvZhm8petYxs6kvQ45vzmYGLMRaBQYlPDSAWP3c1GYt
# CsKgv5Ttxu6LO/UdIOxOinKdhpF79H7rB372dw8YBaLq7dzwg+LppWl55HDU0Qq4
# KKEkWdFbrOsAaV6g5GiO3krdFR4xCjiuiF4fD1grax7mWJ0FBqt5jGdMyeF6slVL
# f+EAj6ocWYNXgZNsz+DgymRnDnFXwivV2IzlWuTpJc4Zj3vawH/5gF2FXiCo43dE
# VNvnNu1+FdN6vCJrgGKy9gtQc0vpaXeZTIFJ+9BtFZFrGTxTnftJEcVEaz4ta5Ji
# rhsKc/XVVOArGpwFB7eqoe6urXMtTAUNMIqqRzn73j4y7t/WI3qaKoXlSzjkoBgv
# xAZUMkC7HS1nexAGHdHaFB4QxNn1xBR+TDfuAs3Ii0NPU2lvRKcrhLnbbUo63zci
# a6zDLtQgJiqWbSJw1ZAsFAUuPG2Pojssj3Fb2rsZWxKKXy5dDOQCv95HAmy5OrUb
# DxbgRhRl//fHEr8AArW12598B2DZHVBblIgp0eeKXA2R
# SIG # End signature block
