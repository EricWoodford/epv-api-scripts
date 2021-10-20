<#
    Creates CyberArk vaults based off AD Accounts
    
#>


[CmdletBinding()]
[OutputType()]
Param
(
    [Parameter(Mandatory = $true)]
    [System.Management.Automation.CredentialAttribute()]$Credentials
)



# Get Script Location 
$ScriptFullPath = $MyInvocation.MyCommand.Path
$ScriptLocation = Split-Path -Parent $ScriptFullPath
$ScriptParameters = @()
$PSBoundParameters.GetEnumerator() | ForEach-Object { $ScriptParameters += ("-{0} '{1}'" -f $_.Key, $_.Value) }
$global:g_ScriptCommand = "{0} {1}" -f $ScriptFullPath, $($ScriptParameters -join ' ')

# Set Log file path
$global:LOG_DATE = $(Get-Date -Format yyyyMMdd) + "-" + $(Get-Date -Format HHmmss)
$global:LOG_FILE_PATH = "$ScriptLocation\GetSecret_$LOG_DATE.log"

$InDebug = $PSBoundParameters.Debug.IsPresent
$InVerbose = $PSBoundParameters.Verbose.IsPresent

Function Get-LogonHeader {
    <# 
    .SYNOPSIS 
        Get-LogonHeader 
    .DESCRIPTION
        Get-LogonHeader - authenticate with CyberArk rest API using native CyberArk account credentials. 
    .PARAMETER Credentials
        The REST API Credentials to authenticate
    #>
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.CredentialAttribute()]$Credentials,
        [Parameter(Mandatory = $false)]
        [ValidateScript( { ($_ -ge 0) -and ($_ -lt 100) })]
        [int]$ConnectionNumber = 0
    )
	
    if ([string]::IsNullOrEmpty($g_LogonHeader))
    {
        # Disable SSL Verification to contact PVWA
        If ($DisableSSLVerify)
        {
            Disable-SSLVerification
        }
		
        # Create the POST Body for the Logon
        # ----------------------------------
        If ($ConnectionNumber -eq 0)
        {
            $logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password } | ConvertTo-Json
        }
        elseif ($ConnectionNumber -gt 0)
        {
            $logonBody = @{ username = $Credentials.username.Replace('\', ''); password = $Credentials.GetNetworkCredential().password; connectionNumber = $ConnectionNumber } | ConvertTo-Json
        }
        try
        {
            # Logon
            $logonToken = Invoke-RestMethod -Method Post -Uri $URL_Logon -Body $logonBody -ContentType "application/json" -TimeoutSec 2700
			
            # Clear logon body
            $logonBody = ""
        }
        catch
        {
            Throw $(New-Object System.Exception ("Get-LogonHeader: $($_.Exception.Response.StatusDescription)", $_.Exception))
        }

        $logonHeader = $null
        If ([string]::IsNullOrEmpty($logonToken))
        {
            Throw "Get-LogonHeader: Logon Token is Empty - Cannot login"
        }
		
        try
        {
            # Create a Logon Token Header (This will be used through out all the script)
            # ---------------------------
            If ($logonToken.PSObject.Properties.Name -contains "CyberArkLogonResult")
            {
                $logonHeader = @{Authorization = $($logonToken.CyberArkLogonResult) }
            }
            else
            {
                $logonHeader = @{Authorization = $logonToken }
            }	

            Set-Variable -Name g_LogonHeader -Value $logonHeader -Scope global		
        }
        catch
        {
            Throw $(New-Object System.Exception ("Get-LogonHeader: Could not create Logon Headers Dictionary", $_.Exception))
        }
    }
}

Function Invoke-Logoff {
    <# 
    .SYNOPSIS 
        Invoke-Logoff
    .DESCRIPTION
        Logoff a PVWA session
    #>
    try
    {
        # Logoff the session
        # ------------------
        If ($null -ne $g_LogonHeader)
        {
            write-logMessage -Type Info -Msg "Logoff Session..."
            Invoke-RestMethod -Method Post -Uri $URL_Logoff -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700 | Out-Null
            Set-Variable -Name g_LogonHeader -Value $null -Scope global
        }
    }
    catch
    {
        Throw $(New-Object System.Exception ("Invoke-Logoff: Failed to logoff session", $_.Exception))
    }
}

Function Write-LogMessage {
    <#
    .SYNOPSIS
        Method to log a message on screen and in a log file

    .DESCRIPTION
        Logging The input Message to the Screen and the Log File.
        The Message Type is presented in colours on the screen based on the type

    .PARAMETER LogFile
        The Log File to write to. By default using the LOG_FILE_PATH
    .PARAMETER MSG
        The message to log
    .PARAMETER Header
        Adding a header line before the message
    .PARAMETER SubHeader
        Adding a Sub header line before the message
    .PARAMETER Footer
        Adding a footer line after the message
    .PARAMETER Type
        The type of the message to log (Info, Warning, Error, Debug)
    #>
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [String]$MSG,
        [Parameter(Mandatory = $false)]
        [Switch]$Header,
        [Parameter(Mandatory = $false)]
        [Switch]$SubHeader,
        [Parameter(Mandatory = $false)]
        [Switch]$Footer,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Debug", "Verbose")]
        [String]$type = "Info",
        [Parameter(Mandatory = $false)]
        [String]$LogFile = $LOG_FILE_PATH
    )
    try
    {
        If ($Header)
        {
            "=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
            Write-Host "======================================="
        }
        ElseIf ($SubHeader)
        { 
            "------------------------------------" | Out-File -Append -FilePath $LOG_FILE_PATH 
            Write-Host "------------------------------------"
        }
	
        $msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
        $writeToFile = $true
        # Replace empty message with 'N/A'
        if ([string]::IsNullOrEmpty($Msg))
        {
            $Msg = "N/A" 
        }
        # Mask Passwords
        if ($Msg -match '((?:"password"|"secret"|"NewCredentials")\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w!@#$%^&*()-\\\/]+))')
        {
            $Msg = $Msg.Replace($Matches[2], "****")
        }
        # Check the message type
        switch ($type)
        {
            "Info"
            { 
                Write-Host $MSG.ToString()
                $msgToWrite += "[INFO]`t$Msg"
            }
            "Warning"
            {
                Write-Host $MSG.ToString() -ForegroundColor DarkYellow
                $msgToWrite += "[WARNING]`t$Msg"
            }
            "Error"
            {
                Write-Host $MSG.ToString() -ForegroundColor Red
                $msgToWrite += "[ERROR]`t$Msg"
            }
            "Debug"
            { 
                if ($InDebug)
                {
                    Write-Debug $MSG
                    $msgToWrite += "[DEBUG]`t$Msg"
                }
                else
                {
                    $writeToFile = $False 
                }
            }
            "Verbose"
            { 
                if ($InVerbose)
                {
                    Write-Verbose $MSG
                    $msgToWrite += "[VERBOSE]`t$Msg"
                }
                else
                {
                    $writeToFile = $False 
                }
            }
        }
		
        If ($writeToFile)
        {
            $msgToWrite | Out-File -Append -FilePath $LOG_FILE_PATH 
        }
        If ($Footer)
        { 
            "=======================================" | Out-File -Append -FilePath $LOG_FILE_PATH 
            Write-Host "======================================="
        }
    }
    catch
    {
        Write-Error "Error in writing log: $($_.Exception.Message)" 
    }
}

Function ConvertTo-URL($sText) {
    <#
    .SYNOPSIS
	HTTP Encode test in URL
    .DESCRIPTION
	HTTP Encode test in URL
    .PARAMETER sText
    The text to encode
    #>
    if ($sText.Trim() -ne "")
    {
        write-logMessage -Type Debug -Msg "Returning URL Encode of $sText"
        return [URI]::EscapeDataString($sText)
    }
    else
    {
        return $sText
    }
}

Function Convert-ToBool {
    param (
        [string]$txt
    )
    $retBool = $false
	
    if ([bool]::TryParse($txt, [ref]$retBool))
    {
        # parsed to a boolean
        return [System.Convert]::ToBoolean($txt)
    }
    else
    {
        write-logMessage -Type Error -Msg "The input ""$txt"" is not in the correct format (true/false), defaulting to False"
        return $false
    }
}

Function Create-SearchCriteria {
	param ([string]$sURL, [string]$sSearch, [string]$sSortParam, [string]$sSafeName, [int]$iLimitPage, [int]$iOffsetPage)
	[string]$retURL = $sURL
	$retURL += "?"
	
	if(![string]::IsNullOrEmpty($sSearch))
	{
		write-debug "Search: $sSearch"
		$retURL += "search=$(Encode-URL $sSearch)&"
	}
	if(![string]::IsNullOrEmpty($sSafeName))
	{
		write-debug "Safe: $sSafeName"
		$retURL += "filter=safename eq $(Encode-URL $sSafeName)&"
	}
	if(![string]::IsNullOrEmpty($sSortParam))
	{
		write-debug "Sort: $sSortParam"
		$retURL += "sort=$(Encode-URL $sSortParam)&"
	}
	if($iLimitPage -gt 0)
	{
		write-debug "Limit: $iLimitPage"
		$retURL += "limit=$iLimitPage&"
	}
		
	if($retURL[-1] -eq '&') { $retURL = $retURL.substring(0,$retURL.length-1) }
	write-debug "URL: $retURL"
	
	return $retURL
}

Function Encode-URL($sText) {
	if ($sText.Trim() -ne "")
	{
		write-debug "Returning URL Encode of $sText"
		return [System.Web.HttpUtility]::UrlEncode($sText.Trim())
	}
	else
	{
		return ""
	}
}

function get-CAUser {
    param (        
        [Parameter(Mandatory = $true)]
        [string]$userName,
        [Parameter(Mandatory = $false)]
        [int]$limit=10
    )

    try {
        $UserURlwithNameFilter = ""
        $UserURlwithNameFilter = $(Create-SearchCriteria -sURL $url_users -sSearch $userName -iLimitPage $Limit)
        Write-Debug $UserURlwithNameFilter
    } catch {
        Write-Error $_.Exception
    }
    try{
        $GetAccountsResponse = Invoke-RestMethod -Method Get -Uri $UserURlwithNameFilter -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700
        if ($GetAccountsResponse.total -eq 1) {
            $UserURlwithNameFilter = $(Create-SearchCriteria -sURL $($url_users+"/"+$GetAccountsResponse.users[0].id) )
            $GetAccountsResponse = Invoke-RestMethod -Method Get -Uri $UserURlwithNameFilter -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700
            return $GetAccountsResponse
        } else {
            return $GetAccountsResponse.users
        }
        
    } catch {
        Write-Error $_.Exception.Response.StatusDescription
    }
    
}

Function Get-Safe {
    <#
        .SYNOPSIS
        Get all Safe details on a specific safe

        .DESCRIPTION
        Get all Safe details on a specific safe

        .EXAMPLE
        Get-Safe -safeName "x0-Win-S-Admins"
    #>
    param (
        [ValidateScript( { $_.Length -le 28 })]
        [String]$safeName
    )
    $_safe = $null
    try
    {
        $accSafeURL = $URL_SpecificSafe -f $(ConvertTo-URL $safeName)
        $_safe = $(Invoke-RestMethod -Uri $accSafeURL -Method "Get" -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700) #-ErrorAction "SilentlyContinue").GetSafeResult
    }
    catch
    {
        Throw $(New-Object System.Exception ("Get-Safe: Error retrieving safe '$safename' details.", $_.Exception))
    }
	
    return $_safe
}

function get-SpoofedADUser {
    param (        
        [string]$SafeUser
    )
    #Create an object that looks like an AD Object using whatever means available. 

    $regex = "[a-z0-9!#$%&'*+/=?^_{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_{|}~-]+)*@(?:a-z0-9?.)+a-z0-9?"

    #Attempt to read from CyberARk existing users.
    $getCYArkUser = get-CAUser -userName $SafeUser
    if ($null -eq $getCYArkUser) { return $null} else {
        write-logMessage -Type Info -Msg "Using CyberArk user account $($getCYArkUser.name)"
        $ADLookAlike = $getCYArkUser | Select-Object @{Name="UserPrincipalName";Expression={$_.username}},@{name="GivenName";Expression={$_.personalDetails.FirstName}},@{Name="SurName";Expression={$_.Personaldetails.LastName}}
        return $ADLookAlike
    } elseif ($SafeUser -match $regex) { # If SafeUser entry matches an email address, attempt to return 
        $userPortion = $safeUser.split("@")[0]    # remove email domain from email address. 
        # ref: https://pscustomobject.github.io/powershell/PowerShell-Convert-to-Title-Case
        $FirstName = (Get-Culture).TextInfo.ToTitleCase($userPortion.split(".")[0].toLower())
        $LastName = (Get-Culture).TextInfo.ToTitleCase($userPortion.split(".")[1].toLower())
        if ($null -eq $FirstName -or $null -eq $LastName) {return $null}  # SMTP address didn't follow first.last@domain format.
        $ADLookAlike = $safeUser | Select-Object @{Name="UserPrincipalName";Expression={$_}},@{name="GivenName";Expression={$FirstName}},@{Name="SurName";Expression={$LastName}}
        return $ADLookAlike
    } else {return $null }
}

function get-Accounts {
    param (        
        [string]$SafeUser
    )
    $response = ""
    try {
        $AccountsURLWithFilters = ""
        $AccountsURLWithFilters = $(Create-SearchCriteria -sURL $URL_Accounts -sSearch $Keywords -sSortParam $SortBy -sSafeName $SafeName -iLimitPage $Limit)
        Write-Debug $AccountsURLWithFilters
    } catch {
        Write-Error $_.Exception
    }
    try{
        $GetAccountsResponse = Invoke-RestMethod -Method Get -Uri $AccountsURLWithFilters -Headers $logonHeader -ContentType "application/json" -TimeoutSec 2700
    } catch {
        Write-Error $_.Exception.Response.StatusDescription
    }	
}

#endregion

# Script Version
$ScriptVersion = "1.0.0" 

# ------ SET global parameters ------
# Set a global Header Token parameter
$global:g_LogonHeader = ""
# Set a global safes list to improve performance
$global:g_SafesList = $null
# Set a global list of all Default sues to ignore
$global:g_DefaultUsers = @("Master", "Batch", "Backup Users", "Auditors", "Operators", "DR Users", "Notification Engines", "PVWAGWAccounts", "PVWAGWUser", "PVWAAppUser", "PasswordManager")

## TDC Specific values:
# ----------------------
$defaultDomain = "tdc.ad.teale.ca.gov"  # default AD domain to lookup user accounts. 
$pvWAURL = "https://cdt.privilegecloud.cyberark.com/PasswordVault"

# Global URLS
# -----------
$URL_PVWAWebServices = $PVWAURL + "/WebServices"
$URL_PVWABaseAPI = $URL_PVWAWebServices + "/PIMServices.svc" # Used to update Safe Members REF: https://docs.cyberark.com/Product-Doc/OnlineHelp/PAS/Latest/en/Content/WebServices/Update%20Safe.htm
# old method $URL_CyberArkAuthentication = $URL_PVWAWebServices + "/auth/cyberark/CyberArkAuthenticationService.svc"
$URL_PVWAAPI = $PVWAURL+"/api"
$URL_CyberArkAuthentication = $URL_PVWAAPI  + "/auth"
$URL_Logon = $URL_CyberArkAuthentication + "/Cyberark/Logon"
$URL_Logoff = $URL_CyberArkAuthentication + "/Logoff"


# URL Methods
# -----------
$URL_Safes = $URL_PVWAAPI + "/Safes"
$URL_SpecificSafe = $URL_Safes + "/{0}"
$URL_SafeMembers = $URL_SpecificSafe + "/Members"
# as of 10/19 the Update and Delete portion of set-safeMember function uses the old 1.0 API. 
$URL_SafeSpecificMember = $URL_PVWABaseAPI + "/Safes"+ "/{0}" + "/Members/{1}"
# users
$url_users = $URL_PVWAAPI+"/Users"

$URL_Accounts = $URL_PVWAAPI+"/Accounts"
$URL_AccountsDetails = $URL_PVWAAPI+"/Accounts/{0}"
$URL_Platforms = $URL_PVWAAPI+"/Platforms/{0}"

Get-LogonHeader -Credential $Credentials
if ($null -ne $g_LogonHeader ) {Write-Host "logged in"}