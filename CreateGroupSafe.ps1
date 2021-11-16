<#
    Creates group CyberArk vaults with multiple members.     
#>


[CmdletBinding()]
[OutputType()]
Param
(
    [Parameter(Mandatory = $true)]
    [System.Management.Automation.CredentialAttribute()]$Credentials,
    
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
    [string]$SafeName,  
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
    [string]$SafeDescription,     
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
    [string[]]$MemberSMTP,
    [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
    [string]$MemberRole = "Owner",
    [Parameter(Mandatory = $false)]
    [switch]$AimUser    
)



# Get Script Location 
$ScriptFullPath = $MyInvocation.MyCommand.Path
$ScriptLocation = Split-Path -Parent $ScriptFullPath
$ScriptParameters = @()
$PSBoundParameters.GetEnumerator() | ForEach-Object { $ScriptParameters += ("-{0} '{1}'" -f $_.Key, $_.Value) }
$global:g_ScriptCommand = "{0} {1}" -f $ScriptFullPath, $($ScriptParameters -join ' ')

# Set Log file path
$global:LOG_DATE = $(Get-Date -Format yyyyMMdd) + "-" + $(Get-Date -Format HHmmss)
$global:LOG_FILE_PATH = "$ScriptLocation\SafeManagement_$LOG_DATE.log"

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

Function Get-Safes {
    <#
        .SYNOPSIS
        Lists the cyberark safes that the APIUser has access to
        .DESCRIPTION
        Lists the cyberark safes that the APIUser has access to
        .EXAMPLE
        Get-Safes
    #>
    try
    {
        If ($null -eq $g_SafesList)
        {
            #write-logMessage -Type Debug -Msg "Retrieving safes from the vault..."
            $AllSafesURL = $URL_Safes+"?includeAccounts=true&offset=8&limit=1000"
            $safes = (Invoke-RestMethod -Uri $AllSafesURL -Method GET -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700).value
            Set-Variable -Name g_SafesList -Value $safes -Scope Global
        }
		
        return $g_SafesList
    }
    catch
    {
        Throw $(New-Object System.Exception ("Get-Safes: There was an error retrieving the safes from the Vault.", $_.Exception))
    }

}

Function Test-Safe {
    <# 
    .SYNOPSIS 
        Returns the Safe members
    .DESCRIPTION
        Returns the Safe members
    .PARAMETER SafeName
        The Safe Name check if exists
    #>
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()] 
        [String]$safeName
    )
		
    try
    {
        $chkSafeExists = $null
        $retResult = $false
        If ($null -ne $g_SafesList)
        {
            # Check Cached safes list first
            $chkSafeExists = ($g_SafesList.safename -contains $safename)
        }
        Else
        {
            # No cache, Get safe details from Vault
            try
            {
                $chkSafeExists = $null -ne $(Get-Safe -safeName $safeName -ErrAction "SilentlyContinue")
            }
            catch
            {
                $chkSafeExists = $false
            }
        }
		
        # Report on safe existence
        If ($chkSafeExists -eq $true)
        {
            # Safe exists
            write-logMessage -Type Info -MSG "test-safe: Safe $safeName exists"
            $retResult = $true
        }
        Else
        {
            # Safe does not exist
            write-logMessage -Type Warning -MSG "test-safe: Safe $safeName does not exist"
            $retResult = $false
        }
    }
    catch
    {
        write-logMessage -Type Error -MSG $_.Exception -ErrorAction "SilentlyContinue"
        $retResult = $false
    }
	
    return $retResult
}

Function New-Safe {
    <#
    .SYNOPSIS
    Allows a user to create a new cyberArk safe

    .DESCRIPTION
    Creates a new cyberark safe

    .EXAMPLE
    New-Safe -safename "x0-Win-S-Admins" -safeDescription "Safe description goes here"

    #>
    [CmdletBinding()]
    [OutputType()]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]$safename,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$safeDescription,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [string]$managingCPM = "PasswordManager",
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [int]$numVersionRetention = 7,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [int]$numDaysRetention = -1,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [bool]$EnableOLAC = $false
    )

    $createSafeBody = @{
       # safe = @{
            "SafeName"                  = "$safename"; 
            "Description"               = "$safeDescription"; 
            "OLACEnabled"               = $enableOLAC; 
            "ManagingCPM"               = "$managingCPM";
            "NumberOfVersionsRetention" = $numVersionRetention;
        #}
    }

    If ($numDaysRetention -gt -1)
    {
        $createSafeBody.Safe.Add("NumberOfDaysRetention", $numDaysRetention)
        $createSafeBody.Safe.Remove("NumberOfVersionsRetention")
    }

    try
    {
        write-logMessage -Type Debug -Msg "Adding the safe $safename to the Vault..."
        $safeAdd = Invoke-RestMethod -Uri $URL_Safes -Body ($createSafeBody | ConvertTo-Json) -Method POST -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700
        # Reset cached Safes list
        #Set-Variable -Name g_SafesList -Value $null -Scope Global
        # Update Safes list to include new safe
        #Get-Safes | out-null
        $g_SafesList += $safeAdd
        return $safeAdd
    }
    catch
    {
        Throw $(New-Object System.Exception ("New-Safe: Error adding $safename to the Vault.", $_.Exception))
    }
}

function remove-safe {
    <#
    .SYNOPSIS
    Allows a user to create a new cyberArk safe

    .DESCRIPTION
    Creates a new cyberark safe

    .EXAMPLE
    New-Safe -safename "x0-Win-S-Admins" -safeDescription "Safe description goes here"

    #>
    [CmdletBinding()]
    [OutputType()]
    param (
        [ValidateScript( { $_.Length -le 28 })]
        [String]$safeName
    )
    $_safe = $null
    try
    {
        $accSafeURL = $URL_SpecificSafe -f $(ConvertTo-URL $safeName)
        $_safe = $(Invoke-RestMethod -Uri $accSafeURL -Method "DELETE" -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700) #-ErrorAction "SilentlyContinue").GetSafeResult
    }
    catch
    {
        Throw $(New-Object System.Exception ("Get-Safe: Error retrieving safe '$safename' details.", $_.Exception))
    }	
    return $_safe
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

Function Set-SafeMember {
    <#
    .SYNOPSIS
    Gives granular permissions to a member on a cyberark safe

    .DESCRIPTION
    Gives granular permission to a cyberArk safe to the particular member based on parameters sent to the command.

    .EXAMPLE
    Set-SafeMember -safename "Win-Local-Admins" -safeMember "Win-Local-Admins" -memberSearchInLocation "LDAP Directory Name"

    .EXAMPLE
    Set-SafeMember -safename "Win-Local-Admins" -safeMember "Administrator" -memberSearchInLocation vault

    #>
    [CmdletBinding()]
    [OutputType()]
    Param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateScript( { Test-Safe -SafeName $_ })]
        $safename,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        #[ValidateScript( { get-CAUser -Safeuser $_ })]
        $safeMember,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [switch]$updateMember,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [switch]$deleteMember,
        [Parameter(Mandatory = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = "Which vault-integrated LDAP directory name the vault should search for the account. Must match one of the directory names defined in the LDAP Integration page of the PVWA.",
            Position = 0)]
        $memberSearchInLocation = "Vault",
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permUseAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permRetrieveAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permListAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permAddAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permUpdateAccountContent = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permUpdateAccountProperties = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permInitiateCPMManagement = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permSpecifyNextAccountContent = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permRenameAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permDeleteAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permUnlockAccounts = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permManageSafe = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permManageSafeMembers = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permBackupSafe = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permViewAuditLog = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permViewSafeMembers = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [int]$permRequestsAuthorizationLevel = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permAccessWithoutConfirmation = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permCreateFolders = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permDeleteFolders = $false,
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [bool]$permMoveAccountsAndFolders = $false
    )

    If ($safeMember -NotIn $g_DefaultUsers)
    {


        $SafeMembersBody = @{
            memberName               = "$safeMember"
            searchIn                 = "$memberSearchInLocation"
            membershipExpirationDate = "$null"
            permissions              = @{
                "useAccounts"= $permUseAccounts; 
                "retrieveAccounts"= $permRetrieveAccounts;
                "listAccounts"= $permListAccounts;
                "addAccounts"= $permAddAccounts ;
                "updateAccountContent"= $permUpdateAccountContent ;
                "updateAccountProperties"= $permUpdateAccountProperties ;
                "initiateCPMAccountManagementOperations"= $permInitiateCPMManagement ;
                "specifyNextAccountContent"= $permSpecifyNextAccountContent ;
                "renameAccounts"= $permRenameAccounts ;
                "deleteAccounts"= $permDeleteAccounts ;
                "unlockAccounts"= $permUnlockAccounts ;
                "manageSafe"= $permManageSafe ;
                "manageSafeMembers"= $permManageSafeMembers ;
                "backupSafe"= $permBackupSafe ;
                "viewAuditLog"= $permViewAuditLog ;
                "viewSafeMembers"= $permViewSafeMembers ;
                "requestsAuthorizationLevel1"= $false ;
                "accessWithoutConfirmation"= $permAccessWithoutConfirmation ;
                "createFolders"= $permCreateFolders ;
                "deleteFolders"= $permDeleteFolders ;
                "moveAccountsAndFolders"= $permMoveAccountsAndFolders ;
            }
        } 

        #$SafeMembersBody | ConvertTo-Json -depth 5
        $AddOnUpdate = $true

        try
        {
            If ($updateMember)
            {
                write-logMessage -Type debug -Msg "Updating safe membership for $safeMember on $safeName in the vault..."
                $urlSafeMembers = ($URL_SafeSpecificMember -f $(ConvertTo-URL $safeName), $safeMember)
                $restMethod = "PUT"
            }
            elseif ($deleteMember)
            {
                write-logMessage -Type Debug -Msg "Deleting $safeMember from $safeName in the vault..."
                $urlSafeMembers = ($URL_SafeSpecificMember -f $(ConvertTo-URL $safeName), $safeMember)
                $restMethod = "DELETE"
            }
            else
            {
                # Adding a member
                write-logMessage -Type Debug -Msg "Adding $safeMember located in $memberSearchInLocation to $safeName in the vault..."
                $urlSafeMembers = ($URL_SafeMembers -f $(ConvertTo-URL $safeName))
                $restMethod = "POST"
            }
           $capture = Invoke-RestMethod -Uri $urlSafeMembers -Body ($safeMembersBody | ConvertTo-Json -Depth 5) -Method $restMethod -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700 -ErrorVariable rMethodErr
        }
        catch
        {
            if ($rMethodErr.message -like "*User or Group is already a member*")
            {
                write-logMessage -Type Warning -Msg "The user $safeMember is already a member. Use the update member method instead"
            }
            elseif ($rMethodErr.message -like "*User or Group was not found.*")
            {   
                If ($AddOnUpdate)
                {
                    # Adding a member
                    write-logMessage -Type Warning -Msg "User or Group was not found. Attempting to adding $safeMember located in $memberSearchInLocation to $safeName in the vault..."
                    $urlSafeMembers = ($URL_SafeMembers -f $(ConvertTo-URL $safeName))
                    $restMethod = "POST"
                    try
                    {
                        $Results = Invoke-RestMethod -Uri $urlSafeMembers -Body ($safeMembersBody | ConvertTo-Json -Depth 5) -Method $restMethod -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700 -ErrorVariable rMethodErr
                    }
                    catch
                    {

                        write-logMessage -Type Error -Msg "There was an error setting the membership for $safeMember on $safeName in the Vault. The error was:"
                        write-logMessage -Type Error -Msg ("{0} ({1})" -f $rMethodErr.message, $_.Exception.Response.StatusDescription)
                    }
                }
                else
                {
                    write-logMessage -Type Warning -Msg "User or Group was not found. To automatically attempt to add use AddOnUpdate"
                }
            }
            else
            {
                write-logMessage -Type Error -Msg "There was an error setting the membership for $safeMember on $safeName in the Vault. The error was:"
                write-logMessage -Type Error -Msg ("{0} ({1})" -f $rMethodErr.message, $_.Exception.Response.StatusDescription)
            }
        }
    }
    else
    {
        write-logMessage -Type Info -Msg "Skipping default user $safeMember..."
    }
}

Function Set-MemberRole {
    param (
        [Parameter(Mandatory = $true)]
        [String]$safeName,
        [Parameter(Mandatory = $true)]
        [string]$memberRole,
        [Parameter(Mandatory = $true)]
        [string]$SafeUser,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [switch]$updateMember,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [switch]$deleteMember
    )

    #End-user's Permissions configuration defined by CyberArk 
    $permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = `
        $permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafe = $permManageSafeMembers = $permBackupSafe = $permViewAuditLog = `
        $permViewSafeMembers = $permAccessWithoutConfirmation = $permCreateFolders = $permDeleteFolders = $permMoveAccountsAndFolders = $permRequestsAuthorizationLevel = $false
    $UserLocation = (get-directoryName).DomainName.toUpper()
    switch ($MemberRole) {
        "Super" {
            $permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = `
            $permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafe = $permManageSafeMembers = $permBackupSafe = $permViewAuditLog = `
            $permViewSafeMembers = $permAccessWithoutConfirmation = $permCreateFolders = $permDeleteFolders = $permMoveAccountsAndFolders = $permRequestsAuthorizationLevel = $true
        }
        "Admin"
        {
            $permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = `
                $permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafe = $permManageSafeMembers = $permBackupSafe = `
                $permViewAuditLog = $permViewSafeMembers = $permAccessWithoutConfirmation = $permCreateFolders = $permDeleteFolders = $permMoveAccountsAndFolders = $true
            $permRequestsAuthorizationLevel = $false
        }
        "Auditor"
        {
            $permListAccounts = $permViewAuditLog = $permViewSafeMembers = $true
        }
        "EndUser"
        {
            $permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permViewAuditLog = $permViewSafeMembers = $true
        }
        "Approver"
        {
            $permListAccounts = $permViewAuditLog = $permViewSafeMembers = $true
            $permRequestsAuthorizationLevel = $false
        }
        "Owner"
        {
            write-logMessage -Type Info -Msg "Granting owner role to $safeuser"
            $permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = $permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafeMembers = $permViewAuditLog = $permViewSafeMembers = $permMoveAccountsAndFolders = $true
            $permRequestsAuthorizationLevel = $false
        }
        "cdt_admin" {
            $permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = `
            $permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafe = $permManageSafeMembers = $permBackupSafe = $permViewAuditLog = `
            $permViewSafeMembers = $permAccessWithoutConfirmation = $permCreateFolders = $permDeleteFolders = $permMoveAccountsAndFolders = $permRequestsAuthorizationLevel = $permManageSafe = $permManageSafeMembers = $permBackupSafe = $permViewAuditLog =  $permViewSafeMembers = $true
            $UserLocation = "Vault"
        }
    }# 
    $alreadyMember = (Get-SafeMembers -safeName $safename) | where-object {$_.membername -eq $safeuser}
    if ($null -eq $alreadyMember) {
        write-logMessage -Type Info -Msg $("Adding $safeUser to $SafeName")
        Set-SafeMember -safename $SafeName -safeMember $SafeUser -memberSearchInLocation $UserLocation `
            -permUseAccounts $permUseAccounts -permRetrieveAccounts $permRetrieveAccounts -permListAccounts $permListAccounts `
            -permAddAccounts $permAddAccounts -permUpdateAccountContent $permUpdateAccountContent -permUpdateAccountProperties $permUpdateAccountProperties `
            -permInitiateCPMManagement $permInitiateCPMManagement -permSpecifyNextAccountContent $permSpecifyNextAccountContent `
            -permRenameAccounts $permRenameAccounts -permDeleteAccounts $permDeleteAccounts -permUnlockAccounts $permUnlockAccounts `
            -permManageSafe $permManageSafe -permManageSafeMembers $permManageSafeMembers -permBackupSafe $permBackupSafe `
            -permViewAuditLog $permViewAuditLog -permViewSafeMembers $permViewSafeMembers `
            -permRequestsAuthorizationLevel $permRequestsAuthorizationLevel -permAccessWithoutConfirmation $permAccessWithoutConfirmation `
            -permCreateFolders $permCreateFolders -permDeleteFolders $permDeleteFolders -permMoveAccountsAndFolders $permMoveAccountsAndFolders
    } else {
        write-logMessage -Type Info -Msg $("Updating $safeUser to $SafeName")
        Set-SafeMember -safename $SafeName -safeMember $SafeUser -memberSearchInLocation $UserLocation `
        -permUseAccounts $permUseAccounts -permRetrieveAccounts $permRetrieveAccounts -permListAccounts $permListAccounts `
        -permAddAccounts $permAddAccounts -permUpdateAccountContent $permUpdateAccountContent -permUpdateAccountProperties $permUpdateAccountProperties `
        -permInitiateCPMManagement $permInitiateCPMManagement -permSpecifyNextAccountContent $permSpecifyNextAccountContent `
        -permRenameAccounts $permRenameAccounts -permDeleteAccounts $permDeleteAccounts -permUnlockAccounts $permUnlockAccounts `
        -permManageSafe $permManageSafe -permManageSafeMembers $permManageSafeMembers -permBackupSafe $permBackupSafe `
        -permViewAuditLog $permViewAuditLog -permViewSafeMembers $permViewSafeMembers `
        -permRequestsAuthorizationLevel $permRequestsAuthorizationLevel -permAccessWithoutConfirmation $permAccessWithoutConfirmation `
        -permCreateFolders $permCreateFolders -permDeleteFolders $permDeleteFolders -permMoveAccountsAndFolders $permMoveAccountsAndFolders -updateMember
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

Function Encode-URL($sText)
{
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

function get-directoryName {
    #Locates the first LDAP directory integrations. Returns the object. 
    $URL_Directory = $URL_PVWAAPI + "/Configuration/LDAP/Directories/"
    $directories = Invoke-RestMethod -Uri $URL_Directory -Headers $g_LogonHeader -Method GET 
    if ($directories.count -eq 1) {return $directories[0]}
}

function get-CAUser {
    param (        
        [Parameter(Mandatory = $true)]
        [string]$userName,
        [Parameter(Mandatory = $false)]
        [int]$limit=10
    )
    #Get CyberArk user accounts that are found in the CyberArk vault. Does not return LDAP accounts.

    try {
        $UserURlwithNameFilter = ""
        $UserURlwithNameFilter = $(Create-SearchCriteria -sURL $url_users -sSearch $userName -iLimitPage $Limit)
        # $SearchFilter = Encode-URL("userName eq "+$userSearch)
       # $UserURlwithNameFilter = $url_users+"?ExtendedDetails=True&filter="+$username
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

Function Get-SafeMembers {
    <#
    .SYNOPSIS
    Returns the permissions of a member on a cyberark safe

    .DESCRIPTION
    Returns the permissions of a cyberArk safe of all members based on parameters sent to the command.

    .EXAMPLE
    Get-SafeMember -safename "Win-Local-Admins" 

    #> 
    param (
        [Parameter(Mandatory = $true)]
        [String]$safeName
    )
    $_safeMembers = $null
    $_safeOwners = $null
    try
    {
        $accSafeMembersURL = $URL_SafeMembers -f $(ConvertTo-URL $safeName)
        $_safeMembers = $(Invoke-RestMethod -Uri $accSafeMembersURL -Method GET -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700 -ErrorAction "SilentlyContinue").value
        # Remove default users and change UserName to MemberName
        $_safeOwners = $_safeMembers | Where-Object { $_.memberName -NotIn $g_DefaultUsers } | Select-Object -Property MemberName, Permissions
    }
    catch
    {
        Throw $(New-Object System.Exception ("Get-SafeMembers: There was an error getting the safe $safeName Members.", $_.Exception))
    }
	
    return $_safeOwners
}

Function Get-CyberArkGroupMembers {
    if ($null -eq (get-command "get-adgroup" -erroraction SilentlyContinue)) {return "needs ActiveDirectory module to add group membership"}    
    $adGroup = get-adgroup -server $defaultDomain -identity "CyberArk-EndUsers"
    if ($null -eq $adgroup ) {        
        return $null
    }
    if ($null -eq $g_ADGroupMembers) {
        write-verbose "reading ad group"
        $FoundADGroupMembers = Get-ADGroupMember -Identity $adgroup.DistinguishedName -Server $defaultDomain | foreach {Get-ADUser -identity $_.DistinguishedName -server $defaultDomain}
        Set-Variable -name g_ADGroupMembers -value $FoundADGroupMembers -scope global -description "Existing members of the LDAP group"
        return $g_ADGroupMembers
    } else {return $g_ADGroupMembers}
}

function Update-CyberArkEndUsersMembers {
    param (
        [Parameter(Mandatory = $true)]
        [string]$userSmtp,        
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.CredentialAttribute()]$adCredential
    )
    # checks to see if the userSMTP entry is a member of the LDAP auth group. 
    if ($null -eq (get-command "get-adgroup" -erroraction SilentlyContinue)) {return "needs ActiveDirectory module to add group membership"}    
    $capture = Get-CyberArkGroupMembers
    $newuser = Get-ADUser -Server $defaultDomain -Filter $filterString 

    $existingMembers = $g_ADGroupMembers | ?{$_.distinguishedname -eq $newuser.distinguishedname}
    if ($null -eq $newUser) {
        write-host "#couldn't find $usersmtp"
    } elseif ($null -eq $existingMembers) {
        write-host "#need to add $userSMTP to 'CyberArk-EndUsers'"
        if ($null -eq $adCredential) {
            write-host $("Add-ADGroupMember -Identity '"+$adGroup.DistinguishedName+"' -Members '"+$newuser.DistinguishedName+"' -Server '"+$defaultDomain+"' -Credential `$adCredential")    
        } else {
            Add-ADGroupMember -Identity $adGroup.DistinguishedName -Members $newuser.DistinguishedName -Server $defaultDomain -Credential $adCredential
            $g_ADGroupMembers = $null
        }
    } else {
        write-verbose "$userSMTP already in 'CyberArk-EndUsers'"
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


# Set boolean based on if ActiveDirectory tools are installed on local machine. 
$useActiveDirectory = ($null -ne (Get-Module -Name "ActiveDirectory"))
if (!$useActiveDirectory) {
    write-logMessage -Type Warning -Msg "Missing: ActiveDirectory powershell Module. This script uses the ActiveDirectory powershell module to read properties from live mailboxes. Will attempt to use CyberArk user properties to populate safe name properties."    
} else {
    if ($null -eq $(get-command -name "get-adUser")) {
        Import-Module -name ActiveDirectory
    }
}


if ($null -eq $mgmtAdminUser) {
#    $mgmtAdminUser = get-credential -message "Need AdminUs$AdminUser to perform action.`n----------------------------------`nEnter mgmt account AdminUs$AdminUser plz:"
}

# Capture CyberArk admin credentials and set global:header variable. 
Get-LogonHeader -Credentials $Credentials
$allSafes = get-Safes
if ($null -eq $allSafes) {
    return "failed to pull safes from CyberArk."
}

$SafeExists = $AllSafes | ?{$_.safename -eq $SafeName}
if ($null -eq $SafeExists)  {
    # Create new Safe For user.
    
    #Look for lowest population CPM server. 
    $ManagingCPMArray = $allSafes | Where-Object {$_.managingCPM -like "CDT*" -and $_.managingCPM -notlike "*,*"} | group-object managingCPM -NoElement | Sort-Object count 
    $lowestPopManagingCPM = $ManagingCPMArray[0].name
    
    write-logMessage -Type Info -Msg "Creating new safe for $($newuser.UserPrincipalName) with safe name of $SafeName on $lowestPopManagingCPM"
    # Create new user's safe 
    New-Safe -SafeName $safeName -ManagingCPM $lowestPopManagingCPM  -safeDescription $SafeDescription               
    do {
        #sit and wait for replication
        # Issue where the global variable isn't getting set when the new safe is created. Easier to rebuild the 
        write-host "." -nonewline   
        $g_SafesList = $null;
        $allSafes = get-safe -safename $safename 
    } while ($null -eq ($AllSafes | Where-Object{$_.safename -eq $SafeName}))
} else {
    write-logMessage -Type Info -Msg "Note:: Safe name $SafeName already exists."
}

$newSafe = get-safe -safename $safename
if($Credentials.username -ne "cdt_admin") {
    Set-MemberRole -safeName $($newSafe.safeUrlId)  -SafeUser "cdt_admin" -memberRole "cdt_admin" -updateMember
}
forEach ($UserSMTP in $MemberSMTP ) {
    $filterString = "userprincipalname -eq '"+$UserSMTP+"'"
    # Find User Object in Active Directory to grab user object. 
    if ($useActiveDirectory) {
        $newuser = Get-ADUser -Server $defaultDomain -Filter $filterString # -Credential $mgmtAdminUser    
    } 
    
    if (!$useActiveDirectory -or $null -eq $newUser ) {
        write-verbose "Couldn't find in AD, searching active user accounts in CyberArk for $userSMTP"
        $newUser = get-SpoofedADUser -SafeUser $UserSMTP        
    }

    #Add Safe Members.
    if ($null -ne $newUser ) {       
        
        #Grab existing safe members
        $safeMembers = Get-SafeMembers -safeName $SafeName

        #Don't do ADD account of alread there. 
        if (!($safemembers.membername -contains $newuser.UserPrincipalName )) {
            # Add current AD user as a member of their own safe. 
            write-logMessage -Type Info -Msg "Adding $($newuser.UserPrincipalName) as owner to safe $SafeName"
            Set-MemberRole -safeName $($newSafe.safeUrlId) -SafeUser $newuser.UserPrincipalName -memberRole $MemberRole               
           
        } else {
            #update role if already there.. 
            write-logMessage -Type Info -Msg "Updating existing member permissions to $MemberRole"
            Set-MemberRole -safeName $($newSafe.safeUrlId)  -SafeUser $newuser.UserPrincipalName -memberRole $MemberRole -updateMember
        }
    
    } else {
        write-host $("ERROR: User not found: "+$userSMTP)
    }
}

if ($AimUser) {
    Set-MemberRole -safeName $($newSafe.safeUrlId)  -SafeUser "AIMWebService" -memberRole "EndUser" -updateMember
    Set-MemberRole -safeName $($newSafe.safeUrlId)  -SafeUser "Orch-Test" -memberRole "EndUser" -updateMember
    Set-MemberRole -safeName $($newSafe.safeUrlId)  -SafeUser "Prov_CDTAARKVMWAPP03P" -memberRole "EndUser" -updateMember
}
Invoke-Logoff

