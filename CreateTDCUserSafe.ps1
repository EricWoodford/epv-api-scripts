<#
    Creates CyberArk vaules based off AD Accounts
    
#>
[CmdletBinding()]
[OutputType()]
Param
(
    [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
    [string[]]$NewUserSMTP,
    [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
    $MemberRole = "EndUser"
)


Function Get-LogonHeader
{
    <# 
.SYNOPSIS 
	Get-LogonHeader
.DESCRIPTION
	Get-LogonHeader
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
            Write-LogMessage -Type Info -Msg "Logoff Session..."
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
        $_safe = $(Invoke-RestMethod -Uri $accSafeURL -Method "Get" -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700 -ErrorAction "SilentlyContinue").GetSafeResult
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

    [CmdletBinding()]
    [OutputType([String])]
    Param
    (
    )

    try
    {
        If ($null -eq $g_SafesList)
        {
            Write-LogMessage -Type Debug -Msg "Retrieving safes from the vault..."
            $safes = (Invoke-RestMethod -Uri $URL_Safes -Method GET -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700).GetSafesResult
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
            Write-LogMessage -Type Info -MSG "Safe $safeName exists"
            $retResult = $true
        }
        Else
        {
            # Safe does not exist
            Write-LogMessage -Type Warning -MSG "Safe $safeName does not exist"
            $retResult = $false
        }
    }
    catch
    {
        Write-LogMessage -Type Error -MSG $_.Exception -ErrorAction "SilentlyContinue"
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
        safe = @{
            "SafeName"                  = "$safename"; 
            "Description"               = "$safeDescription"; 
            "OLACEnabled"               = $enableOLAC; 
            "ManagingCPM"               = "$managingCPM";
            "NumberOfVersionsRetention" = $numVersionRetention;
        }
    }

    If ($numDaysRetention -gt -1)
    {
        $createSafeBody.Safe.Add("NumberOfDaysRetention", $numDaysRetention)
        $createSafeBody.Safe.Remove("NumberOfVersionsRetention")
    }

    try
    {
        Write-LogMessage -Type Debug -Msg "Adding the safe $safename to the Vault..."
        $safeAdd = Invoke-RestMethod -Uri $URL_Safes -Body ($createSafeBody | ConvertTo-Json) -Method POST -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700
        # Reset cached Safes list
        #Set-Variable -Name g_SafesList -Value $null -Scope Global
        # Update Safes list to include new safe
        #Get-Safes | out-null
        $g_SafesList += $safeAdd.AddSafeResult
    }
    catch
    {
        Throw $(New-Object System.Exception ("New-Safe: Error adding $safename to the Vault.", $_.Exception))
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
        [int]$permRequestsAuthorizationLevel = 0,
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
            member = @{
                MemberName               = "$safeMember"
                SearchIn                 = "$memberSearchInLocation"
                MembershipExpirationDate = "$null"
                Permissions              = @(
                    @{Key = "UseAccounts"; Value = $permUseAccounts }
                    @{Key = "RetrieveAccounts"; Value = $permRetrieveAccounts }
                    @{Key = "ListAccounts"; Value = $permListAccounts }
                    @{Key = "AddAccounts"; Value = $permAddAccounts }
                    @{Key = "UpdateAccountContent"; Value = $permUpdateAccountContent }
                    @{Key = "UpdateAccountProperties"; Value = $permUpdateAccountProperties }
                    @{Key = "InitiateCPMAccountManagementOperations"; Value = $permInitiateCPMManagement }
                    @{Key = "SpecifyNextAccountContent"; Value = $permSpecifyNextAccountContent }
                    @{Key = "RenameAccounts"; Value = $permRenameAccounts }
                    @{Key = "DeleteAccounts"; Value = $permDeleteAccounts }
                    @{Key = "UnlockAccounts"; Value = $permUnlockAccounts }
                    @{Key = "ManageSafe"; Value = $permManageSafe }
                    @{Key = "ManageSafeMembers"; Value = $permManageSafeMembers }
                    @{Key = "BackupSafe"; Value = $permBackupSafe }
                    @{Key = "ViewAuditLog"; Value = $permViewAuditLog }
                    @{Key = "ViewSafeMembers"; Value = $permViewSafeMembers }
                    @{Key = "RequestsAuthorizationLevel"; Value = $permRequestsAuthorizationLevel }
                    @{Key = "AccessWithoutConfirmation"; Value = $permAccessWithoutConfirmation }
                    @{Key = "CreateFolders"; Value = $permCreateFolders }
                    @{Key = "DeleteFolders"; Value = $permDeleteFolders }
                    @{Key = "MoveAccountsAndFolders"; Value = $permMoveAccountsAndFolders }
                )
            }  
        }

        try
        {
            If ($updateMember)
            {
                Write-LogMessage -Type Debug -Msg "Updating safe membership for $safeMember on $safeName in the vault..."
                $urlSafeMembers = ($URL_SafeSpecificMember -f $(ConvertTo-URL $safeName), $safeMember)
                $restMethod = "PUT"
            }
            elseif ($deleteMember)
            {
                Write-LogMessage -Type Debug -Msg "Deleting $safeMember from $safeName in the vault..."
                $urlSafeMembers = ($URL_SafeSpecificMember -f $(ConvertTo-URL $safeName), $safeMember)
                $restMethod = "DELETE"
            }
            else
            {
                # Adding a member
                Write-LogMessage -Type Debug -Msg "Adding $safeMember located in $memberSearchInLocation to $safeName in the vault..."
                $urlSafeMembers = ($URL_SafeMembers -f $(ConvertTo-URL $safeName))
                $restMethod = "POST"
            }
            $null = Invoke-RestMethod -Uri $urlSafeMembers -Body ($safeMembersBody | ConvertTo-Json -Depth 5) -Method $restMethod -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700 -ErrorVariable rMethodErr
        }
        catch
        {
            if ($rMethodErr.message -like "*User or Group is already a member*")
            {
                Write-LogMessage -Type Warning -Msg "The user $safeMember is already a member. Use the update member method instead"
            }
            elseif ($rMethodErr.message -like "*User or Group was not found.*")
            {   
                If ($AddOnUpdate)
                {
                    # Adding a member
                    Write-LogMessage -Type Warning -Msg "User or Group was not found. Attempting to adding $safeMember located in $memberSearchInLocation to $safeName in the vault..."
                    $urlSafeMembers = ($URL_SafeMembers -f $(ConvertTo-URL $safeName))
                    $restMethod = "POST"
                    try
                    {
                        $null = Invoke-RestMethod -Uri $urlSafeMembers -Body ($safeMembersBody | ConvertTo-Json -Depth 5) -Method $restMethod -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700 -ErrorVariable rMethodErr
                    }
                    catch
                    {

                        Write-LogMessage -Type Error -Msg "There was an error setting the membership for $safeMember on $safeName in the Vault. The error was:"
                        Write-LogMessage -Type Error -Msg ("{0} ({1})" -f $rMethodErr.message, $_.Exception.Response.StatusDescription)
                    }
                }
                else
                {
                    Write-LogMessage -Type Warning -Msg "User or Group was not found. To automatically attempt to add use AddOnUpdate"
                }
            }
            else
            {
                Write-LogMessage -Type Error -Msg "There was an error setting the membership for $safeMember on $safeName in the Vault. The error was:"
                Write-LogMessage -Type Error -Msg ("{0} ({1})" -f $rMethodErr.message, $_.Exception.Response.StatusDescription)
            }
        }
    }
    else
    {
        Write-LogMessage -Type Info -Msg "Skipping default user $safeMember..."
    }
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
        $_safeMembers = $(Invoke-RestMethod -Uri $accSafeMembersURL -Method GET -Headers $g_LogonHeader -ContentType "application/json" -TimeoutSec 2700 -ErrorAction "SilentlyContinue")
        # Remove default users and change UserName to MemberName
        $_safeOwners = $_safeMembers.members | Where-Object { $_.UserName -NotIn $g_DefaultUsers } | Select-Object -Property @{Name = 'MemberName'; Expression = { $_.UserName } }, Permissions
    }
    catch
    {
        Throw $(New-Object System.Exception ("Get-SafeMembers: There was an error getting the safe $safeName Members.", $_.Exception))
    }
	
    return $_safeOwners
}
Function Convert-ToBool
{
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
        Write-LogMessage -Type Error -Msg "The input ""$txt"" is not in the correct format (true/false), defaulting to False"
        return $false
    }
}

#endregion

# Script Version
$ScriptVersion = "1.9.1"

# ------ SET global parameters ------
# Set a global Header Token parameter
$global:g_LogonHeader = ""
# Set a global safes list to improve performance
$global:g_SafesList = $null
# Set a global list of all Default sues to ignore
$global:g_DefaultUsers = @("Master", "Batch", "Backup Users", "Auditors", "Operators", "DR Users", "Notification Engines", "PVWAGWAccounts", "PVWAGWUser", "PVWAAppUser", "PasswordManager")

# Global URLS
# -----------
$URL_PVWAWebServices = $PVWAURL + "/WebServices"
$URL_PVWABaseAPI = $URL_PVWAWebServices + "/PIMServices.svc"
$URL_CyberArkAuthentication = $URL_PVWAWebServices + "/auth/cyberark/CyberArkAuthenticationService.svc"
$URL_Logon = $URL_CyberArkAuthentication + "/Logon"
$URL_Logoff = $URL_CyberArkAuthentication + "/Logoff"

# URL Methods
# -----------
$URL_Safes = $URL_PVWABaseAPI + "/Safes"
$URL_SpecificSafe = $URL_Safes + "/{0}"
$URL_SafeMembers = $URL_SpecificSafe + "/Members"
$URL_SafeSpecificMember = $URL_SpecificSafe + "/Members/{1}"



## TDC Specific values:
# ----------------------
$defaultDomain = "tdc.ad.teale.ca.gov"
$pvWAURL = "https://cdt.privilegecloud.cyberark.com/PasswordVault"


if ($null -eq $mgmtAdminUser) {
#    $mgmtAdminUser = get-credential -message "Need AdminUs$AdminUser to perform action.`n----------------------------------`nEnter mgmt account AdminUs$AdminUser plz:"
}

# Capture CyberArk admin credentials and set global:header variable. 
Get-LogonHeader
$allSafes = get-Safes
if ($null -eq $allSafes) {
    return "failed to pull safes from CyberArk."
}

forEach ($UserSMTP in $NewUserSMTP ) {
    $filterString = "userprincipalname -eq '"+$UserSMTP+"'"
    # Find User Object in Active Directory to grab user object. 
    $newuser = Get-ADUser -Server $defaultDomain -Filter $filterString # -Credential $mgmtAdminUser    

    #Build SafeName from the AD Object properties.
    $SafeName = "P-"+$newuser.GivenName+"_"+$newuser.Surname;
    #$SafeExists = & '.\Safe Management\Safe-Management.ps1' -PVWAURL $pvWAURL -List -SafeName $safeName -ErrorAction SilentlyContinue

    #See if safe already exists with this safeName value
    $SafeExists = $AllSafes | Where-Object {$_.safename -eq $SafeName}
    if ($null -eq $SafeExists)  {
        # Create new Safe For user.
        #$ManagingCPMArray = & '.\Safe Management\Safe-Management.ps1' -PVWAURL $pvWAURL -list | ?{$_.managingCPM -like "CDT*"} | group-object managingCPM | Sort-Object count 

        #Look for lowest population CPM server. 
        $ManagingCPMArray = $allSafes | Where-Object {$_.managingCPM -like "CDT*"} | group-object managingCPM -NoElement | Sort-Object count 
        $lowestPopManagingCPM = $ManagingCPMArray[0].name
        # & '.\Safe Management\Safe-Management.ps1' -PVWAURL $pvWAURL -Add -SafeName $safeName -ManagingCPM $lowestPopManagingCPM
        # Create new user's safe 
        New-Safe -SafeName $safeName -ManagingCPM $lowestPopManagingCPM
    } 

    #Grab existing safe members
    $safeMembers = Get-SafeMembers -safeName $SafeName

    #Don't do ADD accpimt of alread there. 
    if (!($safemembers.membername -contains $newuser.UserPrincipalName )) {
        # Add current AD user as a member of their own safe. 

        #End-user's Permissions configuration defined by CyberArk 
        $permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = `
            $permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafe = $permManageSafeMembers = $permBackupSafe = $permViewAuditLog = `
            $permViewSafeMembers = $permAccessWithoutConfirmation = $permCreateFolders = $permDeleteFolders = $permMoveAccountsAndFolders = $false
        [int]$permRequestsAuthorizationLevel = 0
        
        switch ($MemberRole) {
            "Admin"
            {
                $permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = `
                    $permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafe = $permManageSafeMembers = $permBackupSafe = `
                    $permViewAuditLog = $permViewSafeMembers = $permAccessWithoutConfirmation = $permCreateFolders = $permDeleteFolders = $permMoveAccountsAndFolders = $true
                $permRequestsAuthorizationLevel = 1
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
                $permRequestsAuthorizationLevel = 1
            }
            "Owner"
            {
                $permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = $permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts = $permManageSafeMembers = $permViewAuditLog = $permViewSafeMembers = $permMoveAccountsAndFolders = $true
                $permRequestsAuthorizationLevel = 1
            }
        }
        
        Set-SafeMember -safename $SafeName -safeMember $newuser.UserPrincipalName -memberSearchInLocation $UserLocation `
            -permUseAccounts $permUseAccounts -permRetrieveAccounts $permRetrieveAccounts -permListAccounts $permListAccounts `
            -permAddAccounts $permAddAccounts -permUpdateAccountContent $permUpdateAccountContent -permUpdateAccountProperties $permUpdateAccountProperties `
            -permInitiateCPMManagement $permInitiateCPMManagement -permSpecifyNextAccountContent $permSpecifyNextAccountContent `
            -permRenameAccounts $permRenameAccounts -permDeleteAccounts $permDeleteAccounts -permUnlockAccounts $permUnlockAccounts `
            -permManageSafe $permManageSafe -permManageSafeMembers $permManageSafeMembers -permBackupSafe $permBackupSafe `
            -permViewAuditLog $permViewAuditLog -permViewSafeMembers $permViewSafeMembers `
            -permRequestsAuthorizationLevel $permRequestsAuthorizationLevel -permAccessWithoutConfirmation $permAccessWithoutConfirmation `
            -permCreateFolders $permCreateFolders -permDeleteFolders $permDeleteFolders -permMoveAccountsAndFolders $permMoveAccountsAndFolders

            
        #Change the permissions granted to CDT_ADMIN:
        $permUseAccounts = $permRetrieveAccounts = $permListAccounts = $permAddAccounts = $permUpdateAccountContent = $permUpdateAccountProperties = $permInitiateCPMManagement = `
            $permSpecifyNextAccountContent = $permRenameAccounts = $permDeleteAccounts = $permUnlockAccounts =  $permAccessWithoutConfirmation = $permCreateFolders = $permDeleteFolders = $permMoveAccountsAndFolders = $false
        [int]$permRequestsAuthorizationLevel = 0
        $permManageSafe = $permManageSafeMembers = $permBackupSafe = $permViewAuditLog =  $permViewSafeMembers = $true

        Set-SafeMember -safename $SafeName -safeMember "CDT_Admin" -updateMember -memberSearchInLocation $UserLocation `
            -permUseAccounts $permUseAccounts -permRetrieveAccounts $permRetrieveAccounts -permListAccounts $permListAccounts `
            -permAddAccounts $permAddAccounts -permUpdateAccountContent $permUpdateAccountContent -permUpdateAccountProperties $permUpdateAccountProperties `
            -permInitiateCPMManagement $permInitiateCPMManagement -permSpecifyNextAccountContent $permSpecifyNextAccountContent `
            -permRenameAccounts $permRenameAccounts -permDeleteAccounts $permDeleteAccounts -permUnlockAccounts $permUnlockAccounts `
            -permManageSafe $permManageSafe -permManageSafeMembers $permManageSafeMembers -permBackupSafe $permBackupSafe `
            -permViewAuditLog $permViewAuditLog -permViewSafeMembers $permViewSafeMembers `
            -permRequestsAuthorizationLevel $permRequestsAuthorizationLevel -permAccessWithoutConfirmation $permAccessWithoutConfirmation `
            -permCreateFolders $permCreateFolders -permDeleteFolders $permDeleteFolders -permMoveAccountsAndFolders $permMoveAccountsAndFolders
    } else {
        $safemembers | ?{$_.membername -eq $newuser.UserPrincipalName}
    }
}
Invoke-Logoff

