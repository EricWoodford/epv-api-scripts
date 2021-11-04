param (
    [Parameter(Mandatory = $true)]
    [String]$safeName,
    [Parameter(Mandatory = $true)]
    [string]$SafeUser
)


$SafeUser = "eric.woodford@state.ca.gov"
$filterString = "userprincipalname -eq '"+$UserSMTP+"'"
$newuser = Get-ADUser -Server $defaultDomain -Filter $filterString # -Credential $mgmtAdminUser    

$NewMember = @{"memberName"="$newuser.UserPrincipalName";"searchIn"= "mtdcdc4.tdc.ad.teale.ca.gov";"Permissions"= @{"useAccounts"=$false;"retrieveAccounts"= $false; "listAccounts"= $false;"addAccounts"= $false;"updateAccountContent"= $false;"updateAccountProperties"= $false;"initiateCPMAccountManagementOperations"= $false;"specifyNextAccountContent"= $false;"renameAccounts"= $false;"deleteAccounts"= $false;"unlockAccounts"= $false;"manageSafe"= $false;"manageSafeMembers"= $false;"backupSafe"= $false;"viewAuditLog"= $false;"viewSafeMembers"= $false;"accessWithoutConfirmation"= $false;"createFolders"= $false;"deleteFolders"= $false;"moveAccountsAndFolders"= $false;"requestsAuthorizationLevel1"= $false;"requestsAuthorizationLevel2"= $false}} | convertto-json -Depth 5
$safename = get-safe -safename $safeName
$url = $URL_Safes+"/"+$safename.safeUrlId +"/members"
Invoke-RestMethod -Method Post -Headers $g_LogonHeader -Uri $url -Body $NewMember