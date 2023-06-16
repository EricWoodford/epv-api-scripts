# check to see if the see if the current user is in the specified user group, if not generate a posh script to add them. 
# input: email address(es) of the users to check.
# output: 

[CmdletBinding()]
[OutputType()]
Param
(
     [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
    [string[]]$NewUserSMTP
)

$MissingADUserReportFile = ".\addUsersToCyberArkEngineers.ps1"
# regex of what an email address should look like.
$regex = "[a-z0-9!#$%&'*+/=?^_{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_{|}~-]+)*@(?:a-z0-9?.)+a-z0-9?"

# default AD domain to lookup user accounts. 
$defaultDomain = "tdc.ad.teale.ca.gov"  
$smtpDomain = "@state.ca.gov"

# get group adding users to.
$adGroup = get-adgroup -server $defaultDomain -identity "CyberArk-EndUsers"  
# read current membership to group, get user objects.
$FoundADGroupMembers = Get-ADGroupMember -Identity $adgroup.DistinguishedName -Server $defaultDomain | foreach {Get-ADUser -identity $_.DistinguishedName -server $defaultDomain}

forEach ($NewUserEntry in $NewUserSMTP ) {    
    # see if 'newUser' is an smtp address or "first last". convert to email address "first.last@domain"
    if ($NewUserEntry -match $regex) { 
        $UserSMTP = $NewUserEntry} 
    else {
        $UserSMTP = ($NewUserEntry.ToLower().split(" ") -join("."))+$smtpDomain
        Write-Verbose $UserSMTP
    }

    # get ad object for user.
    $filterString = "userPrincipalName -eq '"+$UserSMTP+"'"
    $newuser = Get-ADUser -Server $defaultDomain -Filter $filterString # -Credential $mgmtAdminUser      
    if ($null -ne $newUser ) { 
        # compare user to existing group membership
        $existingMembers = $FoundADGroupMembers | where-object {$_.distinguishedname -eq $newuser.distinguishedname}
        if ($null -eq $existingMembers) {
            write-host "#need to add $userSMTP to 'CyberArk-EndUsers'"   
            $("Add-ADGroupMember -Identity '"+$adGroup.DistinguishedName+"' -Members '"+$newuser.DistinguishedName+"' -Server '"+$defaultDomain+"' -Credential `$adCredential")  | Out-File $MissingADUserReportFile -Append
                
        } else {
            write-verbose "$userSMTP already in 'CyberArk-EndUsers'"
        }
    } else {
        write-verbose "ERROR: unable to locate user AD object"
    }
}
#Zip file up to send to AD team to run.
<#
if (test-path $MissingADUserReportFile) {
    $ShortdateStr=(get-date).ToShortDateString().replace("/","-")
    $zipName = $MissingADUserReportFile +"_"+$ShortdateStr +".zip"        
    Compress-Archive -Path $MissingADUserReportFile -DestinationPath $zipName -Update  
    if (Test-Path -Path $zipName) {Remove-Item $MissingADUserReportFile}
} 
#>