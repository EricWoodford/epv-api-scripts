[CmdletBinding()]
[OutputType()]
Param
(
     [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
    [string[]]$NewUserSMTP
)

$MissingADUserReportFile = ".\addUsersToCyberArkEngineers.ps1"
$regex = "[a-z0-9!#$%&'*+/=?^_{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_{|}~-]+)*@(?:a-z0-9?.)+a-z0-9?"
$defaultDomain = "tdc.ad.teale.ca.gov"  # default AD domain to lookup user accounts. 

$adGroup = get-adgroup -server $defaultDomain -identity "CyberArk-EndUsers"  
$FoundADGroupMembers = Get-ADGroupMember -Identity $adgroup.DistinguishedName -Server $defaultDomain | foreach {Get-ADUser -identity $_.DistinguishedName -server $defaultDomain}

forEach ($NewUserEntry in $NewUserSMTP ) {    
    if ($NewUserEntry -match $regex) { 
        $UserSMTP = $NewUserEntry} 
    else {
        $UserSMTP = ($NewUserEntry.ToLower().split(" ") -join("."))+"@state.ca.gov"
        Write-Verbose $UserSMTP
    }

    $filterString = "userPrincipalName -eq '"+$UserSMTP+"'"
    $newuser = Get-ADUser -Server $defaultDomain -Filter $filterString # -Credential $mgmtAdminUser  
    if ($null -ne $newUser ) {      
        
        $existingMembers = $FoundADGroupMembers | ?{$_.distinguishedname -eq $newuser.distinguishedname}
        if ($null -eq $newUser) {
            write-verbose "#couldn't find $usersmtp"
        } elseif ($null -eq $existingMembers) {
            write-host "#need to add $userSMTP to 'CyberArk-EndUsers'"   

            $("Add-ADGroupMember -Identity '"+$adGroup.DistinguishedName+"' -Members '"+$newuser.DistinguishedName+"' -Server '"+$defaultDomain+"' -Credential `$adCredential")  | Out-File $MissingADUserReportFile -Append
                
        } else {
            write-verbose "$userSMTP already in 'CyberArk-EndUsers'"
        }
    } else {
        write-verbose "ERROR: unable to locate user AD object"
    }
}
<#
if (test-path $MissingADUserReportFile) {
    $ShortdateStr=(get-date).ToShortDateString().replace("/","-")
    $zipName = $MissingADUserReportFile +"_"+$ShortdateStr +".zip"        
    Compress-Archive -Path $MissingADUserReportFile -DestinationPath $zipName -Update  
    if (Test-Path -Path $zipName) {Remove-Item $MissingADUserReportFile}
} 
#>