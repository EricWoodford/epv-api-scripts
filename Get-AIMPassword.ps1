# pull the user account credentials from CyberArk web API


param (
    [Parameter(Mandatory = $true,HelpMessage="The account name as shown in the Username field in the CyberArk UI")][string]$AuthUser="doesnotmatter", 
    [Parameter(Mandatory=$false,HelpMessage="Name of accessible safe that contains the credentials. The admin specified this in the CyberArk app.")][string] $safe="IO_Automation_API",
    [Parameter(Mandatory = $false)]
    [switch]$ReturnPasswordOnly
)


function Get-AIMPassword {
    param (
    [Parameter(Mandatory = $true,HelpMessage="URL to the password vault web access. This should be the same for all requests.")]    
    [string]$PVWA_URL,
    [Parameter(Mandatory = $true,HelpMessage="CyberArk Password Vault App Id. This is created by the CyberArk admins in the vault app.")]    
    [string]$AppID,
    [Parameter(Mandatory = $true,HelpMessage="Name of accessible safe that contains the credentials. The admin specified this in the CyberArk app.")]    
    [string]$safe,
    [Parameter(Mandatory = $true,HelpMessage="The account name as shown in the Username field in the CyberArk UI")]    
    [string]$userName, 
    [Parameter(Mandatory = $false)]
    [switch]$ReturnPasswordOnly
)
    # Declaration
    $fetchAIMPassword = "${PVWA_URL}/AIMWebService/api/Accounts?AppID=${AppID}&Safe=${Safe}&Folder=Root&UserName=${userName}"
    write-verbose $fetchAIMPassword
    # Execution
    try {
        $response = Invoke-RestMethod -Uri $fetchAIMPassword -Method GET -ContentType "application/json" -ErrorVariable aimResultErr -skipCert
        Return $response.content
    }
    catch {
        Write-Host "StatusCode: " $_.Exception.Response.StatusCode.value__
        Write-Host "StatusDescription: " $_.Exception.Response.StatusDescription
        Write-Host "Response: " $_.Exception.Message
        Return $null
    }
}
$CCPURL = "https://CDTAARKVMAPP03P.res.tdc.ad.teale.ca.gov"

$password = Get-AIMPassword -PVWA_URL $CCPURL -AppID "ORCH-Test" -Safe $safe -userName $AuthUser

if ($null -eq $password) {return $null}
if ($ReturnPasswordOnly) { 
    # returns password in plain text to cli
    return $password
} else {
    #default action: create a powershell credential object
    $SecurePassword = $Password | convertto-SecureString -AsPlainText -Force
    $newCredentialObj = New-Object System.Management.Automation.PsCredential($AuthUser,$SecurePassword)
    return $newCredentialObj
}

#
# https://cdtaarkvmapp03p.res.tdc.ad.teale.ca.gov/AIMWebService/api/Accounts?AppID=ORCH-Test&Safe=CDT-IO-CCPTest&Folder=Root&Object=cdt-eric