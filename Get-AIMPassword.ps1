function Get-AIMPassword ([string]$PVWA_URL, [string]$AppID, [string]$Safe, [string]$userName) {
    # Declaration
    $fetchAIMPassword = "${PVWA_URL}/AIMWebService/api/Accounts?AppID=${AppID}&Safe=${Safe}&Folder=Root&UserName=${userName}"
    write-host $fetchAIMPassword
    # Execution
    try {
        $response = Invoke-RestMethod -Uri $fetchAIMPassword -Method GET -ContentType "application/json" -ErrorVariable aimResultErr -skipCert
        Return $response.content
    }
    catch {
        Write-Host "StatusCode: " $_.Exception.Response.StatusCode.value__
        Write-Host "StatusDescription: " $_.Exception.Response.StatusDescription
        Write-Host "Response: " $_.Exception.Message
        Return $false
    }
}
$CCPURL = "https://CDTAARKVMAPP03P.res.tdc.ad.teale.ca.gov"

$password = Get-AIMPassword -PVWA_URL $CCPURL -AppID "ORCH-Test" -Safe "CDT-IO-CCPTest" -userName "cdt-eric"
Write-Host "Your password is: ${password}" 
Start-Sleep -s 10


#
# https://cdtaarkvmapp03p.res.tdc.ad.teale.ca.gov/AIMWebService/api/Accounts?AppID=ORCH-Test&Safe=CDT-IO-CCPTest&Folder=Root&Object=cdt-eric