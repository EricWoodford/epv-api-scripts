#Ref: https://cyberark-customers.force.com/s/article/How-to-use-REST-API-SAML-Auth

Function Get-AADToken {
    <# 
        .SYNOPSIS
            Get token from Azure AD so you can use the other cmdlets.
    
        .DESCRIPTION
            Get token from Azure AD so you can use the other cmdlets.
        
        .PARAMETER OMSConnection
            Object that contains all needed parameters for working
            with OMSSearch Module. You can create such object in 
            OMS Automation as connection asset.
    
        .PARAMETER TenantADName
            Valid Azure AD Tenant name. 
            Example: stanoutlook.onmicrosoft.com
    
        .PARAMETER TenantID
            Valid Azure Tenant ID. 
            Example: eeb91fce-4be2-4a30-aad8-39e05fefde0
    
        .PARAMETER Credential
            Valid user credentials to Azure AD. The Azure AD user must
            have at least user rights in OMS and administrator and 
            Contributor rights on the Azure resource group where
            the OMS workspace is located.
    
        .EXAMPLE
            $token = Get-AADToken -TenantADName 'stanoutlook.onmicrosoft.com' -Credential $creds
            Description
            -----------
            Grabs token from Azure AD by Tenant AD Name
    
            Example Variables
            -----------------
            $creds = Get-Credetnial
            
    
        .EXAMPLE
            $token = Get-AADToken -TenantID 'eeb91fce-4be2-4a30-aad8-39e05fefde0' -Credential $creds
            Description
            -----------
            Grabs token from Azure AD by Tenant ID
    
            Example Variables
            -----------------
            $creds = Get-Credetnial
            
    
        .EXAMPLE
            $Token = Get-AADToken -OMSConnection $OMSCon
            Description
            -----------
            Grabs token from Azure AD by using information from asset of type connection in OMS Automation
    
            Example Variables
            -----------------
            $OMSCon = Get-AutomationConnection -Name 'stasoutlook'
            
    
        .OUTPUTS
            System.String. Returns token from Azure AD.
    
    #>        
    [CmdletBinding(DefaultParameterSetName='LoginbyTenantADName')]
    [OutputType([string])]
    PARAM (
            [Parameter(ParameterSetName='OMSConnection',Position=0,Mandatory=$true)]
            [Alias('Connection','c')]
            [Object]$OMSConnection,
    
            [Parameter(ParameterSetName='LoginbyTenantADName',Position=0,Mandatory=$true)]
            
            [Alias('t')]
            [String]$TenantADName,
    
            [Parameter(ParameterSetName='LoginByTenantID',Position=0,Mandatory=$true)]
            [ValidateScript({
                try 
                {
                    [System.Guid]::Parse($_) | Out-Null
                    $true
                } 
                catch 
                {
                    $false
                }
            })]
            [Alias('tID')]
            [String]$TenantID,
    
            [Parameter(ParameterSetName='LoginbyTenantADName',Position=1,Mandatory=$true)]
            [Parameter(ParameterSetName='LoginByTenantID',Position=1,Mandatory=$true)]
            [Alias('cred')]
            [pscredential]
            [System.Management.Automation.CredentialAttribute()]
            $Credential
            )
        Try
        {
            If ($OMSConnection)
            {
                $Username       = $OMSConnection.Username
                $Password       = $OMSConnection.Password
                If ($OMSConnection.TenantID)
                {
                    $TenantID   = $OMSConnection.TenantID
                }
                Else
                {
                    $TenantADName   = $OMSConnection.TenantADName
                }
            }
            Else 
            {
                $Username       = $Credential.Username
                $Password       = $Credential.Password
            }
            # Set well-known client ID for Azure PowerShell
            $clientId = '1950a258-227b-4e31-a9cf-717495945fc2'
    
            # Set Resource URI to Azure Service Management API
            $resourceAppIdURI = 'https://management.azure.com/'
    
            # Set Authority to Azure AD Tenant
            If ($TenantID)
            {
                $authority = 'https://login.microsoftonline.com/common/' + $TenantID
            }
            Else
            {
                $authority = 'https://login.microsoftonline.com/' + $TenantADName
            }
        
    
            $AADcredential = New-Object `
                                -TypeName 'Microsoft.IdentityModel.Clients.ActiveDirectory.UserCredential' `
                                -ArgumentList $Username,$Password
        
            # Create AuthenticationContext tied to Azure AD Tenant
            $authContext = New-Object `
                                -TypeName 'Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext' `
                                -ArgumentList $authority
    
            $authResult = $authContext.AcquireToken($resourceAppIdURI,$clientId,$AADcredential)
            $Token = $authResult.CreateAuthorizationHeader()
        }
        Catch
        {
           $ErrorMessage = 'Failed to aquire Azure AD token.'
           $ErrorMessage += " `n"
           $ErrorMessage += 'Error: '
           $ErrorMessage += $_
           Write-Error -Message $ErrorMessage `
                       -ErrorAction Stop
        }
    
        Return $Token
    }


$TenantId = '52b26be4-7f5d-4e1c-baed-8cf75b7570d5'
$subscriptionId = '7abf4c7a-8dbd-4d80-b693-50379774fbeb'
$userName = 'eric.woodford@state.ca.gov'

$pw = ConvertTo-SecureString -String 'Sma11W00denguy' -AsPlainText -Force
$AzureAdminCred = New-Object System.Management.Automation.PSCredential($userName, $pw)
$Token = Get-AADToken -TenantID $TenantId -Credential $AzureAdminCred

  break

  
  $RESTAPIHeaders = @{'Authorization'=$Token;'Accept'='application/json'}
  $URI = "https://management.azure.com/subscriptions<a href="https://management.azure.com/subscriptions/">/</a>$subscriptionId/resourceGroups?api-version=2014-04-01"
  $GetResourceGroupsRequest = Invoke-WebRequest -UseBasicParsing -Uri $URI -Method GET -Headers $RESTAPIHeaders






  $pvWAURL = "https://cdt.privilegecloud.cyberark.com/PasswordVault"


$URL_SAML = $PVWAURL + "/api/auth/SAML/logon"
$body = @{"concurrentSession"=$true,"apiUse"=$true, "SAMLResponse"=} | ConvertTo-Json

Invoke-RestMethod -Uri $URL_SAML -Method Post -body $body -ContentType 'application/x-www-form-urlencoded'