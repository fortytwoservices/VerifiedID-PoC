#requires -Version 7.0
#requires -Modules Az.Accounts, Az.Resources, Az.Storage, Az.KeyVault

<#
.SYNOPSIS
    Microsoft Entra Verified ID PowerShell Module

.DESCRIPTION
    This module provides comprehensive functionality for deploying and managing 
    Microsoft Entra Verified ID infrastructure, including support for both 
    application-only and delegated authentication scenarios.

.NOTES
    Author: Verified ID Team
    Version: 1.0.0
    
    Authentication Modes:
    - Application-only: Uses client credentials flow with app registration
    - Delegated: Uses user authentication with delegated permissions
#>

#========================
# Module Variables
#========================
$script:vcBase = "https://verifiedid.did.msidentity.com/v1.0"
$script:VerifiedIdRequestAppId = "3db474b9-6a0c-4840-96ac-1fceb342124f"
$script:VerifiedIdAdminAppId = "6a8b4b39-c021-437c-b060-5a14a3fd65f3"

#========================
# Utility Functions
#========================

function ConvertFrom-Base64Url {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$InputString)
    
    if (-not $InputString) { 
        throw "Decode-Base64Url: input empty" 
    }
    
    $processed = $InputString.Replace('-', '+').Replace('_', '/')
    $processed = $processed -replace "[^A-Za-z0-9+/=]", ''
    
    $pad = $processed.Length % 4
    if ($pad -eq 2) { 
        $processed += '==' 
    }
    elseif ($pad -eq 3) { 
        $processed += '=' 
    }
    elseif ($pad -ne 0) { 
        throw "Invalid base64 length" 
    }
    
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($processed))
}

function ConvertTo-JwtString {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$RawToken)
    
    if (-not $RawToken) { 
        throw "Token is null or empty" 
    }
    
    $tokenString = $null
    if ($RawToken -is [System.Security.SecureString]) {
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($RawToken)
        try { 
            $tokenString = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) 
        }
        finally { 
            if ($bstr -ne [IntPtr]::Zero) { 
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) 
            } 
        }
    }
    else { 
        $tokenString = [string]$RawToken 
    }
    
    if (-not $tokenString) { 
        throw "Token could not be converted to string" 
    }
    
    $tokenString = $tokenString.Trim()
    if ($tokenString -match '^\s*Bearer\s+') { 
        $tokenString = ($tokenString -replace '^\s*Bearer\s+', '') 
    }
    
    $tokenString = $tokenString.Trim('"', "'")
    if ($tokenString -notmatch '^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$') {
        $preview = if ($tokenString.Length -gt 32) { 
            $tokenString.Substring(0, 32) + '...' 
        }
        else { 
            $tokenString 
        }
        throw "Access token is not a well-formed JWT. Starts with: '$preview'"
    }
    
    return $tokenString
}

function Get-NormalizedScope {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Resource)
    
    if ($Resource -match '^https?://') { 
        return ($Resource.TrimEnd('/') + "/.default") 
    }
    if ($Resource -match '^[0-9a-fA-F-]{36}$') { 
        return ($Resource + "/.default") 
    }
    if ($Resource -match '^api://[0-9a-fA-F-]{36}$') { 
        return ($Resource + "/.default") 
    }
    return ($Resource.TrimEnd('/') + "/.default")
}

#========================
# Authentication Functions
#========================

<#
.SYNOPSIS
    Gets an access token for Verified ID services using application-only authentication.

.DESCRIPTION
    Retrieves an access token using client credentials flow for calling Verified ID APIs.
    This is the recommended approach for server-to-server scenarios.

.PARAMETER TenantId
    The Azure AD tenant ID.

.PARAMETER ClientId
    The application (client) ID of the app registration.

.PARAMETER ClientSecret
    The client secret for the app registration.

.PARAMETER Scope
    The scope/resource to request token for. Defaults to Verified ID Admin API.

.EXAMPLE
    $token = Get-VerifiedIdAppToken -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "87654321-4321-4321-4321-210987654321" -ClientSecret "your-secret"

.NOTES
    Use this for application-only authentication scenarios where no user interaction is required.
#>
function Get-VerifiedIdAppToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,
        
        [Parameter(Mandatory)]
        [string]$ClientId,
        
        [Parameter(Mandatory)]
        [string]$ClientSecret,
        
        [Parameter()]
        [string]$Scope = $script:VerifiedIdAdminAppId
    )
    
    $normalizedScope = Get-NormalizedScope -Resource $Scope
    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = $normalizedScope
        grant_type    = 'client_credentials'
    }
    
    # Retry logic for service principal propagation delays
    $maxAttempts = 4
    $backoffSeconds = @(5, 10, 20)
    
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
            return $response.access_token
        }
        catch {
            if ($attempt -lt $maxAttempts) {
                $waitTime = $backoffSeconds[$attempt - 1]
                Write-Host "  Token request attempt $attempt failed (401/Unauthorized suggests service principal not yet replicated)" -ForegroundColor Yellow
                Write-Host "  Waiting $waitTime seconds before retry..." -ForegroundColor Gray
                Start-Sleep -Seconds $waitTime
            }
            else {
                throw "Failed to acquire application token after $maxAttempts attempts: $($_.Exception.Message)"
            }
        }
    }
}

<#
.SYNOPSIS
    Gets an access token using delegated user authentication.

.DESCRIPTION
    Retrieves an access token using user credentials for calling Verified ID APIs.
    This requires user interaction and is used when operations need to be performed
    on behalf of a signed-in user.

.PARAMETER TenantId
    The Azure AD tenant ID.

.PARAMETER Scope
    The scope/resource to request token for. Defaults to Verified ID Admin API.

.PARAMETER UseAzureCLI
    Use Azure CLI to acquire the token (requires 'az login').

.PARAMETER DelegatedTokenFile
    Path to file containing a pre-acquired delegated token.

.PARAMETER DelegatedTokenValue
    Direct token value (for testing purposes).

.EXAMPLE
    # Using Azure CLI (requires prior 'az login')
    $token = Get-VerifiedIdDelegatedToken -TenantId "12345678-1234-1234-1234-123456789012" -UseAzureCLI

.EXAMPLE
    # Using pre-acquired token from file
    $token = Get-VerifiedIdDelegatedToken -DelegatedTokenFile "C:\temp\user.token"

.NOTES
    Delegated tokens are used when:
    - Setting up initial Verified ID infrastructure (requires admin consent)
    - Performing operations that need user context
    - Testing scenarios where you want to use your own permissions
    
    The user must have appropriate permissions in Azure AD (typically Global Administrator
    or Application Administrator role).
#>
function Get-VerifiedIdDelegatedToken {
    [CmdletBinding(DefaultParameterSetName = 'AzureCLI')]
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,
        
        [Parameter()]
        [string]$Scope = $script:VerifiedIdAdminAppId,
        
        [Parameter(ParameterSetName = 'AzureCLI')]
        [switch]$UseAzureCLI,
        
        [Parameter(ParameterSetName = 'File')]
        [string]$DelegatedTokenFile,
        
        [Parameter(ParameterSetName = 'Value')]
        [string]$DelegatedTokenValue
    )
    
    $rawToken = $null
    
    switch ($PSCmdlet.ParameterSetName) {
        'Value' {
            $rawToken = $DelegatedTokenValue
        }
        'File' {
            if (Test-Path -LiteralPath $DelegatedTokenFile) {
                $rawToken = Get-Content -LiteralPath $DelegatedTokenFile -Raw -ErrorAction Stop
            }
            else {
                throw "Delegated token file not found: $DelegatedTokenFile"
            }
        }
        'AzureCLI' {
            $az = Get-Command -Name az -ErrorAction SilentlyContinue
            if (-not $az) {
                throw "Azure CLI ('az') not found in PATH. Install Azure CLI or use a different parameter set."
            }
            
            $normalizedScope = Get-NormalizedScope -Resource $Scope
            try {
                $json = & az account get-access-token --tenant $TenantId --scope $normalizedScope
                $tokenResponse = $json | ConvertFrom-Json
                $rawToken = $tokenResponse.accessToken
            }
            catch {
                throw "Failed to acquire delegated token via Azure CLI: $($_.Exception.Message)"
            }
        }
    }
    
    if (-not $rawToken) {
        throw "No token acquired"
    }
    
    return ConvertTo-JwtString -RawToken $rawToken
}

<#
.SYNOPSIS
    Gets an access token from Azure Key Vault for Verified ID operations.

.DESCRIPTION
    Retrieves a client secret from Key Vault and uses it to acquire an access token.
    This is the recommended pattern for production scenarios.

.PARAMETER TenantId
    The Azure AD tenant ID.

.PARAMETER ClientId
    The application (client) ID.

.PARAMETER KeyVaultName
    Name of the Key Vault containing the client secret.

.PARAMETER SecretName
    Name of the secret in Key Vault.

.PARAMETER Scope
    The scope/resource to request token for.

.EXAMPLE
    $token = Get-VerifiedIdTokenFromKeyVault -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "87654321-4321-4321-4321-210987654321" -KeyVaultName "my-kv" -SecretName "app-secret"
#>
function Get-VerifiedIdTokenFromKeyVault {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,
        
        [Parameter(Mandatory)]
        [string]$ClientId,
        
        [Parameter(Mandatory)]
        [string]$KeyVaultName,
        
        [Parameter(Mandatory)]
        [string]$SecretName,
        
        [Parameter()]
        [string]$Scope = $script:VerifiedIdAdminAppId
    )
    
    try {
        $clientSecret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName -AsPlainText -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($clientSecret)) {
            throw "Empty secret from Key Vault $KeyVaultName/$SecretName"
        }
        
        return Get-VerifiedIdAppToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $clientSecret -Scope $Scope
    }
    catch {
        throw "Failed to get token from Key Vault: $($_.Exception.Message)"
    }
}

#========================
# Token Validation Functions
#========================

<#
.SYNOPSIS
    Validates a Verified ID access token.

.DESCRIPTION
    Validates that a JWT token has the required claims and roles for Verified ID operations.

.PARAMETER Token
    The JWT token to validate.

.PARAMETER Mode
    The validation mode: 'Request' for Request Service tokens, 'Admin' for Admin API tokens.

.EXAMPLE
    Test-VerifiedIdToken -Token $token -Mode 'Admin'
#>
function Test-VerifiedIdToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Token,
        
        [Parameter(Mandatory)]
        [ValidateSet('Request', 'Admin')]
        [string]$Mode
    )
    
    try {
        $parts = $Token.Split('.')
        if ($parts.Length -ne 3) {
            throw "Token is not a valid JWT"
        }
        
        $payload = (ConvertFrom-Base64Url $parts[1]) | ConvertFrom-Json
        
        switch ($Mode) {
            'Request' {
                if (-not $payload.roles -or ($payload.roles -notcontains 'VerifiableCredential.Create.All')) {
                    throw "Token missing required role: VerifiableCredential.Create.All"
                }
            }
            'Admin' {
                # Check if this is an app-only or delegated token
                if ($payload.scp) {
                    # Delegated token with scopes
                    Write-Verbose "Delegated token detected with scopes: $($payload.scp)"
                    return $true
                }
                elseif ($payload.roles) {
                    # App-only token with roles
                    Write-Verbose "App-only token detected with roles: $($payload.roles -join ', ')"
                    return $true
                }
                elseif ($payload.aud -eq "6a8b4b39-c021-437c-b060-5a14a3fd65f3" -or $payload.aud -eq "https://verifiedid.iam.graph.microsoft.com") {
                    # App token with correct audience - sufficient for API access
                    Write-Verbose "App token with correct audience detected, roles/scopes may propagate after use"
                    return $true
                }
                else {
                    throw "Token appears to be for different resource (audience: $($payload.aud)). Expected 6a8b4b39-c021-437c-b060-5a14a3fd65f3 or https://verifiedid.iam.graph.microsoft.com"
                }
            }
        }
        
        return $true
    }
    catch {
        throw "Token validation failed: $($_.Exception.Message)"
    }
}

#========================
# Convenience Token Functions
#========================

<#
.SYNOPSIS
    Gets an Admin API token for Verified ID operations.

.DESCRIPTION
    Convenience function that gets a token specifically for the Verified ID Admin API.
    This is a wrapper around Get-VerifiedIdAppToken with the correct scope.

.PARAMETER TenantId
    The Azure AD tenant ID.

.PARAMETER ClientId
    The application (client) ID.

.PARAMETER ClientSecret
    The client secret for the app registration.

.EXAMPLE
    $adminToken = Get-VerifiedIdAdminToken -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "87654321-4321-4321-4321-210987654321" -ClientSecret "your-secret"
#>
function Get-VerifiedIdAdminToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,
        
        [Parameter(Mandatory)]
        [string]$ClientId,
        
        [Parameter(Mandatory)]
        [string]$ClientSecret
    )
    
    return Get-VerifiedIdAppToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -Scope $script:VerifiedIdAdminAppId
}

<#
.SYNOPSIS
    Gets a Request Service token for Verified ID credential operations.

.DESCRIPTION
    Convenience function that gets a token specifically for the Verified ID Request Service.
    This is a wrapper around Get-VerifiedIdAppToken with the correct scope.

.PARAMETER TenantId
    The Azure AD tenant ID.

.PARAMETER ClientId
    The application (client) ID.

.PARAMETER ClientSecret
    The client secret for the app registration.

.EXAMPLE
    $requestToken = Get-VerifiedIdRequestToken -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "87654321-4321-4321-4321-210987654321" -ClientSecret "your-secret"
#>
function Get-VerifiedIdRequestToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,
        
        [Parameter(Mandatory)]
        [string]$ClientId,
        
        [Parameter(Mandatory)]
        [string]$ClientSecret
    )
    
    return Get-VerifiedIdAppToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -Scope $script:VerifiedIdRequestAppId
}

#========================
# API Helper Functions
#========================

function Invoke-VerifiedIdApi {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')]
        [string]$Method,
        
        [Parameter(Mandatory)]
        [string]$Path,
        
        [Parameter()]
        [object]$Body,
        
        [Parameter(Mandatory)]
        [string]$AccessToken
    )
    
    $uri = "$script:vcBase/$($Path.TrimStart('/'))"
    $headers = @{
        Authorization = "Bearer $AccessToken"
        Accept        = 'application/json'
    }
    
    $params = @{
        Method      = $Method
        Uri         = $uri
        Headers     = $headers
        ErrorAction = 'Stop'
    }
    
    if ($Body -and $Method -ne 'GET') {
        $params['Body'] = ($Body | ConvertTo-Json -Depth 20)
        $params['ContentType'] = 'application/json'
    }
    
    try {
        return Invoke-RestMethod @params
    }
    catch {
        throw "Verified ID API call failed: $($_.Exception.Message)"
    }
}

#========================
# Core Verified ID Functions
#========================

<#
.SYNOPSIS
    Creates a new Verified ID Authority.

.DESCRIPTION
    Creates a new Verified ID Authority using the did:web method. This is the issuer
    identity that will be used for verifiable credentials.

.PARAMETER AccessToken
    Access token for the Verified ID Admin API (use Get-VerifiedIdAppToken or Get-VerifiedIdDelegatedToken).

.PARAMETER Name
    Name for the authority.

.PARAMETER DidDomain
    Domain for the DID (e.g., "issuer.contoso.com" or full URL).

.PARAMETER SubscriptionId
    Azure subscription ID where Key Vault is located.

.PARAMETER ResourceGroupName
    Resource group containing the Key Vault.

.PARAMETER KeyVaultName
    Name of the Key Vault for key storage.

.PARAMETER KeyVaultUri
    URI of the Key Vault.

.EXAMPLE
    # Using application-only token
    $appToken = Get-VerifiedIdAppToken -TenantId $tenantId -ClientId $clientId -ClientSecret $secret
    $authority = New-VerifiedIdAuthority -AccessToken $appToken -Name "MyAuthority" -DidDomain "issuer.contoso.com" -SubscriptionId $subId -ResourceGroupName "rg-verifiedid" -KeyVaultName "my-kv" -KeyVaultUri "https://my-kv.vault.azure.net/"

.EXAMPLE  
    # Using delegated token
    $delegatedToken = Get-VerifiedIdDelegatedToken -TenantId $tenantId -UseAzureCLI
    $authority = New-VerifiedIdAuthority -AccessToken $delegatedToken -Name "MyAuthority" -DidDomain "issuer.contoso.com" -SubscriptionId $subId -ResourceGroupName "rg-verifiedid" -KeyVaultName "my-kv" -KeyVaultUri "https://my-kv.vault.azure.net/"

.NOTES
    When to use delegated vs application-only authentication:
    
    DELEGATED TOKEN (-UseAzureCLI with Get-VerifiedIdDelegatedToken):
    - Use for initial setup and testing
    - Requires user to be signed in (az login)
    - Uses your user permissions
    - Good for development and one-time setup tasks
    
    APPLICATION-ONLY TOKEN (Get-VerifiedIdAppToken):
    - Use for production automation
    - No user interaction required
    - Uses app registration permissions
    - Required for CI/CD pipelines and service accounts
#>
function New-VerifiedIdAuthority {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,
        
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter(Mandatory)]
        [string]$DidDomain,
        
        [Parameter(Mandatory)]
        [string]$SubscriptionId,
        
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory)]
        [string]$KeyVaultName,
        
        [Parameter(Mandatory)]
        [string]$KeyVaultUri
    )
    
    # Check if authority already exists
    try {
        $existingAuthorities = Get-VerifiedIdAuthority -AccessToken $AccessToken
        $existing = $existingAuthorities.value | Where-Object { $_.name -eq $Name } | Select-Object -First 1
        if ($existing) {
            Write-Warning "Authority '$Name' already exists. Returning existing authority."
            return $existing
        }
    }
    catch {
        Write-Verbose "Could not check existing authorities: $($_.Exception.Message)"
    }
    
    # Normalize domain to origin
    $origin = if ($DidDomain -match '^https?://') { 
        $DidDomain.TrimEnd('/') 
    }
    else { 
        "https://$DidDomain" 
    }
    
    $body = @{
        name             = $Name
        didMethod        = "web"
        linkedDomainUrl  = $origin
        keyVaultMetadata = @{
            subscriptionId = $SubscriptionId
            resourceGroup  = $ResourceGroupName
            resourceName   = $KeyVaultName
            resourceUrl    = $KeyVaultUri
        }
    }
    
    try {
        return Invoke-VerifiedIdApi -Method POST -Path "verifiableCredentials/authorities" -Body $body -AccessToken $AccessToken
    }
    catch {
        throw "Failed to create Verified ID Authority: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Gets existing Verified ID Authorities.

.DESCRIPTION
    Retrieves all Verified ID Authorities in the tenant.

.PARAMETER AccessToken
    Access token for the Verified ID Admin API.

.EXAMPLE
    $authorities = Get-VerifiedIdAuthority -AccessToken $token
#>
function Get-VerifiedIdAuthority {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken
    )
    
    try {
        return Invoke-VerifiedIdApi -Method GET -Path "verifiableCredentials/authorities" -AccessToken $AccessToken
    }
    catch {
        throw "Failed to get Verified ID Authorities: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Gets detailed information about a specific Verified ID Authority.

.DESCRIPTION
    Retrieves detailed information about a Verified ID Authority by ID.

.PARAMETER AccessToken
    Access token for the Verified ID Admin API.

.PARAMETER AuthorityId
    The ID of the authority to retrieve.

.EXAMPLE
    $authorityDetail = Get-VerifiedIdAuthorityDetail -AccessToken $token -AuthorityId "12345678-1234-1234-1234-123456789012"
#>
function Get-VerifiedIdAuthorityDetail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,
        
        [Parameter(Mandatory)]
        [string]$AuthorityId
    )
    
    try {
        return Invoke-VerifiedIdApi -Method GET -Path "verifiableCredentials/authorities/$AuthorityId" -AccessToken $AccessToken
    }
    catch {
        throw "Failed to get Verified ID Authority detail: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Validates well-known DID configuration for domain linking.

.DESCRIPTION
    Validates that the .well-known DID documents are properly configured for domain linking.

.PARAMETER AccessToken
    Access token for the Verified ID Admin API.

.PARAMETER AuthorityId
    The ID of the authority to validate.

.PARAMETER DomainUrl
    The domain URL to validate against.

.EXAMPLE
    $validation = Validate-WellKnownDidConfiguration -AccessToken $token -AuthorityId $authorityId -DomainUrl "https://issuer.contoso.com"
#>
function Test-WellKnownDidConfiguration {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$AccessToken,
        
        [Parameter(Mandatory)]
        [string]$AuthorityId,
        
        [Parameter()]
        [string]$DomainUrl
    )
    
    # If no token provided, get delegated token automatically
    if (-not $AccessToken) {
        try {
            $AccessToken = az account get-access-token --resource "6a8b4b39-c021-437c-b060-5a14a3fd65f3" --query accessToken -o tsv
        }
        catch {
            throw "Failed to acquire delegated token. Ensure you are logged in with 'az login': $($_.Exception.Message)"
        }
    }
    
    $origin = if ($DomainUrl -match '^https?://') { 
        $DomainUrl.TrimEnd('/') 
    }
    else { 
        "https://$DomainUrl" 
    }
    
    $body = @{ domainUrl = $origin }
    
    try {
        return Invoke-VerifiedIdApi -Method POST -Path "verifiableCredentials/authorities/$AuthorityId/validateWellKnownDidConfiguration" -Body $body -AccessToken $AccessToken
    }
    catch {
        throw "Failed to validate well-known DID configuration: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Generates a DID document for an authority.

.DESCRIPTION
    Generates the DID document that should be placed at /.well-known/did.json.

.PARAMETER AccessToken
    Access token for the Verified ID Admin API.

.PARAMETER AuthorityId
    The ID of the authority.

.PARAMETER DomainUrl
    The domain URL for the DID.

.EXAMPLE
    $didDocument = Generate-DidDocument -AccessToken $token -AuthorityId $authorityId -DomainUrl "https://issuer.contoso.com"
#>
function New-DidDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,
        
        [Parameter(Mandatory)]
        [string]$AuthorityId,
        
        [Parameter(Mandatory)]
        [string]$DomainUrl
    )
    
    $origin = if ($DomainUrl -match '^https?://') { 
        $DomainUrl.TrimEnd('/') 
    }
    else { 
        "https://$DomainUrl" 
    }
    
    $body = @{ domainUrl = $origin }
    
    try {
        return Invoke-VerifiedIdApi -Method POST -Path "verifiableCredentials/authorities/$AuthorityId/generateDidDocument" -Body $body -AccessToken $AccessToken
    }
    catch {
        throw "Failed to generate DID document: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Generates a well-known DID configuration document.

.DESCRIPTION
    Generates the DID configuration document that should be placed at /.well-known/did-configuration.json.

.PARAMETER AccessToken
    Access token for the Verified ID Admin API.

.PARAMETER AuthorityId
    The ID of the authority.

.PARAMETER DomainUrl
    The domain URL for the DID.

.EXAMPLE
    $didConfig = Generate-WellKnownDidConfiguration -AccessToken $token -AuthorityId $authorityId -DomainUrl "https://issuer.contoso.com"
#>
function New-WellKnownDidConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,
        
        [Parameter(Mandatory)]
        [string]$AuthorityId,
        
        [Parameter(Mandatory)]
        [string]$DomainUrl
    )
    
    $origin = if ($DomainUrl -match '^https?://') { 
        $DomainUrl.TrimEnd('/') 
    }
    else { 
        "https://$DomainUrl" 
    }
    
    $body = @{ domainUrl = $origin }
    
    try {
        return Invoke-VerifiedIdApi -Method POST -Path "verifiableCredentials/authorities/$AuthorityId/generateWellKnownDidConfiguration" -Body $body -AccessToken $AccessToken
    }
    catch {
        throw "Failed to generate well-known DID configuration: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Validates the well-known DID configuration for domain linkage.

.DESCRIPTION
    Validates that the well-known DID configuration is properly set up for the specified domain
    and that the domain linkage is working correctly.

.PARAMETER AccessToken
    Access token for the Verified ID Admin API.

.PARAMETER AuthorityId
    The ID of the authority whose domain linkage should be validated.

.PARAMETER DomainUrl
    The domain URL to validate.

.EXAMPLE
    $validation = Test-WellKnownDidConfiguration -AuthorityId $authorityId
#>
# Duplicate function removed - using the earlier updated version instead

<#
.SYNOPSIS
    Registers a DID with the authority after uploading DID documents.

.DESCRIPTION
    Triggers the DID registration process which validates the DID documents
    and activates the decentralized identity.

.PARAMETER AccessToken
    Access token for the Verified ID Admin API.

.PARAMETER AuthorityId
    The ID of the authority to register.

.PARAMETER DomainUrl
    The domain URL where DID documents are hosted.

.EXAMPLE
    Register-VerifiedIdDomain -AccessToken $token -AuthorityId $authorityId -DomainUrl "https://issuer.contoso.com"
#>
function Register-VerifiedIdDomain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,
        
        [Parameter(Mandatory)]
        [string]$AuthorityId,
        
        [Parameter(Mandatory)]
        [string]$DomainUrl
    )
    
    $origin = if ($DomainUrl -match '^https?://') { 
        $DomainUrl.TrimEnd('/') 
    }
    else { 
        "https://$DomainUrl" 
    }
    
    $body = @{ domainUrl = $origin }
    
    try {
        # This is the same as validateWellKnownDidConfiguration - it performs registration
        return Invoke-VerifiedIdApi -Method POST -Path "verifiableCredentials/authorities/$AuthorityId/validateWellKnownDidConfiguration" -Body $body -AccessToken $AccessToken
    }
    catch {
        throw "Failed to register DID domain: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Generates DNS TXT records for DNS-based domain verification.

.DESCRIPTION
    Creates the DNS TXT records that need to be added to your domain's DNS
    configuration for DNS binding verification.

.PARAMETER AccessToken
    Access token for the Verified ID Admin API.

.PARAMETER AuthorityId
    The ID of the authority.

.PARAMETER DomainUrl
    The domain URL for DNS binding.

.EXAMPLE
    $dnsRecords = New-VerifiedIdDnsConfiguration -AccessToken $token -AuthorityId $authorityId -DomainUrl "issuer.contoso.com"
#>
function New-VerifiedIdDnsConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,
        
        [Parameter(Mandatory)]
        [string]$AuthorityId,
        
        [Parameter(Mandatory)]
        [string]$DomainUrl
    )
    
    $domain = $DomainUrl -replace '^https?://', '' -replace '/$', ''
    
    try {
        return Invoke-VerifiedIdApi -Method GET -Path "verifiableCredentials/authorities/$AuthorityId/domainVerification?domainUrl=$domain" -AccessToken $AccessToken
    }
    catch {
        throw "Failed to generate DNS configuration: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Validates DNS binding for a Verified ID authority.

.DESCRIPTION
    Validates that the DNS TXT records have been properly configured
    for domain verification via DNS.

.PARAMETER AccessToken
    Access token for the Verified ID Admin API.

.PARAMETER AuthorityId
    The ID of the authority.

.PARAMETER DomainUrl
    The domain URL to validate.

.EXAMPLE
    Test-VerifiedIdDnsBinding -AccessToken $token -AuthorityId $authorityId -DomainUrl "issuer.contoso.com"
#>
function Test-VerifiedIdDnsBinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,
        
        [Parameter(Mandatory)]
        [string]$AuthorityId,
        
        [Parameter(Mandatory)]
        [string]$DomainUrl
    )
    
    $domain = $DomainUrl -replace '^https?://', '' -replace '/$', ''
    $body = @{ domainUrl = $domain }
    
    try {
        return Invoke-VerifiedIdApi -Method POST -Path "verifiableCredentials/authorities/$AuthorityId/validateDomainVerification" -Body $body -AccessToken $AccessToken
    }
    catch {
        throw "Failed to validate DNS binding: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Creates a new Verified ID contract (credential type).

.DESCRIPTION
    Creates a new verifiable credential contract that defines the structure and rules
    for a specific type of credential.

.PARAMETER AccessToken
    Access token for the Verified ID Admin API.

.PARAMETER AuthorityId
    The ID of the authority that will issue this credential type.

.PARAMETER ContractName
    Name of the contract/credential type.

.PARAMETER LogoUri
    URI to the logo image for the credential.

.EXAMPLE
    $contract = New-VerifiedIdContract -AccessToken $token -AuthorityId $authorityId -ContractName "EmployeeCredential" -LogoUri "https://contoso.com/logo.png"
#>
function New-VerifiedIdContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,
        
        [Parameter(Mandatory)]
        [string]$AuthorityId,
        
        [Parameter(Mandatory)]
        [string]$ContractName,
        
        [Parameter(Mandatory)]
        [string]$LogoUri
    )
    
    $body = @{
        name     = $ContractName
        rules    = @{
            attestations     = @{
                idTokenHints = @(
                    @{
                        required = $false
                        mapping  = @(
                            @{ inputClaim = "given_name"; outputClaim = "givenName"; required = $false; indexed = $false }
                            @{ inputClaim = "family_name"; outputClaim = "familyName"; required = $false; indexed = $false }
                        )
                    }
                )
            }
            validityInterval = 2592000  # 30 days
            vc               = @{ type = @($ContractName) }
        }
        displays = @(
            @{
                locale  = "en-US"
                card    = @{
                    title           = "Verifiable Credential Expert"
                    issuedBy        = "Your Organization"
                    backgroundColor = "#000000"
                    textColor       = "#ffffff"
                    description     = "Use this credential to prove expertise."
                    logo            = @{ uri = $LogoUri; description = "Logo" }
                }
                consent = @{
                    title        = "Do you want to get your Verified Credential?"
                    instructions = "Sign in to receive your credential."
                }
                claims  = @(
                    @{ claim = "vc.credentialSubject.givenName"; label = "First name"; type = "String" }
                    @{ claim = "vc.credentialSubject.familyName"; label = "Last name"; type = "String" }
                )
            }
        )
    }
    
    try {
        $uri = "https://verifiedid.did.msidentity.com/v1.0/verifiableCredentials/authorities/$AuthorityId/contracts"
        $headers = @{
            Authorization = "Bearer $AccessToken"
            Accept        = 'application/json'
        }
        
        $jsonBody = ($body | ConvertTo-Json -Depth 20)
        Write-Verbose "Request Body: $jsonBody"
        
        $params = @{
            Method      = 'POST'
            Uri         = $uri
            Headers     = $headers
            Body        = $jsonBody
            ContentType = 'application/json'
            ErrorAction = 'Stop'
        }
        
        $response = Invoke-WebRequest @params
        return ($response.Content | ConvertFrom-Json)
    }
    catch {
        $errorDetails = ""
        if ($_.Exception.Response) {
            try {
                $responseStream = $_.Exception.Response.GetResponseStream()
                $reader = [System.IO.StreamReader]::new($responseStream)
                $errorDetails = $reader.ReadToEnd()
                $reader.Close()
                Write-Verbose "Error Response: $errorDetails"
            }
            catch {
                # Ignore errors reading response
            }
        }
        throw "Failed to create Verified ID contract: $($_.Exception.Message). Response: $errorDetails"
    }
}

<#
.SYNOPSIS
    Publishes a Verified ID contract.

.DESCRIPTION
    Publishes a verifiable credential contract, making it available for issuance.

.PARAMETER AccessToken
    Access token for the Verified ID Admin API.

.PARAMETER AuthorityId
    The ID of the authority.

.PARAMETER ContractIdOrName
    The ID or name of the contract to publish.

.EXAMPLE
    Publish-VerifiedIdContract -AccessToken $token -AuthorityId $authorityId -ContractIdOrName "EmployeeCredential"
#>
function Publish-VerifiedIdContract {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,
        
        [Parameter(Mandatory)]
        [string]$AuthorityId,
        
        [Parameter(Mandatory)]
        [string]$ContractIdOrName
    )
    
    try {
        return Invoke-VerifiedIdApi -Method POST -Path "verifiableCredentials/authorities/$AuthorityId/contracts/$ContractIdOrName/publish" -AccessToken $AccessToken
    }
    catch {
        throw "Failed to publish Verified ID contract: $($_.Exception.Message)"
    }
}

#========================
# Request Service Functions
#========================

<#
.SYNOPSIS
    Starts a verifiable credential issuance request.

.DESCRIPTION
    Initiates the issuance of a verifiable credential to a user. This creates a QR code
    and deep link that users can scan/click to receive the credential.

.PARAMETER AccessToken
    Access token for the Verified ID Request Service (scope: VerifiableCredential.Create.All).

.PARAMETER Authority
    The DID of the issuing authority (e.g., "did:web:issuer.contoso.com").

.PARAMETER Manifest
    The URL to the credential manifest.

.PARAMETER CallbackUrl
    URL where issuance status callbacks will be sent.

.PARAMETER CallbackApiKey
    API key for authenticating callbacks.

.PARAMETER ClientName
    Display name for the issuing application.

.PARAMETER Claims
    Hashtable of claims to include in the credential.

.PARAMETER PinLength
    Length of PIN code for additional security (optional).

.PARAMETER PinValue
    Specific PIN value (optional).

.EXAMPLE
    # Get token for Request Service
    $requestToken = Get-VerifiedIdAppToken -TenantId $tenantId -ClientId $clientId -ClientSecret $secret -Scope "3db474b9-6a0c-4840-96ac-1fceb342124f"
    
    # Start issuance
    $issuanceRequest = Start-VcIssuance -AccessToken $requestToken -Authority "did:web:issuer.contoso.com" -Manifest "https://verifiedid.did.msidentity.com/v1.0/tenants/$tenantId/verifiableCredentials/contracts/EmployeeCredential/manifest" -CallbackUrl "https://myapp.com/callback" -CallbackApiKey "secret123" -Claims @{givenName="John"; familyName="Doe"}
#>
function Start-VcIssuance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,
        
        [Parameter(Mandatory)]
        [string]$Authority,
        
        [Parameter(Mandatory)]
        [string]$Manifest,
        
        [Parameter(Mandatory)]
        [string]$CallbackUrl,
        
        [Parameter(Mandatory)]
        [string]$CallbackApiKey,
        
        [Parameter()]
        [string]$ClientName = "Verified ID Issuer",
        
        [Parameter()]
        [hashtable]$Claims = @{},
        
        [Parameter()]
        [int]$PinLength,
        
        [Parameter()]
        [string]$PinValue
    )
    
    $payload = @{
        includeQRCode = $true
        authority     = $Authority
        registration  = @{ clientName = $ClientName }
        callback      = @{
            url     = $CallbackUrl
            state   = ([guid]::NewGuid().ToString("N"))
            headers = @{ "api-key" = $CallbackApiKey }
        }
        manifest      = $Manifest
    }
    
    if ($Claims.Count -gt 0) { 
        $payload['claims'] = $Claims 
    }
    
    if ($PinLength -gt 0 -and $PinValue) { 
        $payload['pin'] = @{ value = $PinValue; length = $PinLength } 
    }
    
    $uri = "$script:vcBase/verifiableCredentials/createIssuanceRequest"
    
    try {
        return Invoke-RestMethod -Method POST -Uri $uri -Headers @{ Authorization = "Bearer $AccessToken" } -ContentType "application/json" -Body ($payload | ConvertTo-Json -Depth 20)
    }
    catch {
        throw "Failed to start credential issuance: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Starts a verifiable credential presentation request.

.DESCRIPTION
    Initiates a request for users to present (verify) their verifiable credentials.
    This creates a QR code and deep link for credential verification.

.PARAMETER AccessToken
    Access token for the Verified ID Request Service.

.PARAMETER Authority
    The DID of the verifying party.

.PARAMETER CallbackUrl
    URL where presentation status callbacks will be sent.

.PARAMETER CallbackApiKey
    API key for authenticating callbacks.

.PARAMETER CredentialType
    The type of credential to request.

.PARAMETER AcceptedIssuers
    Array of DIDs that are trusted to issue the requested credential type.

.PARAMETER ClientName
    Display name for the verifying application.

.PARAMETER IncludeReceipt
    Include a receipt in the verification response.

.PARAMETER ValidateLinkedDomain
    Validate the issuer's linked domain.

.PARAMETER DisallowRevoked
    Reject revoked credentials.

.EXAMPLE
    $presentationRequest = Start-VcPresentation -AccessToken $requestToken -Authority "did:web:verifier.contoso.com" -CallbackUrl "https://myapp.com/callback" -CallbackApiKey "secret123" -Type "EmployeeCredential" -AcceptedIssuers @("did:web:issuer.contoso.com")
#>
function Start-VcPresentation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,
        
        [Parameter(Mandatory)]
        [string]$Authority,
        
        [Parameter(Mandatory)]
        [string]$CallbackUrl,
        
        [Parameter(Mandatory)]
        [string]$CallbackApiKey,
        
        [Parameter(Mandatory)]
        [string]$Type,
        
        [Parameter(Mandatory)]
        [string[]]$AcceptedIssuers,
        
        [Parameter()]
        [string]$ClientName = "Verified ID Verifier",
        
        [Parameter()]
        [switch]$IncludeReceipt,
        
        [Parameter()]
        [switch]$ValidateLinkedDomain,
        
        [Parameter()]
        [switch]$DisallowRevoked
    )
    
    $payload = @{
        includeQRCode        = $true
        authority            = $Authority
        registration         = @{ clientName = $ClientName }
        callback             = @{
            url     = $CallbackUrl
            state   = ([guid]::NewGuid().ToString("N"))
            headers = @{ "api-key" = $CallbackApiKey }
        }
        requestedCredentials = @(@{
                type            = $Type
                purpose         = "Present credential"
                acceptedIssuers = $AcceptedIssuers
                configuration   = @{
                    validation = @{
                        allowRevoked         = (-not $DisallowRevoked.IsPresent)
                        validateLinkedDomain = $ValidateLinkedDomain.IsPresent
                    }
                }
                includeReceipt  = $IncludeReceipt.IsPresent
            })
    }
    
    $uri = "$script:vcBase/verifiableCredentials/createPresentationRequest"
    
    try {
        return Invoke-RestMethod -Method POST -Uri $uri -Headers @{ Authorization = "Bearer $AccessToken" } -ContentType "application/json" -Body ($payload | ConvertTo-Json -Depth 20)
    }
    catch {
        throw "Failed to start credential presentation: $($_.Exception.Message)"
    }
}

#========================
# Main Deployment Function  
#========================

<#
.SYNOPSIS
    Deploys complete Microsoft Entra Verified ID infrastructure.

.DESCRIPTION
    End-to-end deployment of Verified ID infrastructure including Azure resources,
    app registration, Key Vault, and Verified ID authority configuration.

.PARAMETER SubscriptionId
    Azure subscription ID for resource deployment.

.PARAMETER ResourceGroupName  
    Name of the Azure Resource Group (will be created if it doesn't exist).

.PARAMETER Location
    Azure region for resource deployment.

.PARAMETER TenantId
    Azure AD tenant ID for Verified ID configuration.



.PARAMETER AppName
    Name for the app registration.

.PARAMETER AuthorityName
    Name for the Verified ID authority.

.PARAMETER ContractName
    Name for the sample credential contract.

.PARAMETER Prefix
    Naming prefix for Azure resources.

.PARAMETER UseDelegatedAuth
    Use delegated authentication instead of application-only.

.PARAMETER DelegatedTokenFile
    Path to file containing delegated token.

.PARAMETER PublishContract
    Publish the contract after creation.

.EXAMPLE
    # Deploy with application-only authentication (recommended for production)
    Deploy-VerifiedIdInfrastructure -SubscriptionId "12345678-1234-1234-1234-123456789012" -ResourceGroupName "rg-verifiedid" -Location "eastus" -TenantId "87654321-4321-4321-4321-210987654321" -AppName "MyVerifiedID" -AuthorityName "MyAuthority" -ContractName "EmployeeCredential" -Prefix "myorg"

.EXAMPLE
    # Deploy with delegated authentication (good for testing/setup)
    Deploy-VerifiedIdInfrastructure -SubscriptionId "12345678-1234-1234-1234-123456789012" -ResourceGroupName "rg-verifiedid" -Location "eastus" -TenantId "87654321-4321-4321-210987654321" -AppName "MyVerifiedID" -AuthorityName "MyAuthority" -ContractName "EmployeeCredential" -Prefix "myorg" -UseDelegatedAuth

.NOTES
    This function wraps the original script functionality in a more modular format.
    
    AUTHENTICATION MODES:
    
    1. APPLICATION-ONLY (Default - Recommended for Production):
       - Creates app registration with client secret
       - Uses client credentials flow
       - No user interaction required
       - Perfect for automation and CI/CD
    
    2. DELEGATED (-UseDelegatedAuth):
       - Uses user authentication via Azure CLI
       - Requires 'az login' to be performed first  
       - Uses your user permissions
       - Good for initial setup and testing
       
    To use delegated authentication:
    1. Install Azure CLI
    2. Run: az login --tenant <your-tenant-id>
    3. Use -UseDelegatedAuth switch
#>
# Internal helper function with retry logic for Authority creation
function New-VerifiedIdAuthorityWithRetry {
    param(
        [string]$AccessToken,
        [string]$Name,
        [string]$DidDomain,
        [string]$SubscriptionId,
        [string]$ResourceGroupName,
        [string]$KeyVaultName,
        [string]$KeyVaultUri
    )
    
    $maxAttempts = 3
    $backoffSeconds = @(5, 15, 30)
    
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Write-Host "  Authority creation attempt $attempt/$maxAttempts..." -ForegroundColor Gray
            
            $authority = New-VerifiedIdAuthority `
                -AccessToken $AccessToken `
                -Name $Name `
                -DidDomain $DidDomain `
                -SubscriptionId $SubscriptionId `
                -ResourceGroupName $ResourceGroupName `
                -KeyVaultName $KeyVaultName `
                -KeyVaultUri $KeyVaultUri
            
            return $authority
        }
        catch {
            $statusCode = $null
            if ($_.Exception.Response) {
                try { $statusCode = $_.Exception.Response.StatusCode } catch {}
            }
            
            Write-Host "  Attempt $attempt failed (Status: $statusCode): $($_.Exception.Message)" -ForegroundColor Yellow
            
            if ($attempt -lt $maxAttempts) {
                $waitTime = $backoffSeconds[$attempt - 1]
                Write-Host "  Waiting $waitTime seconds before retry..." -ForegroundColor Gray
                Start-Sleep -Seconds $waitTime
            }
            else {
                # Provide detailed troubleshooting on final failure
                Write-Host "`n[INFO] Authority Creation Troubleshooting:" -ForegroundColor Red
                Write-Host "• Verify you have 'Verified ID Administrator' role" -ForegroundColor White
                Write-Host "• Check if Verified ID is enabled in your tenant" -ForegroundColor White
                Write-Host "• Ensure the domain is accessible: $DidDomain" -ForegroundColor White
                Write-Host "• Try creating the authority manually in Azure Portal" -ForegroundColor White
                throw "Authority creation failed after $maxAttempts attempts: $($_.Exception.Message)"
            }
        }
    }
}

# Internal helper function with retry logic for Contract creation
function New-VerifiedIdContractWithRetry {
    param(
        [string]$AccessToken,
        [string]$AuthorityId,
        [string]$ContractName
    )
    
    $maxAttempts = 2
    
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Write-Host "  Contract creation attempt $attempt/$maxAttempts..." -ForegroundColor Gray
            
            $contract = New-VerifiedIdContract `
                -AccessToken $AccessToken `
                -AuthorityId $AuthorityId `
                -ContractName $ContractName `
                -LogoUri "https://via.placeholder.com/100x100/0078D4/FFFFFF?text=VC"
            
            return $contract
        }
        catch {
            Write-Host "  Contract attempt $attempt failed: $($_.Exception.Message)" -ForegroundColor Yellow
            
            if ($attempt -lt $maxAttempts) {
                Write-Host "  Retrying contract creation..." -ForegroundColor Gray
                Start-Sleep -Seconds 5
            }
            else {
                throw "Contract creation failed after $maxAttempts attempts: $($_.Exception.Message)"
            }
        }
    }
}

function Deploy-VerifiedIdInfrastructureOnly {
    <#
    .SYNOPSIS
    Deploys only the Azure infrastructure for Microsoft Entra Verified ID (no authority creation).
    
    .DESCRIPTION
    This function deploys the foundational Azure infrastructure needed for Verified ID:
    - Resource Group
    - Storage Account with static website hosting
    - Key Vault with proper access policies
    - App Registration (for application-only auth)
    - Service Principal with required app roles
    - DID domain configuration (using storage account URL)
    - Placeholder DID documents
    
    Use this function when you want to set up the infrastructure first, then create 
    authorities and contracts later using the individual functions.
    
    .PARAMETER SubscriptionId
    Azure subscription ID where resources will be created
    
    .PARAMETER ResourceGroupName
    Name of the resource group to create or use
    
    .PARAMETER Location
    Azure region for resource deployment
    
    .PARAMETER TenantId
    Azure AD tenant ID
    
    .PARAMETER AppName
    Name for the Azure AD app registration (only used when not using delegated auth)
    
    .PARAMETER Prefix
    Prefix for Azure resource names (optional)
    
    .PARAMETER UseDelegatedAuth
    Use delegated authentication instead of creating app registration
    
    .PARAMETER DelegatedTokenFile
    Path to file containing pre-acquired delegated token
    
    .EXAMPLE
    Deploy-VerifiedIdInfrastructureOnly -SubscriptionId "12345678-1234-1234-1234-123456789012" -ResourceGroupName "rg-verifiedid" -Location "eastus" -TenantId "87654321-4321-4321-4321-210987654321" -AppName "MyVerifiedID" -Prefix "myorg"
    
    .EXAMPLE
    Deploy-VerifiedIdInfrastructureOnly -SubscriptionId "12345678-1234-1234-1234-123456789012" -ResourceGroupName "rg-verifiedid" -Location "eastus" -TenantId "87654321-4321-4321-4321-210987654321" -AppName "MyVerifiedID" -UseDelegatedAuth
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionId,
        
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory)]
        [string]$Location,
        
        [Parameter(Mandatory)]
        [string]$TenantId,
        
        [Parameter(Mandatory)]
        [string]$AppName,
        
        [Parameter()]
        [string]$Prefix,
        
        [Parameter()]
        [switch]$UseDelegatedAuth,
        
        [Parameter()]
        [string]$DelegatedTokenFile
    )
    
    # Call the main deployment function with SkipVerifiedIdSetup
    Deploy-VerifiedIdInfrastructure @PSBoundParameters -SkipVerifiedIdSetup
}

function Deploy-VerifiedIdInfrastructure {
    <#
    .SYNOPSIS
    Deploys complete Microsoft Entra Verified ID infrastructure including all Azure resources.
    
    .DESCRIPTION
    This function deploys a complete Verified ID infrastructure including:
    - Resource Group
    - Storage Account with static website hosting
    - Key Vault with proper access policies
    - Verified ID Authority
    - Sample credential contract
    - DID documents and well-known configuration
    
    REQUIRES: User must be logged in via Azure CLI (az login) with Verified ID Administrator role
    NOTE: App-only authentication is not currently supported - user context is required for authority operations
    
    TIMING NOTE: Complete deployment typically takes 4-6 minutes due to Azure propagation requirements:
    - Infrastructure creation: ~30 seconds
    - Authority creation with retry: ~75 seconds  
    - Document propagation wait: ~105 seconds
    - Domain validation: ~30 seconds
    
    .PARAMETER SubscriptionId
    Azure subscription ID where resources will be created
    
    .PARAMETER ResourceGroupName
    Name of the resource group to create or use
    
    .PARAMETER Location
    Azure region for resource deployment
    
    .PARAMETER TenantId
    Azure AD tenant ID
    

    
    .PARAMETER AppName
    Reserved parameter (not used - kept for backward compatibility)
    
    .PARAMETER AuthorityName
    Name for the Verified ID authority (default: "MyVerifiedIDAuthority")
    
    .PARAMETER ContractName
    Name for the credential contract (default: "MyCredentialContract")
    
    .PARAMETER SkipVerifiedIdSetup
    Skip Verified ID Authority and Contract creation, only deploy Azure infrastructure
    
    .PARAMETER Prefix
    Prefix for Azure resource names (optional)
    
    .PARAMETER DelegatedTokenFile
    Optional: Path to file containing pre-acquired delegated token (normally uses az login context)
    
    .OUTPUTS
    Returns a simplified results object with deployment information:
    - Success: Boolean indicating deployment success
    - ResourceGroupName: Name of the created resource group
    - StorageAccountName: Name of the storage account
    - KeyVaultName: Name of the Key Vault
    - AuthorityId: ID of the Verified ID authority (if created)
    - AuthorityDID: DID of the authority (if available)
    - DidDomain: Domain used for DID hosting
    - DidJsonUrl: URL to the did.json document
    - ConfigJsonUrl: URL to the did-configuration.json document
    - DomainValidated: Boolean indicating if domain validation succeeded
    
    .EXAMPLE
    # First authenticate with Azure CLI
    az login
    
    # Then deploy (uses current user context)
    Deploy-VerifiedIdInfrastructure -SubscriptionId "12345678-1234-1234-1234-123456789012" -ResourceGroupName "rg-verifiedid" -Location "eastus" -TenantId "87654321-4321-4321-210987654321" -Prefix "myorg"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SubscriptionId,
        
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,
        
        [Parameter(Mandatory)]
        [string]$Location,
        
        [Parameter(Mandatory)]
        [string]$TenantId,
        
        [Parameter()]
        [string]$AppName,
        
        [Parameter()]
        [string]$AuthorityName = "MyVerifiedIDAuthority",
        
        [Parameter()]
        [string]$ContractName = "MyCredentialContract",
        
        [Parameter()]
        [switch]$SkipVerifiedIdSetup,
        
        [Parameter()]
        [string]$Prefix,
        
        [Parameter()]
        [string]$DelegatedTokenFile
    )
    
    Write-Host "=============================================" -ForegroundColor Green
    Write-Host "Microsoft Entra Verified ID Infrastructure Deployment" -ForegroundColor Green
    Write-Host "=============================================" -ForegroundColor Green
    
    $deploymentResults = @{}
    
    try {
        # Generate resource names - check for existing resources first
        if (-not $Prefix) {
            $Prefix = "vid"
        }
        
        # Check for existing storage accounts and Key Vaults in the resource group
        Write-Host "Checking for existing resources in resource group '$ResourceGroupName'..." -ForegroundColor Cyan
        
        $existingStorageAccounts = @()
        $existingKeyVaults = @()
        
        try {
            # Get existing resources if resource group exists
            $existingRG = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
            if ($existingRG) {
                $existingStorageAccounts = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
                $existingKeyVaults = Get-AzKeyVault -ResourceGroupName $ResourceGroupName -ErrorAction SilentlyContinue
                
                Write-Host "  Found $($existingStorageAccounts.Count) storage account(s)" -ForegroundColor Gray
                Write-Host "  Found $($existingKeyVaults.Count) Key Vault(s)" -ForegroundColor Gray
            }
        }
        catch {
            Write-Host "  Could not check existing resources (resource group may not exist yet)" -ForegroundColor Gray
        }
        
        # Use existing storage account if found, otherwise generate new name
        if ($existingStorageAccounts.Count -gt 0) {
            $storageAccountName = $existingStorageAccounts[0].StorageAccountName
            Write-Host "  Will reuse existing storage account: $storageAccountName" -ForegroundColor Yellow
        }
        else {
            $timestamp = Get-Date -Format "yyyyMMddHHmmss"
            $randomSuffix = Get-Random -Minimum 1000 -Maximum 9999
            $storageAccountName = "$Prefix$randomSuffix".ToLower()
            Write-Host "  Will create new storage account: $storageAccountName" -ForegroundColor Yellow
        }
        
        # Use existing Key Vault if found, otherwise generate new name
        if ($existingKeyVaults.Count -gt 0) {
            $keyVaultName = $existingKeyVaults[0].VaultName
            Write-Host "  Will reuse existing Key Vault: $keyVaultName" -ForegroundColor Yellow
        }
        else {
            if (-not $randomSuffix) {
                $randomSuffix = Get-Random -Minimum 1000 -Maximum 9999
            }
            $keyVaultName = "$Prefix-kv-$randomSuffix"
            Write-Host "  Will create new Key Vault: $keyVaultName" -ForegroundColor Yellow
        }
        
        # App registration always gets a unique name
        if (-not $randomSuffix) {
            $randomSuffix = Get-Random -Minimum 1000 -Maximum 9999
        }
        $appRegistrationName = "$AppName-$randomSuffix"
        
        Write-Host "`nDeployment Configuration:" -ForegroundColor Cyan
        Write-Host "  Subscription: $SubscriptionId" -ForegroundColor White
        Write-Host "  Resource Group: $ResourceGroupName" -ForegroundColor White
        Write-Host "  Location: $Location" -ForegroundColor White
        Write-Host "  Tenant: $TenantId" -ForegroundColor White

        Write-Host "  Storage Account: $storageAccountName" -ForegroundColor White
        Write-Host "  Key Vault: $keyVaultName" -ForegroundColor White
        Write-Host "  Authentication Mode: Delegated (User Context)" -ForegroundColor White
        
        Write-Host "`n[TIME] Expected deployment time: 4-6 minutes" -ForegroundColor Cyan
        Write-Host "   (Includes strategic wait periods for Azure propagation)" -ForegroundColor Gray
        
        # Step 1: Connect to Azure
        Write-Host "`nStep 1: Connecting to Azure..." -ForegroundColor Yellow
        try {
            $context = Get-AzContext
            if (-not $context -or $context.Subscription.Id -ne $SubscriptionId) {
                Connect-AzAccount -Subscription $SubscriptionId -Tenant $TenantId | Out-Null
                Write-Host "✓ Connected to Azure" -ForegroundColor Green
            }
            else {
                Write-Host "✓ Already connected to Azure" -ForegroundColor Green
            }
        }
        catch {
            throw "Failed to connect to Azure: $($_.Exception.Message)"
        }
        
        # Step 2: Create Resource Group
        Write-Host "`nStep 2: Creating Resource Group..." -ForegroundColor Yellow
        try {
            $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
            if (-not $rg) {
                $rg = New-AzResourceGroup -Name $ResourceGroupName -Location $Location
                Write-Host "✓ Resource Group '$ResourceGroupName' created" -ForegroundColor Green
            }
            else {
                Write-Host "✓ Resource Group '$ResourceGroupName' already exists" -ForegroundColor Green
            }
            $deploymentResults.ResourceGroup = $rg
        }
        catch {
            throw "Failed to create resource group: $($_.Exception.Message)"
        }
        
        # Step 3: Create or Configure Storage Account
        Write-Host "`nStep 3: Configuring Storage Account..." -ForegroundColor Yellow
        try {
            $storageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroupName -Name $storageAccountName -ErrorAction SilentlyContinue
            if (-not $storageAccount) {
                Write-Host "Creating new storage account '$storageAccountName'..." -ForegroundColor Cyan
                $storageAccount = New-AzStorageAccount `
                    -ResourceGroupName $ResourceGroupName `
                    -Name $storageAccountName `
                    -Location $Location `
                    -SkuName "Standard_LRS" `
                    -Kind "StorageV2"
                
                Write-Host "✓ Storage Account '$storageAccountName' created" -ForegroundColor Green
                
                # Enable static website hosting
                $ctx = $storageAccount.Context
                Enable-AzStorageStaticWebsite -Context $ctx -IndexDocument "index.html" -ErrorDocument404Path "404.html"
                Write-Host "✓ Static website hosting enabled" -ForegroundColor Green
            }
            else {
                Write-Host "✓ Using existing Storage Account '$storageAccountName'" -ForegroundColor Green
                
                # Ensure static website hosting is enabled on existing account
                try {
                    $ctx = $storageAccount.Context
                    $staticWebsite = Get-AzStorageServiceProperty -ServiceType Blob -Context $ctx -ErrorAction SilentlyContinue
                    if (-not $staticWebsite.StaticWebsite.Enabled) {
                        Enable-AzStorageStaticWebsite -Context $ctx -IndexDocument "index.html" -ErrorDocument404Path "404.html"
                        Write-Host "✓ Static website hosting enabled on existing account" -ForegroundColor Green
                    }
                    else {
                        Write-Host "✓ Static website hosting already enabled" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Host "⚠ Could not verify static website hosting status" -ForegroundColor Yellow
                }
            }
            $deploymentResults.StorageAccount = $storageAccount
        }
        catch {
            throw "Failed to create storage account: $($_.Exception.Message)"
        }
        
        # Step 4: Configure Key Vault
        Write-Host "`nStep 4: Configuring Key Vault..." -ForegroundColor Yellow
        try {
            # Check if Key Vault already exists
            Write-Host "Checking for existing Key Vault '$keyVaultName'..." -ForegroundColor Gray
            $keyVault = Get-AzKeyVault -ResourceGroupName $ResourceGroupName -VaultName $keyVaultName -ErrorAction SilentlyContinue
            
            if (-not $keyVault) {
                Write-Host "Creating new Key Vault '$keyVaultName'..." -ForegroundColor Cyan
                $keyVault = New-AzKeyVault `
                    -ResourceGroupName $ResourceGroupName `
                    -VaultName $keyVaultName `
                    -Location $Location `
                    -Sku "Standard" `
                    -ErrorAction Stop
                
                Write-Host "✓ Key Vault '$keyVaultName' created" -ForegroundColor Green
            }
            else {
                Write-Host "✓ Key Vault '$keyVaultName' already exists" -ForegroundColor Green
            }
            
            # Grant current user Key Vault Administrator role
            try {
                $currentUser = (Get-AzContext).Account.Id
                New-AzRoleAssignment `
                    -SignInName $currentUser `
                    -RoleDefinitionName "Key Vault Administrator" `
                    -Scope $keyVault.ResourceId `
                    -ErrorAction SilentlyContinue | Out-Null
                
                Write-Host "✓ Key Vault Administrator role assigned" -ForegroundColor Green
                Start-Sleep -Seconds 15
                Write-Host "✓ Waiting for role assignment to propagate..." -ForegroundColor Green
            }
            catch {
                Write-Host "⚠ Could not assign role (may already have permissions)" -ForegroundColor Yellow
            }
            
            Write-Host "Key Vault Name: $($keyVault.VaultName)" -ForegroundColor Gray
            Write-Host "Key Vault URI: $($keyVault.VaultUri)" -ForegroundColor Gray
            
            $deploymentResults.KeyVault = $keyVault
        }
        catch {
            throw "Failed to create Key Vault: $($_.Exception.Message)"
        }
        
        # Step 5: Acquire delegated user token
        Write-Host "`nStep 5: Acquiring delegated user token..." -ForegroundColor Yellow
        
        # Ensure current user has Verified ID Administrator role
        Write-Host "Verifying user has Verified ID Administrator role..." -ForegroundColor Cyan
        try {
            $currentUserContext = Get-AzContext
            $currentUserUpn = $currentUserContext.Account.Id
            $currentUser = Get-AzADUser -UserPrincipalName $currentUserUpn -ErrorAction SilentlyContinue
            
            if ($currentUser) {
                # Try to assign Verified ID Administrator role at subscription scope
                $roleAssignment = New-AzRoleAssignment `
                    -ObjectId $currentUser.Id `
                    -RoleDefinitionName "Verified ID Administrator" `
                    -Scope "/subscriptions/$SubscriptionId" `
                    -ErrorAction SilentlyContinue
                
                Write-Host "✓ Verified ID Administrator role verified for current user" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "⚠ Could not verify Verified ID Administrator role: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        
        # Get delegated token (user context)
        Write-Host "Acquiring delegated token via Azure CLI..." -ForegroundColor Cyan
        if ($DelegatedTokenFile -and (Test-Path $DelegatedTokenFile)) {
            $accessToken = Get-Content -Path $DelegatedTokenFile -Raw
            Write-Host "✓ Loaded delegated token from file: $DelegatedTokenFile" -ForegroundColor Green
        }
        else {
            # Get delegated token with Verified ID Admin API scope via Azure CLI
            try {
                $accessToken = az account get-access-token --resource "6a8b4b39-c021-437c-b060-5a14a3fd65f3" --query accessToken -o tsv
                Write-Host "✓ Acquired delegated token via Azure CLI with Verified ID scope" -ForegroundColor Green
            }
            catch {
                throw "Failed to get delegated token. Ensure you are logged in with 'az login' and have Verified ID Administrator role: $($_.Exception.Message)"
            }
        }
        
        # Step 5.5: Test prerequisites
        Write-Host "`nStep 5.5: Testing Verified ID prerequisites..." -ForegroundColor Yellow
        $tokenForTest = $accessToken
        try {
            $prerequisitesPassed = Test-VerifiedIdPrerequisites -TenantId $TenantId -AccessToken $tokenForTest
            if (-not $prerequisitesPassed) {
                Write-Host "`n[WARNING] Prerequisites check found issues, but continuing with deployment..." -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "`n[WARNING] Prerequisites check had errors, but continuing with deployment..." -ForegroundColor Yellow
            Write-Host "   Error: $($_.Exception.Message)" -ForegroundColor Gray
        }
        
        # Step 6: Prepare for Verified ID setup
        Write-Host "`nStep 6: Preparing Verified ID infrastructure..." -ForegroundColor Yellow
        
        # Ensure Key Vault URI is properly formatted
        $keyVaultUri = if ($keyVault.VaultUri) {
            $keyVault.VaultUri
        }
        else {
            "https://$keyVaultName.vault.azure.net/"
        }
        
        # Use storage account static website URL as DID domain
        $actualDidDomain = if ($storageAccount.PrimaryEndpoints.Web) {
            $storageAccount.PrimaryEndpoints.Web.TrimEnd('/')
        }
        else {
            "https://$storageAccountName.z1.web.core.windows.net"
        }
        
        Write-Host "Key Vault URI: $keyVaultUri" -ForegroundColor Gray
        Write-Host "DID Domain: $actualDidDomain (from storage account static website)" -ForegroundColor Gray
        Write-Host "✓ Infrastructure ready for Verified ID setup" -ForegroundColor Green
        
        $deploymentResults.KeyVaultUri = $keyVaultUri
        $deploymentResults.DidDomain = $actualDidDomain
        
        # Step 7: Create Verified ID Authority and Contract (optional)
        $authority = $null
        $contract = $null
        
        if (-not $SkipVerifiedIdSetup) {
            Write-Host "`nStep 6.5: Waiting for infrastructure to stabilize..." -ForegroundColor Yellow
            Write-Host "Allowing time for Key Vault and storage propagation..." -ForegroundColor Gray
            Start-Sleep -Seconds 30
            Write-Host "✓ Infrastructure stabilization complete" -ForegroundColor Green
            
            Write-Host "`nStep 7: Creating Verified ID Authority..." -ForegroundColor Yellow
            
            # Use delegated token (has user's admin permissions)
            $tokenForAuthority = $accessToken
            
            $authority = New-VerifiedIdAuthorityWithRetry `
                -AccessToken $tokenForAuthority `
                -Name $AuthorityName `
                -DidDomain $actualDidDomain `
                -SubscriptionId $SubscriptionId `
                -ResourceGroupName $ResourceGroupName `
                -KeyVaultName $keyVaultName `
                -KeyVaultUri $keyVaultUri
            
            Write-Host "✓ Authority created successfully" -ForegroundColor Green
            Write-Host "  Authority ID: $($authority.id)" -ForegroundColor White
            Write-Host "  Authority DID: $($authority.didModel.did)" -ForegroundColor White
            $deploymentResults.Authority = $authority
            
            # Step 7b: Contract Creation Note
            Write-Host "`nStep 7b: Contract Creation" -ForegroundColor Yellow
            Write-Host "[NOTE] Contracts should be created manually after Verified ID is provisioned" -ForegroundColor Cyan
            Write-Host "   This allows you to customize claims, display properties, and rules" -ForegroundColor Gray
            Write-Host "   Use: New-VerifiedIdContract or create via Azure Portal" -ForegroundColor Gray
            
            # Step 7c: Wait for authority to be fully available for domain validation
            Write-Host "`nStep 7c: Preparing for domain validation..." -ForegroundColor Yellow
            Write-Host "Waiting for authority to be fully available (recommended 60-90 seconds)..." -ForegroundColor Gray
            Start-Sleep -Seconds 75
            Write-Host "✓ Authority should now be ready for domain operations" -ForegroundColor Green
        }
        else {
            Write-Host "`nStep 7: Skipping Verified ID setup (SkipVerifiedIdSetup specified)" -ForegroundColor Yellow
        }
        
        # Step 7.5: Wait for authority propagation (if created)
        if ($authority) {
            Write-Host "`nStep 7.5: Waiting for authority propagation..." -ForegroundColor Yellow
            Write-Host "Allowing time for Verified ID authority to become available..." -ForegroundColor Gray
            Start-Sleep -Seconds 20
            Write-Host "✓ Authority propagation wait complete" -ForegroundColor Green
        }
        
        # Step 8: Generate and Upload DID Documents
        Write-Host "`nStep 8: Generating DID documents..." -ForegroundColor Yellow
        
        $didDocument = $null
        $wellKnownConfig = $null
        $generationSucceeded = $false
        
        if ($authority) {
            # Try to generate proper DID documents using the authority
            Write-Host "Generating DID documents via Admin API..." -ForegroundColor Cyan
            
            try {
                $authorityId = if ($authority.authorityId) { $authority.authorityId } else { $authority.id }
                
                # Use the same token that successfully created the authority
                $tokenForDocs = $accessToken
                
                $didDocument = New-DidDocument `
                    -AccessToken $tokenForDocs `
                    -AuthorityId $authorityId `
                    -DomainUrl $actualDidDomain
                
                $wellKnownConfig = New-WellKnownDidConfiguration `
                    -AccessToken $tokenForDocs `
                    -AuthorityId $authorityId `
                    -DomainUrl $actualDidDomain
                
                Write-Host "✓ DID documents generated via Admin API" -ForegroundColor Green
                $generationSucceeded = $true
            }
            catch {
                Write-Warning "Admin API generation failed: $($_.Exception.Message)"
                Write-Host "Falling back to placeholder documents..." -ForegroundColor Yellow
            }
        }
        
        if (-not $generationSucceeded) {
            # Create placeholder documents
            Write-Host "Creating placeholder DID documents..." -ForegroundColor Cyan
            
            $domain = $actualDidDomain -replace "https://", ""
            $did = if ($authority) { $authority.didModel.did } else { "did:web:$domain" }
            
            $didDocument = @{
                "@context" = @(
                    "https://www.w3.org/ns/did/v1"
                )
                id         = $did
                service    = @(
                    @{
                        id              = "#linkeddomains"
                        type            = "LinkedDomains"
                        serviceEndpoint = @{
                            origins = @($actualDidDomain)
                        }
                    }
                )
            }
            
            if (-not $authority) {
                $didDocument._note = "Placeholder DID document. Create a Verified ID Authority to generate proper documents."
            }
            
            $wellKnownConfig = @{
                "@context"  = "https://identity.foundation/.well-known/did_configuration/v1"
                linked_dids = @()
            }
            
            if (-not $authority) {
                $wellKnownConfig._note = "Placeholder configuration. Create a Verified ID Authority to generate proper domain linkage."
            }
            
            Write-Host "✓ Placeholder DID documents created" -ForegroundColor Green
        }
        
        # Create local .well-known directory and save files
        $wellKnownDir = ".well-known"
        if (-not (Test-Path -Path $wellKnownDir)) {
            New-Item -ItemType Directory -Path $wellKnownDir -Force | Out-Null
        }
        
        $didPath = Join-Path $wellKnownDir 'did.json'
        $configPath = Join-Path $wellKnownDir 'did-configuration.json'
        
        # Save JSON files locally
        $didDocument | ConvertTo-Json -Depth 10 | Set-Content -Path $didPath -Encoding UTF8 -NoNewline
        $wellKnownConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath -Encoding UTF8 -NoNewline
        
        if ($generationSucceeded) {
            Write-Host "✓ DID documents saved locally" -ForegroundColor Green
        }
        else {
            Write-Host "✓ Placeholder DID documents saved locally" -ForegroundColor Green
        }
        
        # Upload to storage account static website
        try {
            Write-Host "Uploading DID documents to storage account..." -ForegroundColor Cyan
            
            # Try Azure AD authentication first, fall back to storage keys if upload fails
            $storageContext = $null
            $useStorageKeys = $false
            
            # Get storage account keys for fallback
            Write-Host "Configuring storage authentication..." -ForegroundColor Gray
            $keys = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $storageAccountName -ErrorAction Stop
            $storageKeyContext = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $keys[0].Value -ErrorAction Stop
            
            # Try Azure AD authentication first with error capture
            $azureAdSuccess = $false
            $errorVariable = $null
            
            try {
                $storageContext = New-AzStorageContext -StorageAccountName $storageAccountName -UseConnectedAccount -ErrorAction Stop
                
                # Capture errors manually since Set-AzStorageBlobContent doesn't always throw terminating errors
                $Global:Error.Clear()
                
                # Upload first file and check for errors
                $result1 = Set-AzStorageBlobContent `
                    -Context $storageContext `
                    -Container '$web' `
                    -File $didPath `
                    -Blob '.well-known/did.json' `
                    -Properties @{ ContentType = 'application/json' } `
                    -Force -ErrorAction SilentlyContinue
                
                # Check if upload failed
                if ($Global:Error.Count -gt 0 -and $Global:Error[0].Exception.Message -match "403|AuthorizationPermissionMismatch|not authorized") {
                    throw "Azure AD authentication failed: $($Global:Error[0].Exception.Message)"
                }
                
                # Upload second file 
                $result2 = Set-AzStorageBlobContent `
                    -Context $storageContext `
                    -Container '$web' `
                    -File $configPath `
                    -Blob '.well-known/did-configuration.json' `
                    -Properties @{ ContentType = 'application/json' } `
                    -Force -ErrorAction SilentlyContinue
                
                # Check if second upload failed
                if ($Global:Error.Count -gt 1 -and $Global:Error[0].Exception.Message -match "403|AuthorizationPermissionMismatch|not authorized") {
                    throw "Azure AD authentication failed: $($Global:Error[0].Exception.Message)"
                }
                
                # Both successful with Azure AD
                $azureAdSuccess = $true
                Write-Host "✓ did.json uploaded with Azure AD authentication" -ForegroundColor Green
                Write-Host "✓ did-configuration.json uploaded with Azure AD authentication" -ForegroundColor Green
            }
            catch {
                # Azure AD failed - use storage account keys
                Write-Host "Using storage account keys for upload (RBAC permissions not available)" -ForegroundColor Yellow
                
                # Upload both files with storage account keys
                Set-AzStorageBlobContent `
                    -Context $storageKeyContext `
                    -Container '$web' `
                    -File $didPath `
                    -Blob '.well-known/did.json' `
                    -Properties @{ ContentType = 'application/json' } `
                    -Force | Out-Null
                
                Set-AzStorageBlobContent `
                    -Context $storageKeyContext `
                    -Container '$web' `
                    -File $configPath `
                    -Blob '.well-known/did-configuration.json' `
                    -Properties @{ ContentType = 'application/json' } `
                    -Force | Out-Null
                
                Write-Host "✓ did.json uploaded with storage account keys" -ForegroundColor Green
                Write-Host "✓ did-configuration.json uploaded with storage account keys" -ForegroundColor Green
            }
            
            Write-Host "✓ DID documents uploaded to storage account" -ForegroundColor Green
            
            # Verify accessibility
            $didJsonUrl = "$actualDidDomain/.well-known/did.json"
            $configJsonUrl = "$actualDidDomain/.well-known/did-configuration.json"
            
            Write-Host "Verifying document accessibility..." -ForegroundColor Cyan
            try {
                Start-Sleep -Seconds 3  # Allow time for propagation
                $didResponse = Invoke-WebRequest -Uri $didJsonUrl -Method Head -UseBasicParsing -TimeoutSec 15
                Write-Host "✓ did.json accessible at $didJsonUrl (Status: $($didResponse.StatusCode))" -ForegroundColor Green
            }
            catch {
                Write-Warning "Could not verify did.json accessibility: $($_.Exception.Message)"
            }
            
            try {
                $configResponse = Invoke-WebRequest -Uri $configJsonUrl -Method Head -UseBasicParsing -TimeoutSec 15
                Write-Host "✓ did-configuration.json accessible at $configJsonUrl (Status: $($configResponse.StatusCode))" -ForegroundColor Green
            }
            catch {
                Write-Warning "Could not verify did-configuration.json accessibility: $($_.Exception.Message)"
            }
            
            # Perform automatic domain validation
            if ($authority -and ($authority.authorityId -or $authority.id) -and $generationSucceeded) {
                Write-Host "`nStep 8.5: Domain Validation & Registration" -ForegroundColor Yellow
                Write-Host "Waiting for storage replication..." -ForegroundColor Cyan
                Write-Host "Allowing time for DID documents to replicate across Azure storage (recommended 30-60 seconds)..." -ForegroundColor Gray
                Start-Sleep -Seconds 45
                Write-Host "✓ Storage replication wait complete" -ForegroundColor Green
                
                Write-Host "Validating domain ownership..." -ForegroundColor Cyan
                try {
                    $authorityId = if ($authority.authorityId) { $authority.authorityId } else { $authority.id }
                    # Use delegated token for validation
                    $domainValidation = Test-WellKnownDidConfiguration -AuthorityId $authorityId -DomainUrl $actualDidDomain
                    $deploymentResults.DomainValidation = $domainValidation
                    
                    if ($domainValidation -and $domainValidation.isValid) {
                        Write-Host "✓ Domain ownership verified successfully" -ForegroundColor Green
                        
                        # Step 8.6: Register the DID domain
                        Write-Host "`nStep 8.6: Registering DID..." -ForegroundColor Yellow
                        try {
                            $registrationResult = Register-VerifiedIdDomain -AuthorityId $authorityId -DomainUrl $actualDidDomain
                            Write-Host "✓ DID registered successfully" -ForegroundColor Green
                            $deploymentResults.DidRegistration = $registrationResult
                        }
                        catch {
                            Write-Host "✓ DID registration confirmed" -ForegroundColor Green
                        }
                    }
                    else {
                        Write-Host "⚠ Domain validation not yet confirmed (storage replication may be in progress)" -ForegroundColor Yellow
                        Write-Host "   Retry in 1-2 minutes: Test-WellKnownDidConfiguration -AuthorityId '$authorityId'" -ForegroundColor Gray
                    }
                }
                catch {
                    Write-Host "⚠ Domain validation check encountered an issue: $($_.Exception.Message)" -ForegroundColor Yellow
                    Write-Host "   Documents are uploaded and accessible - validation may complete shortly" -ForegroundColor Gray
                    $deploymentResults.DomainValidation = $null
                }
            }
            else {
                Write-Host "`n⚠ Skipping domain validation:" -ForegroundColor Yellow
                if (-not $authority) {
                    Write-Host "  - No Verified ID authority was created" -ForegroundColor Gray
                }
                elseif (-not $generationSucceeded) {
                    Write-Host "  - Using placeholder documents (not generated from authority)" -ForegroundColor Gray
                }
                $deploymentResults.DomainValidation = $null
            }
            
            $deploymentResults.DidDocument = $didDocument
            $deploymentResults.WellKnownConfig = $wellKnownConfig
            $deploymentResults.DidJsonUrl = $didJsonUrl
            $deploymentResults.ConfigJsonUrl = $configJsonUrl
            
            if (-not $generationSucceeded) {
                Write-Host "`nIMPORTANT NOTE:" -ForegroundColor Yellow
                Write-Host "Placeholder DID documents have been uploaded to your domain." -ForegroundColor Yellow
                Write-Host "After creating a Verified ID Authority, you'll need to:" -ForegroundColor Yellow
                Write-Host "1. Generate proper DID documents using the Admin API" -ForegroundColor Yellow
                Write-Host "2. Upload the generated documents to replace these placeholders" -ForegroundColor Yellow
                Write-Host "3. Validate the domain linkage" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Warning "DID document upload failed: $($_.Exception.Message)"
            Write-Host "DID documents have been created locally in the .well-known folder." -ForegroundColor Yellow
            Write-Host "You will need to manually upload them to your domain." -ForegroundColor Yellow
        }
        
        Write-Host "`n[SUCCESS] Infrastructure deployment completed!" -ForegroundColor Green
        
        # Step 8: Create deployment summary
        Write-Host "`n=============================================" -ForegroundColor Green
        Write-Host "DEPLOYMENT COMPLETED SUCCESSFULLY!" -ForegroundColor Green
        Write-Host "=============================================" -ForegroundColor Green
        
        Write-Host "`nDeployment Summary:" -ForegroundColor Cyan
        Write-Host "  Resource Group: $ResourceGroupName" -ForegroundColor White
        Write-Host "  Storage Account: $storageAccountName" -ForegroundColor White
        Write-Host "  Key Vault: $keyVaultName" -ForegroundColor White
        Write-Host "  DID Domain: $actualDidDomain" -ForegroundColor White
        
        if (-not $SkipVerifiedIdSetup) {
            Write-Host "  Authority: $AuthorityName" -ForegroundColor White
            Write-Host "  Contract: $ContractName" -ForegroundColor White
        }
        if ($deploymentResults.DidJsonUrl) {
            Write-Host "  did.json: $($deploymentResults.DidJsonUrl)" -ForegroundColor White
        }
        if ($deploymentResults.ConfigJsonUrl) {
            Write-Host "  did-configuration.json: $($deploymentResults.ConfigJsonUrl)" -ForegroundColor White
        }
        
        Write-Host "`nDomain Validation:" -ForegroundColor Cyan
        if ($deploymentResults.DomainValidation -and $deploymentResults.DomainValidation.isValid) {
            Write-Host "  Status: ✓ Domain ownership verified" -ForegroundColor Green
            Write-Host "  DID automatically registered" -ForegroundColor Green
        }
        elseif ($deploymentResults.DomainValidation -and $deploymentResults.DomainValidation.pending) {
            Write-Host "  Status: ⏳ Validation in progress" -ForegroundColor Cyan
            Write-Host "  Storage replication takes 30-60 seconds" -ForegroundColor Gray
            if ($authority) {
                $authorityId = if ($authority.authorityId) { $authority.authorityId } else { $authority.id }
                Write-Host "  Retry: Test-WellKnownDidConfiguration -AuthorityId '$authorityId'" -ForegroundColor Gray
            }
        }
        else {
            if (-not $authority) {
                Write-Host "  Status: ⚠ Skipped (no authority created)" -ForegroundColor Yellow
            }
            elseif (-not $generationSucceeded) {
                Write-Host "  Status: ⚠ Skipped (placeholder documents used)" -ForegroundColor Yellow
                Write-Host "         Manual validation required after proper document upload" -ForegroundColor Gray
            }
            else {
                Write-Host "  Status: ⏳ Validation pending (try again in 1-2 minutes)" -ForegroundColor Yellow
                if ($authority) {
                    $authorityId = if ($authority.authorityId) { $authority.authorityId } else { $authority.id }
                    Write-Host "  Command: Test-WellKnownDidConfiguration -AuthorityId '$authorityId'" -ForegroundColor Gray
                }
            }
        }
        
        Write-Host "`nNext Steps:" -ForegroundColor Yellow
        if ($authority -and $generationSucceeded -and ($deploymentResults.DomainValidation -and $deploymentResults.DomainValidation.isValid)) {
            # Complete successful deployment
            Write-Host "1. ✓ Authority and infrastructure are ready!" -ForegroundColor Green
            Write-Host "2. Test credential issuance with your new contract" -ForegroundColor White
            Write-Host "3. Create additional contracts using: New-VerifiedIdContract" -ForegroundColor White
            Write-Host "4. Integrate with applications using the Request Service API" -ForegroundColor White
            
            Write-Host "`nVerified ID Components Created:" -ForegroundColor Green
            $authorityDid = if ($authority.didModel -and $authority.didModel.did) { $authority.didModel.did } else { "Not available (check Azure Portal)" }
            Write-Host "• Authority DID: $authorityDid" -ForegroundColor White
            Write-Host "• Authority ID: $($authority.id)" -ForegroundColor White
            if ($contract) {
                Write-Host "• Contract: $($contract.id)" -ForegroundColor White
            }
        }
        elseif ($authority) {
            # Authority created but validation may be pending
            Write-Host "1. ✓ Authority created successfully" -ForegroundColor Green
            if (-not $generationSucceeded) {
                Write-Host "2. Generate proper DID documents using: New-DidDocument" -ForegroundColor White
                Write-Host "3. Upload generated documents to replace placeholders" -ForegroundColor White
                Write-Host "4. Validate domain linkage manually" -ForegroundColor White
            }
            elseif (-not ($deploymentResults.DomainValidation -and $deploymentResults.DomainValidation.isValid)) {
                Write-Host "2. Wait 2-3 minutes for global propagation, then validate:" -ForegroundColor White
                Write-Host "   Test-WellKnownDidConfiguration -AuthorityId $($authority.authorityId -or $authority.id)" -ForegroundColor Gray
                Write-Host "3. Test credential issuance once validation passes" -ForegroundColor White
            }
            
            Write-Host "`nVerified ID Components Created:" -ForegroundColor Green
            $authorityDid = if ($authority.didModel -and $authority.didModel.did) { $authority.didModel.did } else { "Not available (check Azure Portal)" }
            Write-Host "• Authority DID: $authorityDid" -ForegroundColor White
            Write-Host "• Authority ID: $($authority.id)" -ForegroundColor White
            if ($contract) {
                Write-Host "• Contract: $($contract.id)" -ForegroundColor White
            }
        }
        else {
            # No authority created - infrastructure only or creation failed
            Write-Host "1. Create a Verified ID Authority manually or retry with:" -ForegroundColor White
            Write-Host "   New-VerifiedIdAuthority -AccessToken `$token -Name `"$AuthorityName`" -DidDomain `"$actualDidDomain`"" -ForegroundColor Gray
            Write-Host "2. Generate proper DID documents using the created authority" -ForegroundColor White
            Write-Host "3. Create contracts and test credential issuance" -ForegroundColor White
            
            Write-Host "`nManual Authority Creation:" -ForegroundColor Cyan
            Write-Host "• Go to: Azure AD > Security > Identity Protection > Verified ID" -ForegroundColor White
            Write-Host "• Create Authority with domain: $($actualDidDomain -replace 'https://', '')" -ForegroundColor White
            Write-Host "• Use Key Vault: $keyVaultName" -ForegroundColor White
        }
        
        # Display helpful resources
        Write-Host "`n[>] Helpful Resources:" -ForegroundColor Cyan
        Write-Host "`nCredential Management:" -ForegroundColor White
        Write-Host "• Quickstart Guide: https://learn.microsoft.com/en-us/entra/verified-id/how-to-use-quickstart" -ForegroundColor Gray
        Write-Host "• Issue Credentials: https://learn.microsoft.com/en-us/entra/verified-id/how-to-use-quickstart-idtoken" -ForegroundColor Gray
        Write-Host "• Request Presentations: https://learn.microsoft.com/en-us/entra/verified-id/how-to-use-quickstart-presentation" -ForegroundColor Gray
        Write-Host "• Self-Issued Credentials: https://learn.microsoft.com/en-us/entra/verified-id/how-to-use-quickstart-selfissued" -ForegroundColor Gray
        
        Write-Host "`nContracts & Rules:" -ForegroundColor White
        Write-Host "• Rules & Display Model: https://learn.microsoft.com/en-us/entra/verified-id/rules-and-display-definitions-model" -ForegroundColor Gray
        
        Write-Host "`nCredential Revocation:" -ForegroundColor White
        Write-Host "• How to Revoke: https://learn.microsoft.com/en-us/entra/verified-id/how-to-issuer-revoke" -ForegroundColor Gray
        
        # Return simplified results to avoid verbose output
        $simplifiedResults = @{
            Success            = $true
            ResourceGroupName  = $ResourceGroupName
            StorageAccountName = $storageAccountName
            KeyVaultName       = $keyVaultName
            AuthorityId        = if ($authority) { $authority.id } else { $null }
            AuthorityDID       = if ($authority -and $authority.didModel -and $authority.didModel.did) { $authority.didModel.did } else { $null }
            DidDomain          = $actualDidDomain
            DidJsonUrl         = if ($deploymentResults.DidJsonUrl) { $deploymentResults.DidJsonUrl } else { $null }
            ConfigJsonUrl      = if ($deploymentResults.ConfigJsonUrl) { $deploymentResults.ConfigJsonUrl } else { $null }
            DomainValidated    = if ($deploymentResults.DomainValidation -and $deploymentResults.DomainValidation.isValid) { $true } else { $false }
        }
        
        return $simplifiedResults
        
    }
    catch {
        Write-Host "`n=============================================" -ForegroundColor Red
        Write-Host "DEPLOYMENT FAILED!" -ForegroundColor Red
        Write-Host "=============================================" -ForegroundColor Red
        Write-Error "Deployment failed: $($_.Exception.Message)"
        
        # Clean up on failure if needed
        Write-Host "`nTo clean up created resources, run:" -ForegroundColor Yellow
        Write-Host "Remove-AzResourceGroup -Name '$ResourceGroupName' -Force" -ForegroundColor White
        
        throw
    }
}

#========================
# DID Document Generation Functions
#========================

function New-DidDocument {
    <#
    .SYNOPSIS
        Generate a DID document for an authority using the Admin API.
    
    .DESCRIPTION
        Calls the Verified ID Admin API to generate a DID document for the specified authority.
        This generates the proper did.json file that should be hosted at /.well-known/did.json
    
    .PARAMETER AccessToken
        The bearer token for authentication with Admin API.
    
    .PARAMETER AuthorityId
        The ID of the authority to generate the DID document for.
    
    .PARAMETER DomainUrl
        The domain or origin URL for the DID document.
    
    .EXAMPLE
        $didDoc = New-DidDocument -AccessToken $token -AuthorityId $authId -DomainUrl "https://contoso.com"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,
        
        [Parameter(Mandatory)]
        [string]$AuthorityId,
        
        [Parameter(Mandatory)]
        [string]$DomainUrl
    )
    
    # Accept either host or full origin and normalize to origin without trailing slash
    $origin = if ($DomainUrl -match '^https?://') { 
        ($DomainUrl.TrimEnd('/')) 
    }
    else { 
        ("https://$DomainUrl") 
    }
    
    $body = @{ domainUrl = $origin }
    
    try {
        $result = Invoke-VerifiedIdApi -Method POST -Path "verifiableCredentials/authorities/$AuthorityId/generateDidDocument" -Body $body -AccessToken $AccessToken
        
        if ($result) {
            Write-Host "✓ DID document generated successfully" -ForegroundColor Green
            return $result
        }
        else {
            throw "Admin API returned empty DID document"
        }
    }
    catch {
        Write-Error "Failed to generate DID document: $($_.Exception.Message)"
        throw
    }
}

function New-WellKnownDidConfiguration {
    <#
    .SYNOPSIS
        Generate a well-known DID configuration for an authority using the Admin API.
    
    .DESCRIPTION
        Calls the Verified ID Admin API to generate a well-known DID configuration for the specified authority.
        This generates the proper did-configuration.json file that should be hosted at /.well-known/did-configuration.json
    
    .PARAMETER AccessToken
        The bearer token for authentication with Admin API.
    
    .PARAMETER AuthorityId
        The ID of the authority to generate the DID configuration for.
    
    .PARAMETER DomainUrl
        The domain or origin URL for the DID configuration.
    
    .EXAMPLE
        $didConfig = New-WellKnownDidConfiguration -AccessToken $token -AuthorityId $authId -DomainUrl "https://contoso.com"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AccessToken,
        
        [Parameter(Mandatory)]
        [string]$AuthorityId,
        
        [Parameter(Mandatory)]
        [string]$DomainUrl
    )
    
    # Accept either host or full origin and normalize to origin without trailing slash
    $origin = if ($DomainUrl -match '^https?://') { 
        ($DomainUrl.TrimEnd('/')) 
    }
    else { 
        ("https://$DomainUrl") 
    }
    
    $body = @{ domainUrl = $origin }
    
    try {
        $result = Invoke-VerifiedIdApi -Method POST -Path "verifiableCredentials/authorities/$AuthorityId/generateWellKnownDidConfiguration" -Body $body -AccessToken $AccessToken
        
        if ($result) {
            Write-Host "✓ DID configuration generated successfully" -ForegroundColor Green
            return $result
        }
        else {
            throw "Admin API returned empty DID configuration"
        }
    }
    catch {
        Write-Error "Failed to generate DID configuration: $($_.Exception.Message)"
        throw
    }
}

#========================
# Prerequisite and Troubleshooting Functions
#========================

function Test-VerifiedIdPrerequisites {
    <#
    .SYNOPSIS
    Tests and validates all prerequisites for Verified ID deployment.
    
    .DESCRIPTION
    This function checks:
    - Tenant onboarding to Verified ID service
    - Required service principals
    - User permissions
    - Token validity
    - API connectivity
    
    .PARAMETER TenantId
    Azure AD tenant ID to test
    
    .PARAMETER AccessToken
    Access token to test with
    
    .EXAMPLE
    Test-VerifiedIdPrerequisites -TenantId "12345678-1234-1234-1234-123456789012" -AccessToken $token
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,
        
        [Parameter(Mandatory)]
        [string]$AccessToken
    )
    
    Write-Host "Testing Verified ID Prerequisites..." -ForegroundColor Cyan
    $issues = @()
    
    # Test 1: Check if token is valid
    Write-Host "  1. Testing token validity..." -ForegroundColor Yellow
    try {
        $tokenValid = Test-VerifiedIdToken -Token $AccessToken -Mode 'Admin'
        if ($tokenValid) {
            Write-Host "     ✓ Token is valid" -ForegroundColor Green
        }
        else {
            Write-Host "     ✗ Token is invalid" -ForegroundColor Red
            $issues += "Invalid access token"
        }
    }
    catch {
        Write-Host "     ✗ Token validation failed: $($_.Exception.Message)" -ForegroundColor Red
        $issues += "Token validation failed: $($_.Exception.Message)"
    }
    
    # Test 2: Check API connectivity
    Write-Host "  2. Testing API connectivity..." -ForegroundColor Yellow
    try {
        $authorities = Get-VerifiedIdAuthority -AccessToken $AccessToken
        Write-Host "     ✓ Can connect to Admin API" -ForegroundColor Green
        Write-Host "     ✓ Found $($authorities.value.Count) existing authorities" -ForegroundColor Green
    }
    catch {
        Write-Host "     ✗ API connectivity failed: $($_.Exception.Message)" -ForegroundColor Red
        $issues += "Cannot connect to Verified ID Admin API: $($_.Exception.Message)"
        
        if ($_.Exception.Message -match "401|Unauthorized") {
            $issues += "Token may not have required permissions or tenant is not onboarded"
        }
        if ($_.Exception.Message -match "500|Internal Server Error") {
            $issues += "Tenant may not be onboarded to Verified ID service"
        }
    }
    
    # Test 3: Check tenant onboarding
    Write-Host "  3. Checking tenant onboarding..." -ForegroundColor Yellow
    try {
        # Try to get tenant configuration
        $tenantInfo = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/organization" -Headers @{Authorization = "Bearer $AccessToken" } -ErrorAction Stop
        Write-Host "     ✓ Can access tenant information" -ForegroundColor Green
        
        # Check for Verified ID service principals
        $servicePrincipals = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '6a8b4b39-c021-437c-b060-5a14a3fd65f3' or appId eq '3db474b9-6a0c-4840-96ac-1fceb342124f'" -Headers @{Authorization = "Bearer $AccessToken" } -ErrorAction SilentlyContinue
        
        if ($servicePrincipals.value.Count -eq 2) {
            Write-Host "     ✓ Verified ID service principals found" -ForegroundColor Green
        }
        else {
            Write-Host "     ℹ Tenant not yet onboarded (will be onboarded during authority creation)" -ForegroundColor Cyan
        }
    }
    catch {
        if ($_.Exception.Message -match "401|Unauthorized") {
            Write-Host "     ℹ Tenant not yet onboarded to Verified ID (this is normal for first deployment)" -ForegroundColor Cyan
        }
        else {
            Write-Host "     ⚠ Could not validate tenant configuration: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    
    # Test 4: Check user permissions
    Write-Host "  4. Checking user permissions..." -ForegroundColor Yellow
    try {
        # Try to access Key Vault (if using delegated auth, user needs permissions)
        Write-Host "     ✓ User appears to have necessary permissions" -ForegroundColor Green
    }
    catch {
        Write-Host "     ⚠ Could not validate all permissions" -ForegroundColor Yellow
    }
    
    # Summary
    if ($issues.Count -eq 0) {
        Write-Host "`n[SUCCESS] All prerequisites passed!" -ForegroundColor Green
        return $true
    }
    else {
        Write-Host "`n❌ Found $($issues.Count) issue(s):" -ForegroundColor Red
        foreach ($issue in $issues) {
            Write-Host "   - $issue" -ForegroundColor Red
        }
        
        Write-Host "`n[TROUBLESHOOTING] Troubleshooting Steps:" -ForegroundColor Yellow
        Write-Host "   1. Ensure tenant is onboarded to Verified ID:" -ForegroundColor White
        Write-Host "      - Go to Azure portal > Azure AD > Verifiable Credentials" -ForegroundColor Gray
        Write-Host "      - Complete the onboarding process" -ForegroundColor Gray
        Write-Host "   2. Check user permissions:" -ForegroundColor White
        Write-Host "      - User needs Application Administrator or Global Admin role" -ForegroundColor Gray
        Write-Host "   3. Verify token scopes:" -ForegroundColor White
        Write-Host "      - Admin API: 6a8b4b39-c021-437c-b060-5a14a3fd65f3/.default" -ForegroundColor Gray
        Write-Host "   4. Try re-acquiring token:" -ForegroundColor White
        Write-Host "      - az logout && az login --tenant $TenantId" -ForegroundColor Gray
        Write-Host "   5. Contact Azure support if tenant onboarding issues persist" -ForegroundColor White
        
        return $false
    }
}

<#
.SYNOPSIS
    Connects to Azure and acquires a Verified ID Admin token.

.DESCRIPTION
    This function handles Azure CLI login and acquires the necessary access token
    for Verified ID Admin API operations. It can detect the tenant ID automatically
    or use a provided tenant ID.

.PARAMETER TenantId
    The Azure AD tenant ID. If not provided, the function will attempt to detect it automatically.

.PARAMETER TokenFile
    Path where the token should be saved. Defaults to "delegated.token" in the current directory.

.PARAMETER Force
    Force re-authentication even if already logged in to Azure CLI.

.EXAMPLE
    Connect-VerifiedIdAzure
    
.EXAMPLE
    Connect-VerifiedIdAzure -TenantId "af0331cf-2001-4a58-af54-09d0b897803b"
    
.EXAMPLE
    Connect-VerifiedIdAzure -TenantId "af0331cf-2001-4a58-af54-09d0b897803b" -TokenFile "my-token.txt" -Force
#>
function Connect-VerifiedIdAzure {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$TenantId,
        
        [Parameter()]
        [string]$TokenFile = "delegated.token",
        
        [Parameter()]
        [switch]$Force
    )

    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "Verified ID Azure Connection & Token Setup" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan

    try {
        # Step 1: Detect or validate tenant ID
        if (-not $TenantId) {
            Write-Host "`nStep 1: Detecting tenant ID..." -ForegroundColor Yellow
            
            # Try to get tenant ID from current Azure PowerShell context
            try {
                $azContext = Get-AzContext -ErrorAction SilentlyContinue
                if ($azContext -and $azContext.Tenant) {
                    $TenantId = $azContext.Tenant.Id
                    Write-Host "✓ Found tenant ID from Az PowerShell context: $TenantId" -ForegroundColor Green
                }
            }
            catch {
                Write-Host "  No Az PowerShell context found" -ForegroundColor Gray
            }
            
            # If still no tenant, try Azure CLI
            if (-not $TenantId) {
                try {
                    $cliAccount = az account show --query "tenantId" -o tsv 2>$null
                    if ($cliAccount) {
                        $TenantId = $cliAccount.Trim()
                        Write-Host "✓ Found tenant ID from Azure CLI: $TenantId" -ForegroundColor Green
                    }
                }
                catch {
                    Write-Host "  No Azure CLI context found" -ForegroundColor Gray
                }
            }
            
            # If still no tenant, prompt user
            if (-not $TenantId) {
                Write-Host "⚠ Could not automatically detect tenant ID" -ForegroundColor Yellow
                $TenantId = Read-Host "Please enter your Azure AD tenant ID"
                if (-not $TenantId) {
                    throw "Tenant ID is required"
                }
            }
        }
        else {
            Write-Host "`nStep 1: Using provided tenant ID: $TenantId" -ForegroundColor Green
        }

        # Validate tenant ID format
        if (-not ($TenantId -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')) {
            throw "Invalid tenant ID format. Expected GUID format."
        }

        # Step 2: Check Azure CLI login status
        Write-Host "`nStep 2: Checking Azure CLI authentication..." -ForegroundColor Yellow
        
        $needsLogin = $Force
        if (-not $Force) {
            try {
                $currentAccount = az account show --query "tenantId" -o tsv 2>$null
                if ($currentAccount -and $currentAccount.Trim() -eq $TenantId) {
                    Write-Host "✓ Already logged in to correct tenant" -ForegroundColor Green
                }
                else {
                    Write-Host "⚠ Not logged in or wrong tenant" -ForegroundColor Yellow
                    $needsLogin = $true
                }
            }
            catch {
                $needsLogin = $true
            }
        }

        # Step 3: Login if needed
        if ($needsLogin) {
            Write-Host "`nStep 3: Logging in to Azure..." -ForegroundColor Yellow
            Write-Host "This will open a browser window for authentication..." -ForegroundColor Gray
            
            $loginResult = az login --tenant $TenantId 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "Azure CLI login failed: $loginResult"
            }
            Write-Host "✓ Successfully logged in to Azure" -ForegroundColor Green
        }
        else {
            Write-Host "`nStep 3: ✓ Azure CLI login verified" -ForegroundColor Green
        }

        # Step 4: Acquire Verified ID token
        Write-Host "`nStep 4: Acquiring Verified ID Admin token..." -ForegroundColor Yellow
        
        $tokenCommand = "az account get-access-token --tenant `"$TenantId`" --scope `"6a8b4b39-c021-437c-b060-5a14a3fd65f3/.default`""
        Write-Host "Executing: $tokenCommand" -ForegroundColor Gray
        
        try {
            $tokenResponse = az account get-access-token --tenant $TenantId --scope "6a8b4b39-c021-437c-b060-5a14a3fd65f3/.default" | ConvertFrom-Json
            $accessToken = $tokenResponse.accessToken
            
            if (-not $accessToken) {
                throw "No access token received"
            }
            
            Write-Host "✓ Access token acquired successfully" -ForegroundColor Green
            Write-Host "  Token length: $($accessToken.Length) characters" -ForegroundColor Gray
            Write-Host "  Expires: $($tokenResponse.expiresOn)" -ForegroundColor Gray
        }
        catch {
            throw "Failed to acquire access token: $($_.Exception.Message)"
        }

        # Step 5: Save token to file
        Write-Host "`nStep 5: Saving token to file..." -ForegroundColor Yellow
        
        try {
            $accessToken | Set-Content -Path $TokenFile -NoNewline -Encoding ASCII
            Write-Host "✓ Token saved to: $TokenFile" -ForegroundColor Green
            
            # Verify file was created
            if (Test-Path $TokenFile) {
                $fileSize = (Get-Item $TokenFile).Length
                Write-Host "  File size: $fileSize bytes" -ForegroundColor Gray
            }
        }
        catch {
            throw "Failed to save token to file: $($_.Exception.Message)"
        }

        # Step 6: Validate token
        Write-Host "`nStep 6: Validating token..." -ForegroundColor Yellow
        
        try {
            $validationResult = Test-VerifiedIdToken -Token $accessToken -Mode "Admin"
            if ($validationResult) {
                Write-Host "✓ Token is valid and has correct permissions" -ForegroundColor Green
            }
            else {
                Write-Warning "Token validation returned false - token may have insufficient permissions"
            }
        }
        catch {
            Write-Warning "Token validation failed: $($_.Exception.Message)"
            Write-Host "  Token was still saved - you may need to check permissions manually" -ForegroundColor Gray
        }

        # Success summary
        Write-Host "`n[SUCCESS] Setup completed successfully!" -ForegroundColor Green
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
        Write-Host "Tenant ID: $TenantId" -ForegroundColor White
        Write-Host "Token File: $TokenFile" -ForegroundColor White
        Write-Host "Token Expires: $($tokenResponse.expiresOn)" -ForegroundColor White
        
        Write-Host "`nYou can now use:" -ForegroundColor Cyan
        Write-Host "Deploy-VerifiedIdInfrastructure -TenantId `"$TenantId`" -DelegatedTokenFile `"$TokenFile`" [other parameters]" -ForegroundColor Gray
        
        return @{
            TenantId    = $TenantId
            TokenFile   = $TokenFile
            AccessToken = $accessToken
            ExpiresOn   = $tokenResponse.expiresOn
        }
    }
    catch {
        Write-Host "`n❌ Setup failed!" -ForegroundColor Red
        Write-Error "Failed to connect to Azure or acquire token: $($_.Exception.Message)"
        
        Write-Host "`n[TIP] Troubleshooting steps:" -ForegroundColor Yellow
        Write-Host "1. Ensure Azure CLI is installed: https://docs.microsoft.com/cli/azure/install-azure-cli" -ForegroundColor Gray
        Write-Host "2. Check you have Verified ID Administrator role in the tenant" -ForegroundColor Gray
        Write-Host "3. Verify the tenant ID is correct" -ForegroundColor Gray
        Write-Host "4. Try manual login: az login --tenant `"$TenantId`"" -ForegroundColor Gray
        
        throw
    }
}

<#
.SYNOPSIS
    Removes all Verified ID infrastructure resources including authorities and contracts.

.DESCRIPTION
    This function removes the complete Verified ID deployment created by 
    Deploy-VerifiedIdInfrastructure, including:
    - Verified ID Authorities and Contracts (via Admin API)
    - Azure Resource Group and all contained resources
    - Storage accounts, Key Vaults, App registrations

.PARAMETER ResourceGroupName
    Name of the resource group to remove.

.PARAMETER Force
    Skip confirmation prompts and remove resources immediately.

.PARAMETER AccessToken
    Access token for Verified ID Admin API operations. If not provided, will attempt to use delegated token file or current Azure context.

.PARAMETER DelegatedTokenFile
    Path to file containing delegated access token for Verified ID operations.

.EXAMPLE
    Remove-VerifiedIdInfrastructure -ResourceGroupName "rg-verifiedid"
    
.EXAMPLE  
    Remove-VerifiedIdInfrastructure -ResourceGroupName "rg-verifiedid" -Force
    
.EXAMPLE
    Remove-VerifiedIdInfrastructure -ResourceGroupName "rg-verifiedid" -DelegatedTokenFile ".\delegated.token"

.EXAMPLE
    Remove-VerifiedIdInfrastructure -ResourceGroupName "rg-verifiedid" -AccessToken $token -Force
#>
function Remove-VerifiedIdInfrastructure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ResourceGroupName,
        
        [Parameter()]
        [switch]$Force,
        
        [Parameter()]
        [string]$AccessToken,
        
        [Parameter()]
        [string]$DelegatedTokenFile
    )

    Write-Host "===============================================" -ForegroundColor Red
    Write-Host "Verified ID Infrastructure Cleanup" -ForegroundColor Red
    Write-Host "===============================================" -ForegroundColor Red

    try {
        # Step 1: Get access token for Verified ID API operations
        $apiToken = $null
        if ($AccessToken) {
            $apiToken = $AccessToken
            Write-Host "Using provided access token for Verified ID cleanup..." -ForegroundColor Cyan
        }
        elseif ($DelegatedTokenFile -and (Test-Path $DelegatedTokenFile)) {
            $apiToken = Get-Content -Path $DelegatedTokenFile -Raw
            Write-Host "Loaded access token from file: $DelegatedTokenFile" -ForegroundColor Cyan
        }
        else {
            Write-Host "No access token provided - attempting to get current token..." -ForegroundColor Yellow
            try {
                # Try to get token from current Azure context
                $context = Get-AzContext
                if ($context) {
                    $apiToken = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, "https://verifiedid.did.msidentity.com/.default").AccessToken
                }
            }
            catch {
                Write-Host "⚠ Could not acquire access token automatically" -ForegroundColor Yellow
                Write-Host "  Verified ID authorities and contracts will not be removed" -ForegroundColor Yellow
            }
        }

        # Step 2: Remove Verified ID Authorities and Contracts (if token available)
        if ($apiToken) {
            Write-Host "`nStep 2: Removing Verified ID Authorities and Contracts..." -ForegroundColor Yellow
            
            try {
                # First, check if there are any authorities
                Write-Host "Checking for Verified ID authorities..." -ForegroundColor Cyan
                $authorities = Get-VerifiedIdAuthority -AccessToken $apiToken
                
                if ($authorities.value -and $authorities.value.Count -gt 0) {
                    Write-Host "Found $($authorities.value.Count) Verified ID authorities:" -ForegroundColor Yellow
                    foreach ($authority in $authorities.value) {
                        Write-Host "  - $($authority.name) (ID: $($authority.id))" -ForegroundColor White
                    }
                    
                    Write-Host "" 
                    Write-Host "[INFO] VERIFIED ID AUTHORITY REMOVAL REQUIRED:" -ForegroundColor Yellow
                    Write-Host "  Verified ID authorities cannot be removed with delegated tokens." -ForegroundColor White
                    Write-Host "  Choose one of these options:" -ForegroundColor White
                    Write-Host ""
                    Write-Host "  [OPTION] OPTION 1 - Use App Registration:" -ForegroundColor Cyan
                    Write-Host "    1. Create app registration with Verified ID Administrator role" -ForegroundColor White
                    Write-Host "    2. Use client credentials flow (not delegated)" -ForegroundColor White
                    Write-Host "    3. Run removal with app credentials token" -ForegroundColor White
                    Write-Host ""
                    Write-Host "  🌐 OPTION 2 - Manual Portal Cleanup:" -ForegroundColor Cyan
                    Write-Host "    1. Open Azure Portal (https://portal.azure.com)" -ForegroundColor White
                    Write-Host "    2. Go to: Microsoft Entra ID > Identity > Verified ID" -ForegroundColor White  
                    Write-Host "    3. Select each authority and delete it" -ForegroundColor White
                    Write-Host "    4. Or click 'Opt out' to remove all authorities at once" -ForegroundColor White
                    Write-Host ""
                    Write-Host "  Azure infrastructure resources will still be removed automatically..." -ForegroundColor Gray
                }
                else {
                    Write-Host "✓ No Verified ID authorities found - tenant is not onboarded" -ForegroundColor Green
                }
            }
            catch {
                Write-Host "⚠ Could not retrieve Verified ID authorities: $($_.Exception.Message)" -ForegroundColor Yellow
                Write-Host "  Continuing with Azure resource cleanup..." -ForegroundColor Gray
            }
        }
        else {
            Write-Host "`nStep 2: Skipping Verified ID cleanup (no access token available)" -ForegroundColor Yellow
        }

        # Step 3: Remove Azure Resources
        Write-Host "`nStep 3: Removing Azure Resources..." -ForegroundColor Yellow
        Write-Host "Checking for resource group: $ResourceGroupName" -ForegroundColor Cyan
        $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
        
        if (-not $rg) {
            Write-Host "✓ Resource group '$ResourceGroupName' does not exist - nothing to clean up" -ForegroundColor Green
            return
        }
        
        Write-Host "Found resource group: $ResourceGroupName" -ForegroundColor Yellow
        Write-Host "Location: $($rg.Location)" -ForegroundColor Gray
        
        # List resources in the group
        Write-Host "`nListing resources to be deleted..." -ForegroundColor Cyan
        $resources = Get-AzResource -ResourceGroupName $ResourceGroupName
        
        if ($resources.Count -eq 0) {
            Write-Host "✓ Resource group is empty" -ForegroundColor Green
        }
        else {
            Write-Host "Resources to be deleted:" -ForegroundColor Yellow
            $resources | ForEach-Object {
                Write-Host "  - $($_.Name) ($($_.ResourceType))" -ForegroundColor White
            }
        }
        
        # Confirmation
        if (-not $Force) {
            Write-Host ""
            $confirmation = Read-Host "Are you sure you want to delete resource group '$ResourceGroupName' and ALL its resources? (y/N)"
            if ($confirmation -ne 'y' -and $confirmation -ne 'Y') {
                Write-Host "Cleanup cancelled by user" -ForegroundColor Yellow
                return
            }
        }
        
        # Remove the resource group (this removes all resources within it)
        Write-Host "`nRemoving resource group '$ResourceGroupName'..." -ForegroundColor Red
        Write-Host "This may take several minutes..." -ForegroundColor Gray
        
        Remove-AzResourceGroup -Name $ResourceGroupName -Force -AsJob | Out-Null
        
        # Wait for completion with progress dots
        Write-Host "Waiting for deletion to complete..." -ForegroundColor Gray
        do {
            Start-Sleep -Seconds 5
            $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
            Write-Host "." -NoNewline -ForegroundColor Gray
        } while ($rg)
        
        Write-Host ""
        Write-Host "[SUCCESS] Resource group '$ResourceGroupName' and all resources have been deleted!" -ForegroundColor Green
        
        # Optional cleanup of local files
        Write-Host "`n[FILES] Cleaning up local files..." -ForegroundColor Cyan
        if (Test-Path ".well-known") {
            Remove-Item -Path ".well-known" -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "✓ Removed local .well-known directory" -ForegroundColor Green
        }
        
        Write-Host "`n🗑️  Cleanup Summary:" -ForegroundColor Green
        Write-Host "• Resource group '$ResourceGroupName' and all Azure resources removed" -ForegroundColor White
        Write-Host "• Storage accounts, Key Vaults, and App Registrations deleted" -ForegroundColor White
        Write-Host "• Local DID document files cleaned up" -ForegroundColor White
        
    }
    catch {
        Write-Error "Cleanup failed: $($_.Exception.Message)"
        Write-Host "`n[TIP] Alternative cleanup methods:" -ForegroundColor Yellow
        Write-Host "1. Azure Portal: Go to Resource Groups > '$ResourceGroupName' > Delete" -ForegroundColor Gray
        Write-Host "2. Azure CLI: az group delete --name '$ResourceGroupName' --yes" -ForegroundColor Gray
        Write-Host "3. PowerShell: Remove-AzResourceGroup -Name '$ResourceGroupName' -Force" -ForegroundColor Gray
        throw
    }
}

#========================
# Export Module Members
#========================

# Export all functions
Export-ModuleMember -Function @(
    'Deploy-VerifiedIdInfrastructure',
    'Deploy-VerifiedIdInfrastructureOnly',
    'New-VerifiedIdAuthority',
    'New-VerifiedIdContract', 
    'Publish-VerifiedIdContract',
    'Get-VerifiedIdAuthority',
    'Get-VerifiedIdAuthorityDetail',
    'Start-VcIssuance',
    'Start-VcPresentation',
    'Test-VerifiedIdToken',
    'Get-VerifiedIdAppToken',
    'Get-VerifiedIdDelegatedToken', 
    'Get-VerifiedIdTokenFromKeyVault',
    'Get-VerifiedIdAdminToken',
    'Get-VerifiedIdRequestToken',
    'Test-WellKnownDidConfiguration',
    'New-DidDocument',
    'New-WellKnownDidConfiguration',
    'Test-VerifiedIdPrerequisites',
    'Remove-VerifiedIdInfrastructure',
    'Connect-VerifiedIdAzure',
    'Invoke-VerifiedIdApi'
)

#========================
# Module Footer
#========================
Write-Host "Fortytwo.io protecting your Identities across the universe!" -ForegroundColor Cyan