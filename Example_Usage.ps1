# Microsoft Entra Verified ID PowerShell Module - Usage Examples
# This file demonstrates how to use the VerifiedID module for different deployment scenarios

#==============================================================================
# Prerequisites
#==============================================================================

# 1. Install required Azure PowerShell modules
# Install-Module -Name Az.Accounts, Az.Resources, Az.Storage, Az.KeyVault -Force

# 2. Import the Verified ID module
# Import-Module .\VerifiedID.psm1 -Force

#==============================================================================
# Example 1: Complete Deployment with Delegated Authentication
#==============================================================================

<#
This example uses your current user credentials (delegated authentication).
Best for: Development, testing, and scenarios where you have admin rights.

Note: Domain validation may require manual completion if using placeholder documents.
#>

# Basic deployment with auto-generated names
$deployment1 = Deploy-VerifiedIdInfrastructure `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "rg-verifiedid-demo" `
    -Location "East US" `
    -TenantId "your-tenant-id" `
    -UseDelegatedAuth

# Custom deployment with specific names
$deployment2 = Deploy-VerifiedIdInfrastructure `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "rg-verifiedid-prod" `
    -Location "West Europe" `
    -TenantId "your-tenant-id" `
    -Prefix "companyname" `
    -AuthorityName "CompanyCredentials" `
    -ContractName "EmployeeID" `
    -UseDelegatedAuth

#==============================================================================
# Example 2: Complete Deployment with Application Authentication
#==============================================================================

<#
This example creates an app registration for service-to-service authentication.
Best for: Production environments, automation, CI/CD pipelines.

Note: The app registration will be granted necessary permissions automatically.
#>

$deployment3 = Deploy-VerifiedIdInfrastructure `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "rg-verifiedid-prod" `
    -Location "West US 2" `
    -TenantId "your-tenant-id" `
    -AppName "VerifiedIdServiceApp" `
    -Prefix "acme" `
    -AuthorityName "ACMEEmployeeCredentials" `
    -ContractName "ACMEEmployeeCard"

# The deployment returns useful information:
Write-Host "Authority DID: $($deployment3.Authority.didModel.did)"
Write-Host "Contract ID: $($deployment3.Contract.id)"
Write-Host "Storage URL: $($deployment3.StorageAccount.PrimaryEndpoints.Web)"

#==============================================================================
# Example 3: Infrastructure-Only Deployment
#==============================================================================

<#
This example deploys only the Azure infrastructure without creating 
the Verified ID authority or contracts. Useful when you want to:
- Set up infrastructure first
- Create authorities manually through the portal
- Use custom domain configuration
#>

$infraOnly = Deploy-VerifiedIdInfrastructureOnly `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "rg-verifiedid-infra" `
    -Location "Central US" `
    -TenantId "your-tenant-id" `
    -Prefix "myorg"

# Later, create authority manually or programmatically:
# $token = Get-VerifiedIdDelegatedToken -TenantId "your-tenant-id"
# $authority = New-VerifiedIdAuthority -AccessToken $token -Name "MyAuthority" -DidDomain "https://myorg-sto-1234.z13.web.core.windows.net"

#==============================================================================
# Example 4: Working with Existing Infrastructure
#==============================================================================

<#
If you already have infrastructure deployed, you can create additional
authorities, contracts, and manage credentials using the individual functions.
#>

# Get access token
$token = Get-VerifiedIdDelegatedToken -TenantId "your-tenant-id"

# Create additional authority
$newAuthority = New-VerifiedIdAuthorityWithRetry `
    -AccessToken $token `
    -Name "DepartmentCredentials" `
    -DidDomain "https://myorg-sto-1234.z13.web.core.windows.net"

# Create additional contracts
$contract1 = New-VerifiedIdContract `
    -AccessToken $token `
    -AuthorityId $newAuthority.authorityId `
    -Name "ManagerCredential" `
    -Type "ManagerID" `
    -Claims @("firstName", "lastName", "department", "level")

$contract2 = New-VerifiedIdContract `
    -AccessToken $token `
    -AuthorityId $newAuthority.authorityId `
    -Name "TrainingCertificate" `
    -Type "TrainingCert" `
    -Claims @("courseName", "completionDate", "score", "instructor")

#==============================================================================
# Example 5: Credential Issuance
#==============================================================================

<#
Once your authority and contracts are set up, you can issue credentials
to users programmatically.
#>

# Issue a credential
$issuanceRequest = Start-VcIssuance `
    -AccessToken $token `
    -AuthorityId $newAuthority.authorityId `
    -ContractId $contract1.id `
    -Claims @{
    firstName  = "John"
    lastName   = "Doe"
    department = "Engineering"
    level      = "Senior"
} `
    -CallbackUrl "https://your-app.com/callback"

Write-Host "Issuance URL: $($issuanceRequest.url)"
Write-Host "Request ID: $($issuanceRequest.requestId)"

#==============================================================================
# Example 6: Credential Verification
#==============================================================================

<#
Verify credentials presented by users.
#>

# Request credential presentation
$presentationRequest = Start-VcPresentation `
    -AccessToken $token `
    -AuthorityId $newAuthority.authorityId `
    -Type "ManagerID" `
    -AcceptedIssuers @($newAuthority.didModel.did) `
    -CallbackUrl "https://your-app.com/verify-callback" `
    -ValidateLinkedDomain

Write-Host "Presentation URL: $($presentationRequest.url)"
Write-Host "Request ID: $($presentationRequest.requestId)"

#==============================================================================
# Example 7: DID Document Management
#==============================================================================

<#
Generate and manage DID documents for domain linkage.
#>

# Generate DID documents for an existing authority
$didDocs = New-DidDocument `
    -AccessToken $token `
    -AuthorityId $authority.authorityId `
    -DomainUrl "https://myorg-sto-1234.z13.web.core.windows.net"

# Upload to storage (manual process - use Azure Portal or Azure CLI)
# The deployment function handles this automatically, but for manual uploads:
# 1. Save $didDocs content to files
# 2. Upload to storage account at /.well-known/did.json and /.well-known/did-configuration.json
# 3. Ensure files have 'application/json' content type

#==============================================================================
# Example 8: Domain Validation
#==============================================================================

<#
Validate that your domain properly hosts the required DID documents.
#>

$validation = Test-WellKnownDidConfiguration `
    -AccessToken $token `
    -AuthorityId $authority.authorityId `
    -DomainUrl "https://myorg-sto-1234.z13.web.core.windows.net"

if ($validation.isValid) {
    Write-Host "✓ Domain validation successful" -ForegroundColor Green
}
else {
    Write-Host "⚠ Domain validation failed:" -ForegroundColor Yellow
    $validation.errors | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
}

#==============================================================================
# Example 9: Cleanup and Removal
#==============================================================================

<#
Remove all deployed resources when no longer needed.
Note: Authority removal requires application-only authentication.
#>

# Complete removal (authorities must be removed manually if using delegated auth)
Remove-VerifiedIdInfrastructure `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "rg-verifiedid-demo" `
    -TenantId "your-tenant-id"

#==============================================================================
# Timing Expectations
#==============================================================================

<#
Deployment Timing (typical):
- Infrastructure Only: 1-2 minutes
- Complete Deployment: 4-6 minutes
  - Infrastructure: ~30 seconds
  - Authority creation: ~75 seconds (includes retries)
  - Document propagation: ~105 seconds
  - Domain validation: ~30 seconds

The module includes strategic wait periods to handle Azure propagation delays.
These ensure reliable deployment on the first run instead of requiring multiple attempts.
#>

#==============================================================================
# Troubleshooting Common Issues
#==============================================================================

<#
1. Domain Validation Fails:
   - Wait 2-3 minutes for global CDN propagation
   - Verify storage account has static website enabled
   - Check that DID documents are properly uploaded

2. Authority Creation Fails:
   - Ensure you have sufficient permissions in the tenant
   - Check that the domain URL is accessible
   - Verify Key Vault exists and is accessible

3. Storage Upload Fails:
   - Check RBAC permissions on storage account
   - Verify storage account has static website enabled
   - Try with storage account keys if RBAC fails

4. Authentication Issues:
   - For delegated auth: Ensure you're logged in with Connect-AzAccount
   - For app auth: Verify app registration has correct permissions
   - Check tenant ID is correct

5. Permission Errors:
   - Ensure Global Admin or Application Administrator role
   - For production: Use app registration with proper permissions
   - Verify service principal has required Azure RBAC roles
#>