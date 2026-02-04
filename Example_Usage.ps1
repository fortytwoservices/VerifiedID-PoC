# Microsoft Entra Verified ID PowerShell Module - Usage Examples
# This file demonstrates how to use the VerifiedID module for different deployment scenarios

#==============================================================================
# Prerequisites
#==============================================================================

# 1. Install required Azure PowerShell modules
# Install-Module -Name Az.Accounts, Az.Resources, Az.Storage, Az.KeyVault -Force

# 2. Authenticate with Azure CLI
# az login

# 3. Import the Verified ID module
# Import-Module .\VerifiedID.psm1 -Force

#==============================================================================
# Example 1: Complete Deployment
#==============================================================================

<#
This example deploys complete Verified ID infrastructure using delegated auth.
Requires: User logged in with az login and having Verified ID Administrator role

The script automatically handles:
  ✅ Creates Azure resources (storage, key vault, etc.)
  ✅ Creates Verified ID Authority
  ✅ Generates and uploads DID documents
  ✅ Makes documents publicly accessible
  ✅ Validates domain ownership (automatic - documents verified accessible)
  ✅ Registers DID automatically
  
No manual steps required!
#>

# Basic deployment with auto-generated names
$deployment = Deploy-VerifiedIdInfrastructure `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "rg-verifiedid-demo" `
    -Location "East US" `
    -TenantId "your-tenant-id"

# Custom deployment with specific names
$deployment = Deploy-VerifiedIdInfrastructure `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "rg-verifiedid-prod" `
    -Location "West Europe" `
    -TenantId "your-tenant-id" `
    -Prefix "companyname" `
    -AuthorityName "CompanyCredentials" `
    -ContractName "EmployeeID"

#==============================================================================
# Example 2: Infrastructure-Only Deployment
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
# Example 3: Working with Existing Infrastructure
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
# Example 4: Credential Issuance
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
# Example 8: Domain Ownership Verification (Automatic, Optional Retry)
#==============================================================================

<#
Domain ownership verification is AUTOMATIC during deployment.
The script validates that your DID documents are accessible at the domain URL.

This confirms you control the domain - no manual steps needed!

If verification was still pending during deployment, you can manually retry.
#>

# Get your authority ID from deployment output
$authorityId = $deployment.AuthorityId

# Automatic verification already happened during deployment.
# If you need to verify status or retry:
$validation = Test-WellKnownDidConfiguration -AuthorityId $authorityId

if ($validation.isValid) {
    Write-Host "✓ Domain ownership verified" -ForegroundColor Green
    Write-Host "✓ DID registered automatically" -ForegroundColor Green
}
else {
    Write-Host "Domain verification in progress. Try again in 30-60 seconds." -ForegroundColor Yellow
    Write-Host "Command: Test-WellKnownDidConfiguration -AuthorityId '$authorityId'" -ForegroundColor Gray
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
- Complete Deployment: 1-2 minutes (fully automated)
  - Infrastructure: ~30 seconds
  - Authority creation: ~10 seconds
  - Authority propagation wait: ~75 seconds (includes retries)
  - Document generation & upload: ~20 seconds
  - Storage replication & validation: ~45 seconds
  - Total: ~1-2 minutes

The module includes strategic wait periods to handle Azure propagation delays.
Domain ownership verification is fully automatic - no manual steps needed!
#>

#==============================================================================
# Troubleshooting Common Issues
#==============================================================================

<#
1. Domain Ownership Verification Not Confirming:
   - Normal! Azure Storage replication takes 30-60 seconds
   - Wait a moment, then run: Test-WellKnownDidConfiguration -AuthorityId $authorityId
   - If still pending, wait 1-2 minutes and retry

2. Domain Ownership Verification Fails:
   - Check DID documents are properly uploaded to storage
   - Verify storage account static website is enabled
   - Check /.well-known/did.json and /.well-known/did-configuration.json exist
   - Wait 45 seconds to 2 minutes for storage replication, then retry

3. Authority Creation Fails:
   - Ensure you have Verified ID Administrator role
   - Check Key Vault exists and is accessible
   - Verify storage account URL is reachable
   - Try redeploying if first attempt fails

4. Storage Upload Fails:
   - Check RBAC permissions on storage account
   - Verify storage account has static website enabled
   - Try with storage account keys if RBAC fails

5. Authentication Issues:
   - For delegated auth: Run 'az login' first
   - Ensure you have Verified ID Administrator role
   - Check correct tenant ID

6. Permission Errors:
   - Ensure Global Admin or Application Administrator role
   - Verify user has Verified ID Administrator role in tenant
   - Check service principal has required Azure RBAC roles
#>