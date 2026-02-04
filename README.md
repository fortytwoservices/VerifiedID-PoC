# Microsoft Entra Verified ID PowerShell Module

A comprehensive PowerShell module for deploying and managing Microsoft Entra Verified ID infrastructure, including Azure resources, authorities, contracts, and credential operations.

## [→] Features

### Complete Infrastructure Deployment
- **Azure Resource Group** creation and management
- **Storage Account** with static website hosting for DID documents  
- **Key Vault** with proper access policies for secure key storage
- **Service Principal** configuration with appropriate roles

### Verified ID Management
- **Authority** creation with automatic propagation handling
- **DID Registration** with automated domain validation
- **DID Documents** generation and upload to Azure Storage
- **Domain Validation** with automatic refresh and registration
- **Contract** creation with customizable claims and display properties
- **Credential Issuance** and **Verification** workflows
- **App Registration** creation with required permissions for Verified ID

### Advanced Capabilities
- **Strategic Timing**: Built-in wait periods for Azure propagation
- **Retry Logic**: Exponential backoff for transient failures
- **Flexible Authentication**: Supports both delegated and application-only auth
- **Comprehensive Cleanup**: Complete infrastructure removal capabilities
- **Error Handling**: Detailed error reporting and recovery suggestions

## [✓] What Gets Automated

The `Deploy-VerifiedIdInfrastructure` function fully automates all the manual steps from the Azure Portal setup wizard:

| Step | Manual Process | Automated By Script |
|------|---|---|
| **1. Infrastructure** | Create storage account, key vault | ✅ Automatic |
| **2. Authority Creation** | Create via Portal | ✅ Automatic |
| **3. DID Documents** | Generate via Admin API | ✅ Automatic |
| **4. Upload DID Documents** | Manual upload to storage | ✅ Automatic |
| **5. Domain Validation** | Click "Refresh" button in Portal | ✅ Automatic |
| **6. DID Registration** | Click "Register" button in Portal | ✅ Automatic |

**Result**: All three setup checkmarks in Azure Portal ✅ automatically completed on first run!

## [i] Prerequisites

### PowerShell Requirements
- **PowerShell 7.0+** (PowerShell Core)
- **Az PowerShell Modules**: `Az.Accounts`, `Az.Resources`, `Az.Storage`, `Az.KeyVault`

### Azure Requirements
- **Azure Subscription** with appropriate permissions
- **Entra ID Tenant** with Microsoft Entra Verified ID enabled
- **Global Administrator** or **Application Administrator** role in the tenant
- **Azure CLI** (`az login`) authenticated before running the script
- **Custom Domain** (optional, can use storage static website domain)

### Authentication
- **Delegated User Authentication**: Script uses your user credentials via `az login`
- **App-Only Authentication**: Not currently supported due to Microsoft API limitations

## [⚙] Installation

### 1. Install Prerequisites
```powershell
# Install required Azure PowerShell modules
Install-Module -Name Az.Accounts, Az.Resources, Az.Storage, Az.KeyVault -Force

# Update to PowerShell 7+ if needed
# Download from: https://github.com/PowerShell/PowerShell/releases
```

### 2. Download and Import Module
```powershell
# Download the module files to a local directory
# Import the module
Import-Module .\VerifiedID.psm1 -Force
```

### 3. Verify Installation
```powershell
Get-Module VerifiedID
Get-Command -Module VerifiedID
```

## [>] Quick Start

### Prerequisites
1. Ensure you have PowerShell 7+ and Az modules installed
2. Authenticate with Azure and Verified ID scope:
   ```powershell
   az login
   az account set --subscription "your-subscription-id"
   ```
3. Import the module:
   ```powershell
   Import-Module .\VerifiedID.psm1 -Force
   ```

### Basic Deployment
```powershell
# Deploy complete Verified ID infrastructure
# Uses your current user credentials (must be logged in with az login)
$deployment = Deploy-VerifiedIdInfrastructure `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "rg-verifiedid-demo" `
    -Location "East US" `
    -TenantId "your-tenant-id"

# Access results
Write-Host "Authority DID: $($deployment.Authority.didModel.did)"
Write-Host "Storage URL: $($deployment.StorageAccount.PrimaryEndpoints.Web)"
```

### Infrastructure Only
```powershell
# Deploy just the Azure infrastructure
$infra = Deploy-VerifiedIdInfrastructureOnly `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "rg-verifiedid-infra" `
    -Location "Central US" `
    -TenantId "your-tenant-id" `
    -Prefix "myorg"
```

## [⏱] Timing Expectations

**Complete Deployment**: 1-2 minutes (fully automated)
- Infrastructure creation: ~30 seconds
- Authority creation: ~10 seconds
- Authority propagation wait: ~75 seconds  
- DID document generation & upload: ~20 seconds
- Storage replication & validation: ~45 seconds
- Total: ~1-2 minutes

**Infrastructure Only**: 1-2 minutes

The script includes strategic wait periods to handle Azure propagation. Domain ownership is automatically verified when DID documents are validated as accessible at the domain.

## [*] Authentication

### How It Works
The script uses **delegated user authentication** - your current user credentials from `az login`:

1. User logs in with `az login` (requires Global Admin or Application Administrator role)
2. Script acquires delegated token using Azure CLI
3. Token carries your user's permissions for Verified ID operations
4. All operations execute with your admin context

### Why Delegated Auth Only?
- **Required by Microsoft**: Authority creation requires user context
- **Simpler Setup**: No app registration needed, uses existing credentials
- **Immediate Access**: User permissions apply immediately, no propagation delays
- **Reduced Complexity**: Fewer moving parts, easier troubleshooting

### App-Only Authentication
❌ **Not currently supported** - Microsoft Verified ID APIs require user context for authority operations. Creating authorities with service principal credentials results in 403 Forbidden errors.

## [*] Core Functions

### Deployment Functions
- `Deploy-VerifiedIdInfrastructure` - Complete infrastructure + Verified ID setup
- `Deploy-VerifiedIdInfrastructureOnly` - Azure infrastructure only
- `Remove-VerifiedIdInfrastructure` - Complete cleanup and removal

### Verified ID Management
- `New-VerifiedIdAuthority` - Create new authority
- `New-VerifiedIdAuthorityWithRetry` - Authority creation with retry logic
- `New-VerifiedIdContract` - Create credential contracts
- `New-VerifiedIdContractWithRetry` - Contract creation with retry logic

### Credential Operations
- `Start-VcIssuance` - Issue credentials to users
- `Start-VcPresentation` - Request credential presentations
- `Publish-VerifiedIdContract` - Publish contracts to make them active

### DID Document Management
- `New-DidDocument` - Generate DID documents via Admin API
- `New-WellKnownDidConfiguration` - Generate well-known configuration
- `Test-WellKnownDidConfiguration` - Validate domain linkage
- `Register-VerifiedIdDomain` - Register DID with authority (triggers domain validation)
- `New-VerifiedIdDnsConfiguration` - Generate DNS records for domain binding
- `Test-VerifiedIdDnsBinding` - Validate DNS binding configuration

### Authentication & Token Functions
- `Get-VerifiedIdAppToken` - Get app-only access tokens
- `Get-VerifiedIdDelegatedToken` - Get delegated access tokens
- `Get-VerifiedIdTokenFromKeyVault` - Retrieve tokens from Key Vault
- `Get-VerifiedIdAdminToken` - Get admin API tokens
- `Get-VerifiedIdRequestToken` - Get request service tokens
- `Test-VerifiedIdToken` - Validate token functionality

### Utility Functions
- `Connect-VerifiedIdAzure` - Azure authentication helper
- `Invoke-VerifiedIdApi` - Direct API calls to Verified ID service
- `Get-VerifiedIdAuthority` - List authorities
- `Get-VerifiedIdAuthorityDetail` - Get detailed authority information

## [📂] Module Structure

```
VerifiedID_Module/
├── VerifiedID.psd1          # Module manifest
├── VerifiedID.psm1          # Main module implementation  
├── Example_Usage.ps1        # Usage examples
└── Module_README.md         # This documentation
```

## [⚙] Configuration Options

### Resource Naming
- `Prefix` - Prefix for all resources (default: auto-generated)
- Custom names supported for all resources
- Automatic suffix generation for uniqueness

### Security Configuration
- Key Vault integration for secure credential storage
- RBAC-based access control
- Proper service principal permissions

### Domain Configuration  
- Custom domain support
- Azure Storage static website hosting
- Automatic DID document generation and hosting
- Automatic domain validation and DID registration

## [*] Deployment Workflow Details

### Step-by-Step Automation

**Step 1-4: Azure Infrastructure**
```powershell
✅ Creates Resource Group
✅ Creates Storage Account with static website 
✅ Creates Key Vault
✅ Assigns permissions
```

**Step 5-7: Verified ID Setup**
```powershell
✅ Acquires delegated user token
✅ Creates Verified ID Authority 
✅ Waits 75 seconds for propagation
✅ Validates prerequisites
```

**Step 8: DID Documents & Domain Ownership**
```powershell
✅ Generates real DID documents via Admin API
✅ Uploads did.json to storage
✅ Uploads did-configuration.json to storage
✅ Validates document accessibility
✅ Waits 45 seconds for storage replication
✅ Verifies domain ownership (documents are accessible)
✅ Automatically registers DID
```

**Result: All three Portal checkmarks ✅✅✅ automatically**

- ✅ Configure organization (Authority created)
- ✅ Register decentralized ID (DID documents hosted)
- ✅ Verify domain ownership (Documents validated as accessible)

## [*] Advanced Usage

### Custom Contract Creation
```powershell
$token = Get-VerifiedIdDelegatedToken -TenantId $tenantId

$contract = New-VerifiedIdContract `
    -AccessToken $token `
    -AuthorityId $authority.id `
    -Name "EmployeeCredential" `
    -Type "EmployeeID" `
    -Claims @("firstName", "lastName", "department", "employeeId") `
    -DisplayName "Employee ID Card" `
    -Description "Official company employee identification"
```

### Credential Issuance
```powershell
$issuance = Start-VcIssuance `
    -AccessToken $token `
    -AuthorityId $authority.id `
    -ContractId $contract.id `
    -Claims @{
        firstName = "John"
        lastName = "Doe" 
        department = "Engineering"
        employeeId = "EMP001"
    } `
    -CallbackUrl "https://your-app.com/callback"
```

### Credential Verification
```powershell
$presentation = Start-VcPresentation `
    -AccessToken $token `
    -AuthorityId $authority.id `
    -Type "EmployeeID" `
    -AcceptedIssuers @($authority.didModel.did) `
    -CallbackUrl "https://your-app.com/verify" `
    -ValidateLinkedDomain
```

### Domain Ownership Verification (Automatic)

During deployment, the script automatically verifies domain ownership:

```powershell
# Script validates that DID documents are hosted and accessible
# This proves you control the domain
# ✅ Verification automatic - no manual action needed
```

**If verification needs retry:**
```powershell
# Run this if initial verification was still propagating
$authorityId = "5f8fcf85-eb11-4207-551a-b29d4475d57d"  # Example
Test-WellKnownDidConfiguration -AuthorityId $authorityId
```

**What happens:**
1. Script uploads `did.json` and `did-configuration.json` to storage
2. Waits 45 seconds for Azure Storage to replicate files globally
3. Microsoft's service fetches and validates these files exist
4. ✅ Domain ownership confirmed (you proved you control the domain)
5. ✅ DID automatically registered

**Helpful Resources:**
- [Quickstart Guide](https://learn.microsoft.com/en-us/entra/verified-id/how-to-use-quickstart)
- [Issue Credentials](https://learn.microsoft.com/en-us/entra/verified-id/how-to-use-quickstart-idtoken)
- [Request Presentations](https://learn.microsoft.com/en-us/entra/verified-id/how-to-use-quickstart-presentation)
- [Self-Issued Credentials](https://learn.microsoft.com/en-us/entra/verified-id/how-to-use-quickstart-selfissued)
- [Rules & Display Model](https://learn.microsoft.com/en-us/entra/verified-id/rules-and-display-definitions-model)
- [Credential Revocation](https://learn.microsoft.com/en-us/entra/verified-id/how-to-issuer-revoke)

## [?] Troubleshooting

### Common Issues and Solutions

**Domain Ownership Verification Not Confirming**
```
This is normal! Azure Storage replication takes 30-60 seconds.
After deployment:
1. If still pending, wait another 30 seconds
2. Run: Test-WellKnownDidConfiguration -AuthorityId $authorityId
3. If still pending, wait 1-2 more minutes and retry
```

**Domain Ownership Verification Fails**
```
Check DID documents are properly uploaded:
- did.json at /.well-known/did.json (HTTP 200 response)
- did-configuration.json at /.well-known/did-configuration.json (HTTP 200 response)
Verify storage static website is enabled
Wait 45 seconds to 2 minutes for Azure Storage replication, then retry
```

**Authority Creation Fails**  
```
Ensure you have Verified ID Administrator role
Verify Key Vault accessibility
Check storage account static website URL is accessible
Try redeploying if first attempt fails
```

**Storage Upload Fails**
```
Check RBAC permissions on storage account
Verify static website is enabled
Try storage account keys if RBAC fails
```

**Authentication Issues**
```
For delegated auth: Use 'az login' first
Confirm user has Verified ID Administrator role
Verify correct tenant ID
```

### Debug Mode
```powershell
$VerbosePreference = "Continue"
$DebugPreference = "Continue"

# Run deployment with detailed logging
Deploy-VerifiedIdInfrastructure -Verbose -Debug
```

## [>] Monitoring and Validation

### Deployment Validation
```powershell
# Check deployment results
$deployment.AuthorityDID
$deployment.AuthorityId
$deployment.DomainValidated

# Validate DID documents
Test-WellKnownDidConfiguration -AccessToken $token -AuthorityId $authorityId -DomainUrl $domain
```

### Health Checks
```powershell
# Test token functionality
Test-VerifiedIdToken -AccessToken $token

# Verify storage hosting
Invoke-WebRequest "$storageUrl/.well-known/did.json"
Invoke-WebRequest "$storageUrl/.well-known/did-configuration.json"
```

## [*] Security Best Practices

### Production Recommendations
1. **Use Application Authentication** for automated scenarios
2. **Store secrets in Key Vault** (automatically configured)
3. **Implement proper RBAC** on Azure resources
4. **Use custom domains** for production authorities
5. **Enable monitoring** on Key Vault and Storage
6. **Rotate credentials regularly**

### Access Control
- Service principals have minimal required permissions
- Key Vault access policies restrict secret access
- Storage accounts use RBAC where possible
- App registrations follow principle of least privilege

## [~] Scaling Considerations

### Multiple Authorities
- Each authority should have its own domain
- Consider separate storage accounts for isolation
- Use consistent naming conventions

### High Availability
- Deploy across multiple regions if needed
- Use Azure Storage geo-redundancy
- Implement proper backup procedures

### Performance
- Storage static websites provide global CDN
- Consider Azure Front Door for custom domains
- Monitor credential issuance volumes

## [*] Contributing

### Development Setup
1. Clone or download the module
2. Install development dependencies
3. Run test deployments in dev environment
4. Follow PowerShell best practices

### Testing
```powershell
# Test individual functions
Test-VerifiedIdToken -AccessToken $token
New-DidDocument -AccessToken $token -AuthorityId $authId -DomainUrl "https://test.com" -WhatIf

# Validate deployment in test environment
Deploy-VerifiedIdInfrastructure -ResourceGroupName "test-rg" -WhatIf
```

## [i] License

This project follows Microsoft's open source guidelines. See individual file headers for specific license information.

## [>] References

- [Microsoft Entra Verified ID Documentation](https://docs.microsoft.com/en-us/azure/active-directory/verifiable-credentials/)
- [Verified ID Admin API Reference](https://docs.microsoft.com/en-us/graph/api/resources/verifiablecredentials-overview)
- [Azure PowerShell Documentation](https://docs.microsoft.com/en-us/powershell/azure/)
- [DID Specification](https://www.w3.org/TR/did-core/)

## [*] Support

For issues and questions:
1. Review the troubleshooting section
2. Check the example usage files
3. Validate prerequisites are met
4. Enable verbose/debug logging for detailed error information

---
**Note**: This module is designed for Microsoft Entra Verified ID and requires appropriate licenses and permissions. Ensure you understand the security implications and follow Microsoft's security best practices when deploying to production environments.
