# Microsoft Entra Verified ID PowerShell Module

A PowerShell module for fully automated deployment and management of Microsoft Entra Verified ID infrastructure on Azure.

---

## Features

- **One-command deployment** — creates every Azure resource and Verified ID object automatically
- **Storage Account** with static website hosting for DID documents
- **Key Vault** switched to Vault Access Policy mode with the correct per-principal permissions required by Verified ID
- **Authority creation** with retry and exponential back-off
- **DID document generation** via the Admin API and automatic upload to storage
- **Domain validation and DID registration** fully automated
- **Credential issuance and presentation** request flows
- **Complete cleanup** via a single removal function
- **Prerequisite diagnostics** — validates token, API connectivity, tenant onboarding, and Key Vault access policy configuration

---

## What the deployment does, step by step

`Deploy-VerifiedIdInfrastructure` executes the following steps in order. Every step includes error handling and descriptive console output.

### Step 1 — Connect to Azure
Verifies that an active Azure PowerShell session exists. If not, prompts for login.

### Step 2 — Resource Group
Creates the resource group if it does not exist.

### Step 3 — Storage Account
Creates a `Standard_LRS StorageV2` storage account and enables **static website hosting** (`$web` container). The static website URL becomes the DID domain (`did:web:<hostname>`).

If the storage account name is already taken globally (e.g. from a previous failed run), the script recovers the existing account from the resource group instead of failing.

### Step 4 — Key Vault *(most important step)*

This step does four things in sequence:

1. **Creates** the Key Vault (`Standard` SKU) if it does not exist.
2. **Assigns `Key Vault Administrator`** to the currently logged-in user so they can manage keys and policies.
3. **Switches the vault to Vault Access Policy mode** (disables RBAC authorization).
   Verified ID cannot use a vault that is in RBAC-only mode — it calls the Key Vault data-plane under its own service principal identity, not under the deploying user. The switch is done via a direct ARM REST PATCH (`Invoke-AzRestMethod`) so it works on any Az module version.
4. **Assigns the three required Key Vault access policies** to the Verified ID service principals:

   | Service Principal | Key Permissions |
   |---|---|
   | Verifiable Credentials Service | Get, Sign |
   | Verifiable Credentials Service Admin | Get, Create, Sign |
   | Verifiable Credentials Service Request | Sign |

   If a service principal is not yet provisioned in the tenant (normal on first-ever use), the step logs an informational message and continues. Re-running after the first authority creation will fill in any missing policies.

### Step 5 — Acquire delegated token
Calls `az account get-access-token` with the Verified ID Admin API scope (`6a8b4b39-c021-437c-b060-5a14a3fd65f3`). Also ensures the current user has the `Verified ID Administrator` role.

### Step 5.5 — Prerequisite check
Runs `Test-VerifiedIdPrerequisites` to validate:
1. Token is valid and has the correct audience
2. The Verified ID Admin API is reachable
3. Tenant onboarding status
4. User permissions

> The Key Vault check is intentionally skipped here because Step 4 already configured the vault. ARM has a short cache lag that would cause a false-positive RBAC error if the vault were queried immediately after the switch.

### Step 6 — Infrastructure ready
Resolves the final Key Vault URI and storage static website URL that will be used for the authority.

### Step 6.5 — Stabilization wait
Waits 30 seconds for Key Vault and storage to propagate before authority creation is attempted.

### Step 7 — Create Verified ID Authority
Calls the Verified ID Admin API to create an authority using `did:web` with the storage static website as the domain. Retried up to 3 times with back-off.

### Step 7c — Propagation wait
Waits 75 seconds for the authority to become fully available in Microsoft's backend before generating DID documents.

### Step 8 — Generate and upload DID documents
Generates `did.json` and `did-configuration.json` via the Admin API and uploads them to the `$web` container of the storage account. Falls back to storage account key authentication if RBAC upload fails. Verifies both URLs return HTTP 200.

### Step 8.5 — Domain validation and DID registration
Waits 45 seconds for storage replication, then calls `Test-WellKnownDidConfiguration` to validate that Microsoft can fetch and verify the DID documents. If validation passes, calls `Register-VerifiedIdDomain` to complete DID registration.

---

## Prerequisites

| Requirement | Detail |
|---|---|
| PowerShell | 7.0+ (PowerShell Core) |
| Az modules | `Az.Accounts`, `Az.Resources`, `Az.Storage`, `Az.KeyVault` |
| Azure CLI | `az login` must be completed before running |
| Azure role | Owner or Contributor on the subscription/resource group |
| Entra role | **Global Administrator** or **Application Administrator** |
| Verified ID role | **Verified ID Administrator** (assigned automatically if missing) |

---

## Installation

```powershell
# Install required Azure PowerShell modules
Install-Module -Name Az.Accounts, Az.Resources, Az.Storage, Az.KeyVault -Force

# Import the module
Import-Module .\VerifiedID.psm1 -Force
```

---

## Quick start

```powershell
# 1. Log in
az login
az account set --subscription "your-subscription-id"

# 2. Import module
Import-Module .\VerifiedID.psm1 -Force

# 3. Deploy
$deployment = Deploy-VerifiedIdInfrastructure `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "rg-verifiedid-demo" `
    -Location "northeurope" `
    -TenantId "your-tenant-id"

# Outputs
$deployment.AuthorityDID    # did:web:...
$deployment.AuthorityId     # GUID
$deployment.DomainValidated # True/False
```

### Optional parameters

| Parameter | Default | Description |
|---|---|---|
| `-Prefix` | auto | Prefix for resource names |
| `-AuthorityName` | `MyVerifiedIDAuthority` | Name of the Verified ID authority |
| `-ContractName` | `MyCredentialContract` | Default contract name |
| `-SkipVerifiedIdSetup` | `$false` | Deploy infrastructure only, skip authority |
| `-DelegatedTokenFile` | — | Path to a pre-acquired token file |

---

## Infrastructure-only deployment

Deploys the Azure resources (storage + Key Vault) without creating an authority. Useful when you want to configure the authority manually or via a separate script.

```powershell
$infra = Deploy-VerifiedIdInfrastructureOnly `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "rg-verifiedid-infra" `
    -Location "northeurope" `
    -TenantId "your-tenant-id"
```

---

## Working with an existing deployment

```powershell
# Get a token
$token = Get-VerifiedIdDelegatedToken -TenantId "your-tenant-id"

# List authorities
$authorities = Get-VerifiedIdAuthority -AccessToken $token

# Create an additional contract
$contract = New-VerifiedIdContract `
    -AccessToken $token `
    -AuthorityId $authorities.value[0].id `
    -Name "EmployeeID" `
    -Type "EmployeeCredential" `
    -Claims @("firstName", "lastName", "department")

# Issue a credential
$issuance = Start-VcIssuance `
    -AccessToken $token `
    -AuthorityId $authorities.value[0].id `
    -ContractId $contract.id `
    -Claims @{ firstName = "Jane"; lastName = "Doe"; department = "Engineering" } `
    -CallbackUrl "https://your-app.example.com/callback"

# Request a presentation
$presentation = Start-VcPresentation `
    -AccessToken $token `
    -AuthorityId $authorities.value[0].id `
    -Type "EmployeeCredential" `
    -AcceptedIssuers @($authorities.value[0].didModel.did) `
    -CallbackUrl "https://your-app.example.com/verify-callback" `
    -ValidateLinkedDomain
```

---

## Diagnosing an existing deployment

`Test-VerifiedIdPrerequisites` validates a live deployment, including the Key Vault access policy configuration:

```powershell
$token = Get-VerifiedIdDelegatedToken -TenantId "your-tenant-id"

Test-VerifiedIdPrerequisites `
    -TenantId "your-tenant-id" `
    -AccessToken $token `
    -KeyVaultName "your-kv-name" `
    -KeyVaultResourceId "/subscriptions/.../vaults/your-kv-name"
```

When `-KeyVaultName` is provided the check will:
- Confirm the vault is in **Vault Access Policy mode** (flags RBAC mode as an error)
- Verify all three VC service principals have the correct key permissions
- Report exactly which permissions are missing if any

---

## Key Vault — why Access Policy mode, not RBAC

Azure Key Vault supports two authorization models:

| Model | Works with Verified ID? |
|---|---|
| **Vault Access Policy** | ✅ Yes |
| **Azure RBAC** | ❌ No |

When Verified ID performs a signing operation it authenticates as its own service principal identity — not as the deploying user. Access policies are evaluated per service-principal object ID against the vault's own policy list. RBAC role assignments (e.g. `Key Vault Crypto Officer`) are not evaluated for data-plane calls when the vault is in Access Policy mode, and conversely, Access Policy entries are ignored when the vault is in RBAC mode.

**This module switches every new vault to Access Policy mode and sets the required policies in Step 4**, before any other Verified ID work begins.

If you manage the Key Vault outside this module, verify the three entries are present under **Key Vault → Access policies**:

| Application | Key permissions |
|---|---|
| Verifiable Credentials Service | Get, Sign |
| Verifiable Credentials Service Admin | Get, Create, Sign |
| Verifiable Credentials Service Request | Sign |

To switch an existing RBAC vault to Access Policy mode without the module:

```powershell
$kvId = (Get-AzKeyVault -VaultName "your-kv").ResourceId
Invoke-AzRestMethod -Method PATCH `
    -Path "${kvId}?api-version=2022-07-01" `
    -Payload '{"properties":{"enableRbacAuthorization":false}}'
```

---

## Cleanup

```powershell
Remove-VerifiedIdInfrastructure `
    -SubscriptionId "your-subscription-id" `
    -ResourceGroupName "rg-verifiedid-demo" `
    -TenantId "your-tenant-id"
```

---

## Troubleshooting

### Domain validation still pending after deployment
Storage replication takes 30–90 seconds. Wait and retry:
```powershell
Test-WellKnownDidConfiguration -AuthorityId "your-authority-id"
```

### Authority creation fails (403 Forbidden)
- Confirm you are logged in with `az login` under an account that has the **Verified ID Administrator** role
- The role is automatically assigned to the current user during deployment, but RBAC propagation can take a minute

### Key Vault access policy errors / signing failures
Run the diagnostic check:
```powershell
Test-VerifiedIdPrerequisites -TenantId "..." -AccessToken $token `
    -KeyVaultName "your-kv" -KeyVaultResourceId $kvId
```
The check will report whether the vault is in the wrong mode or if any of the three service principal policies are missing or incomplete.

### Storage account name conflict
If a previous failed deployment left behind a storage account name, the script recovers it automatically from the resource group. If the name is taken by a different subscription, delete the old resource group first and re-run (a new random suffix is generated each time).

### Token expired or wrong scope
```powershell
az logout
az login --tenant "your-tenant-id"
```

---

## Authentication

The module uses **delegated user authentication** exclusively:

1. User authenticates with `az login`
2. Script acquires a token scoped to the Verified ID Admin API via Azure CLI
3. All Verified ID API calls run under the user's identity

**App-only (service principal) authentication is not supported** by Microsoft for authority management operations — requests return HTTP 403.

---

## Function reference

### Deployment
| Function | Description |
|---|---|
| `Deploy-VerifiedIdInfrastructure` | Full end-to-end deployment |
| `Deploy-VerifiedIdInfrastructureOnly` | Azure resources only, no authority |
| `Remove-VerifiedIdInfrastructure` | Delete all deployed resources |

### Verified ID management
| Function | Description |
|---|---|
| `New-VerifiedIdAuthority` | Create an authority |
| `New-VerifiedIdContract` | Create a credential contract |
| `Publish-VerifiedIdContract` | Publish (activate) a contract |
| `Get-VerifiedIdAuthority` | List all authorities |
| `Get-VerifiedIdAuthorityDetail` | Get full authority detail |

### DID documents
| Function | Description |
|---|---|
| `New-DidDocument` | Generate `did.json` via Admin API |
| `New-WellKnownDidConfiguration` | Generate `did-configuration.json` |
| `Test-WellKnownDidConfiguration` | Validate domain linkage |
| `Register-VerifiedIdDomain` | Register DID domain with authority |

### Credentials
| Function | Description |
|---|---|
| `Start-VcIssuance` | Create a credential issuance request |
| `Start-VcPresentation` | Create a credential presentation request |

### Authentication
| Function | Description |
|---|---|
| `Get-VerifiedIdDelegatedToken` | Get delegated user token |
| `Get-VerifiedIdAppToken` | Get app-only token |
| `Get-VerifiedIdTokenFromKeyVault` | Retrieve token using secret from Key Vault |
| `Get-VerifiedIdAdminToken` | Shortcut for Admin API token |
| `Get-VerifiedIdRequestToken` | Shortcut for Request Service token |
| `Test-VerifiedIdToken` | Validate a token's audience and claims |

### Diagnostics & utilities
| Function | Description |
|---|---|
| `Test-VerifiedIdPrerequisites` | Full deployment health check including Key Vault IAM |
| `Connect-VerifiedIdAzure` | Azure login helper |
| `Invoke-VerifiedIdApi` | Raw call to the Verified ID REST API |

---

## References

- [Microsoft Entra Verified ID documentation](https://learn.microsoft.com/en-us/entra/verified-id/)
- [Verified ID Admin API](https://learn.microsoft.com/en-us/entra/verified-id/admin-api)
- [Key Vault access policies vs RBAC](https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-access-policy)
- [DID Web method specification](https://w3c-ccg.github.io/did-method-web/)
- [Credential rules and display model](https://learn.microsoft.com/en-us/entra/verified-id/rules-and-display-definitions-model)
