@{
    # Script module or binary module file associated with this manifest.
    RootModule           = 'VerifiedID.psm1'

    # Version number of this module.
    ModuleVersion        = '1.2.0'

    # Supported PSEditions
    CompatiblePSEditions = @('Desktop', 'Core')

    # ID used to uniquely identify this module
    GUID                 = 'a1b2c3d4-e5f6-7890-1234-567890abcdef'

    # Author of this module
    Author               = 'Harri Jaakkonen, Fortytwo.io'

    # Company or vendor of this module
    CompanyName          = 'Fortytwo.io'

    # Copyright statement for this module
    Copyright            = '(c) Fortytwo.io. All rights reserved.'

    # Description of the functionality provided by this module
    Description          = 'PowerShell module for deploying and managing Microsoft Entra Verified ID infrastructure'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion    = '7.0'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules      = @(
        'Az.Accounts',
        'Az.Resources', 
        'Az.Storage',
        'Az.KeyVault'
    )

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport    = @(
        'Deploy-VerifiedIdInfrastructure',
        'Deploy-VerifiedIdInfrastructureOnly',
        'Remove-VerifiedIdInfrastructure',
        'Connect-VerifiedIdAzure',
        'New-VerifiedIdAuthority',
        'Get-VerifiedIdAuthority',
        'Get-VerifiedIdAuthorityDetail',
        'New-VerifiedIdContract',
        'Publish-VerifiedIdContract',
        'Start-VcIssuance',
        'Start-VcPresentation',
        'Test-WellKnownDidConfiguration',
        'New-DidDocument',
        'New-WellKnownDidConfiguration',
        'Get-VerifiedIdAppToken',
        'Get-VerifiedIdDelegatedToken',
        'Get-VerifiedIdTokenFromKeyVault',
        'Get-VerifiedIdAdminToken',
        'Get-VerifiedIdRequestToken',
        'Test-VerifiedIdToken',
        'Test-VerifiedIdPrerequisites',
        'Invoke-VerifiedIdApi'
    )

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport      = @()

    # Variables to export from this module
    VariablesToExport    = @()

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport      = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData          = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags         = @('Azure', 'VerifiedID', 'Identity', 'DID', 'VerifiableCredentials')

            # A URL to the license for this module.
            LicenseUri   = 'https://opensource.org/licenses/MIT'

            # A URL to the main website for this project.
            ProjectUri   = 'https://github.com/microsoft/verified-id'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            ReleaseNotes = 'v1.2.0: Fixed manifest function exports, added Deploy-VerifiedIdInfrastructureOnly and Test-VerifiedIdPrerequisites, removed internal helper functions from export list'

            # Prerelease string of this module
            # Prerelease = ''

            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            # RequireLicenseAcceptance = $false

            # External dependent modules of this module
            # ExternalModuleDependencies = @()
        } # End of PSData hashtable
    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''
}