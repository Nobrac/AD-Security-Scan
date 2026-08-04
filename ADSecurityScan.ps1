#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only security and hygiene assessment of an Active Directory domain.

.DESCRIPTION
    Runs a catalogue of 39 read-only checks across Kerberos, delegation,
    privileged accounts, passwords, account hygiene, infrastructure, directory
    permissions and Active Directory Certificate Services, then writes a
    prioritised HTML report.

    Nothing is written to the directory. Only Get-AD* cmdlets are used. A
    standard domain user account is sufficient for 38 of the 39 checks - which
    is the point: what this script can see, so can anyone holding a single
    compromised account.

    Checks are selected by number, by range, by check ID or by category. Run
    without arguments for an interactive menu.

.PARAMETER Select
    Which checks to run. Accepts any mix of:
        numbers      1,4,9
        ranges       7-14
        check IDs    KRB-001, ADCS-002
        categories   Kerberos, Permissions, ACL, ADCS
        keywords     all, fast
    Example: -Select 1-6,ADCS,PWD-002

.PARAMETER FullScan
    Run every check in the catalogue. Equivalent to -Select all.

.PARAMETER ListChecks
    Print the numbered catalogue and exit without running anything.

.PARAMETER Server
    Target domain controller or domain name. Default: automatic discovery.

.PARAMETER Credential
    Alternate credentials for the queries.

.PARAMETER OutputPath
    Directory for the reports. Default: current directory.

.PARAMETER StaleDays
    Days without logon before an account counts as stale. Default: 90.

.PARAMETER MaxObjectsPerFinding
    Objects listed per finding in the HTML report. Default: 50. The complete
    set always goes into the JSON export.

.PARAMETER IncludeJson
    Also write a JSON export containing every affected object.

.PARAMETER IncludeCsv
    Also write a flat CSV of all affected objects.

.PARAMETER NoReport
    Skip file output entirely.

.PARAMETER Compact
    Collapse the console report to one line per finding. By default every
    affected object is listed underneath its finding.

.PARAMETER MaxConsoleObjects
    How many objects per finding the console lists before truncating.
    Default: 15. The HTML and JSON output are unaffected.

.PARAMETER Quiet
    Suppress the console report. Useful for scheduled runs.

.PARAMETER PassThru
    Emit the finding objects on the pipeline. Without this the script prints
    its console report and returns nothing, so you do not get a second
    unreadable object dump underneath the report.

.EXAMPLE
    .\Invoke-ADSecurityScan.ps1
    Interactive menu, full detail in the console.

.EXAMPLE
    .\Invoke-ADSecurityScan.ps1 -FullScan -OutputPath C:\Reports -IncludeJson

.EXAMPLE
    .\Invoke-ADSecurityScan.ps1 -Select 1-6,ACL-001,ADCS -Compact

.EXAMPLE
    .\Invoke-ADSecurityScan.ps1 -Select ACL -MaxConsoleObjects 200

.EXAMPLE
    $f = .\Invoke-ADSecurityScan.ps1 -Select fast -PassThru -Quiet -NoReport
    $f | Where-Object Severity -eq 'Critical'
    $f | Where-Object Id -eq 'KRB-001' | Select-Object -ExpandProperty Objects

.NOTES
    Verified against: -
    Please run in a lab domain before first production use.
#>

[CmdletBinding()]
param(
    [string[]] $Select,

    [switch] $FullScan,

    [switch] $ListChecks,

    [string] $Server,

    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,

    [string] $OutputPath = (Get-Location).Path,

    [ValidateRange(7, 3650)]
    [int] $StaleDays = 90,

    [ValidateRange(5, 5000)]
    [int] $MaxObjectsPerFinding = 50,

    [switch] $IncludeJson,

    [switch] $IncludeCsv,

    [switch] $NoReport,

    # Collapse the console report to one line per finding. By default every
    # affected object is listed.
    [switch] $Compact,

    # How many objects per finding the console lists before truncating.
    [ValidateRange(1, 10000)]
    [int] $MaxConsoleObjects = 15,

    # Suppress the console report entirely.
    [switch] $Quiet,

    # Emit the finding objects on the pipeline for further processing.
    [switch] $PassThru,

    # Path to the approved-exception file. Defaults to
    # ADSecurityScan.exceptions.json next to this script, if present.
    [string] $ExceptionFile,

    # Ignore the exception file even if one exists.
    [switch] $NoExceptions,

    # Skip checks whose scope is the whole forest (certificate services).
    # Useful when scanning several domains of the same forest in sequence.
    [switch] $SkipForestWide,

    # Define functions and the catalogue, then return without scanning.
    # Used by the Pester tests to dot-source the script on any platform.
    [switch] $InitializeOnly
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

#############################################################################
# REGION: Constants
#############################################################################

# userAccountControl bits, used with LDAP matching rule 1.2.840.113556.1.4.803.
$script:Uac = @{
    AccountDisabled       = 2
    PasswdNotRequired     = 32
    EncryptedTextPwd      = 128
    TrustedForDelegation  = 524288
    DontExpirePassword    = 65536
    NotDelegated          = 1048576
    DontRequirePreauth    = 4194304
    TrustedToAuthForDeleg = 16777216
}

$script:BitAnd  = '1.2.840.113556.1.4.803'    # bitwise AND
$script:InChain = '1.2.840.113556.1.4.1941'   # resolves nested group membership

$script:SeverityRank = @{
    'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Info' = 4; 'Pass' = 5
}

# Well-known GUIDs for extended rights and security-relevant attributes.
$script:Guid = @{
    '00000000-0000-0000-0000-000000000000' = 'ALL (wildcard GUID)'
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All'
    '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set'
    '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Synchronize'
    '00299570-246d-11d0-a768-00aa006e0529' = 'Reset Password'
    'ab721a53-1e2f-11d0-9819-00aa0040529b' = 'Change Password'
    'bf9679c0-0de6-11d0-a285-00aa003049e2' = 'attribute: member'
    '5b47d60f-6090-40b2-9f37-2a4de88f3063' = 'attribute: msDS-KeyCredentialLink'
    '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79' = 'attribute: msDS-AllowedToActOnBehalfOfOtherIdentity'
    'f3a64788-5306-11d1-a9c5-0000f80367c1' = 'attribute: servicePrincipalName'
    'bf967a68-0de6-11d0-a285-00aa003049e2' = 'attribute: userAccountControl'
    'bf9679a8-0de6-11d0-a285-00aa003049e2' = 'attribute: scriptPath'
    '28630ebb-41d5-11d1-a9c1-0000f80367c1' = 'attribute: userPrincipalName'
    '0e10c968-78fb-11d2-90d4-00c04f79dc55' = 'Certificate-Enrollment'
    'a05b8cc2-17bc-4802-a710-e7c15ab866a2' = 'Certificate-AutoEnrollment'
}

# Attributes whose write access is effectively account takeover.
$script:TakeoverAttribute = @(
    'bf9679c0-0de6-11d0-a285-00aa003049e2'  # member - add yourself to the group
    '5b47d60f-6090-40b2-9f37-2a4de88f3063'  # msDS-KeyCredentialLink - shadow credentials
    '3f78c3e5-f79a-46bd-a0b8-9d18116ddc79'  # RBCD - act on behalf of
    'f3a64788-5306-11d1-a9c5-0000f80367c1'  # SPN - make the account roastable
    'bf967a68-0de6-11d0-a285-00aa003049e2'  # userAccountControl - toggle delegation / preauth
    'bf9679a8-0de6-11d0-a285-00aa003049e2'  # scriptPath - code execution at logon
    '28630ebb-41d5-11d1-a9c1-0000f80367c1'  # userPrincipalName - identity swap
)

# Extended rights that lead to takeover.
$script:TakeoverRight = @(
    '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
    '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    '89e95b76-444d-4c62-991a-0facbeda640c'
    '00299570-246d-11d0-a768-00aa006e0529'
)

# Certificate template flags.
$script:NameFlag = @{
    EnrolleeSuppliesSubject    = 0x00000001
    EnrolleeSuppliesAltSubject = 0x00010000
}
$script:EnrollFlag = @{
    PendAllRequests     = 0x00000002   # certificate manager approval
    NoSecurityExtension = 0x00080000   # SID extension not embedded
}

# EKUs that make a certificate usable for domain authentication.
$script:AuthEku = @{
    '1.3.6.1.5.5.7.3.2'      = 'Client Authentication'
    '1.3.6.1.5.2.3.4'        = 'PKINIT Client Authentication'
    '1.3.6.1.4.1.311.20.2.2' = 'Smart Card Logon'
    '2.5.29.37.0'            = 'Any Purpose'
}
$script:AgentEku       = '1.3.6.1.4.1.311.20.2.1'   # Certificate Request Agent
$script:AnyEku         = '2.5.29.37.0'
$script:EnrollRight    = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
$script:AutoEnrollRight = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

# Microsoft documentation per check. Every direct link below was verified to
# resolve; where Microsoft has no single canonical page for a topic, the entry
# points at a Microsoft Learn search with precise terms instead of at a guessed
# URL that might rot into a 404.
$script:Doc = @{
    Gmsa        = @{ Title = 'Group Managed Service Accounts overview'
                     Url   = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview' }
    AdminSd     = @{ Title = 'Appendix C: Protected Accounts and Groups in Active Directory'
                     Url   = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory' }
    PrivGroups  = @{ Title = 'Appendix B: Privileged Accounts and Groups in Active Directory'
                     Url   = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory' }
    AttackSurf  = @{ Title = 'Reducing the Active Directory Attack Surface'
                     Url   = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface' }
    Krbtgt      = @{ Title = 'AD Forest Recovery: Reset the krbtgt password'
                     Url   = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password' }
    Laps        = @{ Title = 'Key concepts in Windows LAPS'
                     Url   = 'https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts-overview' }
    Protected   = @{ Title = 'Protected Users Security Group'
                     Url   = 'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group' }
    Silos       = @{ Title = 'Authentication Policies and Authentication Policy Silos'
                     Url   = 'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos' }
    Delegation  = @{ Title = 'Get rid of accounts that use Kerberos unconstrained delegation'
                     Url   = 'https://learn.microsoft.com/en-us/archive/blogs/389thoughts/get-rid-of-accounts-that-use-kerberos-unconstrained-delegation' }
    CertBinding = @{ Title = 'KB5014754: Certificate-based authentication changes on Windows domain controllers'
                     Url   = 'https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16' }
    CPassword   = @{ Title = 'MS14-025: Vulnerability in Group Policy Preferences (includes the cleanup script)'
                     Url   = 'https://support.microsoft.com/en-us/help/2962486/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevati' }
    SidFilter   = @{ Title = 'Configuring SID Filtering Settings: Domain and Forest Trusts'
                     Url   = 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772633(v=ws.10)' }
    EncTypes    = @{ Title = 'Network security: Configure encryption types allowed for Kerberos'
                     Url   = 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos' }
    Reversible  = @{ Title = 'Store passwords using reversible encryption'
                     Url   = 'https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption' }
    CredProt    = @{ Title = 'Credentials Protection and Management'
                     Url   = 'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection-and-management' }

    # Search-based entries: Microsoft has no single canonical page for these, so
    # the link opens a Learn search with the right terms rather than guessing.
    PwdPolicy   = @{ Title = 'Microsoft Learn: password policy settings'
                     Url   = 'https://learn.microsoft.com/en-us/search/?terms=password%20policy%20security%20policy%20settings' }
    Maq         = @{ Title = 'Microsoft Learn: ms-DS-MachineAccountQuota'
                     Url   = 'https://learn.microsoft.com/en-us/search/?terms=ms-DS-MachineAccountQuota' }
    FuncLevel   = @{ Title = 'Microsoft Learn: Active Directory functional levels'
                     Url   = 'https://learn.microsoft.com/en-us/search/?terms=Active%20Directory%20forest%20and%20domain%20functional%20levels' }
    Delegate    = @{ Title = 'Microsoft Learn: delegating administration of AD objects'
                     Url   = 'https://learn.microsoft.com/en-us/search/?terms=delegating%20administration%20Active%20Directory%20organizational%20units' }
    GpoDelegate = @{ Title = 'Microsoft Learn: delegating Group Policy management'
                     Url   = 'https://learn.microsoft.com/en-us/search/?terms=delegating%20Group%20Policy%20Object%20permissions' }
    AdcsDesign  = @{ Title = 'Microsoft Learn: certificate template security and enrollment permissions'
                     Url   = 'https://learn.microsoft.com/en-us/search/?terms=certificate%20template%20security%20enrollment%20permissions%20AD%20CS' }
    AdcsRoles   = @{ Title = 'Microsoft Learn: role-based administration for certification authorities'
                     Url   = 'https://learn.microsoft.com/en-us/search/?terms=certification%20authority%20role-based%20administration' }
    AdcsAgent   = @{ Title = 'Microsoft Learn: restricted enrollment agents'
                     Url   = 'https://learn.microsoft.com/en-us/search/?terms=restricted%20enrollment%20agent%20certificate%20services' }
    AdcsSan     = @{ Title = 'Microsoft Learn: EDITF_ATTRIBUTESUBJECTALTNAME2'
                     Url   = 'https://learn.microsoft.com/en-us/search/?terms=EDITF_ATTRIBUTESUBJECTALTNAME2' }
}

# Which document belongs to which check.
$script:CheckDoc = @{
    'KRB-001'   = 'Gmsa'
    'KRB-002'   = 'AttackSurf'
    'KRB-003'   = 'Krbtgt'
    'KRB-004'   = 'EncTypes'
    'DEL-001'   = 'Delegation'
    'DEL-002'   = 'Delegation'
    'DEL-003'   = 'Delegation'
    'PRIV-001'  = 'PrivGroups'
    'PRIV-002'  = 'Protected'
    'PRIV-003'  = 'AdminSd'
    'PWD-001'   = 'Gmsa'
    'PWD-002'   = 'AttackSurf'
    'PWD-003'   = 'Reversible'
    'PWD-004'   = 'Gmsa'
    'PWD-005'   = 'PwdPolicy'
    'ACC-001'   = 'AttackSurf'
    'ACC-002'   = 'AttackSurf'
    'ACC-003'   = 'SidFilter'
    'ACC-004'   = 'CredProt'
    'INF-001'   = 'Maq'
    'INF-002'   = 'FuncLevel'
    'INF-003'   = 'AttackSurf'
    'INF-004'   = 'Laps'
    'TRUST-001' = 'SidFilter'
    'GPO-001'   = 'CPassword'
    'ACL-001'   = 'AttackSurf'
    'ACL-002'   = 'PrivGroups'
    'ACL-003'   = 'AdminSd'
    'ACL-004'   = 'AdminSd'
    'ACL-005'   = 'Delegate'
    'ACL-006'   = 'AttackSurf'
    'ACL-007'   = 'Silos'
    'ACL-008'   = 'GpoDelegate'
    'ACL-009'   = 'PrivGroups'
    'ADCS-001'  = 'AdcsRoles'
    'ADCS-002'  = 'AdcsDesign'
    'ADCS-003'  = 'AdcsDesign'
    'ADCS-004'  = 'AdcsAgent'
    'ADCS-005'  = 'AdcsDesign'
    'ADCS-006'  = 'AdcsRoles'
    'ADCS-007'  = 'AdcsSan'
    'ADCS-008'  = 'CertBinding'
    'ADCS-009'  = 'AdcsDesign'
}

# Caches - several checks need the same expensive lookups.
$script:Cache = @{
    Domain      = $null
    PrivGroups  = $null
    PrivUsers   = $null
    DcObjects   = $null
    TrustedSids = $null
    LowPrivSids = $null
    AdcsPaths   = 'unset'
    Templates   = $null
    SidLookup   = @{}
}

#############################################################################
# REGION: Core helpers
#############################################################################

function Get-ADHParameter {
    <# Common splat for every AD cmdlet, so Server/Credential are set in one place. #>
    $p = @{}
    if ($Server) { $p['Server'] = $Server }
    if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
        $p['Credential'] = $Credential
    }
    return $p
}

function Get-ADHDomain {
    if (-not $script:Cache.Domain) {
        $p = Get-ADHParameter
        $script:Cache.Domain = Get-ADDomain @p
    }
    return $script:Cache.Domain
}

function New-ADHFinding {
    <#
        One finding object per check, returned even when nothing was found
        (severity 'Pass'). Keeps the report complete and makes it obvious what
        was actually looked at.
    #>
    param(
        [Parameter(Mandatory)] [string] $Id,
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)]
        [ValidateSet('Critical','High','Medium','Low','Info','Pass')]
        [string] $Severity,
        [string]   $Summary     = '',
        [string]   $Remediation = '',
        [object[]] $Objects     = @()
    )

    # An empty foreach assignment yields $null, and @($null) has Count 1 - which
    # would report one phantom object on every clean check. Filter explicitly.
    $clean = @($Objects | Where-Object { $null -ne $_ })

    # Attach the matching Microsoft documentation, if the check has one.
    $reference = $null
    if ($script:CheckDoc.ContainsKey($Id)) {
        $reference = $script:Doc[$script:CheckDoc[$Id]]
    }

    [PSCustomObject]@{
        PSTypeName  = 'ADSecurityScan.Finding'
        Id          = $Id
        Category    = $Category
        Title       = $Title
        Severity    = $Severity
        Count       = $clean.Count
        Summary     = $Summary
        Remediation = $Remediation
        Reference   = $reference
        Objects     = $clean
    }
}

function New-ADHObject {
    param(
        [Parameter(Mandatory)] [string] $Name,
        [string] $DistinguishedName = '',
        [string] $Details = ''
    )
    [PSCustomObject]@{
        PSTypeName        = 'ADSecurityScan.Object'
        Name              = $Name
        DistinguishedName = $DistinguishedName
        Details           = $Details
    }
}

function Get-ADHAge {
    <# Age in whole days, tolerant of $null and non-date values. #>
    param($Value)
    if ($null -eq $Value) { return $null }
    try   { return [int]((Get-Date) - [datetime]$Value).TotalDays }
    catch { return $null }
}

function Get-ADHProp {
    <# Property access that survives Set-StrictMode when the attribute is absent. #>
    param($Object, [string] $Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    if ($Object.PSObject.Properties.Name -contains $Name) {
        $v = $Object.$Name
        if ($null -ne $v) { return $v }
    }
    return $Default
}

function Test-ADHSchemaAttribute {
    <#
        Checks whether an attribute exists in the schema. Required because
        querying an attribute that was never added (LAPS before the schema
        extension) is a hard error rather than an empty result.
    #>
    param([Parameter(Mandatory)][string] $LdapDisplayName)

    $p = Get-ADHParameter
    try {
        $schemaNc = (Get-ADRootDSE @p).schemaNamingContext
        $found = Get-ADObject @p -SearchBase $schemaNc `
                    -LDAPFilter "(lDAPDisplayName=$LdapDisplayName)" -ErrorAction SilentlyContinue
        return [bool]$found
    }
    catch { return $false }
}

#############################################################################
# REGION: Identity and permission helpers
#############################################################################

function Get-ADHPrivilegedGroup {
    <#
        Tier-0 groups resolved by well-known SID so the checks work in
        non-English domains too.
    #>
    if ($script:Cache.PrivGroups) { return $script:Cache.PrivGroups }

    $p = Get-ADHParameter
    $domainSid = (Get-ADHDomain).DomainSID.Value

    $wanted = @(
        @{ Sid = "$domainSid-512"; Label = 'Domain Admins' }
        @{ Sid = "$domainSid-519"; Label = 'Enterprise Admins' }
        @{ Sid = "$domainSid-518"; Label = 'Schema Admins' }
        @{ Sid = 'S-1-5-32-544';   Label = 'Administrators (builtin)' }
        @{ Sid = 'S-1-5-32-548';   Label = 'Account Operators' }
        @{ Sid = 'S-1-5-32-549';   Label = 'Server Operators' }
        @{ Sid = 'S-1-5-32-550';   Label = 'Print Operators' }
        @{ Sid = 'S-1-5-32-551';   Label = 'Backup Operators' }
    )

    $result = foreach ($w in $wanted) {
        try {
            # The security descriptor comes along here so the permission checks
            # do not have to fetch it again object by object.
            $g = Get-ADGroup @p -Identity $w.Sid -Properties Name, nTSecurityDescriptor -ErrorAction Stop
            [PSCustomObject]@{ Label = $w.Label; Group = $g }
        }
        catch {
            Write-Verbose ('Group {0} not found: {1}' -f $w.Sid, $_.Exception.Message)
        }
    }

    $script:Cache.PrivGroups = @($result | Where-Object { $null -ne $_ })
    return $script:Cache.PrivGroups
}

function Get-ADHPrivilegedUser {
    <#
        All user accounts flagged adminCount=1, cached, with the security
        descriptor included. One LDAP query instead of one round trip per
        account later on - in a domain with a few hundred privileged accounts
        this is the single biggest runtime saving in the script.
    #>
    if ($script:Cache.PrivUsers) { return $script:Cache.PrivUsers }

    $p = Get-ADHParameter
    $script:Cache.PrivUsers = @(Get-ADUser @p `
        -LDAPFilter '(&(objectCategory=person)(objectClass=user)(adminCount=1))' `
        -Properties adminCount, Enabled, PasswordLastSet, nTSecurityDescriptor)
    return $script:Cache.PrivUsers
}

function Get-ADHDomainControllerObject {
    <#
        Domain controller computer objects including their security descriptor,
        fetched in a single query. primaryGroupID 516 is "Domain Controllers",
        521 is "Read-only Domain Controllers".
    #>
    if ($script:Cache.DcObjects) { return $script:Cache.DcObjects }

    $p = Get-ADHParameter
    $script:Cache.DcObjects = @(Get-ADComputer @p `
        -LDAPFilter '(&(objectCategory=computer)(|(primaryGroupID=516)(primaryGroupID=521)))' `
        -Properties nTSecurityDescriptor, operatingSystem, dNSHostName)
    return $script:Cache.DcObjects
}

function Get-ADHTrustedSid {
    <#
        Principals that legitimately hold sweeping rights in the directory.
        Everything outside this list is reported.

        Deliberately NOT listed: Account Operators, Server Operators, Backup
        Operators, Print Operators, Pre-Windows 2000 Compatible Access. Those
        groups routinely carry historical rights, which is exactly why they
        belong in the report.
    #>
    if ($script:Cache.TrustedSids) { return $script:Cache.TrustedSids }

    $d = (Get-ADHDomain).DomainSID.Value
    $script:Cache.TrustedSids = @(
        'S-1-5-18'      # Local System
        'S-1-5-32-544'  # Administrators
        'S-1-5-9'       # Enterprise Domain Controllers
        'S-1-5-10'      # Principal Self
        'S-1-3-0'       # Creator Owner
        "$d-512"        # Domain Admins
        "$d-518"        # Schema Admins
        "$d-519"        # Enterprise Admins
        "$d-516"        # Domain Controllers
        "$d-521"        # Read-only Domain Controllers
        "$d-526"        # Key Admins
        "$d-527"        # Enterprise Key Admins
        "$d-498"        # Enterprise Read-only Domain Controllers
    )
    return $script:Cache.TrustedSids
}

function Get-ADHLowPrivilegedSid {
    <#
        Principals whose enrolment right effectively means "anyone on the
        network". A finding on one of these weighs far more than a delegation
        to a single named service account.
    #>
    if ($script:Cache.LowPrivSids) { return $script:Cache.LowPrivSids }

    $d = (Get-ADHDomain).DomainSID.Value
    $script:Cache.LowPrivSids = @{
        'S-1-1-0'      = 'Everyone'
        'S-1-5-11'     = 'Authenticated Users'
        'S-1-5-32-545' = 'Users'
        "$d-513"       = 'Domain Users'
        "$d-514"       = 'Domain Guests'
        "$d-515"       = 'Domain Computers'
    }
    return $script:Cache.LowPrivSids
}

function Resolve-ADHIdentity {
    <# IdentityReference to SID string, memoised. #>
    param($IdentityReference)

    $key = $IdentityReference.Value
    if ($script:Cache.SidLookup.ContainsKey($key)) { return $script:Cache.SidLookup[$key] }

    $sid = $null
    try {
        if ($IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
            $sid = $IdentityReference.Value
        }
        else {
            $sid = $IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        }
    }
    catch { $sid = $null }

    $script:Cache.SidLookup[$key] = $sid
    return $sid
}

function Get-ADHGuidLabel {
    param([string] $Guid)
    if ([string]::IsNullOrEmpty($Guid)) { return '' }
    $g = $Guid.ToLower()
    if ($script:Guid.ContainsKey($g)) { return $script:Guid[$g] }
    return $g
}

function Get-ADHSecurityDescriptor {
    param([Parameter(Mandatory)][string] $DistinguishedName)

    $p = Get-ADHParameter
    try {
        return (Get-ADObject @p -Identity $DistinguishedName -Properties nTSecurityDescriptor -ErrorAction Stop).nTSecurityDescriptor
    }
    catch {
        Write-Verbose ('Security descriptor unreadable for {0}: {1}' -f $DistinguishedName, $_.Exception.Message)
        return $null
    }
}

function Get-ADHDangerousAce {
    <#
        Core of the permission analysis: reduces a DACL to the ACEs that give
        an untrusted principal effective control over the object.
    #>
    param(
        [Parameter(Mandatory)] $SecurityDescriptor,
        [switch] $IncludeInherited
    )

    $trusted = Get-ADHTrustedSid

    foreach ($ace in $SecurityDescriptor.Access) {

        if ($ace.AccessControlType -ne 'Allow') { continue }
        if ($ace.IsInherited -and -not $IncludeInherited) { continue }

        $sid = Resolve-ADHIdentity $ace.IdentityReference
        if ($sid -and ($trusted -contains $sid)) { continue }
        # Admin groups from trusted foreign domains carry the same RIDs.
        if ($sid -and ($sid -match '-(512|518|519)$')) { continue }

        $rights     = $ace.ActiveDirectoryRights.ToString()
        $objectType = $ace.ObjectType.ToString()
        $dangerous  = $false
        $reason     = ''

        if ($rights -match 'GenericAll|WriteDacl|WriteOwner') {
            $dangerous = $true
            $reason    = 'full control or control over permissions'
        }
        elseif ($rights -match 'GenericWrite') {
            $dangerous = $true
            $reason    = 'write access to all attributes'
        }
        elseif ($rights -match 'WriteProperty|Self') {
            if ($objectType -eq '00000000-0000-0000-0000-000000000000') {
                $dangerous = $true
                $reason    = 'unscoped write access'
            }
            elseif ($script:TakeoverAttribute -contains $objectType.ToLower()) {
                $dangerous = $true
                $reason    = 'write access to a takeover-capable attribute'
            }
        }
        elseif ($rights -match 'ExtendedRight') {
            if ($objectType -eq '00000000-0000-0000-0000-000000000000') {
                $dangerous = $true
                $reason    = 'all extended rights'
            }
            elseif ($script:TakeoverRight -contains $objectType.ToLower()) {
                $dangerous = $true
                $reason    = 'critical extended right'
            }
        }

        if (-not $dangerous) { continue }

        [PSCustomObject]@{
            Sid         = $sid
            Identity    = $ace.IdentityReference.Value
            Rights      = $rights
            ObjectLabel = Get-ADHGuidLabel $objectType
            Inherited   = $ace.IsInherited
            Reason      = $reason
        }
    }
}

function Format-ADHAce {
    param($Ace)
    '{0} -> {1} [{2}]{3}' -f `
        $Ace.Identity, $Ace.Reason, $Ace.Rights,
        $(if ($Ace.ObjectLabel -and $Ace.ObjectLabel -ne 'ALL (wildcard GUID)') { " on $($Ace.ObjectLabel)" } else { '' })
}

#############################################################################
# REGION: Certificate services helpers
#############################################################################

function Get-ADHAdcsPath {
    <# Base paths in the configuration NC. Returns $null when no PKI exists. #>
    if ($script:Cache.AdcsPaths -ne 'unset') { return $script:Cache.AdcsPaths }

    $p = Get-ADHParameter
    try {
        $configNc = (Get-ADRootDSE @p).configurationNamingContext
        $pki = 'CN=Public Key Services,CN=Services,{0}' -f $configNc
        $null = Get-ADObject @p -Identity $pki -ErrorAction Stop
        $script:Cache.AdcsPaths = @{
            Config     = $configNc
            Pki        = $pki
            Templates  = "CN=Certificate Templates,$pki"
            Enrollment = "CN=Enrollment Services,$pki"
            NtAuth     = "CN=NTAuthCertificates,$pki"
        }
    }
    catch { $script:Cache.AdcsPaths = $null }

    return $script:Cache.AdcsPaths
}

function Get-ADHCertificateAuthority {
    param($Paths)
    $p = Get-ADHParameter
    try {
        return @(Get-ADObject @p -SearchBase $Paths.Enrollment `
            -LDAPFilter '(objectClass=pKIEnrollmentService)' `
            -Properties certificateTemplates, dNSHostName, Name)
    }
    catch { return @() }
}

function Get-ADHCertificateTemplate {
    <# Reads all templates once and enriches them with decoded flags. #>
    param($Paths)

    if ($script:Cache.Templates) { return $script:Cache.Templates }

    $p = Get-ADHParameter
    $props = @(
        'displayName','name','nTSecurityDescriptor',
        'msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag','msPKI-RA-Signature',
        'pKIExtendedKeyUsage','msPKI-Certificate-Application-Policy',
        'msPKI-Template-Schema-Version'
    )

    # Only templates published on a CA can actually be requested.
    $published = @()
    foreach ($ca in (Get-ADHCertificateAuthority -Paths $Paths)) {
        $published += @(Get-ADHProp $ca 'certificateTemplates' @())
    }
    $published = @($published | Select-Object -Unique)

    $raw = @(Get-ADObject @p -SearchBase $Paths.Templates `
        -LDAPFilter '(objectClass=pKICertificateTemplate)' -Properties $props)

    $script:Cache.Templates = foreach ($t in $raw) {
        $nameFlag   = [int](Get-ADHProp $t 'msPKI-Certificate-Name-Flag' 0)
        $enrollFlag = [int](Get-ADHProp $t 'msPKI-Enrollment-Flag' 0)

        $ekus = @(@(Get-ADHProp $t 'pKIExtendedKeyUsage' @()) +
                  @(Get-ADHProp $t 'msPKI-Certificate-Application-Policy' @()) |
                  Select-Object -Unique)

        [PSCustomObject]@{
            Name              = $t.Name
            DisplayName       = Get-ADHProp $t 'displayName' $t.Name
            DistinguishedName = $t.DistinguishedName
            Sd                = Get-ADHProp $t 'nTSecurityDescriptor'
            Published         = ($published -contains $t.Name)
            SchemaVersion     = [int](Get-ADHProp $t 'msPKI-Template-Schema-Version' 1)
            Ekus              = @($ekus)
            SuppliesSubject   = (($nameFlag -band $script:NameFlag.EnrolleeSuppliesSubject) -ne 0) -or
                                (($nameFlag -band $script:NameFlag.EnrolleeSuppliesAltSubject) -ne 0)
            RequiresApproval  = (($enrollFlag -band $script:EnrollFlag.PendAllRequests) -ne 0)
            NoSecurityExt     = (($enrollFlag -band $script:EnrollFlag.NoSecurityExtension) -ne 0)
            AuthorizedSigs    = [int](Get-ADHProp $t 'msPKI-RA-Signature' 0)
        }
    }

    $script:Cache.Templates = @($script:Cache.Templates | Where-Object { $null -ne $_ })
    return $script:Cache.Templates
}

function Get-ADHTemplateEnroller {
    <# Low-privileged principals holding enrolment rights on a template. #>
    param($Template)

    if (-not $Template.Sd) { return @() }
    $lowPriv = Get-ADHLowPrivilegedSid
    $result = @()

    foreach ($ace in $Template.Sd.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }

        $r  = $ace.ActiveDirectoryRights.ToString()
        $ot = $ace.ObjectType.ToString().ToLower()

        $grantsEnroll = ($r -match 'GenericAll') -or
                        ($r -match 'ExtendedRight' -and (
                            $ot -eq '00000000-0000-0000-0000-000000000000' -or
                            $ot -eq $script:EnrollRight -or
                            $ot -eq $script:AutoEnrollRight))
        if (-not $grantsEnroll) { continue }

        $sid = Resolve-ADHIdentity $ace.IdentityReference
        if ($sid -and $lowPriv.ContainsKey($sid)) { $result += $lowPriv[$sid] }
    }

    return @($result | Select-Object -Unique)
}

function Get-ADHTemplateWriter {
    <# Principals with write or full control over the template object itself. #>
    param($Template)

    if (-not $Template.Sd) { return @() }
    $trusted = Get-ADHTrustedSid
    $result = @()

    foreach ($ace in $Template.Sd.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }

        $r = $ace.ActiveDirectoryRights.ToString()
        if ($r -notmatch 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty') { continue }
        if ($r -eq 'ExtendedRight') { continue }   # plain enrolment is not a finding here

        $sid = Resolve-ADHIdentity $ace.IdentityReference
        if ($sid -and ($trusted -contains $sid)) { continue }
        if ($sid -and ($sid -match '-(512|516|518|519)$')) { continue }

        $result += ('{0} [{1}]' -f $ace.IdentityReference.Value, $r)
    }

    return @($result | Select-Object -Unique)
}

function Test-ADHTemplateHasAuthEku {
    param($Template)
    # An empty EKU list means no restriction, so authentication is possible too.
    if (@($Template.Ekus).Count -eq 0) { return $true }
    foreach ($e in $Template.Ekus) {
        if ($script:AuthEku.ContainsKey($e)) { return $true }
    }
    return $false
}

#############################################################################
# REGION: Checks - Kerberos
#############################################################################

function Test-ADHKerberoastable {
    $p = Get-ADHParameter
    $filter = "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))(!(userAccountControl:$script:BitAnd`:=$($script:Uac.AccountDisabled))))"

    $accounts = @(Get-ADUser @p -LDAPFilter $filter -Properties servicePrincipalName, PasswordLastSet, adminCount)

    $objects = foreach ($a in $accounts) {
        $age = Get-ADHAge $a.PasswordLastSet
        New-ADHObject -Name $a.SamAccountName -DistinguishedName $a.DistinguishedName -Details (
            'SPNs: {0} | password age: {1} | privileged: {2}' -f `
                (@($a.servicePrincipalName) -join ', '),
                $(if ($null -ne $age) { "$age days" } else { 'unknown' }),
                $(if ($a.adminCount -eq 1) { 'YES' } else { 'no' }))
    }

    $priv = @($accounts | Where-Object { $_.adminCount -eq 1 }).Count
    $sev = if ($priv -gt 0) { 'Critical' } elseif (@($accounts).Count -gt 0) { 'High' } else { 'Pass' }

    New-ADHFinding -Id 'KRB-001' -Category 'Kerberos' -Severity $sev `
        -Title 'Kerberoastable accounts (user objects with an SPN)' `
        -Summary ('Any authenticated domain user can request a service ticket for these accounts and crack the password offline. {0} of them are privileged.' -f $priv) `
        -Remediation 'Migrate to group managed service accounts, which rotate a 240-character password automatically. Where that is not possible, set a passphrase of at least 25 characters and remove the account from privileged groups.' `
        -Objects $objects
}

function Test-ADHAsRepRoastable {
    $p = Get-ADHParameter
    $filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:$script:BitAnd`:=$($script:Uac.DontRequirePreauth)))"

    $accounts = @(Get-ADUser @p -LDAPFilter $filter -Properties PasswordLastSet, Enabled, adminCount)

    $objects = foreach ($a in $accounts) {
        $age = Get-ADHAge $a.PasswordLastSet
        New-ADHObject -Name $a.SamAccountName -DistinguishedName $a.DistinguishedName -Details (
            'enabled: {0} | password age: {1}' -f `
                $(if ($a.Enabled) { 'yes' } else { 'no' }),
                $(if ($null -ne $age) { "$age days" } else { 'unknown' }))
    }

    $sev = if (@($accounts).Count -gt 0) { 'High' } else { 'Pass' }

    New-ADHFinding -Id 'KRB-002' -Category 'Kerberos' -Severity $sev `
        -Title 'Kerberos pre-authentication disabled' `
        -Summary 'Without pre-authentication the KDC hands out an encrypted blob to anyone who asks, with no authentication at all. That blob is then cracked offline.' `
        -Remediation 'Clear the "Do not require Kerberos preauthentication" flag. If a legacy system genuinely needs it, isolate the account and give it a very long passphrase.' `
        -Objects $objects
}

function Test-ADHKrbtgtAge {
    $p = Get-ADHParameter
    $krbtgt = Get-ADUser @p -Identity 'krbtgt' -Properties PasswordLastSet
    $age = Get-ADHAge $krbtgt.PasswordLastSet

    $sev = if ($null -eq $age) { 'Info' } elseif ($age -gt 365) { 'High' } elseif ($age -gt 180) { 'Medium' } else { 'Pass' }

    New-ADHFinding -Id 'KRB-003' -Category 'Kerberos' -Severity $sev `
        -Title 'krbtgt password age' `
        -Summary 'The krbtgt key signs every Kerberos ticket in the domain. An old key extends the useful life of any golden ticket that may already have been forged.' `
        -Remediation 'Reset the password twice, waiting at least one full replication cycle between resets (24 hours is a safe default). Do this every six months, and always after a suspected compromise.' `
        -Objects @(New-ADHObject -Name 'krbtgt' -DistinguishedName $krbtgt.DistinguishedName `
            -Details ('password last set: {0} ({1} days)' -f $krbtgt.PasswordLastSet, $age))
}

function Test-ADHWeakKerberosEncryption {
    $p = Get-ADHParameter

    # msDS-SupportedEncryptionTypes bits. An unset attribute means "domain
    # default", which on anything below a 2008 functional level still includes
    # RC4, so those accounts are reported as well when they hold an SPN.
    $bits = @{
        DesCrc  = 0x01
        DesMd5  = 0x02
        Rc4     = 0x04
        Aes128  = 0x08
        Aes256  = 0x10
    }

    $accounts = @(Get-ADObject @p `
        -LDAPFilter '(&(|(objectCategory=person)(objectCategory=computer))(|(servicePrincipalName=*)(adminCount=1)))' `
        -Properties sAMAccountName, objectClass, 'msDS-SupportedEncryptionTypes', servicePrincipalName, adminCount)

    $objects = @()
    $desCount = 0

    foreach ($a in $accounts) {
        $etype = Get-ADHProp $a 'msDS-SupportedEncryptionTypes'
        $hasSpn = @(Get-ADHProp $a 'servicePrincipalName' @()).Count -gt 0
        $priv   = ((Get-ADHProp $a 'adminCount' 0) -eq 1)

        $issue = $null
        if ($null -eq $etype -or [int]$etype -eq 0) {
            # Nothing configured - the KDC falls back to the domain default.
            if ($hasSpn) { $issue = 'no encryption types configured, KDC falls back to the domain default' }
        }
        else {
            $e = [int]$etype
            $des = (($e -band $bits.DesCrc) -ne 0) -or (($e -band $bits.DesMd5) -ne 0)
            $aes = (($e -band $bits.Aes128) -ne 0) -or (($e -band $bits.Aes256) -ne 0)
            $rc4 = (($e -band $bits.Rc4) -ne 0)

            if ($des)              { $issue = 'DES enabled'; $desCount++ }
            elseif ($rc4 -and -not $aes) { $issue = 'RC4 only, no AES' }
        }

        if (-not $issue) { continue }

        $objects += New-ADHObject -Name (Get-ADHProp $a 'sAMAccountName' $a.Name) `
            -DistinguishedName $a.DistinguishedName -Details (
                '{0} | class: {1} | SPN: {2} | privileged: {3}' -f `
                    $issue, $a.objectClass,
                    $(if ($hasSpn) { 'yes' } else { 'no' }),
                    $(if ($priv) { 'YES' } else { 'no' }))
    }

    $sev = if ($desCount -gt 0) { 'High' } elseif ($objects.Count -gt 0) { 'Medium' } else { 'Pass' }

    New-ADHFinding -Id 'KRB-004' -Category 'Kerberos' -Severity $sev `
        -Title 'Weak Kerberos encryption on accounts with an SPN or privileges' `
        -Summary ('{0} accounts negotiate DES or RC4 rather than AES. RC4 service tickets crack orders of magnitude faster than AES, so this multiplies the impact of every finding in KRB-001. DES is broken outright and enabled on {1} of them.' -f $objects.Count, $desCount) `
        -Remediation 'Set msDS-SupportedEncryptionTypes to AES128 and AES256 only (value 24) on service accounts, then reset the password so new keys are generated. Move the domain to AES-only once event 4769 shows no RC4 tickets in flight. Never leave DES enabled - no supported system requires it.' `
        -Objects $objects
}

#############################################################################
# REGION: Checks - Delegation
#############################################################################

function Test-ADHUnconstrainedDelegation {
    $p = Get-ADHParameter
    # primaryGroupID 516/521 are domain controllers and RODCs, where this is by design.
    $filter = "(&(userAccountControl:$script:BitAnd`:=$($script:Uac.TrustedForDelegation))(!(primaryGroupID=516))(!(primaryGroupID=521)))"

    $objs = @(Get-ADObject @p -LDAPFilter $filter -Properties sAMAccountName, objectClass)

    $objects = foreach ($o in $objs) {
        New-ADHObject -Name (Get-ADHProp $o 'sAMAccountName' $o.Name) `
            -DistinguishedName $o.DistinguishedName -Details ('object class: {0}' -f $o.objectClass)
    }

    $sev = if (@($objs).Count -gt 0) { 'Critical' } else { 'Pass' }

    New-ADHFinding -Id 'DEL-001' -Category 'Delegation' -Severity $sev `
        -Title 'Unconstrained delegation outside domain controllers' `
        -Summary 'These systems cache the forwarded TGT of every user who authenticates to them. Compromise one and coax a domain admin into connecting, and the domain is gone.' `
        -Remediation 'Move to constrained or resource-based constrained delegation. Additionally add privileged accounts to Protected Users, which stops their tickets being forwarded at all.' `
        -Objects $objects
}

function Test-ADHConstrainedDelegationTransition {
    $p = Get-ADHParameter
    $filter = "(userAccountControl:$script:BitAnd`:=$($script:Uac.TrustedToAuthForDeleg))"

    $objs = @(Get-ADObject @p -LDAPFilter $filter -Properties sAMAccountName, objectClass, 'msDS-AllowedToDelegateTo')

    $objects = foreach ($o in $objs) {
        $targets = @(Get-ADHProp $o 'msDS-AllowedToDelegateTo' @())
        New-ADHObject -Name (Get-ADHProp $o 'sAMAccountName' $o.Name) `
            -DistinguishedName $o.DistinguishedName `
            -Details ('targets: {0}' -f $(if ($targets.Count) { $targets -join ', ' } else { 'none' }))
    }

    $sev = if (@($objs).Count -gt 0) { 'High' } else { 'Pass' }

    New-ADHFinding -Id 'DEL-002' -Category 'Delegation' -Severity $sev `
        -Title 'Constrained delegation with protocol transition' `
        -Summary 'Protocol transition ("use any authentication protocol") lets the account mint a ticket for any user without that user being involved. If a target service points at a domain controller, this is equivalent to domain compromise.' `
        -Remediation 'Review every delegation target and reduce it to what the application actually needs. Switch to "Kerberos only" wherever the application supports it.' `
        -Objects $objects
}

function Test-ADHResourceBasedDelegation {
    $p = Get-ADHParameter
    $objs = @(Get-ADObject @p -LDAPFilter '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)' -Properties sAMAccountName, objectClass)

    $objects = foreach ($o in $objs) {
        New-ADHObject -Name (Get-ADHProp $o 'sAMAccountName' $o.Name) `
            -DistinguishedName $o.DistinguishedName -Details ('object class: {0}' -f $o.objectClass)
    }

    $sev = if (@($objs).Count -gt 0) { 'Medium' } else { 'Pass' }

    New-ADHFinding -Id 'DEL-003' -Category 'Delegation' -Severity $sev `
        -Title 'Resource-based constrained delegation configured' `
        -Summary 'RBCD has plenty of legitimate uses, but it is also a favourite persistence mechanism: anyone who can write to a computer object can add themselves here and take the machine over.' `
        -Remediation 'Match every entry against a documented purpose. An entry nobody can account for is an incident, not a misconfiguration.' `
        -Objects $objects
}

#############################################################################
# REGION: Checks - Privileged accounts
#############################################################################

function Test-ADHPrivilegedGroupMembership {
    $p = Get-ADHParameter
    $objects = @()
    $total = 0

    foreach ($entry in Get-ADHPrivilegedGroup) {
        $dn = $entry.Group.DistinguishedName
        $members = @(Get-ADUser @p -LDAPFilter "(memberOf:$script:InChain`:=$dn)" -Properties Enabled)
        $total += $members.Count

        $objects += New-ADHObject -Name $entry.Label -DistinguishedName $dn -Details (
            '{0} user accounts (nested included), {1} enabled: {2}' -f `
                $members.Count,
                @($members | Where-Object { $_.Enabled }).Count,
                $(if ($members.Count) { (@($members | Select-Object -First 20 -ExpandProperty SamAccountName)) -join ', ' } else { '-' }))
    }

    $sev = if ($total -gt 25) { 'High' } elseif ($total -gt 10) { 'Medium' } else { 'Info' }

    New-ADHFinding -Id 'PRIV-001' -Category 'Privileges' -Severity $sev `
        -Title 'Tier-0 group membership' `
        -Summary ('{0} user accounts across highly privileged groups. Rules of thumb: Domain Admins under five, Enterprise and Schema Admins empty during normal operations.' -f $total) `
        -Remediation 'Recertify every membership. Populate Enterprise and Schema Admins only for the duration of a specific change. The operator groups (Account, Server, Backup, Print) are unnecessary in most environments and should be emptied - Account Operators in particular can modify most user objects in the domain.' `
        -Objects $objects
}

function Test-ADHUnprotectedPrivilegedAccounts {
    $p = Get-ADHParameter
    $domainSid = (Get-ADHDomain).DomainSID.Value

    $protectedMembers = @()
    try {
        $protectedDn = (Get-ADGroup @p -Identity "$domainSid-525" -ErrorAction Stop).DistinguishedName
        $protectedMembers = @(Get-ADUser @p -LDAPFilter "(memberOf:$script:InChain`:=$protectedDn)" |
                              Select-Object -ExpandProperty DistinguishedName)
    }
    catch { Write-Verbose 'Protected Users group not present (requires 2012 R2 domain functional level).' }

    $filter = "(&(objectCategory=person)(objectClass=user)(adminCount=1)(!(userAccountControl:$script:BitAnd`:=$($script:Uac.NotDelegated)))(!(userAccountControl:$script:BitAnd`:=$($script:Uac.AccountDisabled))))"
    $candidates = @(Get-ADUser @p -LDAPFilter $filter)
    $unprotected = @($candidates | Where-Object { $protectedMembers -notcontains $_.DistinguishedName })

    $objects = foreach ($u in $unprotected) {
        New-ADHObject -Name $u.SamAccountName -DistinguishedName $u.DistinguishedName `
            -Details 'not in Protected Users and not marked as sensitive/non-delegable'
    }

    $sev = if (@($unprotected).Count -gt 0) { 'High' } else { 'Pass' }

    New-ADHFinding -Id 'PRIV-002' -Category 'Privileges' -Severity $sev `
        -Title 'Privileged accounts without delegation protection' `
        -Summary 'Unprotected privileged credentials can be forwarded and reused by any system holding delegation rights.' `
        -Remediation 'Add these accounts to Protected Users and additionally set "Account is sensitive and cannot be delegated". Test first: Protected Users blocks NTLM, DES and RC4, and disables credential caching, which breaks some legacy applications.' `
        -Objects $objects
}

function Test-ADHOrphanedAdminCount {
    $p = Get-ADHParameter

    $privDns = @()
    foreach ($entry in Get-ADHPrivilegedGroup) {
        $dn = $entry.Group.DistinguishedName
        $privDns += @(Get-ADUser @p -LDAPFilter "(memberOf:$script:InChain`:=$dn)" |
                      Select-Object -ExpandProperty DistinguishedName)
    }
    $privDns = @($privDns | Select-Object -Unique)

    $orphans = @(Get-ADHPrivilegedUser | Where-Object { $privDns -notcontains $_.DistinguishedName })

    $objects = foreach ($o in $orphans) {
        New-ADHObject -Name $o.SamAccountName -DistinguishedName $o.DistinguishedName `
            -Details ('enabled: {0}' -f $(if ($o.Enabled) { 'yes' } else { 'no' }))
    }

    $sev = if (@($orphans).Count -gt 0) { 'Medium' } else { 'Pass' }

    New-ADHFinding -Id 'PRIV-003' -Category 'Privileges' -Severity $sev `
        -Title 'Orphaned adminCount flags' `
        -Summary 'These accounts still carry adminCount=1 from a former privileged membership. AdminSDHolder keeps inheritance disabled on them, which makes their effective permissions hard to reason about and blocks intended delegations.' `
        -Remediation 'After confirming the account is no longer used for privileged work, clear adminCount and re-enable inheritance on the object. Confirm first - a service account that was only temporarily removed from a group will look identical.' `
        -Objects $objects
}

#############################################################################
# REGION: Checks - Passwords
#############################################################################

function Test-ADHPasswordNeverExpires {
    $p = Get-ADHParameter
    $filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:$script:BitAnd`:=$($script:Uac.DontExpirePassword))(!(userAccountControl:$script:BitAnd`:=$($script:Uac.AccountDisabled))))"

    $accounts = @(Get-ADUser @p -LDAPFilter $filter -Properties PasswordLastSet, adminCount)

    $objects = foreach ($a in $accounts) {
        $age = Get-ADHAge $a.PasswordLastSet
        New-ADHObject -Name $a.SamAccountName -DistinguishedName $a.DistinguishedName -Details (
            'password age: {0} | adminCount: {1}' -f `
                $(if ($null -ne $age) { "$age days" } else { 'unknown' }),
                $(if ($a.adminCount -eq 1) { '1' } else { '-' }))
    }

    $priv = @($accounts | Where-Object { $_.adminCount -eq 1 }).Count
    $sev = if ($priv -gt 0) { 'High' } elseif (@($accounts).Count -gt 0) { 'Medium' } else { 'Pass' }

    New-ADHFinding -Id 'PWD-001' -Category 'Passwords' -Severity $sev `
        -Title 'Enabled accounts with non-expiring passwords' `
        -Summary ('{0} enabled accounts, {1} of them privileged. A password leaked once stays valid indefinitely.' -f @($accounts).Count, $priv) `
        -Remediation 'Use group managed service accounts for services so rotation is automatic. For the rest, prefer a fine-grained password policy with a long minimum length over an indefinite lifetime.' `
        -Objects $objects
}

function Test-ADHPasswordNotRequired {
    $p = Get-ADHParameter
    $filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:$script:BitAnd`:=$($script:Uac.PasswdNotRequired))(!(userAccountControl:$script:BitAnd`:=$($script:Uac.AccountDisabled))))"

    $accounts = @(Get-ADUser @p -LDAPFilter $filter -Properties PasswordLastSet)

    $objects = foreach ($a in $accounts) {
        New-ADHObject -Name $a.SamAccountName -DistinguishedName $a.DistinguishedName `
            -Details ('password last set: {0}' -f $a.PasswordLastSet)
    }

    $sev = if (@($accounts).Count -gt 0) { 'Critical' } else { 'Pass' }

    New-ADHFinding -Id 'PWD-002' -Category 'Passwords' -Severity $sev `
        -Title 'Enabled accounts that may have a blank password' `
        -Summary 'The domain password policy is not enforced for these accounts. They are permitted to hold an empty password.' `
        -Remediation 'Clear the PASSWD_NOTREQD flag and set a new password. Where the flag came from a migration, first establish whether the account is still needed at all.' `
        -Objects $objects
}

function Test-ADHReversibleEncryption {
    $p = Get-ADHParameter
    $filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:$script:BitAnd`:=$($script:Uac.EncryptedTextPwd)))"

    $accounts = @(Get-ADUser @p -LDAPFilter $filter -Properties Enabled)

    $objects = foreach ($a in $accounts) {
        New-ADHObject -Name $a.SamAccountName -DistinguishedName $a.DistinguishedName `
            -Details ('enabled: {0}' -f $(if ($a.Enabled) { 'yes' } else { 'no' }))
    }

    $sev = if (@($accounts).Count -gt 0) { 'Critical' } else { 'Pass' }

    New-ADHFinding -Id 'PWD-003' -Category 'Passwords' -Severity $sev `
        -Title 'Passwords stored with reversible encryption' `
        -Summary 'The password is effectively stored in clear text inside NTDS.dit. Anyone who reads the database reads the passwords.' `
        -Remediation 'Clear the flag and then force a password change - clearing alone does not remove the stored clear-text value. The usual cause is a legacy application using CHAP or digest authentication.' `
        -Objects $objects
}

function Test-ADHStalePrivilegedPasswords {
    $p = Get-ADHParameter
    $threshold = 365

    $priv = @()
    foreach ($entry in Get-ADHPrivilegedGroup) {
        $dn = $entry.Group.DistinguishedName
        $priv += @(Get-ADUser @p -LDAPFilter "(memberOf:$script:InChain`:=$dn)" -Properties PasswordLastSet, Enabled)
    }

    $old = @($priv | Where-Object {
        $_.Enabled -and $null -ne $_.PasswordLastSet -and (Get-ADHAge $_.PasswordLastSet) -gt $threshold
    } | Sort-Object DistinguishedName -Unique)

    $objects = foreach ($o in $old) {
        New-ADHObject -Name $o.SamAccountName -DistinguishedName $o.DistinguishedName `
            -Details ('password age: {0} days' -f (Get-ADHAge $o.PasswordLastSet))
    }

    $sev = if (@($old).Count -gt 0) { 'High' } else { 'Pass' }

    New-ADHFinding -Id 'PWD-004' -Category 'Passwords' -Severity $sev `
        -Title ('Privileged accounts with passwords older than {0} days' -f $threshold) `
        -Summary 'Long-unchanged privileged passwords usually indicate hard-coded service credentials or forgotten break-glass accounts.' `
        -Remediation 'Rotate the passwords and use the occasion to establish what each account is still doing. Break-glass accounts should be rotated on a schedule and their use alerted on.' `
        -Objects $objects
}

function Test-ADHDomainPasswordPolicy {
    $p = Get-ADHParameter
    $pol = Get-ADDefaultDomainPasswordPolicy @p

    $issues = @()
    if ($pol.MinPasswordLength -lt 14)    { $issues += ('minimum length is {0}, 14 or more recommended' -f $pol.MinPasswordLength) }
    if (-not $pol.ComplexityEnabled)      { $issues += 'complexity requirements disabled' }
    if ($pol.LockoutThreshold -eq 0)      { $issues += 'no account lockout configured' }
    elseif ($pol.LockoutThreshold -gt 10) { $issues += ('lockout threshold is {0}, 10 or fewer recommended' -f $pol.LockoutThreshold) }
    if ($pol.ReversibleEncryptionEnabled) { $issues += 'reversible encryption enabled domain-wide' }
    if ($pol.PasswordHistoryCount -lt 24) { $issues += ('password history is {0}, 24 recommended' -f $pol.PasswordHistoryCount) }

    $objects = @(New-ADHObject -Name 'Default domain policy' -Details (
        'min length: {0} | complexity: {1} | history: {2} | lockout threshold: {3} | max age: {4}' -f `
            $pol.MinPasswordLength, $pol.ComplexityEnabled, $pol.PasswordHistoryCount,
            $pol.LockoutThreshold, $pol.MaxPasswordAge))

    foreach ($i in $issues) { $objects += New-ADHObject -Name 'Deviation' -Details $i }

    $sev = if ($issues.Count -ge 3) { 'High' } elseif ($issues.Count -gt 0) { 'Medium' } else { 'Pass' }

    New-ADHFinding -Id 'PWD-005' -Category 'Passwords' -Severity $sev `
        -Title 'Default domain password policy' `
        -Summary ('{0} deviation(s) from common guidance.' -f $issues.Count) `
        -Remediation 'Favour length over forced rotation. Layer fine-grained password policies on top for privileged accounts and service accounts, and screen new passwords against a breached-password list.' `
        -Objects $objects
}

#############################################################################
# REGION: Checks - Account hygiene
#############################################################################

function Test-ADHStaleUsers {
    $p = Get-ADHParameter
    $cutoff = (Get-Date).AddDays(-$StaleDays)

    $accounts = @(Get-ADUser @p -LDAPFilter "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:$script:BitAnd`:=$($script:Uac.AccountDisabled))))" `
                    -Properties LastLogonDate, whenCreated |
                  Where-Object {
                      ($null -eq $_.LastLogonDate -and $_.whenCreated -lt $cutoff) -or
                      ($null -ne $_.LastLogonDate -and $_.LastLogonDate -lt $cutoff)
                  })

    $objects = foreach ($a in $accounts) {
        New-ADHObject -Name $a.SamAccountName -DistinguishedName $a.DistinguishedName -Details (
            'last logon: {0} | created: {1}' -f `
                $(if ($a.LastLogonDate) { $a.LastLogonDate.ToString('yyyy-MM-dd') } else { 'never' }),
                $a.whenCreated.ToString('yyyy-MM-dd'))
    }

    $sev = if (@($accounts).Count -gt 50) { 'Medium' } elseif (@($accounts).Count -gt 0) { 'Low' } else { 'Pass' }

    New-ADHFinding -Id 'ACC-001' -Category 'Account hygiene' -Severity $sev `
        -Title ('Enabled user accounts with no logon for {0} days' -f $StaleDays) `
        -Summary 'Dormant enabled accounts widen the attack surface while nobody would notice unusual activity on them. Note that lastLogonTimestamp only replicates every 9 to 14 days, so these dates are approximate.' `
        -Remediation 'Automate the lifecycle: disable after the threshold, move to a quarantine OU, delete after a further 90 days. Tie it to the HR leaver process so it does not depend on someone remembering.' `
        -Objects $objects
}

function Test-ADHStaleComputers {
    $p = Get-ADHParameter
    $cutoff = (Get-Date).AddDays(-$StaleDays)

    $computers = @(Get-ADComputer @p -LDAPFilter "(!(userAccountControl:$script:BitAnd`:=$($script:Uac.AccountDisabled)))" `
                     -Properties LastLogonDate, operatingSystem, whenCreated |
                   Where-Object {
                       ($null -eq $_.LastLogonDate -and $_.whenCreated -lt $cutoff) -or
                       ($null -ne $_.LastLogonDate -and $_.LastLogonDate -lt $cutoff)
                   })

    $objects = foreach ($c in $computers) {
        New-ADHObject -Name $c.Name -DistinguishedName $c.DistinguishedName -Details (
            'OS: {0} | last logon: {1}' -f `
                (Get-ADHProp $c 'operatingSystem' 'unknown'),
                $(if ($c.LastLogonDate) { $c.LastLogonDate.ToString('yyyy-MM-dd') } else { 'never' }))
    }

    $sev = if (@($computers).Count -gt 50) { 'Medium' } elseif (@($computers).Count -gt 0) { 'Low' } else { 'Pass' }

    New-ADHFinding -Id 'ACC-002' -Category 'Account hygiene' -Severity $sev `
        -Title ('Enabled computer accounts with no logon for {0} days' -f $StaleDays) `
        -Summary 'Dormant computer accounts keep their password and are convenient for persistence, since nobody is watching a machine that no longer exists.' `
        -Remediation 'Disable and move to a quarantine OU automatically. Take care with cluster name objects and machines that are only powered on seasonally.' `
        -Objects $objects
}

function Test-ADHSidHistory {
    $p = Get-ADHParameter
    $objs = @(Get-ADObject @p -LDAPFilter '(sIDHistory=*)' -Properties sAMAccountName, sIDHistory, objectClass)

    $objects = foreach ($o in $objs) {
        New-ADHObject -Name (Get-ADHProp $o 'sAMAccountName' $o.Name) `
            -DistinguishedName $o.DistinguishedName `
            -Details ('class: {0} | SID history entries: {1}' -f $o.objectClass, @($o.sIDHistory).Count)
    }

    $sev = if (@($objs).Count -gt 0) { 'Medium' } else { 'Pass' }

    New-ADHFinding -Id 'ACC-003' -Category 'Account hygiene' -Severity $sev `
        -Title 'Objects carrying SID history' `
        -Summary 'SID history normally comes from a migration. Once the migration is finished it becomes a hidden channel for access and a well-known persistence technique.' `
        -Remediation 'Clean up after the migration completes. Prioritise any entry pointing at a privileged SID - that is a takeover in a single attribute.' `
        -Objects $objects
}

function Test-ADHCredentialsInAttributes {
    $p = Get-ADHParameter

    # Deliberately broad, multilingual and case-insensitive. False positives are
    # cheap to dismiss; a missed clear-text password is not.
    $patterns = @(
        'passwor[dt]', 'kennwort', 'passwd', '\bpwd\b', '\bpw\b', '\bpass\b',
        'mot de passe', 'contrase', 'wachtwoord', 'credential', 'zugangsdaten',
        'login.{0,12}[:=]', 'initialpassw', 'standardkennwort'
    )
    $regex = [regex]::new(($patterns -join '|'), 'IgnoreCase')

    $fields = @('description', 'info', 'comment')

    $accounts = @(Get-ADObject @p `
        -LDAPFilter '(&(|(objectCategory=person)(objectCategory=computer)(objectCategory=group))(|(description=*)(info=*)(comment=*)))' `
        -Properties sAMAccountName, description, info, comment, objectClass)

    $objects = @()

    foreach ($a in $accounts) {
        $hits = @()
        foreach ($f in $fields) {
            $value = Get-ADHProp $a $f
            if (-not $value) { continue }
            # description is multi-valued in the schema.
            foreach ($v in @($value)) {
                if ([string]::IsNullOrWhiteSpace($v)) { continue }
                $m = $regex.Match([string]$v)
                if ($m.Success) {
                    # The matched keyword is reported, never the field contents -
                    # this report must not become the thing it warns about.
                    $hits += ('{0} (keyword "{1}", {2} chars)' -f $f, $m.Value, ([string]$v).Length)
                }
            }
        }
        if (-not $hits.Count) { continue }

        $objects += New-ADHObject -Name (Get-ADHProp $a 'sAMAccountName' $a.Name) `
            -DistinguishedName $a.DistinguishedName `
            -Details ('class: {0} | {1}' -f $a.objectClass, ($hits -join '; '))
    }

    $sev = if ($objects.Count -gt 5) { 'High' } elseif ($objects.Count -gt 0) { 'Medium' } else { 'Pass' }

    New-ADHFinding -Id 'ACC-004' -Category 'Account hygiene' -Severity $sev `
        -Title 'Possible credentials in description, info or comment attributes' `
        -Summary ('{0} objects have text in a freely readable attribute that mentions passwords or credentials. Every authenticated user in the domain can read these fields, and enumerating them takes one LDAP query. Expect false positives - the point is that each one needs a human to look.' -f $objects.Count) `
        -Remediation 'Review each hit and remove any credential from the attribute. Note that clearing it does not undo the exposure: treat every password found this way as compromised and rotate it. For the recurring cases (handover notes, service documentation) provide a password manager rather than a field in the directory. This check reports only the matched keyword, never the field contents.' `
        -Objects $objects
}

#############################################################################
# REGION: Checks - Infrastructure
#############################################################################

function Test-ADHMachineAccountQuota {
    $p = Get-ADHParameter
    $domain = Get-ADHDomain
    $maq = (Get-ADObject @p -Identity $domain.DistinguishedName -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'

    $sev = if ($maq -gt 0) { 'Medium' } else { 'Pass' }

    New-ADHFinding -Id 'INF-001' -Category 'Infrastructure' -Severity $sev `
        -Title 'MachineAccountQuota' `
        -Summary ('Current value: {0}. Any value above zero lets every domain user create computer accounts, which is a prerequisite for several privilege escalation paths.' -f $maq) `
        -Remediation 'Set ms-DS-MachineAccountQuota to 0 and delegate the "create computer objects" right to the client management team on the relevant OUs instead.' `
        -Objects @(New-ADHObject -Name 'ms-DS-MachineAccountQuota' -DistinguishedName $domain.DistinguishedName -Details ('value: {0}' -f $maq))
}

function Test-ADHDomainControllers {
    $p = Get-ADHParameter
    $dcs = @(Get-ADDomainController @p -Filter *)
    $domain = Get-ADHDomain
    $forest = Get-ADForest @p

    $objects = foreach ($dc in $dcs) {
        New-ADHObject -Name $dc.HostName -Details (
            'OS: {0} {1} | global catalog: {2} | site: {3}' -f `
                $dc.OperatingSystem, $dc.OperatingSystemVersion, $dc.IsGlobalCatalog, $dc.Site)
    }

    $objects = @($objects)
    $objects += New-ADHObject -Name 'Functional levels' `
        -Details ('domain: {0} | forest: {1}' -f $domain.DomainMode, $forest.ForestMode)

    $legacy = @($dcs | Where-Object { $_.OperatingSystem -match '2003|2008|2012' })
    $sev = if ($legacy.Count -gt 0) { 'High' }
           elseif ("$($domain.DomainMode)" -match '2003|2008|2012') { 'Medium' }
           else { 'Info' }

    New-ADHFinding -Id 'INF-002' -Category 'Infrastructure' -Severity $sev `
        -Title 'Domain controllers and functional levels' `
        -Summary ('{0} domain controllers, {1} of them on an unsupported operating system.' -f $dcs.Count, $legacy.Count) `
        -Remediation 'Replace legacy controllers, then raise the functional level. Protections such as Protected Users and authentication policy silos only become available once the level is high enough.' `
        -Objects $objects
}

function Test-ADHLegacyOperatingSystems {
    $p = Get-ADHParameter
    $filter = '(&(objectCategory=computer)(|(operatingSystem=*2003*)(operatingSystem=*2008*)(operatingSystem=*2012*)(operatingSystem=*Windows XP*)(operatingSystem=*Windows 7*)(operatingSystem=*Windows 8*)))'

    $computers = @(Get-ADComputer @p -LDAPFilter $filter -Properties operatingSystem, LastLogonDate, Enabled |
                   Where-Object { $_.Enabled })

    $objects = foreach ($c in $computers) {
        New-ADHObject -Name $c.Name -DistinguishedName $c.DistinguishedName -Details (
            'OS: {0} | last logon: {1}' -f `
                $c.operatingSystem,
                $(if ($c.LastLogonDate) { $c.LastLogonDate.ToString('yyyy-MM-dd') } else { 'never' }))
    }

    $sev = if (@($computers).Count -gt 0) { 'High' } else { 'Pass' }

    New-ADHFinding -Id 'INF-003' -Category 'Infrastructure' -Severity $sev `
        -Title 'Enabled computer accounts running end-of-life operating systems' `
        -Summary 'These systems receive no security updates. They also tend to force weak protocols to stay enabled across the whole domain because nothing else can talk to them.' `
        -Remediation 'Replace them, or move them into an isolated network segment with no domain membership. Track which legacy protocol each one actually requires before decommissioning, so the protocol can be turned off afterwards.' `
        -Objects $objects
}

function Test-ADHLapsCoverage {
    $p = Get-ADHParameter

    $legacyAttr  = 'ms-Mcs-AdmPwdExpirationTime'
    $windowsAttr = 'msLAPS-PasswordExpirationTime'
    $hasLegacy   = Test-ADHSchemaAttribute -LdapDisplayName $legacyAttr
    $hasWindows  = Test-ADHSchemaAttribute -LdapDisplayName $windowsAttr

    if (-not $hasLegacy -and -not $hasWindows) {
        return New-ADHFinding -Id 'INF-004' -Category 'Infrastructure' -Severity 'High' `
            -Title 'LAPS not present in the schema' `
            -Summary 'Neither Windows LAPS nor legacy LAPS has extended the schema. Local administrator passwords are almost certainly identical across machines, which is the foundation of lateral movement.' `
            -Remediation 'Enable Windows LAPS - it ships in the operating system from Windows 11 and Server 2019 onwards - and roll it out by group policy. Restrict and audit read access to the password attribute from day one.' `
            -Objects @()
    }

    $attr   = if ($hasWindows) { $windowsAttr } else { $legacyAttr }
    $all      = @(Get-ADComputer @p -LDAPFilter '(&(objectCategory=computer)(!(primaryGroupID=516))(!(primaryGroupID=521)))' -Properties Enabled | Where-Object { $_.Enabled })
    $withLaps = @(Get-ADComputer @p -LDAPFilter "($attr=*)" -Properties $attr, Enabled | Where-Object { $_.Enabled })
    $lapsDns  = @($withLaps | Select-Object -ExpandProperty DistinguishedName)

    $missing = @($all | Where-Object { $lapsDns -notcontains $_.DistinguishedName })
    $pct = if ($all.Count -gt 0) { [math]::Round(($withLaps.Count / $all.Count) * 100, 1) } else { 0 }

    $objects = foreach ($m in ($missing | Select-Object -First 500)) {
        New-ADHObject -Name $m.Name -DistinguishedName $m.DistinguishedName -Details 'no managed local administrator password'
    }

    $sev = if ($pct -lt 50) { 'High' } elseif ($pct -lt 90) { 'Medium' } else { 'Pass' }

    New-ADHFinding -Id 'INF-004' -Category 'Infrastructure' -Severity $sev `
        -Title 'LAPS coverage' `
        -Summary ('{0} of {1} enabled computers have a managed local administrator password ({2} percent). Attribute in use: {3}.' -f $withLaps.Count, $all.Count, $pct, $attr) `
        -Remediation 'Extend the group policy scope to every client and server OU. Keep read access to the password attribute narrow and audited - a broad read right on this attribute is equivalent to local administrator on every machine.' `
        -Objects $objects
}

#############################################################################
# REGION: Checks - Trusts
#############################################################################

function Test-ADHTrustConfiguration {
    $p = Get-ADHParameter

    $trusts = @()
    try   { $trusts = @(Get-ADTrust @p -Filter * -Properties *) }
    catch { Write-Verbose ('Trusts could not be enumerated: {0}' -f $_.Exception.Message) }

    if (-not $trusts.Count) {
        return New-ADHFinding -Id 'TRUST-001' -Category 'Trusts' -Severity 'Pass' `
            -Title 'Trust relationships' `
            -Summary 'No trust relationships are defined for this domain.' `
            -Remediation 'Nothing to do.'
    }

    $objects = @()
    $critical = 0

    foreach ($t in $trusts) {
        $issues = @()

        $intraForest  = [bool](Get-ADHProp $t 'IntraForest' $false)
        $direction    = Get-ADHProp $t 'Direction' 'unknown'
        $inbound      = ("$direction" -match 'Inbound|BiDirectional')
        $quarantined  = [bool](Get-ADHProp $t 'SIDFilteringQuarantined' $false)
        $forestAware  = [bool](Get-ADHProp $t 'SIDFilteringForestAware' $false)
        $selectiveAuth = [bool](Get-ADHProp $t 'SelectiveAuthentication' $false)
        $tgtDelegation = [bool](Get-ADHProp $t 'TGTDelegation' $false)

        # SID filtering only matters where foreign SIDs can arrive, i.e. on
        # inbound or bidirectional trusts that leave the forest.
        if (-not $intraForest -and $inbound) {
            $forestTrust = ("$(Get-ADHProp $t 'TrustType' '')" -match 'Forest') -or
                           ("$(Get-ADHProp $t 'ForestTransitive' '')" -eq 'True')

            if ($forestTrust) {
                if ($forestAware) {
                    $issues += 'SID history allowed across the forest trust (SID filtering relaxed)'
                    $critical++
                }
            }
            elseif (-not $quarantined) {
                $issues += 'external trust without SID filtering quarantine'
                $critical++
            }

            if (-not $selectiveAuth) {
                $issues += 'no selective authentication - every principal from the trusted domain can authenticate everywhere'
            }
        }

        if ($tgtDelegation) {
            $issues += 'TGT delegation enabled - unconstrained delegation reaches across this trust'
            $critical++
        }

        $detail = 'direction: {0} | type: {1} | intra-forest: {2}' -f `
            $direction, (Get-ADHProp $t 'TrustType' 'unknown'), $(if ($intraForest) { 'yes' } else { 'no' })

        if ($issues.Count) { $detail += ' | ISSUES: ' + ($issues -join '; ') }
        else               { $detail += ' | no issues found' }

        $objects += New-ADHObject -Name (Get-ADHProp $t 'Name' $t.DistinguishedName) `
            -DistinguishedName $t.DistinguishedName -Details $detail
    }

    $withIssues = @($objects | Where-Object { $_.Details -match 'ISSUES' }).Count
    $sev = if ($critical -gt 0) { 'Critical' } elseif ($withIssues -gt 0) { 'Medium' } else { 'Pass' }

    New-ADHFinding -Id 'TRUST-001' -Category 'Trusts' -Severity $sev `
        -Title 'Trust relationship configuration' `
        -Summary ('{0} trust(s), {1} with findings. A trust without SID filtering lets the trusted side inject arbitrary SIDs - including those of your Domain Admins - which defeats the tier-0 separation inside this domain entirely.' -f $trusts.Count, $withIssues) `
        -Remediation 'Enable SID filtering quarantine on external trusts (netdom trust /quarantine:yes) and keep SID history disabled on forest trusts (netdom trust /enablesidhistory:no). Disable TGT delegation (netdom trust /EnableTGTDelegation:No). Enable selective authentication where the trusted domain is not administered to your own standard, and treat any trust to a domain you do not control as an extension of your own attack surface.' `
        -Objects $objects
}

#############################################################################
# REGION: Checks - Group policy
#############################################################################

function Test-ADHSysvolCpassword {
    <#
        Group Policy Preferences could store credentials in SYSVOL, encrypted
        with a key Microsoft published in the protocol documentation - so the
        value is readable by every domain user. MS14-025 removed the ability to
        create new ones, but existing files survive migrations and upgrades.

        This check reports the presence and location of the attribute only. It
        does not decrypt anything; the finding is that the file exists at all.
    #>
    $domain = Get-ADHDomain
    $root = '\\{0}\SYSVOL\{0}\Policies' -f $domain.DNSRoot

    if (-not (Test-Path -LiteralPath $root -ErrorAction SilentlyContinue)) {
        return New-ADHFinding -Id 'GPO-001' -Category 'Group policy' -Severity 'Info' `
            -Title 'Group policy preferences with stored credentials' `
            -Summary ('SYSVOL could not be reached at {0}. The check needs SMB access to a domain controller.' -f $root) `
            -Remediation 'Re-run from a system that can reach SYSVOL, or inspect the Policies folder manually for XML files containing a cpassword attribute.'
    }

    # The preference extensions that ever supported stored credentials.
    $names = @('Groups.xml','Services.xml','ScheduledTasks.xml','DataSources.xml','Printers.xml','Drives.xml')
    $objects = @()

    try {
        $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Include $names -ErrorAction SilentlyContinue)
    }
    catch {
        $files = @()
        Write-Verbose ('SYSVOL enumeration failed: {0}' -f $_.Exception.Message)
    }

    foreach ($f in $files) {
        try {
            $content = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
        }
        catch { continue }

        if ($content -notmatch 'cpassword\s*=\s*"[^"]+"') { continue }

        # Report where it is and who it applies to - never the value.
        $userName = ''
        $m = [regex]::Match($content, '(?:runAs|userName|accountName|newName)\s*=\s*"([^"]*)"')
        if ($m.Success) { $userName = $m.Groups[1].Value }

        $gpoId = ''
        $g = [regex]::Match($f.FullName, '\{[0-9A-Fa-f-]{36}\}')
        if ($g.Success) { $gpoId = $g.Value }

        $objects += New-ADHObject -Name $f.Name -DistinguishedName $f.FullName -Details (
            'GPO: {0} | account: {1} | last written: {2}' -f `
                $(if ($gpoId) { $gpoId } else { 'unknown' }),
                $(if ($userName) { $userName } else { 'not stated' }),
                $f.LastWriteTime.ToString('yyyy-MM-dd'))
    }

    $objects = @($objects)
    $sev = if ($objects.Count -gt 0) { 'Critical' } else { 'Pass' }

    New-ADHFinding -Id 'GPO-001' -Category 'Group policy' -Severity $sev `
        -Title 'Group policy preferences with stored credentials (cpassword)' `
        -Summary ('{0} policy file(s) in SYSVOL contain a cpassword attribute. The encryption key for this attribute is public, and SYSVOL is readable by every authenticated user, so these passwords should be considered known to anyone with a domain account.' -f $objects.Count) `
        -Remediation 'Treat every account named in these files as compromised and rotate its password first - deleting the file does not undo the exposure. Then remove the preference item from the GPO (editing the GPO rewrites the XML; deleting the file directly leaves the policy broken). Use LAPS for local administrator passwords instead. This check reports file paths only and never decrypts the value.' `
        -Objects $objects
}

#############################################################################
# REGION: Checks - Directory permissions
#############################################################################

function Test-ADHDcSyncRights {
    $domain = Get-ADHDomain
    $sd = Get-ADHSecurityDescriptor -DistinguishedName $domain.DistinguishedName

    if (-not $sd) {
        return New-ADHFinding -Id 'ACL-001' -Category 'Permissions' -Severity 'Info' `
            -Title 'Replication rights on the domain root' `
            -Summary 'The security descriptor of the domain root could not be read.' `
            -Remediation 'Check the permissions of the account running the scan.'
    }

    $trusted = Get-ADHTrustedSid
    $replRights = @(
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
        '89e95b76-444d-4c62-991a-0facbeda640c'
    )

    # Collect per principal - only the combination of Get-Changes and
    # Get-Changes-All yields a full directory dump.
    $byPrincipal = @{}

    foreach ($ace in $sd.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if ($ace.ActiveDirectoryRights.ToString() -notmatch 'ExtendedRight|GenericAll') { continue }

        $sid = Resolve-ADHIdentity $ace.IdentityReference
        if ($sid -and ($trusted -contains $sid)) { continue }
        if ($sid -and ($sid -match '-(512|516|518|519|498|521)$')) { continue }

        $ot = $ace.ObjectType.ToString().ToLower()
        $granted = @()
        if ($ace.ActiveDirectoryRights.ToString() -match 'GenericAll' -or
            $ot -eq '00000000-0000-0000-0000-000000000000') {
            $granted = $replRights
        }
        elseif ($replRights -contains $ot) {
            $granted = @($ot)
        }
        if (-not $granted.Count) { continue }

        $key = $ace.IdentityReference.Value
        if (-not $byPrincipal.ContainsKey($key)) { $byPrincipal[$key] = @{ Sid = $sid; Rights = @() } }
        $byPrincipal[$key].Rights = @($byPrincipal[$key].Rights + $granted | Select-Object -Unique)
    }

    $objects = foreach ($k in $byPrincipal.Keys) {
        $r = $byPrincipal[$k].Rights
        $full = ($r -contains '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2') -and
                ($r -contains '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
        New-ADHObject -Name $k -DistinguishedName $byPrincipal[$k].Sid -Details (
            '{0} | rights: {1}' -f `
                $(if ($full) { 'FULL REPLICATION POSSIBLE' } else { 'partial rights' }),
                (($r | ForEach-Object { Get-ADHGuidLabel $_ }) -join ', '))
    }

    $objects = @($objects)
    $hasFull = @($objects | Where-Object { $_.Details -match 'FULL REPLICATION' }).Count -gt 0
    $sev = if ($hasFull) { 'Critical' } elseif ($objects.Count -gt 0) { 'High' } else { 'Pass' }

    New-ADHFinding -Id 'ACL-001' -Category 'Permissions' -Severity $sev `
        -Title 'Directory replication rights on the domain root (DCSync)' `
        -Summary 'Holding both replication rights allows pulling the password hashes of every account, krbtgt included, without ever logging on to a domain controller. Only domain controllers and directory synchronisation services need this.' `
        -Remediation 'Match every entry to a documented purpose. Entra Connect and MIM service accounts are the usual legitimate holders - and that makes them tier-0 accounts, to be protected accordingly. Remove everything else.' `
        -Objects $objects
}

function Test-ADHPrivilegedGroupAcl {
    $objects = @()

    foreach ($entry in Get-ADHPrivilegedGroup) {
        $sd = Get-ADHProp $entry.Group 'nTSecurityDescriptor'
        if (-not $sd) { continue }
        $dn = $entry.Group.DistinguishedName

        foreach ($ace in (Get-ADHDangerousAce -SecurityDescriptor $sd)) {
            $objects += New-ADHObject -Name $entry.Label -DistinguishedName $dn -Details (Format-ADHAce $ace)
        }
    }

    $objects = @($objects)
    $sev = if ($objects.Count -gt 0) { 'Critical' } else { 'Pass' }

    New-ADHFinding -Id 'ACL-002' -Category 'Permissions' -Severity $sev `
        -Title 'Dangerous permissions on tier-0 groups' `
        -Summary 'These principals can change the membership of privileged groups, or grant themselves the rights to do so. That is equivalent to being a member - without appearing in the membership list.' `
        -Remediation 'Remove the permission. Where a delegation is genuinely required, express it as a narrow write right on the member attribute granted to a dedicated role group, rather than full control.' `
        -Objects $objects
}

function Test-ADHPrivilegedUserAcl {
    $objects = @()

    foreach ($a in (Get-ADHPrivilegedUser)) {
        $sd = Get-ADHProp $a 'nTSecurityDescriptor'
        if (-not $sd) { continue }

        foreach ($ace in (Get-ADHDangerousAce -SecurityDescriptor $sd)) {
            $objects += New-ADHObject -Name $a.SamAccountName -DistinguishedName $a.DistinguishedName -Details (Format-ADHAce $ace)
        }
    }

    $objects = @($objects)
    $sev = if ($objects.Count -gt 0) { 'Critical' } else { 'Pass' }

    New-ADHFinding -Id 'ACL-003' -Category 'Permissions' -Severity $sev `
        -Title 'Dangerous permissions on privileged accounts' `
        -Summary 'Resetting the password, writing msDS-KeyCredentialLink or holding full control over an admin account each amount to complete takeover of that account.' `
        -Remediation 'Remove the permissions. Because these objects are governed by AdminSDHolder, the fix belongs in the AdminSDHolder ACL (see ACL-004) - changes made directly on the object are reverted within 60 minutes.' `
        -Objects $objects
}

function Test-ADHAdminSdHolderAcl {
    $domain = Get-ADHDomain
    $dn = 'CN=AdminSDHolder,CN=System,{0}' -f $domain.DistinguishedName
    $sd = Get-ADHSecurityDescriptor -DistinguishedName $dn

    if (-not $sd) {
        return New-ADHFinding -Id 'ACL-004' -Category 'Permissions' -Severity 'Info' `
            -Title 'Permissions on AdminSDHolder' -Summary 'Object could not be read.' `
            -Remediation 'Check the permissions of the account running the scan.'
    }

    $objects = @(foreach ($ace in (Get-ADHDangerousAce -SecurityDescriptor $sd)) {
        New-ADHObject -Name 'AdminSDHolder' -DistinguishedName $dn -Details (Format-ADHAce $ace)
    })

    $sev = if ($objects.Count -gt 0) { 'Critical' } else { 'Pass' }

    New-ADHFinding -Id 'ACL-004' -Category 'Permissions' -Severity $sev `
        -Title 'Dangerous permissions on AdminSDHolder' `
        -Summary 'The AdminSDHolder ACL is stamped onto every privileged user and group in the domain once an hour. An entry here is an entry on every admin object simultaneously, and a remarkably durable persistence mechanism.' `
        -Remediation 'Remove ACEs that are not required, then monitor the object. Any modification to AdminSDHolder should raise an alert (directory service change, event 5136).' `
        -Objects $objects
}

function Test-ADHOrganizationalUnitAcl {
    $p = Get-ADHParameter
    $objects = @()

    $ous = @(Get-ADOrganizationalUnit @p -Filter * -Properties nTSecurityDescriptor)

    foreach ($ou in $ous) {
        $sd = Get-ADHProp $ou 'nTSecurityDescriptor'
        if (-not $sd) { continue }

        foreach ($ace in (Get-ADHDangerousAce -SecurityDescriptor $sd)) {
            $objects += New-ADHObject -Name $ou.Name -DistinguishedName $ou.DistinguishedName -Details (Format-ADHAce $ace)
        }
    }

    $objects = @($objects)
    $sev = if ($objects.Count -gt 20) { 'High' } elseif ($objects.Count -gt 0) { 'Medium' } else { 'Pass' }

    New-ADHFinding -Id 'ACL-005' -Category 'Permissions' -Severity $sev `
        -Title 'Broad delegations on organizational units' `
        -Summary ('{0} delegations granting full control or unscoped write access across {1} OUs. By default these rights inherit down to every user and computer object inside.' -f $objects.Count, $ous.Count) `
        -Remediation 'Scope delegations to the specific object type and attributes the task needs. The delegation wizard regularly grants more than intended. Prioritise OUs holding servers or privileged accounts.' `
        -Objects $objects
}

function Test-ADHObjectOwnership {
    $trusted = Get-ADHTrustedSid
    $objects = @()

    $targets = @()
    foreach ($entry in Get-ADHPrivilegedGroup) {
        $targets += [PSCustomObject]@{ Name = $entry.Label; Dn = $entry.Group.DistinguishedName
                                       Sd = (Get-ADHProp $entry.Group 'nTSecurityDescriptor') }
    }
    foreach ($u in (Get-ADHPrivilegedUser)) {
        $targets += [PSCustomObject]@{ Name = $u.SamAccountName; Dn = $u.DistinguishedName
                                       Sd = (Get-ADHProp $u 'nTSecurityDescriptor') }
    }
    foreach ($dc in (Get-ADHDomainControllerObject)) {
        $targets += [PSCustomObject]@{ Name = $dc.Name; Dn = $dc.DistinguishedName
                                       Sd = (Get-ADHProp $dc 'nTSecurityDescriptor') }
    }

    foreach ($t in $targets) {
        $sd = $t.Sd
        if (-not $sd) { continue }

        $ownerSid = $null
        try   { $ownerSid = $sd.GetOwner([System.Security.Principal.SecurityIdentifier]).Value }
        catch { continue }

        if ($trusted -contains $ownerSid) { continue }
        if ($ownerSid -match '-(512|516|518|519)$') { continue }

        # Fall back to the raw SID when the account cannot be resolved - a
        # deleted or foreign principal as owner is itself worth reporting.
        $ownerName = $ownerSid
        try {
            $ownerName = (New-Object System.Security.Principal.SecurityIdentifier($ownerSid)).Translate([System.Security.Principal.NTAccount]).Value
        }
        catch { Write-Verbose ('Owner SID {0} could not be translated.' -f $ownerSid) }

        $objects += New-ADHObject -Name $t.Name -DistinguishedName $t.Dn -Details ('owner: {0}' -f $ownerName)
    }

    $objects = @($objects)
    $sev = if ($objects.Count -gt 0) { 'High' } else { 'Pass' }

    New-ADHFinding -Id 'ACL-006' -Category 'Permissions' -Severity $sev `
        -Title 'Privileged objects owned by non-privileged principals' `
        -Summary 'An object owner can rewrite that object permissions at will, regardless of what the current ACL says. A non-privileged owner therefore nullifies every protection applied to the object.' `
        -Remediation 'Reset ownership to Domain Admins or Administrators. The common cause is an object created by a helpdesk account, which then holds ownership by default.' `
        -Objects $objects
}

function Test-ADHDomainControllerAcl {
    $objects = @()

    foreach ($dc in (Get-ADHDomainControllerObject)) {
        $sd = Get-ADHProp $dc 'nTSecurityDescriptor'
        if (-not $sd) { continue }

        foreach ($ace in (Get-ADHDangerousAce -SecurityDescriptor $sd)) {
            $objects += New-ADHObject -Name $dc.Name -DistinguishedName $dc.DistinguishedName -Details (Format-ADHAce $ace)
        }
    }

    $objects = @($objects)
    $sev = if ($objects.Count -gt 0) { 'Critical' } else { 'Pass' }

    New-ADHFinding -Id 'ACL-007' -Category 'Permissions' -Severity $sev `
        -Title 'Dangerous permissions on domain controller objects' `
        -Summary 'Write access to a domain controller computer object - particularly to msDS-AllowedToActOnBehalfOfOtherIdentity or msDS-KeyCredentialLink - leads directly to compromise of that controller.' `
        -Remediation 'Remove every entry beyond the defaults. There is essentially no legitimate reason to delegate write access on a domain controller object.' `
        -Objects $objects
}

function Test-ADHGpoAcl {
    $p = Get-ADHParameter
    $domain = Get-ADHDomain
    $objects = @()

    # Which GPOs are linked to the domain root or the DC OU? Those affect tier 0.
    $tier0Links = @()
    foreach ($dn in @($domain.DistinguishedName, ('OU=Domain Controllers,{0}' -f $domain.DistinguishedName))) {
        try {
            $o = Get-ADObject @p -Identity $dn -Properties gPLink -ErrorAction Stop
            $link = Get-ADHProp $o 'gPLink'
            if ($link) {
                $tier0Links += ([regex]::Matches($link, '\{[0-9A-Fa-f-]{36}\}') | ForEach-Object { $_.Value.ToUpper() })
            }
        }
        catch {
            # Without this the tier-0 marking is simply absent, so the finding
            # stays valid but loses a priority hint. Worth seeing with -Verbose.
            Write-Verbose ('gPLink on {0} could not be read: {1}' -f $dn, $_.Exception.Message)
        }
    }
    $tier0Links = @($tier0Links | Select-Object -Unique)

    $gpos = @(Get-ADObject @p -LDAPFilter '(objectClass=groupPolicyContainer)' -Properties displayName, nTSecurityDescriptor, Name)

    foreach ($g in $gpos) {
        $sd = Get-ADHProp $g 'nTSecurityDescriptor'
        if (-not $sd) { continue }

        $isTier0 = $tier0Links -contains $g.Name.ToUpper()
        $label = Get-ADHProp $g 'displayName' $g.Name

        foreach ($ace in (Get-ADHDangerousAce -SecurityDescriptor $sd)) {
            $objects += New-ADHObject -Name $label -DistinguishedName $g.DistinguishedName -Details (
                '{0}{1}' -f $(if ($isTier0) { '[LINKED TO TIER 0] ' } else { '' }), (Format-ADHAce $ace))
        }
    }

    $objects = @($objects)
    $tier0Count = @($objects | Where-Object { $_.Details -match 'TIER 0' }).Count
    $sev = if ($tier0Count -gt 0) { 'Critical' } elseif ($objects.Count -gt 0) { 'High' } else { 'Pass' }

    New-ADHFinding -Id 'ACL-008' -Category 'Permissions' -Severity $sev `
        -Title 'Write access on group policy objects' `
        -Summary ('Anyone who can edit a GPO executes code on every system it applies to. {0} of these findings affect GPOs linked to the domain root or the Domain Controllers OU.' -f $tier0Count) `
        -Remediation 'Limit edit rights to a dedicated GPO management team, and let only tier-0 accounts manage GPOs with tier-0 scope. Alert on GPO modification (event 5136 in the directory, 5145 on SYSVOL).' `
        -Objects $objects
}

function Test-ADHGroupMembershipDelegation {
    $p = Get-ADHParameter
    $trusted = Get-ADHTrustedSid
    $objects = @()

    $memberAttr = 'bf9679c0-0de6-11d0-a285-00aa003049e2'
    $groups = @(Get-ADGroup @p -Filter * -Properties nTSecurityDescriptor, GroupScope)

    foreach ($g in $groups) {
        $sd = Get-ADHProp $g 'nTSecurityDescriptor'
        if (-not $sd) { continue }

        foreach ($ace in $sd.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            if ($ace.IsInherited) { continue }

            $r  = $ace.ActiveDirectoryRights.ToString()
            $ot = $ace.ObjectType.ToString().ToLower()
            if ($r -notmatch 'WriteProperty|Self|GenericWrite|GenericAll') { continue }
            if ($ot -ne $memberAttr -and $ot -ne '00000000-0000-0000-0000-000000000000') { continue }

            $sid = Resolve-ADHIdentity $ace.IdentityReference
            if ($sid -and ($trusted -contains $sid)) { continue }
            if ($sid -and ($sid -match '-(512|516|518|519)$')) { continue }

            $objects += New-ADHObject -Name $g.Name -DistinguishedName $g.DistinguishedName -Details (
                '{0} can change membership [{1}] | scope: {2}' -f $ace.IdentityReference.Value, $r, $g.GroupScope)
        }
    }

    $objects = @($objects)
    $sev = if ($objects.Count -gt 30) { 'Medium' } elseif ($objects.Count -gt 0) { 'Low' } else { 'Pass' }

    New-ADHFinding -Id 'ACL-009' -Category 'Permissions' -Severity $sev `
        -Title 'Delegated write access on group membership' `
        -Summary ('{0} delegations across all groups in the domain. Individually usually harmless, collectively the raw material for escalation chains: group A can modify group B, and group B is a local administrator somewhere.' -f $objects.Count) `
        -Remediation 'Inventory these and match them to a documented purpose. Focus on whether any delegating group in turn holds rights on systems where privileged accounts log on.' `
        -Objects $objects
}

#############################################################################
# REGION: Checks - Certificate services
#############################################################################

function Test-ADHAdcsInventory {
    $paths = Get-ADHAdcsPath
    if (-not $paths) {
        return New-ADHFinding -Id 'ADCS-001' -Category 'Certificate services' -Severity 'Info' `
            -Title 'No certificate services found in the directory' `
            -Summary 'The configuration naming context contains no Public Key Services container. The remaining ADCS checks are skipped.' `
            -Remediation 'No action required. If a PKI is in use, it operates outside this directory.'
    }

    $p = Get-ADHParameter
    $objects = @()
    $cas = @(Get-ADHCertificateAuthority -Paths $paths)

    foreach ($ca in $cas) {
        $tmpl = @(Get-ADHProp $ca 'certificateTemplates' @())
        $objects += New-ADHObject -Name $ca.Name -DistinguishedName $ca.DistinguishedName -Details (
            'host: {0} | published templates: {1}' -f (Get-ADHProp $ca 'dNSHostName' 'unknown'), $tmpl.Count)
    }

    $templates = @(Get-ADHCertificateTemplate -Paths $paths)
    $objects += New-ADHObject -Name 'Templates total' -Details (
        '{0} defined, {1} published on at least one CA' -f $templates.Count, @($templates | Where-Object { $_.Published }).Count)

    try {
        $ntAuth = Get-ADObject @p -Identity $paths.NtAuth -Properties cACertificate -ErrorAction Stop
        $certs = @(Get-ADHProp $ntAuth 'cACertificate' @())
        $objects += New-ADHObject -Name 'NTAuthCertificates' -DistinguishedName $paths.NtAuth `
            -Details ('{0} certificate authorities are trusted for domain authentication' -f $certs.Count)
    }
    catch {
        Write-Verbose ('NTAuthCertificates could not be read: {0}' -f $_.Exception.Message)
    }

    New-ADHFinding -Id 'ADCS-001' -Category 'Certificate services' -Severity 'Info' `
        -Title 'Certificate services inventory' `
        -Summary ('{0} certificate authority (or authorities) registered in the directory.' -f $cas.Count) `
        -Remediation 'Reconcile every NTAuthCertificates entry against a CA you actually operate - a foreign certificate there permits issuing arbitrary logon certificates. Also confirm whether web enrolment or the certificate enrolment service is reachable over HTTP; those endpoints are relay targets unless extended protection for authentication is enforced (ESC8).' `
        -Objects $objects
}

function Test-ADHAdcsSuppliedSubject {
    $paths = Get-ADHAdcsPath
    if (-not $paths) { return }

    $objects = @()
    $publishedCount = 0

    foreach ($t in (Get-ADHCertificateTemplate -Paths $paths)) {
        if (-not $t.SuppliesSubject)              { continue }
        if ($t.RequiresApproval)                  { continue }
        if ($t.AuthorizedSigs -gt 0)              { continue }
        if (-not (Test-ADHTemplateHasAuthEku $t)) { continue }

        $enrollers = Get-ADHTemplateEnroller -Template $t
        if (-not $enrollers.Count) { continue }
        if ($t.Published) { $publishedCount++ }

        $objects += New-ADHObject -Name $t.DisplayName -DistinguishedName $t.DistinguishedName -Details (
            '{0} | enrollable by: {1} | EKU: {2}' -f `
                $(if ($t.Published) { 'PUBLISHED' } else { 'not published' }),
                ($enrollers -join ', '),
                $(if ($t.Ekus.Count) { ($t.Ekus | ForEach-Object { if ($script:AuthEku.ContainsKey($_)) { $script:AuthEku[$_] } else { $_ } }) -join ', ' } else { 'none (unrestricted)' }))
    }

    $objects = @($objects)
    $sev = if ($publishedCount -gt 0) { 'Critical' } elseif ($objects.Count -gt 0) { 'High' } else { 'Pass' }

    New-ADHFinding -Id 'ADCS-002' -Category 'Certificate services' -Severity $sev `
        -Title 'Templates allowing a requester-supplied subject with an authentication EKU (ESC1)' `
        -Summary 'On these templates the requester chooses which identity the certificate is issued for, and the resulting certificate can be used to authenticate to the domain. With no approval step this is a direct path from any user account to any other identity.' `
        -Remediation 'Fastest mitigation: unpublish the template from the CA if the business can spare it. Proper fix: turn off "Supply in the request" and build the subject from directory information instead. Where that is impossible, require certificate manager approval and narrow enrolment from broad groups to a named role group.' `
        -Objects $objects
}

function Test-ADHAdcsAnyPurpose {
    $paths = Get-ADHAdcsPath
    if (-not $paths) { return }

    $objects = @()

    foreach ($t in (Get-ADHCertificateTemplate -Paths $paths)) {
        $anyPurpose = $t.Ekus -contains $script:AnyEku
        $noEku      = (@($t.Ekus).Count -eq 0)
        if (-not $anyPurpose -and -not $noEku) { continue }

        $enrollers = Get-ADHTemplateEnroller -Template $t
        if (-not $enrollers.Count) { continue }

        $objects += New-ADHObject -Name $t.DisplayName -DistinguishedName $t.DistinguishedName -Details (
            '{0} | {1} | enrollable by: {2}' -f `
                $(if ($t.Published) { 'PUBLISHED' } else { 'not published' }),
                $(if ($anyPurpose) { 'Any Purpose EKU' } else { 'no EKU defined' }),
                ($enrollers -join ', '))
    }

    $objects = @($objects)
    $sev = if (@($objects | Where-Object { $_.Details -match 'PUBLISHED' }).Count -gt 0) { 'Critical' }
           elseif ($objects.Count -gt 0) { 'High' } else { 'Pass' }

    New-ADHFinding -Id 'ADCS-003' -Category 'Certificate services' -Severity $sev `
        -Title 'Templates without a purpose restriction (ESC2)' `
        -Summary 'Certificates from these templates are valid for any purpose, including domain authentication and, depending on the template, acting as a subordinate CA.' `
        -Remediation 'Restrict application policies to the purpose actually required. Any Purpose has essentially no legitimate role in an enterprise PKI.' `
        -Objects $objects
}

function Test-ADHAdcsEnrollmentAgent {
    $paths = Get-ADHAdcsPath
    if (-not $paths) { return }

    $objects = @()

    foreach ($t in (Get-ADHCertificateTemplate -Paths $paths)) {
        if ($t.Ekus -notcontains $script:AgentEku) { continue }

        $enrollers = Get-ADHTemplateEnroller -Template $t
        if (-not $enrollers.Count) { continue }

        $objects += New-ADHObject -Name $t.DisplayName -DistinguishedName $t.DistinguishedName -Details (
            '{0} | approval required: {1} | enrollable by: {2}' -f `
                $(if ($t.Published) { 'PUBLISHED' } else { 'not published' }),
                $(if ($t.RequiresApproval) { 'yes' } else { 'NO' }),
                ($enrollers -join ', '))
    }

    $objects = @($objects)
    $sev = if ($objects.Count -gt 0) { 'High' } else { 'Pass' }

    New-ADHFinding -Id 'ADCS-004' -Category 'Certificate services' -Severity $sev `
        -Title 'Broadly enrollable enrollment agent templates (ESC3)' `
        -Summary 'An enrollment agent may countersign certificate requests on behalf of other users. Whoever can obtain such a certificate can subsequently have logon certificates issued for other identities.' `
        -Remediation 'Restrict enrolment to a small, named group. On the CA itself, additionally configure enrollment agent restrictions so an agent can only sign for defined templates and defined user groups.' `
        -Objects $objects
}

function Test-ADHAdcsTemplateAcl {
    $paths = Get-ADHAdcsPath
    if (-not $paths) { return }

    $objects = @()

    foreach ($t in (Get-ADHCertificateTemplate -Paths $paths)) {
        foreach ($w in (Get-ADHTemplateWriter -Template $t)) {
            $objects += New-ADHObject -Name $t.DisplayName -DistinguishedName $t.DistinguishedName -Details (
                '{0}{1}' -f $(if ($t.Published) { '[PUBLISHED] ' } else { '' }), $w)
        }
    }

    $objects = @($objects)
    $sev = if (@($objects | Where-Object { $_.Details -match 'PUBLISHED' }).Count -gt 0) { 'Critical' }
           elseif ($objects.Count -gt 0) { 'High' } else { 'Pass' }

    New-ADHFinding -Id 'ADCS-005' -Category 'Certificate services' -Severity $sev `
        -Title 'Write access on certificate templates (ESC4)' `
        -Summary 'Anyone able to edit a template can reconfigure it into one that permits authentication as an arbitrary identity. Write access on a published template is therefore one step away from ESC1.' `
        -Remediation 'Keep write and full control on template objects with the PKI administrators only. Audit modifications to objects under Public Key Services (directory service changes, event 5136).' `
        -Objects $objects
}

function Test-ADHAdcsContainerAcl {
    $paths = Get-ADHAdcsPath
    if (-not $paths) { return }

    $objects = @()
    $targets = @(
        @{ Dn = $paths.Pki;        Label = 'container: Public Key Services' }
        @{ Dn = $paths.Templates;  Label = 'container: Certificate Templates' }
        @{ Dn = $paths.Enrollment; Label = 'container: Enrollment Services' }
        @{ Dn = $paths.NtAuth;     Label = 'object: NTAuthCertificates' }
    )
    foreach ($ca in (Get-ADHCertificateAuthority -Paths $paths)) {
        $targets += @{ Dn = $ca.DistinguishedName; Label = ('certificate authority: {0}' -f $ca.Name) }
    }

    foreach ($t in $targets) {
        $sd = Get-ADHSecurityDescriptor -DistinguishedName $t.Dn
        if (-not $sd) { continue }

        foreach ($ace in (Get-ADHDangerousAce -SecurityDescriptor $sd)) {
            $objects += New-ADHObject -Name $t.Label -DistinguishedName $t.Dn -Details (Format-ADHAce $ace)
        }
    }

    $objects = @($objects)
    $sev = if ($objects.Count -gt 0) { 'Critical' } else { 'Pass' }

    New-ADHFinding -Id 'ADCS-006' -Category 'Certificate services' -Severity $sev `
        -Title 'Dangerous permissions on PKI objects (ESC5/ESC7)' `
        -Summary 'Write access to the PKI containers allows publishing new templates or adding a rogue CA certificate to NTAuthCertificates. Either grants the ability to issue logon certificates for arbitrary identities without touching the existing CA.' `
        -Remediation 'Reduce permissions to the PKI administrators. On the CA itself, keep the "Manage CA" and "Issue and manage certificates" roles separate and assigned to different people.' `
        -Objects $objects
}

function Test-ADHAdcsEditFlags {
    $paths = Get-ADHAdcsPath
    if (-not $paths) { return }

    $objects = @()
    $found = $false
    $unreadable = 0

    foreach ($ca in (Get-ADHCertificateAuthority -Paths $paths)) {
        # Note: $host is an automatic variable and must not be reused here.
        $caHost = Get-ADHProp $ca 'dNSHostName'
        if (-not $caHost) { $unreadable++; continue }

        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $caHost)
            $key  = $base.OpenSubKey("SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$($ca.Name)")
            if (-not $key) { $unreadable++; continue }

            $editFlags = [int]$key.GetValue('EditFlags', 0)
            $san = (($editFlags -band 0x00040000) -ne 0)   # EDITF_ATTRIBUTESUBJECTALTNAME2
            if ($san) { $found = $true }

            $objects += New-ADHObject -Name $ca.Name -DistinguishedName $caHost -Details (
                'EditFlags: 0x{0:X} | subject alternative name from request: {1}' -f `
                    $editFlags, $(if ($san) { 'ENABLED' } else { 'disabled' }))

            $key.Close(); $base.Close()
        }
        catch {
            $unreadable++
            $objects += New-ADHObject -Name $ca.Name -DistinguishedName $caHost `
                -Details ('registry not readable: {0}' -f $_.Exception.Message)
        }
    }

    $objects = @($objects)
    $sev = if ($found) { 'Critical' } elseif ($unreadable -gt 0) { 'Info' } elseif ($objects.Count -gt 0) { 'Pass' } else { 'Info' }

    New-ADHFinding -Id 'ADCS-007' -Category 'Certificate services' -Severity $sev `
        -Title 'CA accepts a subject alternative name from the request (ESC6)' `
        -Summary ('With this flag set, any requester may supply an arbitrary alternative name on ANY template - the per-template settings stop applying. {0}' -f `
            $(if ($unreadable -gt 0) { "Registry access failed for $unreadable CA(s); please check those manually." } else { '' })) `
        -Remediation 'Check and clear on the CA: certutil -config "<CA>" -getreg policy\EditFlags, then certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 and restart the certificate service. Afterwards review already-issued certificates for unexpected alternative names. This check needs local administrator rights on the CA host and the remote registry service.' `
        -Objects $objects
}

function Test-ADHAdcsNoSecurityExtension {
    $paths = Get-ADHAdcsPath
    if (-not $paths) { return }

    $objects = @()

    foreach ($t in (Get-ADHCertificateTemplate -Paths $paths)) {
        if (-not $t.NoSecurityExt) { continue }
        $objects += New-ADHObject -Name $t.DisplayName -DistinguishedName $t.DistinguishedName -Details (
            '{0} | schema version: {1}' -f $(if ($t.Published) { 'PUBLISHED' } else { 'not published' }), $t.SchemaVersion)
    }

    $objects = @($objects)
    $sev = if (@($objects | Where-Object { $_.Details -match 'PUBLISHED' }).Count -gt 0) { 'High' }
           elseif ($objects.Count -gt 0) { 'Medium' } else { 'Pass' }

    New-ADHFinding -Id 'ADCS-008' -Category 'Certificate services' -Severity $sev `
        -Title 'Templates without the embedded SID security extension (ESC9)' `
        -Summary 'Without the security extension the domain controller maps the certificate to an account by name alone. If that name comes under an attacker control, strong certificate mapping is bypassed.' `
        -Remediation 'Remove the CT_FLAG_NO_SECURITY_EXTENSION flag and move domain controllers to full enforcement mode for StrongCertificateBindingEnforcement. Before switching, review Kerberos-Key-Distribution-Center events 39 and 41 to find affected legacy systems.' `
        -Objects $objects
}

function Test-ADHAdcsBroadEnrollment {
    $paths = Get-ADHAdcsPath
    if (-not $paths) { return }

    $objects = @()

    foreach ($t in (Get-ADHCertificateTemplate -Paths $paths)) {
        if (-not $t.Published) { continue }
        $enrollers = Get-ADHTemplateEnroller -Template $t
        if (-not $enrollers.Count) { continue }

        $objects += New-ADHObject -Name $t.DisplayName -DistinguishedName $t.DistinguishedName -Details (
            'enrollable by: {0} | approval: {1} | requester supplies subject: {2}' -f `
                ($enrollers -join ', '),
                $(if ($t.RequiresApproval) { 'yes' } else { 'no' }),
                $(if ($t.SuppliesSubject) { 'yes' } else { 'no' }))
    }

    $objects = @($objects)
    $sev = if ($objects.Count -gt 10) { 'Medium' } elseif ($objects.Count -gt 0) { 'Low' } else { 'Pass' }

    New-ADHFinding -Id 'ADCS-009' -Category 'Certificate services' -Severity $sev `
        -Title 'Published templates with broad enrolment rights' `
        -Summary ('{0} published templates can be requested by all domain users or computers. Individually often benign, but collectively this is the surface on which every other ADCS finding becomes exploitable.' -f $objects.Count) `
        -Remediation 'Scope enrolment rights to the groups that actually need each template. Unpublish templates nobody requests - that reduces attack surface at no operational cost.' `
        -Objects $objects
}

#############################################################################
# REGION: Check catalogue
#############################################################################

function New-CatalogueEntry {
    param(
        [int] $Number, [string] $Id, [string] $Category, [string] $Name,
        [ValidateSet('Fast','Medium','Slow')] [string] $Cost,
        [ValidateSet('Domain','Forest')] [string] $Scope,
        [scriptblock] $Action
    )
    [PSCustomObject]@{
        Number = $Number; Id = $Id; Category = $Category
        Name = $Name; Cost = $Cost; Scope = $Scope; Action = $Action
    }
}

$script:Catalogue = @(
    New-CatalogueEntry  1 'KRB-001'   'Kerberos'             'Kerberoastable accounts (SPN on user objects)'      'Fast'   'Domain' { Test-ADHKerberoastable }
    New-CatalogueEntry  2 'KRB-002'   'Kerberos'             'Kerberos pre-authentication disabled'               'Fast'   'Domain' { Test-ADHAsRepRoastable }
    New-CatalogueEntry  3 'KRB-003'   'Kerberos'             'krbtgt password age'                                'Fast'   'Domain' { Test-ADHKrbtgtAge }
    New-CatalogueEntry  4 'KRB-004'   'Kerberos'             'Weak encryption (DES/RC4) on SPN and admin accounts' 'Medium' 'Domain' { Test-ADHWeakKerberosEncryption }

    New-CatalogueEntry  5 'DEL-001'   'Delegation'           'Unconstrained delegation outside DCs'               'Fast'   'Domain' { Test-ADHUnconstrainedDelegation }
    New-CatalogueEntry  6 'DEL-002'   'Delegation'           'Constrained delegation with protocol transition'    'Fast'   'Domain' { Test-ADHConstrainedDelegationTransition }
    New-CatalogueEntry  7 'DEL-003'   'Delegation'           'Resource-based constrained delegation configured'   'Fast'   'Domain' { Test-ADHResourceBasedDelegation }

    New-CatalogueEntry  8 'PRIV-001'  'Privileges'           'Tier-0 group membership'                            'Fast'   'Domain' { Test-ADHPrivilegedGroupMembership }
    New-CatalogueEntry  9 'PRIV-002'  'Privileges'           'Privileged accounts without delegation protection'  'Fast'   'Domain' { Test-ADHUnprotectedPrivilegedAccounts }
    New-CatalogueEntry 10 'PRIV-003'  'Privileges'           'Orphaned adminCount flags'                          'Fast'   'Domain' { Test-ADHOrphanedAdminCount }

    New-CatalogueEntry 11 'PWD-001'   'Passwords'            'Non-expiring passwords on enabled accounts'         'Fast'   'Domain' { Test-ADHPasswordNeverExpires }
    New-CatalogueEntry 12 'PWD-002'   'Passwords'            'Accounts that may have a blank password'            'Fast'   'Domain' { Test-ADHPasswordNotRequired }
    New-CatalogueEntry 13 'PWD-003'   'Passwords'            'Passwords stored with reversible encryption'        'Fast'   'Domain' { Test-ADHReversibleEncryption }
    New-CatalogueEntry 14 'PWD-004'   'Passwords'            'Privileged passwords older than one year'           'Fast'   'Domain' { Test-ADHStalePrivilegedPasswords }
    New-CatalogueEntry 15 'PWD-005'   'Passwords'            'Default domain password policy'                     'Fast'   'Domain' { Test-ADHDomainPasswordPolicy }

    New-CatalogueEntry 16 'ACC-001'   'Account hygiene'      'Stale enabled user accounts'                        'Medium' 'Domain' { Test-ADHStaleUsers }
    New-CatalogueEntry 17 'ACC-002'   'Account hygiene'      'Stale enabled computer accounts'                    'Medium' 'Domain' { Test-ADHStaleComputers }
    New-CatalogueEntry 18 'ACC-003'   'Account hygiene'      'Objects carrying SID history'                       'Fast'   'Domain' { Test-ADHSidHistory }
    New-CatalogueEntry 19 'ACC-004'   'Account hygiene'      'Possible credentials in description/info fields'    'Medium' 'Domain' { Test-ADHCredentialsInAttributes }

    New-CatalogueEntry 20 'INF-001'   'Infrastructure'       'MachineAccountQuota'                                'Fast'   'Domain' { Test-ADHMachineAccountQuota }
    New-CatalogueEntry 21 'INF-002'   'Infrastructure'       'Domain controllers and functional levels'           'Fast'   'Domain' { Test-ADHDomainControllers }
    New-CatalogueEntry 22 'INF-003'   'Infrastructure'       'End-of-life operating systems'                      'Fast'   'Domain' { Test-ADHLegacyOperatingSystems }
    New-CatalogueEntry 23 'INF-004'   'Infrastructure'       'LAPS coverage'                                      'Medium' 'Domain' { Test-ADHLapsCoverage }

    New-CatalogueEntry 24 'TRUST-001' 'Trusts'               'Trust relationship configuration (SID filtering)'   'Fast'   'Domain' { Test-ADHTrustConfiguration }

    New-CatalogueEntry 25 'GPO-001'   'Group policy'         'Stored credentials in SYSVOL (cpassword)'           'Slow'   'Domain' { Test-ADHSysvolCpassword }

    New-CatalogueEntry 26 'ACL-001'   'Permissions'          'Replication rights on the domain root (DCSync)'     'Fast'   'Domain' { Test-ADHDcSyncRights }
    New-CatalogueEntry 27 'ACL-002'   'Permissions'          'Dangerous permissions on tier-0 groups'             'Fast'   'Domain' { Test-ADHPrivilegedGroupAcl }
    New-CatalogueEntry 28 'ACL-003'   'Permissions'          'Dangerous permissions on privileged accounts'       'Medium' 'Domain' { Test-ADHPrivilegedUserAcl }
    New-CatalogueEntry 29 'ACL-004'   'Permissions'          'Dangerous permissions on AdminSDHolder'             'Fast'   'Domain' { Test-ADHAdminSdHolderAcl }
    New-CatalogueEntry 30 'ACL-005'   'Permissions'          'Broad delegations on organizational units'          'Slow'   'Domain' { Test-ADHOrganizationalUnitAcl }
    New-CatalogueEntry 31 'ACL-006'   'Permissions'          'Privileged objects with non-privileged owners'      'Medium' 'Domain' { Test-ADHObjectOwnership }
    New-CatalogueEntry 32 'ACL-007'   'Permissions'          'Dangerous permissions on DC objects'                'Fast'   'Domain' { Test-ADHDomainControllerAcl }
    New-CatalogueEntry 33 'ACL-008'   'Permissions'          'Write access on group policy objects'               'Slow'   'Domain' { Test-ADHGpoAcl }
    New-CatalogueEntry 34 'ACL-009'   'Permissions'          'Delegated write access on group membership'         'Slow'   'Domain' { Test-ADHGroupMembershipDelegation }

    New-CatalogueEntry 35 'ADCS-001'  'Certificate services' 'Certificate services inventory'                     'Fast'   'Forest' { Test-ADHAdcsInventory }
    New-CatalogueEntry 36 'ADCS-002'  'Certificate services' 'Requester-supplied subject with auth EKU (ESC1)'    'Medium' 'Forest' { Test-ADHAdcsSuppliedSubject }
    New-CatalogueEntry 37 'ADCS-003'  'Certificate services' 'Templates without purpose restriction (ESC2)'       'Medium' 'Forest' { Test-ADHAdcsAnyPurpose }
    New-CatalogueEntry 38 'ADCS-004'  'Certificate services' 'Broad enrollment agent templates (ESC3)'            'Medium' 'Forest' { Test-ADHAdcsEnrollmentAgent }
    New-CatalogueEntry 39 'ADCS-005'  'Certificate services' 'Write access on certificate templates (ESC4)'       'Medium' 'Forest' { Test-ADHAdcsTemplateAcl }
    New-CatalogueEntry 40 'ADCS-006'  'Certificate services' 'Dangerous permissions on PKI objects (ESC5/7)'      'Fast'   'Forest' { Test-ADHAdcsContainerAcl }
    New-CatalogueEntry 41 'ADCS-007'  'Certificate services' 'CA accepts SAN from request (ESC6)'                 'Slow'   'Forest' { Test-ADHAdcsEditFlags }
    New-CatalogueEntry 42 'ADCS-008'  'Certificate services' 'Templates without SID security extension (ESC9)'    'Medium' 'Forest' { Test-ADHAdcsNoSecurityExtension }
    New-CatalogueEntry 43 'ADCS-009'  'Certificate services' 'Published templates with broad enrolment'           'Medium' 'Forest' { Test-ADHAdcsBroadEnrollment }
)

#############################################################################
# REGION: Selection
#############################################################################

# The checks that map to a direct, single-step path to domain compromise.
# This is the list to run when someone asks "we have twenty minutes, what
# matters?" - everything here is either already a compromise or one move away
# from one.
$script:EssentialId = @(
    'KRB-001'   # kerberoastable privileged service accounts
    'KRB-003'   # krbtgt key age
    'DEL-001'   # unconstrained delegation
    'DEL-002'   # protocol transition
    'PRIV-001'  # who is actually tier 0
    'PWD-002'   # accounts that may have no password
    'PWD-003'   # reversible encryption
    'TRUST-001' # SID filtering
    'GPO-001'   # cpassword in SYSVOL
    'ACL-001'   # DCSync
    'ACL-004'   # AdminSDHolder
    'ACL-007'   # DC objects
    'ACL-008'   # GPOs linked to tier 0
    'ADCS-002'  # ESC1
)

$script:Preset = @(
    [PSCustomObject]@{
        Key = 'full'; Label = 'Everything'
        Hint = 'the complete catalogue'
        Filter = { $script:Catalogue }
    }
    [PSCustomObject]@{
        Key = 'quick'; Label = 'Quick pass'
        Hint = 'fast checks only'
        Filter = { @($script:Catalogue | Where-Object { $_.Cost -eq 'Fast' }) }
    }
    [PSCustomObject]@{
        Key = 'essential'; Label = 'Tier-0 essentials'
        Hint = 'paths to domain compromise'
        Filter = { @($script:Catalogue | Where-Object { $script:EssentialId -contains $_.Id }) }
    }
)

function Get-ADHCategorySummary {
    <# Categories in catalogue order, with counts for the menu. #>
    $seen = @()
    foreach ($c in $script:Catalogue) {
        if ($seen -contains $c.Category) { continue }
        $seen += $c.Category

        $inCat = @($script:Catalogue | Where-Object { $_.Category -eq $c.Category })
        [PSCustomObject]@{
            Name   = $c.Category
            Checks = $inCat
            Count  = $inCat.Count
            Slow   = @($inCat | Where-Object { $_.Cost -eq 'Slow' }).Count
            Forest = @($inCat | Where-Object { $_.Scope -eq 'Forest' }).Count -eq $inCat.Count
        }
    }
}

function Write-ADHMenuRow {
    param([string] $Key, [string] $Label, [string] $Note, [string] $Trailing = '', [string] $KeyColor = 'White')
    Write-Host ('   {0,-4}' -f $Key) -ForegroundColor $KeyColor -NoNewline
    if ($Note) {
        Write-Host ('{0,-50}' -f $Label) -NoNewline
        if ($Trailing) {
            Write-Host ('{0,-13}' -f $Note) -ForegroundColor DarkGray -NoNewline
            Write-Host $Trailing -ForegroundColor DarkYellow
        }
        else {
            Write-Host $Note -ForegroundColor DarkGray
        }
    }
    else {
        Write-Host $Label
    }
}

function Show-ScanMenu {
    <#
        Top-level menu: three profiles, then one entry per category. Picking a
        whole category is the common case, so it should not require knowing
        which numbers the checks happen to occupy.
    #>
    $categories = @(Get-ADHCategorySummary)

    Write-Host ''
    Write-Host '  SCAN PROFILES' -ForegroundColor Cyan
    Write-Host ''

    $n = 1
    foreach ($p in $script:Preset) {
        $set = & $p.Filter
        $slow = @($set | Where-Object { $_.Cost -eq 'Slow' }).Count
        Write-ADHMenuRow -Key $n -Label ('{0} - {1}' -f $p.Label, $p.Hint) `
            -Note ('{0} checks' -f @($set).Count) `
            -Trailing $(if ($slow) { "$slow slow" } else { '' })
        $n++
    }

    Write-Host ''
    Write-Host '  CATEGORIES' -ForegroundColor Cyan
    Write-Host ''

    foreach ($cat in $categories) {
        $label = $cat.Name
        if ($cat.Forest) { $label += '  (forest-wide)' }
        Write-ADHMenuRow -Key $n -Label $label `
            -Note ('{0} check{1}' -f $cat.Count, $(if ($cat.Count -eq 1) { '' } else { 's' })) `
            -Trailing $(if ($cat.Slow) { "$($cat.Slow) slow" } else { '' })
        $n++
    }

    Write-Host ''
    Write-ADHMenuRow -Key 'L' -Label ('List all {0} checks and pick individually' -f $script:Catalogue.Count) -Note '' -KeyColor 'DarkGray'
    Write-ADHMenuRow -Key 'Q' -Label 'Cancel' -Note '' -KeyColor 'DarkGray'
    Write-Host ''

    return $categories
}

function Show-CheckCatalogue {
    Write-Host ''
    Write-Host '  #   ID         Cost    Scope   Check' -ForegroundColor White
    Write-Host ('  ' + ('-' * 74)) -ForegroundColor DarkGray

    $lastCategory = ''
    foreach ($c in $script:Catalogue) {
        if ($c.Category -ne $lastCategory) {
            Write-Host ''
            Write-Host ('  {0}' -f $c.Category.ToUpper()) -ForegroundColor Cyan
            $lastCategory = $c.Category
        }
        $costColor = switch ($c.Cost) { 'Slow' { 'DarkYellow' } 'Medium' { 'Gray' } default { 'DarkGray' } }
        Write-Host ('  {0,-4}' -f $c.Number) -ForegroundColor White -NoNewline
        Write-Host ('{0,-11}' -f $c.Id) -ForegroundColor DarkGray -NoNewline
        Write-Host ('{0,-8}' -f $c.Cost) -ForegroundColor $costColor -NoNewline
        Write-Host ('{0,-8}' -f $c.Scope) -ForegroundColor DarkGray -NoNewline
        Write-Host $c.Name
    }
    Write-Host ''
}

function Resolve-CheckSelection {
    <#
        Turns selection tokens into catalogue entries. Accepts numbers, ranges,
        check IDs, ID prefixes, category names and the keywords all / fast.
        Unrecognised tokens produce a warning rather than an error, so one typo
        does not discard the whole selection.
    #>
    param([string[]] $Tokens)

    $selected = @()
    $unknown  = @()

    foreach ($raw in $Tokens) {
        foreach ($token in ($raw -split '[,;]')) {
            $t = $token.Trim()
            if (-not $t) { continue }

            # Keywords - these mirror the profiles offered by the interactive menu
            if ($t -match '^(all|full|\*)$')     { $selected += $script:Catalogue; continue }
            if ($t -match '^(fast|quick)$')      { $selected += @($script:Catalogue | Where-Object { $_.Cost -eq 'Fast' }); continue }
            if ($t -match '^(essential|tier0)$') { $selected += @($script:Catalogue | Where-Object { $script:EssentialId -contains $_.Id }); continue }
            if ($t -match '^slow$')              { $selected += @($script:Catalogue | Where-Object { $_.Cost -eq 'Slow' }); continue }
            if ($t -match '^domain$')            { $selected += @($script:Catalogue | Where-Object { $_.Scope -eq 'Domain' }); continue }
            if ($t -match '^forest$')            { $selected += @($script:Catalogue | Where-Object { $_.Scope -eq 'Forest' }); continue }

            # Range, e.g. 7-14
            if ($t -match '^(\d+)\s*-\s*(\d+)$') {
                $from = [int]$Matches[1]; $to = [int]$Matches[2]
                if ($from -gt $to) { $tmp = $from; $from = $to; $to = $tmp }
                $hit = @($script:Catalogue | Where-Object { $_.Number -ge $from -and $_.Number -le $to })
                if ($hit.Count) { $selected += $hit } else { $unknown += $t }
                continue
            }

            # Single number
            if ($t -match '^\d+$') {
                $hit = @($script:Catalogue | Where-Object { $_.Number -eq [int]$t })
                if ($hit.Count) { $selected += $hit } else { $unknown += $t }
                continue
            }

            # Exact check ID
            $hit = @($script:Catalogue | Where-Object { $_.Id -eq $t })
            if ($hit.Count) { $selected += $hit; continue }

            # Category name
            $hit = @($script:Catalogue | Where-Object { $_.Category -like "$t*" })
            if ($hit.Count) { $selected += $hit; continue }

            # ID prefix, e.g. ACL or ADCS
            $hit = @($script:Catalogue | Where-Object { $_.Id -like "$t-*" })
            if ($hit.Count) { $selected += $hit; continue }

            $unknown += $t
        }
    }

    if ($unknown.Count) {
        Write-Warning ('Ignored unrecognised selection token(s): {0}' -f (($unknown | Select-Object -Unique) -join ', '))
    }

    return @($selected | Sort-Object Number -Unique)
}

function Read-CheckSelection {
    <#
        Interactive menu. Two levels: pick a profile or one or more categories,
        or drop into the full list to pick individual checks. Returns catalogue
        entries, or an empty array when the user cancels.
    #>
    while ($true) {

        $categories = @(Show-ScanMenu)
        $presetCount = @($script:Preset).Count

        $answer = Read-Host '  Select (e.g. 3, or 5,7,12)'
        $answer = "$answer".Trim()

        if ([string]::IsNullOrWhiteSpace($answer) -or $answer -match '^(q|quit|exit|cancel)$') {
            return @()
        }

        # --- Individual picker -------------------------------------------------
        if ($answer -match '^(l|list)$') {
            Show-CheckCatalogue
            Write-Host '  Numbers, ranges and IDs all work:' -ForegroundColor DarkGray
            Write-Host '    3,7,22           individual checks' -ForegroundColor DarkGray
            Write-Host '    1-14             a range'           -ForegroundColor DarkGray
            Write-Host '    ADCS, Kerberos   a whole group'     -ForegroundColor DarkGray
            Write-Host ''

            $detail = Read-Host '  Select checks (empty to go back)'
            if ([string]::IsNullOrWhiteSpace($detail)) { continue }

            $picked = Resolve-CheckSelection -Tokens @($detail)
            if (-not @($picked).Count) {
                Write-Host '  Nothing matched. Try again.' -ForegroundColor Yellow
                continue
            }
            return $picked
        }

        # A range at this level is ambiguous: "1-3" could mean the first three
        # menu rows or checks 1 to 3. Rather than silently picking one reading,
        # send the user to the list where ranges have an unambiguous meaning.
        if ($answer -match '^\s*\d+\s*-\s*\d+\s*$') {
            Write-Host ''
            Write-Host '  Ranges refer to individual check numbers, not menu rows.' -ForegroundColor Yellow
            Write-Host '  Press L to open the full list, or pick menu rows as 1,2,3.' -ForegroundColor Yellow
            Write-Host ''
            continue
        }

        # --- Menu numbers ------------------------------------------------------
        $selected = @()
        $bad = @()

        foreach ($token in ($answer -split '[,;\s]+')) {
            if (-not $token) { continue }

            if ($token -notmatch '^\d+$') { $bad += $token; continue }
            $i = [int]$token

            if ($i -ge 1 -and $i -le $presetCount) {
                $selected += & $script:Preset[$i - 1].Filter
            }
            elseif ($i -gt $presetCount -and $i -le ($presetCount + $categories.Count)) {
                $selected += $categories[$i - $presetCount - 1].Checks
            }
            else { $bad += $token }
        }

        # Anything that was not a menu number gets one more chance as a check ID,
        # category name or range - typing "ADCS" here should just work.
        if ($bad.Count -and -not $selected.Count) {
            $selected = @(Resolve-CheckSelection -Tokens @($answer))
        }
        elseif ($bad.Count) {
            Write-Host ('  Ignored: {0}' -f ($bad -join ', ')) -ForegroundColor Yellow
        }

        $selected = @($selected | Sort-Object Number -Unique)

        if (-not $selected.Count) {
            Write-Host '  Nothing matched. Try again.' -ForegroundColor Yellow
            continue
        }

        # --- Confirm -----------------------------------------------------------
        $slow = @($selected | Where-Object { $_.Cost -eq 'Slow' }).Count
        Write-Host ''
        Write-Host ('  {0} check{1} selected:' -f $selected.Count, $(if ($selected.Count -eq 1) { '' } else { 's' })) -ForegroundColor Cyan

        foreach ($cat in ($selected | Select-Object -ExpandProperty Category -Unique)) {
            $inCat = @($selected | Where-Object { $_.Category -eq $cat })
            Write-Host ('    {0,-24} {1}' -f $cat, (($inCat.Id) -join ', ')) -ForegroundColor DarkGray
        }

        if ($slow) {
            Write-Host ''
            Write-Host ('  {0} of these read a security descriptor per object and will take a while.' -f $slow) -ForegroundColor DarkYellow
        }

        Write-Host ''
        $confirm = Read-Host '  Start scan? [Y/n]'
        if ("$confirm".Trim() -match '^(n|no)$') { continue }

        return $selected
    }
}

#############################################################################
# REGION: Approved exceptions
#############################################################################

function Get-ADHExceptionPath {
    <#
        Explicit parameter wins; otherwise look for the default file next to
        the script. Returns $null when there is nothing to load.
    #>
    if ($NoExceptions) { return $null }
    if ($ExceptionFile) {
        if (Test-Path -LiteralPath $ExceptionFile) { return $ExceptionFile }
        throw ('Exception file not found: {0}' -f $ExceptionFile)
    }

    $root = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $default = Join-Path $root 'ADSecurityScan.exceptions.json'
    if (Test-Path -LiteralPath $default) { return $default }
    return $null
}

function Get-ADHException {
    <#
        Loads and normalises the exception file. Every entry needs a checkId, an
        object pattern, a reason and an expiry date - an exception without an
        end date is not an exception, it is a permanent blind spot.
    #>
    param([string] $Path)

    if (-not $Path) { return @() }

    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json
    }
    catch {
        Write-Warning ('Exception file could not be parsed, continuing without exceptions: {0}' -f $_.Exception.Message)
        return @()
    }

    $entries = @(Get-ADHProp $raw 'exceptions' @())
    $result = @()
    $today = (Get-Date).Date

    foreach ($e in $entries) {
        $checkId = Get-ADHProp $e 'checkId'
        $object  = Get-ADHProp $e 'object'
        $reason  = Get-ADHProp $e 'reason'
        $expires = Get-ADHProp $e 'expires'

        if (-not $checkId -or -not $object) {
            Write-Warning 'Exception entry without checkId or object was skipped.'
            continue
        }
        if (-not $reason) {
            Write-Warning ('Exception for {0}/{1} has no reason and was skipped.' -f $checkId, $object)
            continue
        }

        $expiryDate = $null
        if ($expires) {
            try { $expiryDate = ([datetime]$expires).Date }
            catch {
                Write-Warning ('Exception for {0}/{1} has an unreadable expiry date and was skipped.' -f $checkId, $object)
                continue
            }
        }
        else {
            Write-Warning ('Exception for {0}/{1} has no expiry date and was skipped. Exceptions must expire.' -f $checkId, $object)
            continue
        }

        $result += [PSCustomObject]@{
            CheckId    = $checkId
            Object     = $object
            Reason     = $reason
            ApprovedBy = Get-ADHProp $e 'approvedBy' 'not stated'
            Expires    = $expiryDate
            Expired    = ($expiryDate -lt $today)
            DaysLeft   = [int]($expiryDate - $today).TotalDays
        }
    }

    return @($result)
}

function Test-ADHExceptionMatch {
    <# Does this exception cover this finding object? #>
    param($Exception, $Finding, $Object)

    if ($Exception.Expired) { return $false }
    if ($Finding.Id -notlike $Exception.CheckId) { return $false }

    return ($Object.Name -like $Exception.Object) -or
           ($Object.DistinguishedName -like $Exception.Object)
}

function Invoke-ADHExceptionFilter {
    <#
        Removes covered objects from each finding and downgrades a finding to
        Pass when nothing is left. Informational findings keep their severity -
        an inventory with everything excepted is still an inventory.
    #>
    param(
        [Parameter(Mandatory)] [System.Collections.Generic.List[object]] $Findings,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Exceptions
    )

    $active = @($Exceptions | Where-Object { -not $_.Expired })
    if (-not $active.Count) { return 0 }

    $suppressed = 0

    for ($i = 0; $i -lt $Findings.Count; $i++) {
        $f = $Findings[$i]
        if (-not $f.Objects.Count) { continue }

        $kept = @()
        $removed = 0

        foreach ($o in $f.Objects) {
            $covered = $false
            foreach ($x in $active) {
                if (Test-ADHExceptionMatch -Exception $x -Finding $f -Object $o) { $covered = $true; break }
            }
            if ($covered) { $removed++ } else { $kept += $o }
        }

        if (-not $removed) { continue }
        $suppressed += $removed

        $newSeverity = $f.Severity
        $note = ' [{0} object(s) covered by approved exceptions]' -f $removed

        if (-not $kept.Count -and $f.Severity -in @('Critical','High','Medium','Low')) {
            $newSeverity = 'Pass'
            $note = ' [all {0} object(s) covered by approved exceptions]' -f $removed
        }

        $Findings[$i] = [PSCustomObject]@{
            PSTypeName  = 'ADSecurityScan.Finding'
            Id          = $f.Id
            Category    = $f.Category
            Title       = $f.Title
            Severity    = $newSeverity
            Count       = $kept.Count
            Summary     = $f.Summary + $note
            Remediation = $f.Remediation
            Reference   = (Get-ADHProp $f 'Reference')
            Objects     = @($kept)
        }
    }

    return $suppressed
}

function New-ADHExceptionFinding {
    <#
        Makes the exception file itself auditable: what is currently suppressed,
        what has expired, and what is about to.
    #>
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Exceptions,
        [string] $Path,
        [int] $Suppressed
    )

    $expired = @($Exceptions | Where-Object { $_.Expired })
    $soon    = @($Exceptions | Where-Object { -not $_.Expired -and $_.DaysLeft -le 30 })
    $active  = @($Exceptions | Where-Object { -not $_.Expired })

    $objects = foreach ($x in ($Exceptions | Sort-Object Expires)) {
        $state = if ($x.Expired)          { 'EXPIRED' }
                 elseif ($x.DaysLeft -le 30) { 'expires soon' }
                 else                      { 'active' }

        New-ADHObject -Name ('{0} -> {1}' -f $x.CheckId, $x.Object) -DistinguishedName $Path -Details (
            '{0} | expires {1} ({2} days) | approved by: {3} | reason: {4}' -f `
                $state, $x.Expires.ToString('yyyy-MM-dd'), $x.DaysLeft, $x.ApprovedBy, $x.Reason)
    }

    $sev = if ($expired.Count -gt 0) { 'Medium' } elseif ($soon.Count -gt 0) { 'Low' } else { 'Info' }

    New-ADHFinding -Id 'EXC-001' -Category 'Exceptions' -Severity $sev `
        -Title 'Approved exceptions' `
        -Summary ('{0} active exception(s) suppressed {1} object(s) in this run. {2} have expired and are no longer suppressing anything, {3} expire within 30 days.' -f `
            $active.Count, $Suppressed, $expired.Count, $soon.Count) `
        -Remediation 'Review expired entries: either the finding was remediated and the entry can go, or the risk is still accepted and needs re-approving with a new date. An exception that silently renews itself is how a report stops being read.' `
        -Objects @($objects)
}

#############################################################################
# REGION: Console output
#############################################################################

function Get-ADHConsoleWidth {
    <# Capped, because full-width lines on an ultrawide terminal are hard to read. #>
    try {
        $w = $Host.UI.RawUI.WindowSize.Width
        if ($w -gt 40) { return [Math]::Min($w - 2, 104) }
    }
    catch {
        # No raw UI (redirected output, remoting, scheduled task). Purely
        # cosmetic, so fall through to the default width without a word.
    }
    return 100
}

function Write-ADHRule {
    param([string] $Char = '-', [string] $Color = 'DarkGray', [int] $Indent = 2)
    Write-Host ((' ' * $Indent) + ($Char * ((Get-ADHConsoleWidth) - $Indent))) -ForegroundColor $Color
}

function Write-ADHSectionHeading {
    param([string] $Text, [string] $Color = 'Cyan')
    Write-Host ''
    Write-Host ('  {0}' -f $Text.ToUpper()) -ForegroundColor $Color
    Write-Host ''
}

function Write-ADHField {
    <# Aligned "label   value" pair used in the banner and the output block. #>
    param([string] $Label, [string] $Value, [string] $Color = 'White')
    Write-Host ('   {0,-14}' -f $Label) -ForegroundColor DarkGray -NoNewline
    Write-Host $Value -ForegroundColor $Color
}

function Write-ADHBanner {
    param([Parameter(Mandatory)] [hashtable] $Context, [Parameter(Mandatory)] [object[]] $Selected)

    $width = Get-ADHConsoleWidth
    $left  = ' Active Directory Security Assessment'
    $right = 'read-only '
    $pad   = [Math]::Max(1, $width - 2 - $left.Length - $right.Length)

    Write-Host ''
    Write-ADHRule '=' 'DarkCyan'
    Write-Host ('  {0}{1}' -f $left, (' ' * $pad)) -ForegroundColor Cyan -NoNewline
    Write-Host $right -ForegroundColor DarkGray
    Write-ADHRule '=' 'DarkCyan'
    Write-Host ''

    Write-ADHField 'Domain'      $Context.Domain
    Write-ADHField 'Controller'  $(if ($Context.Server) { $Context.Server } else { 'auto-discovered' })
    Write-ADHField 'Running as'  $Context.RunAs
    Write-ADHField 'Stale after' ('{0} days' -f $Context.StaleDays)

    $slow = @($Selected | Where-Object { $_.Cost -eq 'Slow' }).Count
    Write-ADHField 'Checks' ('{0} of {1}{2}' -f `
        @($Selected).Count, $Context.TotalChecks,
        $(if ($slow) { "   ($slow slow - these read a security descriptor per object)" } else { '' }))
    Write-Host ''
}

function Write-ADHCheckResult {
    <#
        One line per check, printed as it completes: position, ID, name padded
        out with dots, then the outcome. Far more useful mid-scan than a
        timestamp, because the interesting checks announce themselves.
    #>
    param(
        [int] $Index, [int] $Total,
        [Parameter(Mandatory)] $Check,
        $Finding,
        [double] $Seconds
    )

    $width  = Get-ADHConsoleWidth
    $digits = "$Total".Length
    $prefix = '   [{0}/{1}]  ' -f "$Index".PadLeft($digits), $Total
    $id     = '{0,-10}' -f $Check.Id

    $severity = if ($Finding) { $Finding.Severity } else { 'Failed' }
    $count    = if ($Finding -and $Finding.Count -gt 0) { "$($Finding.Count)" } else { '-' }

    # Seven columns are reserved for the timing in the width calculation even
    # when nothing is printed there, so severity and count stay aligned across
    # rows. Nothing follows it, so an empty timing prints nothing rather than
    # trailing spaces.
    $timing = if ($Seconds -ge 3) { '{0,6:N0}s' -f $Seconds } else { '' }

    $nameRoom = [Math]::Max(10, $width - $prefix.Length - $id.Length - 9 - 5 - 7 - 2)
    $name     = Format-ADHTruncate $Check.Name $nameRoom
    $dots     = '.' * [Math]::Max(1, $nameRoom - $name.Length)

    Write-Host $prefix -ForegroundColor DarkGray -NoNewline
    Write-Host $id -ForegroundColor Gray -NoNewline
    Write-Host $name -NoNewline
    Write-Host (' ' + $dots + ' ') -ForegroundColor DarkGray -NoNewline
    Write-Host ('{0,-9}' -f $severity.ToUpper()) -ForegroundColor (Get-ADHSeverityColor $severity) -NoNewline
    Write-Host ('{0,4}' -f $count) -ForegroundColor $(if ($count -eq '-') { 'DarkGray' } else { 'White' }) -NoNewline
    Write-Host $timing -ForegroundColor DarkGray
}

function Register-ADHFormatData {
    <#
        PowerShell falls back to Format-List once an object has more than four
        properties, which renders the nested Objects collection as an unreadable
        blob. Registering proper views gives findings a clean default table and
        makes Format-List readable as well.

        The definition is written to the temp directory and loaded once per
        session. Failure here is cosmetic, so it never aborts the scan.
    #>
    # Set-StrictMode makes reading a never-assigned variable an error, so test
    # for existence rather than truthiness.
    if (Test-Path -LiteralPath 'Variable:\global:ADHFormatRegistered') { return }

    $xml = @'
<?xml version="1.0" encoding="utf-8"?>
<Configuration>
  <ViewDefinitions>

    <View>
      <Name>ADSecurityScan.Finding.Table</Name>
      <ViewSelectedBy><TypeName>ADSecurityScan.Finding</TypeName></ViewSelectedBy>
      <TableControl>
        <TableHeaders>
          <TableColumnHeader><Label>Severity</Label><Width>9</Width></TableColumnHeader>
          <TableColumnHeader><Label>ID</Label><Width>10</Width></TableColumnHeader>
          <TableColumnHeader><Label>Objects</Label><Width>8</Width><Alignment>Right</Alignment></TableColumnHeader>
          <TableColumnHeader><Label>Check</Label></TableColumnHeader>
        </TableHeaders>
        <TableRowEntries>
          <TableRowEntry>
            <Wrap/>
            <TableColumnItems>
              <TableColumnItem><PropertyName>Severity</PropertyName></TableColumnItem>
              <TableColumnItem><PropertyName>Id</PropertyName></TableColumnItem>
              <TableColumnItem><PropertyName>Count</PropertyName></TableColumnItem>
              <TableColumnItem><PropertyName>Title</PropertyName></TableColumnItem>
            </TableColumnItems>
          </TableRowEntry>
        </TableRowEntries>
      </TableControl>
    </View>

    <View>
      <Name>ADSecurityScan.Finding.List</Name>
      <ViewSelectedBy><TypeName>ADSecurityScan.Finding</TypeName></ViewSelectedBy>
      <ListControl>
        <ListEntries>
          <ListEntry>
            <ListItems>
              <ListItem><PropertyName>Id</PropertyName></ListItem>
              <ListItem><PropertyName>Severity</PropertyName></ListItem>
              <ListItem><PropertyName>Category</PropertyName></ListItem>
              <ListItem><PropertyName>Title</PropertyName></ListItem>
              <ListItem><PropertyName>Summary</PropertyName></ListItem>
              <ListItem><PropertyName>Remediation</PropertyName></ListItem>
              <ListItem>
                <Label>Reference</Label>
                <ScriptBlock>if ($_.Reference) { "$($_.Reference.Title)`n    $($_.Reference.Url)" } else { '(none)' }</ScriptBlock>
              </ListItem>
              <ListItem>
                <Label>Objects</Label>
                <ScriptBlock>if (-not $_.Objects.Count) { '(none)' } else { "`n" + (($_.Objects | ForEach-Object { "  $($_.Name)`n    $($_.Details)`n    $($_.DistinguishedName)" }) -join "`n`n") }</ScriptBlock>
              </ListItem>
            </ListItems>
          </ListEntry>
        </ListEntries>
      </ListControl>
    </View>

    <View>
      <Name>ADSecurityScan.Object.Table</Name>
      <ViewSelectedBy><TypeName>ADSecurityScan.Object</TypeName></ViewSelectedBy>
      <TableControl>
        <TableHeaders>
          <TableColumnHeader><Label>Name</Label><Width>28</Width></TableColumnHeader>
          <TableColumnHeader><Label>Details</Label></TableColumnHeader>
        </TableHeaders>
        <TableRowEntries>
          <TableRowEntry>
            <Wrap/>
            <TableColumnItems>
              <TableColumnItem><PropertyName>Name</PropertyName></TableColumnItem>
              <TableColumnItem><PropertyName>Details</PropertyName></TableColumnItem>
            </TableColumnItems>
          </TableRowEntry>
        </TableRowEntries>
      </TableControl>
    </View>

  </ViewDefinitions>
</Configuration>
'@

    try {
        $path = Join-Path ([System.IO.Path]::GetTempPath()) 'ADSecurityScan.Format.ps1xml'
        $xml | Out-File -LiteralPath $path -Encoding UTF8 -Force
        Update-FormatData -PrependPath $path -ErrorAction Stop
        $global:ADHFormatRegistered = $true
    }
    catch {
        Write-Verbose ('Format data could not be registered: {0}' -f $_.Exception.Message)
    }
}

function Get-ADHSeverityColor {
    param([string] $Severity)
    switch ($Severity) {
        'Critical' { 'Red' }
        'High'     { 'DarkYellow' }
        'Medium'   { 'Yellow' }
        'Low'      { 'Cyan' }
        'Pass'     { 'Green' }
        default    { 'Gray' }
    }
}

function Format-ADHTruncate {
    param([string] $Text, [int] $Max)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    if ($Text.Length -le $Max) { return $Text }
    return $Text.Substring(0, [Math]::Max(1, $Max - 3)) + '...'
}

function Write-ADHConsoleReport {
    <#
        Structured console output. Without -Detail this is one line per finding
        grouped by severity; with -Detail every affected object is listed with
        its attributes on separate lines.
    #>
    param(
        [Parameter(Mandatory)] [object[]] $Findings,
        [switch] $ShowObjects,
        [int] $MaxObjects = 15
    )

    $width = Get-ADHConsoleWidth
    $order = @('Critical','High','Medium','Low','Info','Pass')

    $actionable = @($Findings | Where-Object { $_.Severity -in @('Critical','High','Medium','Low') })
    Write-ADHSectionHeading 'Findings'

    if (-not $actionable.Count) {
        Write-Host '   Nothing actionable found in the selected checks.' -ForegroundColor Green
        Write-Host ''
        return
    }

    $first = $true
    foreach ($sev in $order) {
        $group = @($Findings | Where-Object { $_.Severity -eq $sev } | Sort-Object Id)
        if (-not $group.Count) { continue }

        $color = Get-ADHSeverityColor $sev
        $label = '{0} ({1})' -f $sev.ToUpper(), $group.Count

        if (-not $first) { Write-Host '' }
        $first = $false
        Write-Host ('  {0} ' -f $label) -ForegroundColor $color -NoNewline
        Write-Host ('-' * [Math]::Max(4, $width - $label.Length - 4)) -ForegroundColor DarkGray
        Write-Host ''

        foreach ($f in $group) {
            $countText = if ($f.Count -gt 0) { '{0,5}' -f $f.Count } else { '    -' }
            $nameRoom  = [Math]::Max(20, $width - 20)
            $title     = Format-ADHTruncate $f.Title $nameRoom

            Write-Host ('   {0,-10}' -f $f.Id) -ForegroundColor $color -NoNewline
            # The parentheses matter: without them -f binds to the trailing
            # literal instead of the assembled format string.
            Write-Host (('{0,-' + $nameRoom + '}') -f $title) -NoNewline
            Write-Host $countText -ForegroundColor $(if ($f.Count -gt 0) { 'White' } else { 'DarkGray' })

            if (-not $ShowObjects -or $f.Count -eq 0) { continue }

            # Detail block: one indented paragraph per affected object.
            foreach ($o in ($f.Objects | Select-Object -First $MaxObjects)) {
                Write-Host ''
                Write-Host ('        {0}' -f $o.Name) -ForegroundColor White

                foreach ($part in ($o.Details -split '\s\|\s')) {
                    if ([string]::IsNullOrWhiteSpace($part)) { continue }
                    Write-Host ('          {0}' -f (Format-ADHTruncate $part.Trim() ($width - 12)))
                }

                if ($o.DistinguishedName) {
                    Write-Host ('          {0}' -f (Format-ADHTruncate $o.DistinguishedName ($width - 12))) -ForegroundColor DarkGray
                }
            }

            if ($f.Count -gt $MaxObjects) {
                Write-Host ''
                Write-Host ('        ... and {0} more - see the HTML report, or raise -MaxConsoleObjects' -f ($f.Count - $MaxObjects)) -ForegroundColor DarkGray
            }
            Write-Host ''
        }
    }
    Write-Host ''
}

function Write-ADHConsoleSummary {
    param([Parameter(Mandatory)] [object[]] $Findings, $Elapsed)

    Write-ADHSectionHeading 'Result'

    $total = @($Findings).Count

    foreach ($s in @('Critical','High','Medium','Low','Info','Pass')) {
        $n = @($Findings | Where-Object { $_.Severity -eq $s }).Count
        if ($n -eq 0) { continue }

        # A crude proportional bar: enough to see the shape at a glance without
        # pretending to be a chart.
        $blocks = [Math]::Max(1, [int][Math]::Round(($n / [Math]::Max(1, $total)) * 40))
        Write-Host ('   {0,-10}' -f $s) -ForegroundColor (Get-ADHSeverityColor $s) -NoNewline
        Write-Host ('{0,4}  ' -f $n) -NoNewline
        Write-Host ('#' * $blocks) -ForegroundColor (Get-ADHSeverityColor $s)
    }

    Write-Host ''
    Write-Host ('   {0} check{1} in {2:mm\:ss}' -f $total, $(if ($total -eq 1) { '' } else { 's' }), $Elapsed) -ForegroundColor DarkGray
}

#############################################################################
# REGION: HTML report
#############################################################################

function ConvertTo-ADHHtml {
    param(
        [Parameter(Mandatory)] [object[]] $Findings,
        [Parameter(Mandatory)] [hashtable] $Context
    )

    function Protect-Html {
        param([string] $Text)
        if ([string]::IsNullOrEmpty($Text)) { return '' }
        return [System.Net.WebUtility]::HtmlEncode($Text)
    }

    $css = @'
:root{
  --ink:#15181C; --ink-soft:#5B6672; --ink-faint:#8B95A1;
  --paper:#FFFFFF; --surface:#EFF2F5; --rule:#D3DAE1;
  --sev-critical:#A81E12; --sev-high:#BA5A00; --sev-medium:#7E6500;
  --sev-low:#2F6394; --sev-info:#5B6672; --sev-pass:#1C6B49;
  --mono:ui-monospace,"Cascadia Mono","Consolas","DejaVu Sans Mono",monospace;
  --sans:"Segoe UI",-apple-system,"Helvetica Neue",Arial,sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--sans);
     font-size:15px;line-height:1.55;-webkit-font-smoothing:antialiased}
.wrap{max-width:1080px;margin:0 auto;padding:48px 28px 96px}

header{border-bottom:2px solid var(--ink);padding-bottom:20px;margin-bottom:8px}
.eyebrow{font-family:var(--mono);font-size:11px;letter-spacing:.16em;
         text-transform:uppercase;color:var(--ink-faint);margin:0 0 10px}
h1{font-size:30px;line-height:1.15;font-weight:650;margin:0 0 14px;letter-spacing:-.02em}
.meta{display:flex;flex-wrap:wrap;gap:0 32px;font-family:var(--mono);font-size:12px;color:var(--ink-soft)}
.meta b{color:var(--ink);font-weight:600}

.ledger{margin:28px 0 40px;border:1px solid var(--rule);background:var(--surface)}
.ledger-h{font-family:var(--mono);font-size:11px;letter-spacing:.14em;text-transform:uppercase;
          color:var(--ink-soft);padding:10px 14px;border-bottom:1px solid var(--rule)}
.cells{display:grid;grid-template-columns:repeat(auto-fill,minmax(104px,1fr));gap:1px;background:var(--rule)}
.cell{background:var(--paper);padding:10px 12px 12px;text-decoration:none;display:block}
.cell:hover{background:#F7F9FB}
.cell .bar{height:4px;width:100%;margin-bottom:8px;background:var(--sev-info)}
.cell .cid{font-family:var(--mono);font-size:12px;font-weight:600;color:var(--ink);display:block}
.cell .cnt{font-family:var(--mono);font-size:11px;color:var(--ink-faint)}

.count-row{display:flex;flex-wrap:wrap;gap:1px;background:var(--rule);border:1px solid var(--rule);margin-bottom:16px}
.tally{flex:1 1 120px;background:var(--paper);padding:14px 16px;border:0;text-align:left;
       font-family:inherit;cursor:pointer;display:block;transition:background .12s;
       box-shadow:inset 0 0 0 0 transparent}
.tally:hover:not(:disabled){background:#F7F9FB}
.tally:disabled{cursor:default;opacity:.45}
.tally:focus-visible{outline:2px solid var(--sev-low);outline-offset:-2px}
/* Selected state stays light so the severity-coloured number keeps its contrast. */
.tally[aria-pressed="true"]{background:#E4EAF0;box-shadow:inset 0 -3px 0 0 currentColor}
.tally .n{font-family:var(--mono);font-size:26px;font-weight:600;line-height:1;display:block}
.tally .l{font-family:var(--mono);font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--ink-soft)}
.filter-note{font-family:var(--mono);font-size:12px;color:var(--ink-soft);margin:0 0 28px;display:none}
.filter-note button{font-family:var(--mono);font-size:12px;background:none;border:0;padding:0 0 0 8px;
                    color:var(--sev-low);cursor:pointer;text-decoration:underline}
#findings{margin-top:28px}
.is-hidden{display:none !important}

.f-ref{margin:10px 0 0;font-family:var(--mono);font-size:12px}
.f-ref a{color:var(--sev-low);text-decoration:none;border-bottom:1px solid var(--rule)}
.f-ref a:hover{border-bottom-color:var(--sev-low)}
.f-ref span{color:var(--ink-faint);letter-spacing:.08em;text-transform:uppercase;margin-right:8px}

section.cat{margin-bottom:44px}
h2{font-size:13px;font-family:var(--mono);letter-spacing:.16em;text-transform:uppercase;
   color:var(--ink-soft);margin:0 0 14px;padding-bottom:8px;border-bottom:1px solid var(--rule)}

article.f{border-left:5px solid var(--sev-info);background:var(--surface);
          padding:16px 20px;margin-bottom:14px}
article.f.pass{background:transparent;border-left-color:var(--sev-pass);padding:10px 20px}
.f-top{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
.f-id{font-family:var(--mono);font-size:12px;font-weight:600;color:var(--ink-soft)}
.f-sev{font-family:var(--mono);font-size:11px;letter-spacing:.1em;text-transform:uppercase;font-weight:600}
.f-title{font-size:17px;font-weight:620;margin:6px 0 8px;letter-spacing:-.01em;flex-basis:100%}
.f-sum{margin:0 0 10px;color:var(--ink)}
.f-rem{margin:0;padding-left:14px;border-left:2px solid var(--rule);color:var(--ink-soft);font-size:14px}
.f-rem b{font-family:var(--mono);font-size:11px;letter-spacing:.1em;text-transform:uppercase;
         color:var(--ink-faint);display:block;margin-bottom:2px}

details{margin-top:12px}
summary{cursor:pointer;font-family:var(--mono);font-size:12px;color:var(--ink-soft);padding:6px 0}
summary:hover{color:var(--ink)}
summary:focus-visible{outline:2px solid var(--sev-low);outline-offset:2px}
table{width:100%;border-collapse:collapse;margin-top:8px;font-family:var(--mono);font-size:12px}
th{text-align:left;font-weight:600;color:var(--ink-soft);border-bottom:1px solid var(--rule);
   padding:6px 10px 6px 0;font-size:11px;letter-spacing:.08em;text-transform:uppercase}
td{padding:5px 10px 5px 0;border-bottom:1px solid var(--rule);vertical-align:top;
   word-break:break-word;color:var(--ink)}
td.dn{color:var(--ink-faint);font-size:11px}
.trunc{font-family:var(--mono);font-size:11px;color:var(--ink-faint);margin-top:8px}

footer{margin-top:64px;padding-top:16px;border-top:1px solid var(--rule);
       font-family:var(--mono);font-size:11px;color:var(--ink-faint);line-height:1.7}

@media print{
  body{font-size:11pt}
  .wrap{max-width:none;padding:0}
  details{display:block}
  details>summary{display:none}
  article.f{break-inside:avoid;background:transparent;border-left-width:3px}
  /* A filtered view must not silently print an incomplete report. */
  .is-hidden{display:block !important}
  .count-row,.filter-note{display:none}
}
@media (max-width:640px){
  .wrap{padding:28px 16px 64px}
  h1{font-size:23px}
  .meta{gap:0 18px}
}
'@

    $sevClass = @{
        'Critical' = 'critical'; 'High' = 'high'; 'Medium' = 'medium'
        'Low' = 'low'; 'Info' = 'info'; 'Pass' = 'pass'
    }

    $cells = foreach ($f in ($Findings | Sort-Object { $script:SeverityRank[$_.Severity] }, Id)) {
        $c = $sevClass[$f.Severity]
        @"
<a class="cell" href="#$($f.Id)">
  <span class="bar" style="background:var(--sev-$c)"></span>
  <span class="cid">$(Protect-Html $f.Id)</span>
  <span class="cnt">$($f.Count) obj.</span>
</a>
"@
    }

    $tallies = foreach ($s in @('Critical','High','Medium','Low','Info','Pass')) {
        $n = @($Findings | Where-Object { $_.Severity -eq $s }).Count
        $c = $sevClass[$s]
        $disabled = if ($n -eq 0) { ' disabled' } else { '' }
        @"
<button type="button" class="tally" data-sev="$c" aria-pressed="false"$disabled
        style="color:var(--sev-$c)" title="Show only $s findings">
  <span class="n" style="color:var(--sev-$c)">$n</span><span class="l">$s</span>
</button>
"@
    }

    $sections = foreach ($cat in ($Findings | Select-Object -ExpandProperty Category -Unique | Sort-Object)) {
        $items = foreach ($f in ($Findings | Where-Object { $_.Category -eq $cat } |
                                 Sort-Object { $script:SeverityRank[$_.Severity] }, Id)) {
            $c = $sevClass[$f.Severity]
            $passClass = if ($f.Severity -eq 'Pass') { ' pass' } else { '' }

            $ref = Get-ADHProp $f 'Reference'
            $refHtml = ''
            if ($ref) {
                $refHtml = @"
<p class="f-ref"><span>Reference</span><a href="$(Protect-Html $ref.Url)" target="_blank" rel="noopener">$(Protect-Html $ref.Title)</a></p>
"@
            }

            $detail = ''
            if ($f.Objects.Count -gt 0) {
                $rows = foreach ($o in ($f.Objects | Select-Object -First $MaxObjectsPerFinding)) {
                    "<tr><td>$(Protect-Html $o.Name)</td><td>$(Protect-Html $o.Details)</td><td class=""dn"">$(Protect-Html $o.DistinguishedName)</td></tr>"
                }
                $trunc = if ($f.Objects.Count -gt $MaxObjectsPerFinding) {
                    "<p class=""trunc"">$($f.Objects.Count - $MaxObjectsPerFinding) further objects are in the JSON export only.</p>"
                } else { '' }

                $detail = @"
<details>
  <summary>show $($f.Objects.Count) affected objects</summary>
  <table><thead><tr><th>Name</th><th>Details</th><th>Distinguished name</th></tr></thead>
  <tbody>$($rows -join "`n")</tbody></table>
  $trunc
</details>
"@
            }

            @"
<article class="f$passClass" id="$(Protect-Html $f.Id)" data-sev="$c" style="border-left-color:var(--sev-$c)">
  <div class="f-top">
    <span class="f-id">$(Protect-Html $f.Id)</span>
    <span class="f-sev" style="color:var(--sev-$c)">$(Protect-Html $f.Severity)</span>
    <span class="f-title">$(Protect-Html $f.Title)</span>
  </div>
  <p class="f-sum">$(Protect-Html $f.Summary)</p>
  <p class="f-rem"><b>Remediation</b>$(Protect-Html $f.Remediation)</p>
  $refHtml
  $detail
</article>
"@
        }

        "<section class=""cat""><h2>$(Protect-Html $cat)</h2>$($items -join "`n")</section>"
    }

    @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AD security assessment - $(Protect-Html $Context.Domain)</title>
<style>$css</style>
</head>
<body>
<div class="wrap">

<header>
  <p class="eyebrow">Active Directory / read-only assessment</p>
  <h1>Security assessment: $(Protect-Html $Context.Domain)</h1>
  <div class="meta">
    <span>Generated <b>$(Protect-Html $Context.Timestamp)</b></span>
    <span>Domain controller <b>$(Protect-Html $Context.Server)</b></span>
    <span>Run as <b>$(Protect-Html $Context.RunAs)</b></span>
    <span>Stale threshold <b>$($Context.StaleDays) days</b></span>
  </div>
</header>

<div class="ledger">
  <div class="ledger-h">Check strip - $($Findings.Count) of $($Context.TotalChecks) checks run</div>
  <div class="cells">$($cells -join "`n")</div>
</div>

<div class="count-row">$($tallies -join "`n")</div>

<p class="filter-note" id="filterNote"></p>

<div id="findings">
$($sections -join "`n")
</div>

<footer>
  Generated by Invoke-ADSecurityScan.ps1 - read-only queries, no directory modifications.<br>
  Last logon values come from lastLogonTimestamp and may lag reality by up to 14 days.<br>
  Not a substitute for a full security review: SYSVOL permissions, GPO contents and trust relationships are out of scope.
</footer>

</div>

<script>
(function () {
  // Clicking a severity tally filters the report down to that severity and
  // jumps to the findings. Clicking it again restores the full view. Findings
  // are grouped by category, so a severity is scattered across sections -
  // filtering is what actually produces "the High section".
  var tallies = document.querySelectorAll('.tally[data-sev]');
  var articles = document.querySelectorAll('article.f[data-sev]');
  var sections = document.querySelectorAll('section.cat');
  var note = document.getElementById('filterNote');
  var active = null;

  function apply(sev) {
    active = sev;

    articles.forEach(function (a) {
      a.classList.toggle('is-hidden', sev !== null && a.dataset.sev !== sev);
    });

    // Hide category sections that no longer contain anything visible.
    sections.forEach(function (s) {
      var visible = s.querySelectorAll('article.f:not(.is-hidden)').length;
      s.classList.toggle('is-hidden', visible === 0);
    });

    tallies.forEach(function (t) {
      t.setAttribute('aria-pressed', String(t.dataset.sev === sev));
    });

    if (sev === null) {
      note.style.display = 'none';
      note.textContent = '';
    } else {
      var shown = document.querySelectorAll('article.f:not(.is-hidden)').length;
      note.style.display = 'block';
      note.textContent = 'Showing ' + shown + ' ' + sev + ' finding(s) only.';
      var reset = document.createElement('button');
      reset.type = 'button';
      reset.textContent = 'show all';
      reset.addEventListener('click', function () { apply(null); });
      note.appendChild(reset);
    }
  }

  tallies.forEach(function (t) {
    t.addEventListener('click', function () {
      var sev = t.dataset.sev;
      if (active === sev) { apply(null); return; }
      apply(sev);
      document.getElementById('findings').scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  });

  // Printing must never produce a silently incomplete report.
  window.addEventListener('beforeprint', function () { if (active !== null) { apply(null); } });
})();
</script>

</body>
</html>
"@
}

#############################################################################
# REGION: Main
#############################################################################

# Everything above is definitions. Stop here when the caller only wants the
# functions and the catalogue in scope - the Pester tests dot-source the script
# this way, which is why this sits before Import-Module ActiveDirectory.
if ($InitializeOnly) { return }

if ($ListChecks) {
    Show-CheckCatalogue
    return
}

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    throw 'The ActiveDirectory module was not found. Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0'
}

Register-ADHFormatData

# --- Decide which checks to run ---
$toRun = @()

if ($FullScan) {
    $toRun = $script:Catalogue
}
elseif ($Select) {
    $toRun = Resolve-CheckSelection -Tokens $Select
}
elseif ([Environment]::UserInteractive) {
    $toRun = Read-CheckSelection
}
else {
    Write-Warning 'Non-interactive session and no selection given - running the full catalogue.'
    $toRun = $script:Catalogue
}

# Certificate services live in the configuration partition and are therefore
# identical for every domain in the forest. When walking a multi-domain forest,
# run them once and skip them afterwards.
if ($SkipForestWide) {
    $before = @($toRun).Count
    $toRun = @($toRun | Where-Object { $_.Scope -ne 'Forest' })
    $skipped = $before - @($toRun).Count
    if ($skipped -gt 0) {
        Write-Host ('  Skipping {0} forest-wide check(s) as requested.' -f $skipped) -ForegroundColor DarkGray
    }
}

if (-not @($toRun).Count) {
    Write-Host ''
    Write-Host '  Nothing selected. Use -ListChecks to see the catalogue.' -ForegroundColor Yellow
    Write-Host ''
    return
}

$domainInfo = Get-ADHDomain
$p = Get-ADHParameter

$context = @{
    Domain      = $domainInfo.DNSRoot
    Server      = if ($Server) { $Server } else { @(Get-ADDomainController @p -Discover -ErrorAction SilentlyContinue).HostName -join ',' }
    Timestamp   = (Get-Date).ToString('yyyy-MM-dd HH:mm')
    RunAs       = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    StaleDays   = $StaleDays
    TotalChecks = $script:Catalogue.Count
}

if (-not $Quiet) { Write-ADHBanner -Context $context -Selected $toRun }

$findings = New-Object System.Collections.Generic.List[object]
$started = Get-Date
$index = 0
$total = @($toRun).Count

if (-not $Quiet) { Write-ADHSectionHeading 'Running' }

foreach ($check in $toRun) {
    $index++
    $checkStart = Get-Date
    $result = $null

    try {
        $result = & $check.Action
        if ($result) { $findings.Add($result) }
    }
    catch {
        $result = New-ADHFinding -Id $check.Id -Category 'Errors' -Severity 'Info' `
            -Title ('Check {0} could not be completed' -f $check.Id) `
            -Summary $_.Exception.Message `
            -Remediation 'Verify permissions and domain controller reachability, then re-run with -Verbose.'
        $findings.Add($result)
        if (-not $Quiet) {
            Write-ADHCheckResult -Index $index -Total $total -Check $check -Finding $null `
                -Seconds ((Get-Date) - $checkStart).TotalSeconds
            Write-Host ('              {0}' -f $_.Exception.Message) -ForegroundColor DarkYellow
        }
        continue
    }

    if (-not $Quiet) {
        Write-ADHCheckResult -Index $index -Total $total -Check $check -Finding $result `
            -Seconds ((Get-Date) - $checkStart).TotalSeconds
    }
}

$elapsed = (Get-Date) - $started

# --- Apply approved exceptions ---
$exceptionPath = Get-ADHExceptionPath
if ($exceptionPath) {
    $exceptions = Get-ADHException -Path $exceptionPath
    $suppressed = Invoke-ADHExceptionFilter -Findings $findings -Exceptions $exceptions
    $findings.Add((New-ADHExceptionFinding -Exceptions $exceptions -Path $exceptionPath -Suppressed $suppressed))

    if (-not $Quiet) {
        Write-Host ''
        Write-Host ('   {0} exception(s) loaded from {1}, {2} object(s) suppressed' -f `
            @($exceptions).Count, (Split-Path -Leaf $exceptionPath), $suppressed) -ForegroundColor DarkGray
    }
}

if (-not $Quiet) {
    Write-ADHConsoleReport -Findings $findings `
        -ShowObjects:(-not $Compact) -MaxObjects $MaxConsoleObjects
    Write-ADHConsoleSummary -Findings $findings -Elapsed $elapsed
}

# --- File output ---
if (-not $NoReport) {
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmm'
    $base  = Join-Path $OutputPath ('ADSecurityScan_{0}_{1}' -f $context.Domain, $stamp)

    if (-not $Quiet) { Write-ADHSectionHeading 'Output' }

    $htmlPath = "$base.html"
    ConvertTo-ADHHtml -Findings $findings -Context $context | Out-File -LiteralPath $htmlPath -Encoding UTF8
    if (-not $Quiet) { Write-ADHField 'HTML' $htmlPath 'Green' }

    if ($IncludeJson) {
        $jsonPath = "$base.json"
        $findings | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $jsonPath -Encoding UTF8
        if (-not $Quiet) { Write-ADHField 'JSON' $jsonPath 'Green' }
    }

    if ($IncludeCsv) {
        $csvPath = "$base.csv"
        $flat = foreach ($f in $findings) {
            foreach ($o in $f.Objects) {
                [PSCustomObject]@{
                    CheckId           = $f.Id
                    Category          = $f.Category
                    Severity          = $f.Severity
                    Check             = $f.Title
                    Object            = $o.Name
                    Details           = $o.Details
                    DistinguishedName = $o.DistinguishedName
                }
            }
        }
        $flat | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
        if (-not $Quiet) { Write-ADHField 'CSV' $csvPath 'Green' }
    }

    if (-not $Quiet) {
        Write-Host ''
        Write-Host '   Reports map out the domain in detail - store them like credentials.' -ForegroundColor DarkGray
        Write-Host ''
    }
}

# Findings only reach the pipeline on request - otherwise the console report
# above would be followed by a second, redundant object dump.
if ($PassThru) {
    $findings
}
elseif (-not $Quiet -and -not $Compact) {
    Write-Host '   Tip: -Compact for one line per finding, -PassThru to get the objects.' -ForegroundColor DarkGray
    Write-Host ''
}
