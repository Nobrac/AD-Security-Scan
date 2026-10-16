<div align="center">

# AD-Security-Scan

43 read-only checks against Active Directory, run from a standard domain user account.

![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)
&nbsp;
![Platform: Windows](https://img.shields.io/badge/platform-Windows-0078D6)
&nbsp;
![Checks: 43](https://img.shields.io/badge/checks-43-0A7B4E)
&nbsp;
![Access: read-only](https://img.shields.io/badge/access-read--only-6E44FF)
&nbsp;
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

</div>

AD-Security-Scan is a single PowerShell script. It queries a domain over LDAP, looks for the misconfigurations that lead to domain compromise and writes a prioritised console report plus an HTML report. Everything it finds is visible to anyone with one compromised user credential.

It covers Kerberoasting and AS-REP roasting, unconstrained and resource-based delegation, DCSync rights on the domain root, write access on AdminSDHolder and tier-0 groups, GPOs linked to the Domain Controllers OU, and certificate template misconfigurations (ESC1 to ESC9) that let a normal user request a logon certificate for any identity in the forest.

The script only uses `Get-AD*` cmdlets and contains no `Set-`, `New-` or `Remove-` calls. It installs no agent, service or scheduled task and makes no schema change. The only files it writes go to the output directory you name. Every check except `ADCS-007` runs as an ordinary domain user; `ADCS-007` reads the CA registry remotely and falls back to an `Info` finding without admin rights on the CA. The one side effect is LDAP load on the queried controller, so in large domains run it outside business hours against a controller that is not the PDC emulator.

> [!NOTE]
> Most of the code and documentation here was written by Claude (Anthropic) in a pair-programming workflow. I defined the requirements, reviewed the results, and tested and deployed everything in a real Active Directory environment. Review it before running it in production, as you would any code you did not write.

## What it checks

Each check has a catalogue number and an ID, so you can run any subset by number, range, ID or category.

### Kerberos and delegation

| # | ID | Check | Why it matters |
| --- | --- | --- | --- |
| 1 | `KRB-001` | Kerberoastable accounts (SPN on user objects) | Any domain user can request a ticket and crack the password offline |
| 2 | `KRB-002` | Kerberos pre-authentication disabled | The KDC hands out a crackable blob with no authentication at all |
| 3 | `KRB-003` | krbtgt password age | An old key extends the life of any golden ticket indefinitely |
| 4 | `KRB-004` | Weak encryption (DES/RC4) on SPN and admin accounts | RC4 tickets crack much faster than AES; DES is broken outright |
| 5 | `DEL-001` | Unconstrained delegation outside DCs | The host caches every visitor's TGT, including a domain admin's |
| 6 | `DEL-002` | Constrained delegation with protocol transition | Mint a ticket for any user; with a DC service as target that is domain compromise |
| 7 | `DEL-003` | Resource-based constrained delegation configured | Legitimate feature, common persistence mechanism |

### Privileged accounts and passwords

| # | ID | Check | Why it matters |
| --- | --- | --- | --- |
| 8 | `PRIV-001` | Tier-0 group membership | Includes the operator groups everyone forgets to empty |
| 9 | `PRIV-002` | Privileged accounts without delegation protection | Credentials that can still be forwarded and reused |
| 10 | `PRIV-003` | Orphaned adminCount flags | AdminSDHolder keeps inheritance off, permissions stop making sense |
| 11 | `PWD-001` | Non-expiring passwords on enabled accounts | Leaked once, valid forever |
| 12 | `PWD-002` | Accounts that may have a blank password | The domain policy is not enforced for them |
| 13 | `PWD-003` | Passwords stored with reversible encryption | Effectively clear text inside NTDS.dit |
| 14 | `PWD-004` | Privileged passwords older than one year | Hard-coded service credentials and forgotten break-glass accounts |
| 15 | `PWD-005` | Default domain password policy | Length, complexity, history, lockout |

### Account hygiene and infrastructure

| # | ID | Check | Why it matters |
| --- | --- | --- | --- |
| 16 | `ACC-001` | Stale enabled user accounts | Nobody notices unusual activity on an account nobody uses |
| 17 | `ACC-002` | Stale enabled computer accounts | Keeps its password, convenient for persistence |
| 18 | `ACC-003` | Objects carrying SID history | A hidden access channel once the migration is done |
| 19 | `ACC-004` | Possible credentials in description/info fields | Every authenticated user can read these |
| 20 | `INF-001` | MachineAccountQuota | Above zero, every user can create computer accounts |
| 21 | `INF-002` | Domain controllers and functional levels | Legacy DCs block Protected Users and authentication policy silos |
| 22 | `INF-003` | End-of-life operating systems | No patches, and they force weak protocols to stay enabled |
| 23 | `INF-004` | LAPS coverage | Identical local admin passwords enable lateral movement |

### Trusts and group policy

| # | ID | Check | Why it matters |
| --- | --- | --- | --- |
| 24 | `TRUST-001` | Trust configuration: SID filtering, TGT delegation, selective auth | Without SID filtering the other side can inject your Domain Admins' SIDs |
| 25 | `GPO-001` | Stored credentials in SYSVOL (cpassword) | The decryption key is public and SYSVOL is readable by every domain user |

### Directory permissions

| # | ID | Check | Why it matters |
| --- | --- | --- | --- |
| 26 | `ACL-001` | Replication rights on the domain root (DCSync) | Pull every password hash, krbtgt included, without touching a DC |
| 27 | `ACL-002` | Dangerous permissions on tier-0 groups | Membership without appearing in the membership list |
| 28 | `ACL-003` | Dangerous permissions on privileged accounts | Password reset or `msDS-KeyCredentialLink` write is full takeover |
| 29 | `ACL-004` | Dangerous permissions on AdminSDHolder | One ACE stamped hourly onto every admin object in the domain |
| 30 | `ACL-005` | Broad delegations on organizational units | The delegation wizard grants more than people intend |
| 31 | `ACL-006` | Privileged objects with non-privileged owners | An owner can rewrite the ACL regardless of what it says |
| 32 | `ACL-007` | Dangerous permissions on DC objects | Write access here is direct domain controller compromise |
| 33 | `ACL-008` | Write access on group policy objects | Editing a GPO is code execution everywhere it applies |
| 34 | `ACL-009` | Delegated write access on group membership | Harmless one by one, an escalation chain together |

### Certificate services (AD CS)

These checks are forest-scoped and give the same result for every domain in the forest. Use `-SkipForestWide` when walking a multi-domain forest so they run once.

| # | ID | Check | Reference |
| --- | --- | --- | --- |
| 35 | `ADCS-001` | Certificate services inventory (CAs, templates, NTAuth) | |
| 36 | `ADCS-002` | Requester-supplied subject with an authentication EKU | ESC1 |
| 37 | `ADCS-003` | Templates without a purpose restriction | ESC2 |
| 38 | `ADCS-004` | Broadly enrollable enrollment agent templates | ESC3 |
| 39 | `ADCS-005` | Write access on certificate templates | ESC4 |
| 40 | `ADCS-006` | Dangerous permissions on PKI objects | ESC5 / ESC7 |
| 41 | `ADCS-007` | CA accepts a subject alternative name from the request | ESC6 |
| 42 | `ADCS-008` | Templates without the SID security extension | ESC9 |
| 43 | `ADCS-009` | Published templates with broad enrolment rights | |

Templates that exist but are not published on any CA cannot be requested. They still appear in the report at a lower rating, since publishing one takes a single click.

## Requirements

- Windows with PowerShell 5.1 or 7.x.
- The RSAT `ActiveDirectory` module: `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` (on a server: `Install-WindowsFeature RSAT-AD-PowerShell`).
- A standard domain account. Do not run it as Domain Admin, or you measure what an admin can see instead of what an attacker with one user account can see.
- Optional: local admin on the CA host, only for `ADCS-007`.

> [!IMPORTANT]
> Run it in a lab or test domain first. The script is read-only, but read any script from the internet before you run it in production.

## Quick start

Files downloaded from the internet carry a zone marker that stops PowerShell from running them, so unblock the script first:

```powershell
Unblock-File .\Invoke-ADSecurityScan.ps1
```

You can check that it parses without executing anything:

```powershell
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path .\Invoke-ADSecurityScan.ps1), [ref]$null, [ref]$errors) | Out-Null
$errors
```

List the checks, then run it. Without arguments you get a menu of profiles and categories:

```powershell
.\Invoke-ADSecurityScan.ps1 -ListChecks
.\Invoke-ADSecurityScan.ps1
```

`-Select essential` runs the fourteen Tier-0 checks. A full scan with all export formats:

```powershell
.\Invoke-ADSecurityScan.ps1 -FullScan -OutputPath C:\Reports -IncludeJson -IncludeCsv
```

The HTML report is written to the output directory as `ADSecurityScan_<domain>_<timestamp>.html`. It has everything inlined, so it opens offline and prints to PDF.

## Selecting checks

The menu offers three profiles (Everything, 43 checks; Quick pass, 25 fast checks; Tier-0 essentials, 14 checks) and one row per category. Enter several rows as `5,7,12`. You see a summary, a warning if slow checks are included, and a confirmation prompt before anything runs. `L` opens the full numbered list for picking single checks. The menu rejects ranges at the top level because `1-3` could mean menu rows or check numbers; inside the `L` list, ranges refer to catalogue numbers.

Tier-0 essentials are the checks where a finding is already a compromise or one step from one: `KRB-001`, `KRB-003`, `DEL-001`, `DEL-002`, `PRIV-001`, `PWD-002`, `PWD-003`, `TRUST-001`, `GPO-001`, `ACL-001`, `ACL-004`, `ACL-007`, `ACL-008`, `ADCS-002`.

`-Select` takes the same profiles plus more specific tokens, and you can combine them: `-Select 1-6,ADCS,PWD-002`.

| Token | Selects |
| --- | --- |
| `all` / `full` | every check |
| `quick` / `fast` | fast checks only, about a minute |
| `essential` / `tier0` | the Tier-0 essentials profile |
| `slow` | only the expensive checks, for a separate off-hours run |
| `domain` / `forest` | by scope; `domain` skips the ADCS checks |
| `Kerberos`, `Permissions` | a whole category by name |
| `ACL`, `ADCS`, `PWD` | every check with that ID prefix |
| `KRB-001` | one check by ID |
| `7` | one check by catalogue number |
| `1-14` | a range of catalogue numbers |

The script warns about unrecognised tokens and skips them. Fast checks are single LDAP queries. Slow checks read one security descriptor per object or reach outside LDAP, and they account for most of the runtime.

## Output

While the scan runs, each check prints its ID, outcome and object count, plus the elapsed time if it took over three seconds. Findings follow, grouped by severity, with each affected object listed:

```
  CRITICAL (5) ------------------------------------------------------------------------------------

   ACL-001   Replication rights on the domain root (DCSync)                                      2

        CONTOSO\svc-legacy-sync
          FULL REPLICATION POSSIBLE
          rights: DS-Replication-Get-Changes, DS-Replication-Get-Changes-All
          CN=svc-legacy-sync,OU=Service,DC=contoso,DC=local
```

The console lists 15 objects per finding (`-MaxConsoleObjects` changes that). `-Compact` prints one line per finding, which reads better for a full scan, and `-Quiet` turns console output off for scheduled runs.

| Format | Contains | Use it for |
| --- | --- | --- |
| Console | findings with objects, colour-coded by severity | working through results |
| HTML | everything, with severity filters, Microsoft references and collapsible object tables | handing over, PDF, management |
| JSON (`-IncludeJson`) | every finding and object, untruncated | diffing runs, ticket systems |
| CSV (`-IncludeCsv`) | one row per affected object | Excel, assigning owners |

In the HTML report, clicking a severity tally filters the report to that severity; click it again or use *show all* to reset. Printing always resets the filter first, so a PDF is never silently incomplete. Each finding links to the Microsoft page that explains how to fix it (for example the gMSA overview for `KRB-001`, MS14-025 for `GPO-001`, KB5014754 for `ADCS-008`). Where Microsoft has no single page, the link opens a Microsoft Learn search.

The script returns nothing on the pipeline by default, because PowerShell would print the nested objects as a second, unreadable dump. `-PassThru` returns the finding objects with proper formatting, including the references:

```powershell
$f = .\Invoke-ADSecurityScan.ps1 -FullScan -PassThru -Quiet

$f                                                    # table: Severity, ID, Objects, Check
$f | Where-Object Severity -eq 'Critical'
$f | Where-Object Id -eq 'KRB-001' | Format-List
$f | Where-Object Id -eq 'ACL-005' | Select-Object -ExpandProperty Objects | Out-GridView
```

```powershell
$f = .\Invoke-ADSecurityScan.ps1 -Select essential -PassThru -Quiet -NoReport
$f | Select-Object Id, Severity, @{n='Doc';e={$_.Reference.Url}}
```

## Approved exceptions

Some findings are intentional, such as the DCSync rights of an Entra Connect account. To stop them showing up as critical on every run, put a file called `ADSecurityScan.exceptions.json` next to the script. The script loads it automatically:

```json
{
  "exceptions": [
    {
      "checkId": "ACL-001",
      "object": "CONTOSO\\svc-entraconnect",
      "reason": "Entra Connect sync account. DCSync is required by the product; treated as tier 0.",
      "approvedBy": "Security Board, ticket CHG-2041",
      "expires": "2026-12-31"
    }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `checkId` | Exact ID or wildcard, e.g. `ACL-001`, `ACL-*` |
| `object` | Matched with `-like` against the object name and its distinguished name, so `svc-sql-prd*` works |
| `reason` | Why the risk is accepted |
| `approvedBy` | Who signed it off |
| `expires` | `yyyy-MM-dd`, the date the acceptance runs out |

> [!IMPORTANT]
> All fields are mandatory, including `expires`. You cannot write an exception that never expires.

Once an entry expires, the finding comes back at full severity. Each run adds an `EXC-001` finding that lists what is suppressed, what has expired and what expires within 30 days. If every object in a finding is covered, the finding drops to `Pass` with a note. Use `-ExceptionFile` to load a different file, or `-NoExceptions` to ignore it for one run.

## Handling the reports

> [!WARNING]
> The output is a target list. It shows Kerberoastable service accounts with password ages, hosts with unconstrained delegation, who holds DCSync and which certificate template lets any user request a Domain Admin certificate. That is the reconnaissance an attacker would otherwise have to do, sorted by usefulness. The scan is read-only; the reports are sensitive.

Treat the reports like credentials:

- Keep them out of `Downloads`, file shares and tickets that many people can read.
- Do not send them by mail. Share a location instead of an attachment.
- Never commit them. Exclude `ADSecurityScan_*` in `.gitignore`.
- Store them where your tier-0 data lives and delete them once remediation is done.

`ACC-004` reports only which keyword matched, never the field contents, and `GPO-001` reports file paths without decrypting anything.

## Parameters

| Parameter | Purpose |
| --- | --- |
| `-Select <tokens>` | Checks to run: numbers, ranges, IDs, categories, profiles |
| `-FullScan` | Run every check |
| `-ListChecks` | Print the numbered catalogue and exit |
| `-Server <dc>` | Target a specific domain controller or domain |
| `-Credential` | Alternate credentials |
| `-OutputPath <dir>` | Report directory (default: current) |
| `-StaleDays <n>` | Inactivity threshold for `ACC-001` / `ACC-002`, default 90 |
| `-IncludeJson` / `-IncludeCsv` | Additional export formats |
| `-NoReport` | Skip file output |
| `-Compact` | One line per finding instead of full detail |
| `-MaxConsoleObjects <n>` | Objects listed per finding in the console, default 15 |
| `-MaxObjectsPerFinding <n>` | Objects listed per finding in the HTML, default 50 |
| `-Quiet` | Suppress the console report |
| `-PassThru` | Return finding objects on the pipeline |
| `-ExceptionFile <path>` | Use a different exceptions file |
| `-NoExceptions` | Ignore the exceptions file for this run |
| `-SkipForestWide` | Skip the forest-scoped ADCS checks |

## Where to start

A first scan of a domain that was never assessed finds a lot. Working through it by severity is slower than this order:

1. Findings that already mean compromise: `ACL-001` with full replication rights, `ACL-004`, `PWD-003`, and any `ADCS-002` finding on a published template. Treat an unexplained entry here as an incident.
2. Single-step paths to the domain: `DEL-001`, `ACL-007`, `ACL-008` where a GPO is linked to tier 0, and `KRB-001` on privileged accounts. These are usually small, well-scoped changes.
3. Foundations: `INF-004` (LAPS), `INF-001` (set MachineAccountQuota to zero), `PRIV-001` (empty the operator groups). They limit the damage from everything you have not fixed yet.
4. The rest: `ACL-005`, `ACL-009`, `ACC-001`, `ACC-002` have the biggest object counts and the least urgency. Handle them as recurring hygiene.

> [!TIP]
> Export JSON on every run and keep the files. Diffing two scans shows what changed, and unrequested changes in tier 0 are the findings to act on first.

## Troubleshooting

**`File cannot be loaded because running scripts is disabled on this system.`**
Execution policy. Run `powershell.exe -ExecutionPolicy Bypass -File .\Invoke-ADSecurityScan.ps1`, or `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` for the current session. A file from a browser or mail attachment also needs `Unblock-File .\Invoke-ADSecurityScan.ps1`; the zone marker is separate from the execution policy.

**`The ActiveDirectory module was not found.`**
Install the RSAT module as shown under [Requirements](#requirements). The script needs only that module, not all of RSAT.

**`The variable "$x" cannot be retrieved because it has not been set.`**
The script runs under `Set-StrictMode -Version Latest`, and AD objects have many optional attributes. Open an issue with the variable or property the error names. As a stopgap, lower the strict mode to `-Version 2.0` at the top of the script; that still catches uninitialised variables but not missing properties.

**A check fails with access denied.**
Some security descriptors are not readable by every account, and `Get-ADDomainController -Discover` can fail across sites. A failed check becomes an `Info` finding with the error message and the scan continues. Re-run with `-Verbose` to see the object. If several permission checks fail, make sure you are querying a controller in the domain you meant.

**`ADCS-007` always reports `Info` / "registry not readable".**
Expected without local admin on the CA host or with Remote Registry disabled there. Check by hand on the CA with `certutil -config "<CA-Host>\<CA-Name>" -getreg policy\EditFlags` and look for `EDITF_ATTRIBUTESUBJECTALTNAME2`.

**`ACL-005` returns hundreds of findings.**
This is common. The Delegation of Control wizard often grants full control where someone wanted password resets, and those rights inherit downward. Start with the OUs that hold servers and privileged accounts. If a group is legitimately delegated in your environment, add its SID to `Get-ADHTrustedSid`.

**The scan is very slow.**
With 100,000 objects a full scan can take 45 minutes or more. Use `-Select fast` first, run the permission checks separately outside business hours, and point `-Server` at a controller that is not the PDC emulator.

**Garbled characters.**
The script uses ASCII only. If you modified it, PowerShell 5.1 consoles use an OEM code page; run `chcp 65001` first.

**"Nothing selected".**
Your tokens matched no checks. Category names must match the catalogue (`Permissions`, not `ACLs`); ID prefixes are separate tokens (`ACL`, `ADCS`, `PWD`). `-ListChecks` shows both.

## Design notes and limitations

- Only SYSTEM, Administrators, Domain/Enterprise/Schema Admins, Domain Controllers, SELF, Creator Owner and the Key Admins are exempt from the permission checks. Account, Server, Backup and Print Operators and *Pre-Windows 2000 Compatible Access* are reported, because they often carry historical rights. Add a SID to `Get-ADHTrustedSid` to exempt it.
- A check that finds nothing reports `Pass`, so the report shows what was examined.
- Permission analysis covers the domain root, AdminSDHolder, tier-0 groups and accounts, all OUs, GPOs and groups, and DC objects. It does not follow escalation chains through arbitrary objects; use a graph tool for that.
- Groups are resolved by well-known SID, so localised domains (German, French, ...) work. Nested membership uses `LDAP_MATCHING_RULE_IN_CHAIN`.
- `lastLogonTimestamp` replicates every 9 to 14 days, so dates in `ACC-001` and `ACC-002` are approximate.
- SYSVOL file permissions and GPO contents are not evaluated, only the directory permissions on GPO objects.
- ESC8 (web enrolment over HTTP) is listed as a manual check in `ADCS-001`. Probing it would mean sending traffic beyond directory reads.
- Cross-forest paths are out of scope. `TRUST-001` reports the trust configuration this domain can see.
- One domain per run. In a multi-domain forest, run it once per domain with `-Server`.
- Severity thresholds (how many tier-0 members, how old a password) are experience-based defaults. Adjust them to your environment.
- `ACC-004` is a keyword search and produces false positives, such as "reset password at first logon".
- `GPO-001` needs SMB access to SYSVOL.
- The script changes nothing. Remediation is up to you.

## License

[MIT](LICENSE)
