<div align="center">

# AD-Security-Scan

### 39 read-only checks against your Active Directory — run from a plain user account, because that is all an attacker needs.

A single PowerShell script that queries a domain over LDAP, finds the misconfigurations that actually lead to domain compromise, and turns them into a prioritised console output and an HTML report you can hand to management.

![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)
&nbsp;
![Platform: Windows](https://img.shields.io/badge/platform-Windows-0078D6)
&nbsp;
![Checks: 39](https://img.shields.io/badge/checks-39-0A7B4E)
&nbsp;
![Access: read-only](https://img.shields.io/badge/access-read--only-6E44FF)
&nbsp;
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

[Checks](#what-it-checks) · [Quick start](#quick-start) · [Output](#output) · [Triage](#where-to-start) · [Troubleshooting](#troubleshooting)

</div>

---

AD-Security-Scan answers the question every internal assessment starts with: *if someone phished one ordinary user today, what would they find?* The script runs entirely from a standard domain account and reads nothing but LDAP — no agent, no installation, no write access, no Domain Admin. Everything it reports is visible to anyone holding a single compromised credential, which is exactly what makes the report persuasive.

It covers the paths that turn one account into domain ownership: Kerberoasting and AS-REP roasting, unconstrained and resource-based delegation, DCSync rights on the domain root, write access on AdminSDHolder and tier-0 groups, GPOs linked to the Domain Controllers OU, and the certificate template misconfigurations (ESC1–ESC9) that let a normal user request a logon certificate for any identity in the forest.

Everything is one file. Copy it to a management workstation with RSAT and run it.

> [!NOTE]
> **Built with AI assistance.** Most of the code and documentation in this repository was written by Claude (Anthropic) in a pair-programming workflow: I defined the requirements, reviewed the results, and tested and deployed everything in a real Active Directory environment. As with any code you did not write yourself, review it before running it in production.

---

## Contents

- [Why a plain user account](#why-a-plain-user-account)
- [What it checks](#what-it-checks)
- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Selecting checks](#selecting-checks)
- [Output](#output)
- [Screenshots](#screenshots)
- [Parameter reference](#parameter-reference)
- [Where to start](#where-to-start)
- [Troubleshooting](#troubleshooting)
- [Design decisions](#design-decisions)
- [Limitations & notes](#limitations--notes)
- [Repository layout](#repository-layout)

---

## Why a plain user account

Most AD assessment tooling wants Domain Admin. This one does not, and that is the point rather than a limitation.

| | |
| --- | --- |
| **Read-only by construction** | Only `Get-AD*` cmdlets. No `Set-`, `New-` or `Remove-` anywhere in the file. The only writes go to the output directory you name. |
| **No Domain Admin** | 38 of 39 checks run from an ordinary domain user. The exception is `ADCS-007`, which reads the CA's registry remotely — it degrades to an `Info` finding and the scan continues. |
| **Nothing installed** | No agent, no service, no scheduled task, no schema change. Copy one `.ps1`, run it, delete it. |
| **The findings are the argument** | "A standard account can see this" lands very differently in a management meeting than a list of settings. |

The only side effect is LDAP load on the queried controller. In large domains, run outside business hours and target a controller that is not the PDC emulator.

```
        ┌──────────────────────────────┐
        │  Management workstation      │
        │  Invoke-ADSecurityScan.ps1   │   standard domain user
        └───────────────┬──────────────┘
                        │  LDAP  (read-only, no writes)
                        ▼
        ┌──────────────────────────────┐
        │  Domain controller           │   directory + configuration NC
        └───────────────┬──────────────┘
                        │
       ┌────────────────┼─────────────────┐
       ▼                ▼                 ▼
  console report    HTML report     JSON / CSV export
  (triage now)      (hand over)     (diff, ticket, SIEM)
```

---

## What it checks

39 checks across eight categories. Each one is numbered, so you can run any subset by number, range, ID or category.

### Kerberos & delegation

| # | ID | Check | Why it matters |
| --- | --- | --- | --- |
| 1 | `KRB-001` | Kerberoastable accounts (SPN on user objects) | Any domain user can request a ticket and crack the password offline |
| 2 | `KRB-002` | Kerberos pre-authentication disabled | The KDC hands out a crackable blob with no authentication at all |
| 3 | `KRB-003` | krbtgt password age | An old key extends the life of any golden ticket indefinitely |
| 4 | `DEL-001` | Unconstrained delegation outside DCs | The host caches every visitor's TGT — including a domain admin's |
| 5 | `DEL-002` | Constrained delegation with protocol transition | Mint a ticket for any user; a DC service as target means game over |
| 6 | `DEL-003` | Resource-based constrained delegation configured | Legitimate feature, favourite persistence mechanism |

### Privileged accounts & passwords

| # | ID | Check | Why it matters |
| --- | --- | --- | --- |
| 7 | `PRIV-001` | Tier-0 group membership | Includes the operator groups everyone forgets to empty |
| 8 | `PRIV-002` | Privileged accounts without delegation protection | Credentials that can still be forwarded and reused |
| 9 | `PRIV-003` | Orphaned adminCount flags | AdminSDHolder keeps inheritance off, permissions stop making sense |
| 10 | `PWD-001` | Non-expiring passwords on enabled accounts | Leaked once, valid forever |
| 11 | `PWD-002` | Accounts that may have a blank password | The domain policy is not enforced for them |
| 12 | `PWD-003` | Passwords stored with reversible encryption | Effectively clear text inside NTDS.dit |
| 13 | `PWD-004` | Privileged passwords older than one year | Hard-coded service credentials and forgotten break-glass accounts |
| 14 | `PWD-005` | Default domain password policy | Length, complexity, history, lockout |

### Account hygiene & infrastructure

| # | ID | Check | Why it matters |
| --- | --- | --- | --- |
| 15 | `ACC-001` | Stale enabled user accounts | Nobody notices unusual activity on an account nobody uses |
| 16 | `ACC-002` | Stale enabled computer accounts | Keeps its password, convenient for persistence |
| 17 | `ACC-003` | Objects carrying SID history | A hidden access channel once the migration is done |
| 18 | `INF-001` | MachineAccountQuota | Above zero, every user can create computer accounts |
| 19 | `INF-002` | Domain controllers and functional levels | Legacy DCs block Protected Users and authentication policy silos |
| 20 | `INF-003` | End-of-life operating systems | No patches, and they force weak protocols to stay enabled |
| 21 | `INF-004` | LAPS coverage | Identical local admin passwords are the basis of lateral movement |

### Directory permissions

| # | ID | Check | Why it matters |
| --- | --- | --- | --- |
| 22 | `ACL-001` | Replication rights on the domain root (DCSync) | Pull every password hash, krbtgt included, without touching a DC |
| 23 | `ACL-002` | Dangerous permissions on tier-0 groups | Membership without appearing in the membership list |
| 24 | `ACL-003` | Dangerous permissions on privileged accounts | Password reset or `msDS-KeyCredentialLink` write is full takeover |
| 25 | `ACL-004` | Dangerous permissions on AdminSDHolder | One ACE stamped hourly onto every admin object in the domain |
| 26 | `ACL-005` | Broad delegations on organizational units | The delegation wizard grants more than people intend |
| 27 | `ACL-006` | Privileged objects with non-privileged owners | An owner can rewrite the ACL regardless of what it currently says |
| 28 | `ACL-007` | Dangerous permissions on DC objects | Write access here is direct domain controller compromise |
| 29 | `ACL-008` | Write access on group policy objects | Editing a GPO is code execution everywhere it applies |
| 30 | `ACL-009` | Delegated write access on group membership | Individually harmless, collectively an escalation chain |

### Certificate services (AD CS)

| # | ID | Check | Reference |
| --- | --- | --- | --- |
| 31 | `ADCS-001` | Certificate services inventory (CAs, templates, NTAuth) | — |
| 32 | `ADCS-002` | Requester-supplied subject with an authentication EKU | ESC1 |
| 33 | `ADCS-003` | Templates without a purpose restriction | ESC2 |
| 34 | `ADCS-004` | Broadly enrollable enrollment agent templates | ESC3 |
| 35 | `ADCS-005` | Write access on certificate templates | ESC4 |
| 36 | `ADCS-006` | Dangerous permissions on PKI objects | ESC5 / ESC7 |
| 37 | `ADCS-007` | CA accepts a subject alternative name from the request | ESC6 |
| 38 | `ADCS-008` | Templates without the SID security extension | ESC9 |
| 39 | `ADCS-009` | Published templates with broad enrolment rights | — |

> [!NOTE]
> Templates that exist but are published on no CA cannot be requested. They still appear in the report, rated lower — publishing one is a single click.

---

## Prerequisites

| Requirement | Notes |
| --- | --- |
| **PowerShell 5.1 or 7.x** | Windows only. Ships with the OS since Windows 10 / Server 2016. |
| **RSAT `ActiveDirectory` module** | `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` |
| **A domain account** | Standard user is enough. Do **not** run this as Domain Admin — you would be measuring the wrong thing. |
| Local admin on the CA *(optional)* | Only for `ADCS-007`, which reads the CA registry remotely. Without it that one check reports `Info`. |

> [!IMPORTANT]
> Run it in a lab or test domain first. The script is read-only, but no script from the internet belongs in production before you have read it.

---

## Quick start

**1. Get the script and unblock it.** Files downloaded from the internet carry a zone marker that PowerShell refuses to execute:

```powershell
Unblock-File .\Invoke-ADSecurityScan.ps1
```

**2. Check it before you run it** — the parser executes nothing:

```powershell
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path .\Invoke-ADSecurityScan.ps1), [ref]$null, [ref]$errors) | Out-Null
$errors
```

**3. See what is available:**

```powershell
.\Invoke-ADSecurityScan.ps1 -ListChecks
```

**4. Run it.** With no arguments you get an interactive menu:

```powershell
.\Invoke-ADSecurityScan.ps1
```

Or go straight to a full scan with all three export formats:

```powershell
.\Invoke-ADSecurityScan.ps1 -FullScan -OutputPath C:\Reports -IncludeJson -IncludeCsv
```

**5. Read the HTML report.** It lands in the output directory as `ADSecurityScan_<domain>_<timestamp>.html`, opens in any browser, prints cleanly to PDF, and needs no internet access — everything is inlined.

---

## Selecting checks

`-Select` and the interactive prompt accept any mix of the following. Combine them freely: `-Select 1-6,ADCS,PWD-002`.

| Token | Selects |
| --- | --- |
| `all` | every check |
| `fast` | every check marked *Fast* — a first pass in about a minute |
| `7` | one check by number |
| `1-14` | a range |
| `KRB-001` | one check by ID |
| `ACL`, `ADCS`, `PWD` | every check with that ID prefix |
| `Kerberos`, `Permissions` | a whole category by name |

Unrecognised tokens produce a warning and are skipped, so one typo in a long list does not cost you the run.

Every check carries a cost class shown in the menu. *Fast* checks are single LDAP queries; *Slow* checks read one security descriptor per object and dominate the runtime.

---

## Output

By default the script prints every finding with its affected objects, grouped and coloured by severity, and returns nothing on the pipeline. That last part is deliberate — emitting the objects as well would print a second, unreadable dump underneath the report, because PowerShell renders nested collections badly.

```
  HIGH  --------------------------------------------------------------------
  KRB-001   Kerberoastable accounts (user objects with an SPN)           (8)

      eviadmin
        SPNs: HTTP/eviprod.example.local
        password age: 34 days
        privileged: no
        CN=eviadmin,OU=DOM-USER-SERVER,OU=DOM-MGMT,DC=example,DC=local

      svc-sql-prd19a-oltp
        SPNs: MSSQLSvc/sql01.example.local:PRD19A
        password age: 1550 days
        privileged: no
        CN=svc-sql-prd19a-oltp,OU=GRP-DB,OU=GROUPS-MGMT,DC=example,DC=local
```

The console shows 15 objects per finding before truncating — raise it with `-MaxConsoleObjects 200`. `-Compact` collapses everything to one line per finding for a quick pass over a full scan.

| Format | Contains | Good for |
| --- | --- | --- |
| **Console** | findings with objects, colour-coded by severity | working through results interactively |
| **HTML** | everything, with a check strip, severity tallies and collapsible object tables | handing over, printing to PDF, management |
| **JSON** (`-IncludeJson`) | every finding and every object, untruncated | diffing runs, feeding a ticket system |
| **CSV** (`-IncludeCsv`) | one flat row per affected object | Excel, pivot tables, assigning owners |

`-PassThru` returns the finding objects. They carry proper format definitions, so they render as a clean table rather than a wall of text:

```powershell
$f = .\Invoke-ADSecurityScan.ps1 -FullScan -PassThru -Quiet

$f                                                    # table: Severity, ID, Objects, Check
$f | Where-Object Severity -eq 'Critical'
$f | Where-Object Id -eq 'KRB-001' | Format-List
$f | Where-Object Id -eq 'ACL-005' | Select-Object -ExpandProperty Objects | Out-GridView
```

---

## Screenshots

![HTML report overview](screenshots/report_1.PNG)

*The HTML report: check strip across the top, severity tallies, then findings grouped by category.*

![Finding detail](screenshots/report_2.PNG)

*Each finding carries a plain-language summary, a concrete remediation, and the full list of affected objects.*

---

## Parameter reference

| Parameter | Purpose |
| --- | --- |
| `-Select <tokens>` | Which checks to run — numbers, ranges, IDs, categories, `all`, `fast` |
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

---

## Where to start

A first full scan in a domain that has never been assessed produces a lot. Fixing it top-to-bottom by severity is not the fastest route to a safer domain. Suggested order:

**1. Things that are already a compromise.** `ACL-001` with full replication rights, `ACL-004`, `PWD-003`, and any `ADCS-002` finding on a published template. These are not hardening items — an unexplained entry here is an incident, and should be treated as one before anything else.

**2. Single-step paths to domain ownership.** `DEL-001`, `ACL-007`, `ACL-008` where a GPO is linked to tier 0, `KRB-001` on privileged accounts. Each of these is one move away from the whole domain, and each is usually a small, well-scoped change.

**3. The foundations that make everything else harder.** `INF-004` (LAPS), `INF-001` (MachineAccountQuota to zero), `PRIV-001` (empty the operator groups). Low drama, high leverage, and they shrink the blast radius of everything you have not fixed yet.

**4. The long tail.** `ACL-005`, `ACL-009`, `ACC-001`, `ACC-002`. These produce the largest object counts and the least urgency. Work them as a recurring hygiene task, not a project.

> [!TIP]
> Export to JSON on every run and keep the files. The second scan is far more useful than the first, because the diff shows what changed — and changes in tier 0 that nobody requested are the findings worth waking up for.

---

## Troubleshooting

**`File cannot be loaded because running scripts is disabled on this system.`**
Execution policy. For a one-off run, launch the shell with `powershell.exe -ExecutionPolicy Bypass -File .\Invoke-ADSecurityScan.ps1`, or set `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` for the current session only. If the file came from a browser or a mail attachment you also need `Unblock-File .\Invoke-ADSecurityScan.ps1` — the zone marker is a separate mechanism from the execution policy.

**`The ActiveDirectory module was not found.`**
RSAT is missing. `Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0` on Windows 10/11, or `Install-WindowsFeature RSAT-AD-PowerShell` on a server. The script needs the module, not the whole RSAT bundle.

**`The variable "$x" cannot be retrieved because it has not been set.`**
The script runs under `Set-StrictMode -Version Latest`, which turns reads of unset variables and missing properties into hard errors instead of silent `$null`. That is intentional — it catches real bugs — but AD objects have plenty of optional attributes. If you hit one, the error names the variable or property; open an issue with that line. As a stopgap you can lower the strict mode to `-Version 2.0` at the top of the script, which still checks for uninitialised variables but not for absent properties.

**A check fails with an access-denied error.**
Some security descriptors are not readable by every account, and `Get-ADDomainController -Discover` can fail across site boundaries. Failed checks are recorded as `Info` findings with the exception message rather than aborting the scan — re-run with `-Verbose` to see which object it stumbled on. If several permission checks fail, verify you are querying a controller in the domain you think you are.

**`ADCS-007` always reports `Info` / "registry not readable".**
Expected without local administrator rights on the CA host, or when the Remote Registry service is disabled there. Every other ADCS check works from LDAP alone. Verify manually on the CA with `certutil -config "<CA-Host>\<CA-Name>" -getreg policy\EditFlags` and look for `EDITF_ATTRIBUTESUBJECTALTNAME2`.

**`ACL-005` returns hundreds of findings.**
Not a bug, and not unusual. The Delegation of Control wizard routinely grants full control where someone wanted "reset passwords in this OU", and those rights inherit to every object below. Sort by OU depth and start with the OUs holding servers and privileged accounts. If a specific group is legitimately delegated in your environment, add its SID to `Get-ADHTrustedSid` and re-run.

**The scan is very slow.**
The *Slow* checks read one security descriptor per object. In a domain with 100,000 objects a full scan takes 45 minutes or more. Use `-Select fast` for a first pass, run the permission checks separately outside business hours, and point `-Server` at a controller that is not the PDC emulator.

**The output is full of garbled characters.**
The script deliberately uses ASCII only, but if you have modified it: PowerShell 5.1 consoles run on an OEM code page by default and mangle box-drawing characters. `chcp 65001` before running, or stick to ASCII.

**Nothing runs and it says "Nothing selected".**
The selection tokens matched no checks. Run `-ListChecks` to see the catalogue, and note that category names must match (`Permissions`, not `ACLs`) while ID prefixes are separate (`ACL`, `ADCS`, `PWD`).

---

## Design decisions

**The trusted-principal list is deliberately short.** Only SYSTEM, Administrators, Domain/Enterprise/Schema Admins, Domain Controllers, SELF, Creator Owner and the Key Admins are exempt from the permission checks. Account, Server, Backup and Print Operators are **not** exempt, and neither is *Pre-Windows 2000 Compatible Access*. Those groups routinely carry historical rights, which is exactly why they belong in the report. If your environment uses one of them legitimately, add its SID to `Get-ADHTrustedSid`.

**Every check reports, including the clean ones.** A check that finds nothing returns a `Pass` finding rather than staying silent, so the report shows what was actually examined. "We looked and it was fine" is information; absence is not.

**The permission analysis has a bounded scope** — domain root, AdminSDHolder, tier-0 groups and accounts, all OUs, all GPOs, all groups, DC objects. A domain-wide ACL sweep across every object would be slow and would bury the signal. Escalation chains through arbitrary intermediate objects need a graph tool; this is not one.

**Group resolution uses well-known SIDs**, not names, so the checks work identically in German, French or any other localised domain. Nested memberships are resolved with `LDAP_MATCHING_RULE_IN_CHAIN` rather than recursive cmdlet calls.

---

## Limitations & notes

- **`lastLogonTimestamp` replicates every 9–14 days.** The dates in `ACC-001` and `ACC-002` are approximations by design, not bugs.
- SYSVOL filesystem permissions and GPO *contents* are not evaluated — only the directory permissions on the GPO objects.
- **ESC8** (web enrolment reachable over HTTP) is flagged as a manual check in `ADCS-001` rather than probed, since that would mean sending traffic rather than reading the directory.
- Trust relationships and cross-forest paths are out of scope.
- One domain per run. In a multi-domain forest, call it once per domain with `-Server`.
- Severity thresholds (how many tier-0 members is "too many", how old a password is "stale") are experience-based defaults. Adjust them to your environment rather than treating them as standards.
- This is an assessment aid. It deliberately changes nothing — remediation stays a conscious, reviewed action.

---

## Repository layout

```
README.md                     this file
LICENSE                       MIT
.gitignore                    keeps generated reports and exports out of git
.github/workflows/            CI: PSScriptAnalyzer on every push
screenshots/                  images used in this README
Invoke-ADSecurityScan.ps1     the scanner — everything is in this one file
```

The script has no dependencies beyond the RSAT `ActiveDirectory` module and needs no build step. Download the single file, unblock it, run it.

## License

[MIT](LICENSE) — see the `LICENSE` file.
