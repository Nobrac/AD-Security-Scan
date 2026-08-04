<div align="center">

# AD-Security-Scan

### 43 read-only checks against your Active Directory — run from a plain user account, because that is all an attacker needs.

A single PowerShell script that queries a domain over LDAP, finds the misconfigurations that actually lead to domain compromise, and turns them into a prioritised console output and an HTML report you can hand to management.

![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)
&nbsp;
![Platform: Windows](https://img.shields.io/badge/platform-Windows-0078D6)
&nbsp;
![Checks: 43](https://img.shields.io/badge/checks-43-0A7B4E)
&nbsp;
![Access: read-only](https://img.shields.io/badge/access-read--only-6E44FF)
&nbsp;
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

[Checks](#what-it-checks) · [Quick start](#quick-start) · [Output](#output) · [Exceptions](#approved-exceptions) · [Triage](#where-to-start) · [Troubleshooting](#troubleshooting)

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
- [Approved exceptions](#approved-exceptions)
- [Handling the reports](#handling-the-reports)
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

43 checks across ten categories. Each one is numbered, so you can run any subset by number, range, ID or category.

### Kerberos & delegation

| # | ID | Check | Why it matters |
| --- | --- | --- | --- |
| 1 | `KRB-001` | Kerberoastable accounts (SPN on user objects) | Any domain user can request a ticket and crack the password offline |
| 2 | `KRB-002` | Kerberos pre-authentication disabled | The KDC hands out a crackable blob with no authentication at all |
| 3 | `KRB-003` | krbtgt password age | An old key extends the life of any golden ticket indefinitely |
| 4 | `KRB-004` | Weak encryption (DES/RC4) on SPN and admin accounts | RC4 tickets crack orders of magnitude faster than AES; DES is broken outright |
| 5 | `DEL-001` | Unconstrained delegation outside DCs | The host caches every visitor's TGT — including a domain admin's |
| 6 | `DEL-002` | Constrained delegation with protocol transition | Mint a ticket for any user; a DC service as target means game over |
| 7 | `DEL-003` | Resource-based constrained delegation configured | Legitimate feature, favourite persistence mechanism |

### Privileged accounts & passwords

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

### Account hygiene & infrastructure

| # | ID | Check | Why it matters |
| --- | --- | --- | --- |
| 16 | `ACC-001` | Stale enabled user accounts | Nobody notices unusual activity on an account nobody uses |
| 17 | `ACC-002` | Stale enabled computer accounts | Keeps its password, convenient for persistence |
| 18 | `ACC-003` | Objects carrying SID history | A hidden access channel once the migration is done |
| 19 | `ACC-004` | Possible credentials in description/info fields | Every authenticated user can read these, and it works far too often |
| 20 | `INF-001` | MachineAccountQuota | Above zero, every user can create computer accounts |
| 21 | `INF-002` | Domain controllers and functional levels | Legacy DCs block Protected Users and authentication policy silos |
| 22 | `INF-003` | End-of-life operating systems | No patches, and they force weak protocols to stay enabled |
| 23 | `INF-004` | LAPS coverage | Identical local admin passwords are the basis of lateral movement |

### Trusts & group policy

| # | ID | Check | Why it matters |
| --- | --- | --- | --- |
| 24 | `TRUST-001` | Trust configuration: SID filtering, TGT delegation, selective auth | A trust without SID filtering lets the other side inject your Domain Admins' SIDs |
| 25 | `GPO-001` | Stored credentials in SYSVOL (cpassword) | The decryption key is public and SYSVOL is world-readable inside the domain |

### Directory permissions

| # | ID | Check | Why it matters |
| --- | --- | --- | --- |
| 26 | `ACL-001` | Replication rights on the domain root (DCSync) | Pull every password hash, krbtgt included, without touching a DC |
| 27 | `ACL-002` | Dangerous permissions on tier-0 groups | Membership without appearing in the membership list |
| 28 | `ACL-003` | Dangerous permissions on privileged accounts | Password reset or `msDS-KeyCredentialLink` write is full takeover |
| 29 | `ACL-004` | Dangerous permissions on AdminSDHolder | One ACE stamped hourly onto every admin object in the domain |
| 30 | `ACL-005` | Broad delegations on organizational units | The delegation wizard grants more than people intend |
| 31 | `ACL-006` | Privileged objects with non-privileged owners | An owner can rewrite the ACL regardless of what it currently says |
| 32 | `ACL-007` | Dangerous permissions on DC objects | Write access here is direct domain controller compromise |
| 33 | `ACL-008` | Write access on group policy objects | Editing a GPO is code execution everywhere it applies |
| 34 | `ACL-009` | Delegated write access on group membership | Individually harmless, collectively an escalation chain |

### Certificate services (AD CS)

Forest-scoped — identical for every domain in the forest. Use `-SkipForestWide` when walking a multi-domain forest so you only run them once.

| # | ID | Check | Reference |
| --- | --- | --- | --- |
| 35 | `ADCS-001` | Certificate services inventory (CAs, templates, NTAuth) | — |
| 36 | `ADCS-002` | Requester-supplied subject with an authentication EKU | ESC1 |
| 37 | `ADCS-003` | Templates without a purpose restriction | ESC2 |
| 38 | `ADCS-004` | Broadly enrollable enrollment agent templates | ESC3 |
| 39 | `ADCS-005` | Write access on certificate templates | ESC4 |
| 40 | `ADCS-006` | Dangerous permissions on PKI objects | ESC5 / ESC7 |
| 41 | `ADCS-007` | CA accepts a subject alternative name from the request | ESC6 |
| 42 | `ADCS-008` | Templates without the SID security extension | ESC9 |
| 43 | `ADCS-009` | Published templates with broad enrolment rights | — |

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

**4. Run it.** With no arguments you get a menu of profiles and categories:

```powershell
.\Invoke-ADSecurityScan.ps1
```

If you would rather not choose, `-Select essential` runs the fourteen checks that matter most.

Or go straight to a full scan with all three export formats:

```powershell
.\Invoke-ADSecurityScan.ps1 -FullScan -OutputPath C:\Reports -IncludeJson -IncludeCsv
```

**5. Read the HTML report.** It lands in the output directory as `ADSecurityScan_<domain>_<timestamp>.html`, opens in any browser, prints cleanly to PDF, and needs no internet access — everything is inlined.

---

## Selecting checks

Running without arguments opens a two-level menu. The first level is three profiles and one row per category — picking "everything in Kerberos" is one keystroke, not a range you have to look up:

```
  SCAN PROFILES

   1   Everything - the complete catalogue               43 checks    5 slow
   2   Quick pass - fast checks only                     25 checks
   3   Tier-0 essentials - paths to domain compromise    14 checks    2 slow

  CATEGORIES

   4   Kerberos                                          4 checks
   5   Delegation                                        3 checks
   6   Privileges                                        3 checks
   7   Passwords                                         5 checks
   8   Account hygiene                                   4 checks
   9   Infrastructure                                    4 checks
   10  Trusts                                            1 check
   11  Group policy                                      1 check      1 slow
   12  Permissions                                       9 checks     3 slow
   13  Certificate services  (forest-wide)               9 checks     1 slow

   L   List all 43 checks and pick individually
   Q   Cancel

  Select (e.g. 3, or 5,7,12):
```

Pick several with `5,7,12`. Before anything runs you get a summary of what was selected, a warning if slow checks are included, and a confirmation prompt. `L` drops into the full numbered list when you really do want individual checks.

**Tier-0 essentials** is the answer to "we have twenty minutes, what matters?" — the checks where a finding is either already a compromise or one move away from one: `KRB-001`, `KRB-003`, `DEL-001`, `DEL-002`, `PRIV-001`, `PWD-002`, `PWD-003`, `TRUST-001`, `GPO-001`, `ACL-001`, `ACL-004`, `ACL-007`, `ACL-008`, `ADCS-002`.

### Non-interactive selection

`-Select` accepts the same profiles as the menu, plus anything more specific. Combine freely: `-Select 1-6,ADCS,PWD-002`.

| Token | Selects |
| --- | --- |
| `all` / `full` | every check |
| `quick` / `fast` | fast checks only — a first pass in about a minute |
| `essential` / `tier0` | the Tier-0 essentials profile |
| `slow` | only the expensive checks, for a separate off-hours run |
| `domain` / `forest` | by scope — `domain` skips the ADCS checks |
| `Kerberos`, `Permissions` | a whole category by name |
| `ACL`, `ADCS`, `PWD` | every check with that ID prefix |
| `KRB-001` | one check by ID |
| `7` | one check by catalogue number |
| `1-14` | a range of catalogue numbers |

Unrecognised tokens produce a warning and are skipped, so one typo in a long list does not cost you the run.

Every check carries a cost class shown in the menu. *Fast* checks are single LDAP queries; *Slow* checks read one security descriptor per object, or reach outside LDAP, and dominate the runtime.

---

## Output

While the scan runs, each check reports as it finishes — position, ID, outcome and object count, with the elapsed time shown for anything that took more than three seconds:

```
  ==================================================================================================
   Active Directory Security Assessment                                                   read-only
  ==================================================================================================

   Domain        contoso.local
   Controller    dc01.contoso.local
   Running as    CONTOSO\s.gassner
   Stale after   90 days
   Checks        14 of 43   (2 slow - these read a security descriptor per object)

  RUNNING

   [ 1/14]  KRB-001   Kerberoastable accounts (SPN on user objects) .......... HIGH        8
   [ 2/14]  KRB-003   krbtgt password age .................................... MEDIUM      1
   [ 3/14]  DEL-001   Unconstrained delegation outside DCs ................... CRITICAL    2
   [ 4/14]  DEL-002   Constrained delegation with protocol transition ........ PASS        -
   ...
   [ 9/14]  GPO-001   Stored credentials in SYSVOL (cpassword) ............... CRITICAL    3    14s
```

Then the findings themselves, grouped by severity. By default every affected object is listed with its attributes on separate lines and the distinguished name dimmed:

```
  CRITICAL (5) ------------------------------------------------------------------------------------

   ACL-001   Replication rights on the domain root (DCSync)                                      2

        CONTOSO\svc-legacy-sync
          FULL REPLICATION POSSIBLE
          rights: DS-Replication-Get-Changes, DS-Replication-Get-Changes-All
          CN=svc-legacy-sync,OU=Service,DC=contoso,DC=local
```

And a result block with a rough distribution, followed by the file paths:

```
  RESULT

   Critical     5  ##############
   High         3  #########
   Medium       1  ###
   Pass         5  ##############

   14 checks in 04:12

  OUTPUT

   HTML          C:\Reports\ADSecurityScan_contoso.local_20260804-1712.html
   JSON          C:\Reports\ADSecurityScan_contoso.local_20260804-1712.json
```

The console shows 15 objects per finding before truncating — raise it with `-MaxConsoleObjects 200`. `-Compact` drops the object detail and leaves one line per finding, which is the better view for a full scan. `-Quiet` suppresses the console output entirely, for scheduled runs.

| Format | Contains | Good for |
| --- | --- | --- |
| **Console** | findings with objects, colour-coded by severity | working through results interactively |
| **HTML** | everything, with a check strip, clickable severity filters, per-finding Microsoft references and collapsible object tables | handing over, printing to PDF, management |
| **JSON** (`-IncludeJson`) | every finding and every object, untruncated | diffing runs, feeding a ticket system |
| **CSV** (`-IncludeCsv`) | one flat row per affected object | Excel, pivot tables, assigning owners |

The script returns nothing on the pipeline unless you ask. That is deliberate: emitting the objects as well would print a second, unreadable dump underneath the report, because PowerShell renders nested collections badly. `-PassThru` returns the finding objects, which carry proper format definitions and render as a clean table:

```powershell
$f = .\Invoke-ADSecurityScan.ps1 -FullScan -PassThru -Quiet

$f                                                    # table: Severity, ID, Objects, Check
$f | Where-Object Severity -eq 'Critical'
$f | Where-Object Id -eq 'KRB-001' | Format-List
$f | Where-Object Id -eq 'ACL-005' | Select-Object -ExpandProperty Objects | Out-GridView
```

### The HTML report

Two things in the report are worth knowing about.

**The severity tallies are clickable.** Findings are grouped by category, so a severity is scattered across sections — clicking *Critical* filters the whole report down to those findings and jumps to them, which is what actually produces "the Critical section". Click the same tally again, or use *show all*, to go back. Printing always resets the filter first, so a filtered view can never turn into a silently incomplete PDF.

**Every finding links to Microsoft documentation.** Not to explain the finding — the report already does that — but to answer "where do I go to change this". `KRB-001` points at the gMSA overview, `ACL-004` at the AdminSDHolder appendix, `GPO-001` at the MS14-025 article that contains the cleanup script, `ADCS-008` at KB5014754.

Where Microsoft has no single canonical page for a topic, the link opens a Microsoft Learn search with precise terms instead of a guessed URL that would rot into a 404. Every direct link was verified to resolve at the time of writing.

The references are on the finding objects too, so `-PassThru` gives you them as data:

```powershell
$f = .\Invoke-ADSecurityScan.ps1 -Select essential -PassThru -Quiet -NoReport
$f | Select-Object Id, Severity, @{n='Doc';e={$_.Reference.Url}}
```

---

## Approved exceptions

The first full scan of a domain that has never been assessed finds things that turn out to be intentional. If the report flags your Entra Connect account as a critical DCSync finding on every run, people stop reading it — and stop noticing the real findings sitting next to it.

Put a file called `ADSecurityScan.exceptions.json` next to the script and it is picked up automatically:

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
| `checkId` | Exact ID or wildcard — `ACL-001`, `ACL-*` |
| `object` | Matched with `-like` against both the object name and its distinguished name, so `svc-sql-prd*` works |
| `reason` | Why this is accepted, written for whoever reads it in a year |
| `approvedBy` | Who signed it off |
| `expires` | `yyyy-MM-dd` — the date the acceptance runs out |

> [!IMPORTANT]
> **All four fields are mandatory, including the expiry date.** There is deliberately no way to write an exception that never expires. A permanent exception is not an accepted risk, it is a blind spot nobody revisits — and it will still be there long after the person who approved it has left.

Expired entries stop suppressing anything, so the finding reappears at full severity. Every run adds an `EXC-001` finding listing what is currently suppressed, what has expired and what expires within 30 days, which makes the exception file itself auditable.

When every object in a finding is covered, the finding drops to `Pass` with a note. That is the point: a report that **can** reach all-green is a report worth reading.

Use `-ExceptionFile` to point somewhere else, or `-NoExceptions` to ignore the file for one run. See `ADSecurityScan.exceptions.example.json` for a fuller example.

---

## Handling the reports

> [!WARNING]
> **The output is a ready-made target list.** Kerberoastable service accounts with password ages, hosts with unconstrained delegation, who holds DCSync, which certificate template lets any user request a Domain Admin certificate — this is precisely the reconnaissance an attacker would otherwise have to perform themselves, sorted by usefulness.

Treat the reports like credentials, not like documentation:

- Do not leave them in `Downloads`, on a file share, or in a ticket everyone can read.
- Do not send them by mail. Share a location, not an attachment.
- Never commit them — the supplied `.gitignore` excludes `ADSecurityScan_*` for exactly this reason.
- Store them where the tier-0 data lives, and delete them when the remediation is done.
- The scan itself is read-only and harmless. The output is not.

Two checks are careful about this by design: `ACC-004` reports only which keyword matched, never the field contents, and `GPO-001` reports file paths without decrypting anything. Neither turns the report into the thing it warns about.

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
The selection tokens matched no checks. Run `-ListChecks` to see the catalogue. Category names must match the catalogue (`Permissions`, not `ACLs`), while ID prefixes are separate tokens (`ACL`, `ADCS`, `PWD`).

**In the menu I typed a range and got the wrong checks.**
You cannot — the menu refuses ranges and tells you why. At the top level `1` means the first profile, so `1-3` would be ambiguous between menu rows and check numbers. Press `L` first; inside the full list, ranges refer unambiguously to catalogue numbers.

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
- `ACC-004` is a keyword search and will produce false positives — a description reading "reset password at first logon" matches. That is intended; each hit costs a glance, a missed clear-text credential costs more.
- `GPO-001` needs SMB access to SYSVOL. It reports the presence and location of stored credentials and deliberately does not decrypt them.
- `TRUST-001` reports the trust configuration this domain can see. It says nothing about how well the domain on the other side is run.
- This is an assessment aid. It deliberately changes nothing — remediation stays a conscious, reviewed action.

---

## Repository layout

```
README.md                                 this file
LICENSE                                   MIT
.gitignore                                keeps generated reports out of git
ADSecurityScan.exceptions.example.json    template for approved exceptions
Invoke-ADSecurityScan.ps1                 the scanner — everything is in this one file
```

The scanner has no dependencies beyond the RSAT `ActiveDirectory` module and needs no build step. Download the single file, unblock it, run it — everything else in the repository is for development or optional configuration.

## License

[MIT](LICENSE) — see the `LICENSE` file.
