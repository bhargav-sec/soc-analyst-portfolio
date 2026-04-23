# RDP Brute Force — Failed Attack Investigation

**Platform:** LetsDefend | **Alert ID:** SOC176 | **Severity:** Medium | **Verdict:** True Positive (attack failed)

## Scenario
Alert fired for repeated RDP login failures from a single external IP (`218.92.0.56`) against an internal host `Matthew` (`172.16.17.148`). The alert trigger noted attempts across multiple non-existent accounts — classic brute-force behaviour.

## Investigation Steps

### 1. Threat intel on source IP
Checked `218.92.0.56` on VirusTotal → **9 vendors flagged as malicious**. IP is part of known brute-force scanning infrastructure (frequently seen in threat intel feeds for SSH/RDP credential stuffing).

### 2. Log analysis — failed authentications
Pivoted to Log Management and filtered on destination `172.16.17.148`. Found multiple Windows Security events:

- **EventID 4625** (Account failed to log on) — repeated failures from `218.92.0.56`
- Usernames attempted included `admin` — a standard dictionary target
- No lockout evidence — attack pace may have been throttled below account lockout threshold

### 3. Check for successful compromise
Critical question: did any attempt succeed? Searched for:
destination_address=172.16.17.148 EventID=4624 source_address=218.92.0.56
**Result: 0 events.** No successful logon (EventID 4624) from the attacker IP → the brute force failed to obtain credentials.

### 4. Scope check
Confirmed the attacker IP only targeted `Matthew`. No lateral attempts against other hosts in the environment were observed during the alert window.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force: Password Guessing | T1110.001 |
| Reconnaissance | Active Scanning | T1595 |
| Initial Access (attempted) | Valid Accounts | T1078 |

## Indicators of Compromise

- **Source IP:** `218.92.0.56` (9 vendors flagged on VT)
- **Targeted host:** `172.16.17.148` (`Matthew`)
- **Protocol:** RDP (TCP 3389)
- **Usernames attempted:** `admin` (among others)
- **Windows Event ID observed:** 4625 (failed logon) — multiple
- **Windows Event ID NOT observed:** 4624 (successful logon) — confirmed zero

## Verdict & Response

**True Positive — real brute-force attack, but unsuccessful.**

Recommended actions:
1. **Block** `218.92.0.56` at perimeter firewall (likely already blocked outside this lab scenario)
2. **Enforce MFA** on all RDP-accessible accounts
3. **Restrict RDP exposure** — RDP should never be directly exposed to the internet; put behind VPN or Zero Trust gateway
4. **Disable or rename** the `admin` account — attacker-targeted names should not exist
5. **Configure account lockout policy** if not already in place (e.g., 5 failed attempts → 15 min lockout)
6. **Enable Network Level Authentication (NLA)** on RDP endpoints
7. **Hunt** for the same IP pattern hitting other hosts in the estate

## What I'd Do Differently

- In a production environment I'd cross-reference the attacker IP against threat intel feeds (AlienVault OTX, AbuseIPDB) for historical activity and pivot to identify other hosts this IP may have targeted over the past 30 days.
- Would check whether any other IPs in the same /24 subnet showed similar patterns — brute force campaigns often rotate across subnets to evade rate-based detections.
- Worth verifying whether RDP should be reachable from the internet at all — root cause of exposure is often more important than the individual alert.

## References
- [MITRE ATT&CK — T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- [Windows Security Event ID 4625](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [Windows Security Event ID 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- LetsDefend SOC176 alert

---
*Investigation performed on LetsDefend free-tier platform.*
