# Demo 01 - Basic ATT&CK Hunt

This scenario uses `endpoint.jsonl`, a small set of normalized endpoint /
process-creation log events (Sysmon-style + a Windows Security 4625) captured
from a host you own. It contains a mix of benign activity and several
attacker tradecraft patterns.

## Run it

```bash
# Human-readable table (exits 1 because findings exist)
python -m ttphunt hunt demos/01-basic/endpoint.jsonl

# Machine-readable for pipelines
python -m ttphunt hunt demos/01-basic/endpoint.jsonl --format json

# Self-contained shareable HTML report (the tool's UI)
python -m ttphunt hunt demos/01-basic/endpoint.jsonl --format html -o report.html

# Filter by a single technique
python -m ttphunt hunt demos/01-basic/endpoint.jsonl -t T1490

# List the active rule pack
python -m ttphunt rules
```

## What you should see

TTPHUNT flags the malicious lines while leaving benign ones alone:

| Technique  | Tactic            | What tripped it                              |
|------------|-------------------|----------------------------------------------|
| T1059.001  | Execution         | PowerShell `-EncodedCommand` + download cradle |
| T1105      | Command & Control | `certutil -urlcache -f` remote file pull      |
| T1490      | Impact            | `vssadmin delete shadows` (ransomware precursor) |
| T1070.001  | Defense Evasion   | `wevtutil cl Security` log clearing           |
| T1547.001  | Persistence       | `reg add ...\Run` autostart                   |
| T1110      | Credential Access | Windows event 4625 failed logon               |

The benign `notepad.exe` and routine `whoami` lines produce no findings.

## Exit codes

- `0` - no findings
- `1` - findings present (so `&&` chains / CI gates trigger)
- `2` - input/rule load error
