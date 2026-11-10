"""
Expand the TriageMate labelled set from the course sources.

Keeps every alert already in data/all_alerts.jsonl. Adds:
  - new OTRF Security-Datasets recordings (technique event, a second
    related event, one benign background event, one false positive)
  - extra Splunk Attack Data logs for T1486 and T1490
  - synthetic alerts from data/generate_alerts.py only to fill categories
    that the public recordings do not cover

Re-running replaces previously expanded rows (new source paths and
synthetic ids) and leaves the original 53 in place.

Usage:
    python data/expand_dataset.py
"""
import importlib.util
import io
import json
import random
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
CACHE = DATA / "_cache"
ALERTS_PATH = DATA / "all_alerts.jsonl"
LABELS_PATH = DATA / "all_labels.csv"

OTRF_RAW = "https://github.com/OTRF/Security-Datasets/raw/master/"
# raw.githubusercontent.com returns Git LFS pointers for these logs.
# media.githubusercontent.com returns the file contents.
SPLUNK_RAW = "https://media.githubusercontent.com/media/splunk/attack_data/master/"

# Recordings not already used by the original 53 alerts.
NEW_OTRF = [
    ("credential_access", "cmd_dumping_ntds_dit_file_volume_shadow_copy.zip"),
    ("credential_access", "empire_mimikatz_backupkeys_dcerpc_smb_lsarpc.zip"),
    ("credential_access", "empire_mimikatz_extract_keys.zip"),
    ("credential_access", "empire_mimikatz_lsadump_inject_protected_mode.zip"),
    ("credential_access", "empire_over_pth_patch_lsass.zip"),
    ("credential_access", "empire_powerdump_sam_access.zip"),
    ("credential_access", "empire_shell_rubeus_asktgt_createnetonly.zip"),
    ("credential_access", "rdp_interactive_taskmanager_lsass_dump.zip"),
    ("lateral_movement", "aadinternals_export_adfsdatabaseconfig_remotely.zip"),
    ("lateral_movement", "covenant_com_wsman_automation.zip"),
    ("lateral_movement", "covenant_dcom_executeexcel4macro_blocked.zip"),
    ("lateral_movement", "covenant_dcom_iertutil_dll_hijack.zip"),
    ("lateral_movement", "covenant_dcom_registerxll.zip"),
    ("lateral_movement", "covenant_psremoting_grunt.zip"),
    ("lateral_movement", "covenant_sc_query_dcerpc_smb_svcctl.zip"),
    ("lateral_movement", "covenant_sharpsc_create_dcerpc_smb_svcctl.zip"),
    ("lateral_movement", "covenant_sharpsc_query_dcerpc_smb_svcctl.zip"),
    ("lateral_movement", "covenant_sharpsc_start_dcerpc_smb_svcctl.zip"),
    ("lateral_movement", "covenant_sharpsc_stop_dcerpc_smb_svcctl.zip"),
    ("lateral_movement", "covenant_wmi_remote_event_subscription_ActiveScriptEventConsumers.zip"),
    ("lateral_movement", "covenant_wmi_wbemcomn_dll_hijack.zip"),
    ("lateral_movement", "empire_msbuild_dcerpc_wmi_smb.zip"),
    ("lateral_movement", "empire_shell_dcerpc_smb_service_dll_hijack.zip"),
    ("lateral_movement", "empire_wmic_add_user_backdoor.zip"),
    ("lateral_movement", "schtask_modification.zip"),
]

NEW_SPLUNK = [
    "datasets/attack_techniques/T1486/bitlocker_sus_commands/bitlocker_sus_commands.log",
    "datasets/attack_techniques/T1486/dcrypt/windows-sysmon.log",
    "datasets/attack_techniques/T1486/sam_sam_note/windows-sysmon.log",
    "datasets/attack_techniques/T1486/sam_sam_note/windows-security.log",
    "datasets/attack_techniques/T1486/sam_sam_note/windows-powershell.log",
    "datasets/attack_techniques/T1490/atomic_red_team/windows-sysmon.log",
    "datasets/attack_techniques/T1490/atomic_red_team/shadow-powershell.log",
    "datasets/attack_techniques/T1490/atomic_red_team/windows-security_bcdedit_wbadmin.log",
    "datasets/attack_techniques/T1490/shadowcopy_del/wmicshadowcopydelete_sysmon.log",
    "datasets/attack_techniques/T1490/shadowcopy_del/windows-powershell.log",
    "datasets/attack_techniques/T1490/ransomware_notes/windows-sysmon.log",
    "datasets/attack_techniques/T1490/known_services_killed_by_ransomware/windows-xml.log",
]

# How many labelled alerts to aim for after the real rows are in.
# Real rows are never dropped to hit these numbers.
TARGETS = {
    "credential_attack": 45,
    "lateral_movement": 40,
    "ransomware": 18,
    "benign": 45,
    "false_positive": 40,
}

BENIGN_IMAGES = {
    "svchost.exe", "sihost.exe", "taskhostw.exe", "ctfmon.exe", "dllhost.exe",
    "searchindexer.exe", "explorer.exe", "runtimebroker.exe", "fontdrvhost.exe",
    "dwm.exe", "csrss.exe", "lsass.exe", "services.exe", "winlogon.exe",
}
ATTACK_TOKENS = (
    "mimikatz", "comsvcs", "ntdsutil", "ntds.dit", "procdump", "dumpert",
    "rubeus", "sekurlsa", "dcsync", "esentutl", "psexec", "psexesvc",
    "vssadmin", "wbadmin", "bcdedit", "shadow", "bitlocker", "ransom",
    ".locked", "restore_files", "ninjacopy", "secretsdump",
)
FP_IMAGES = {"powershell.exe", "cmd.exe", "wmic.exe", "schtasks.exe", "sc.exe"}
FP_SAFE_HINTS = (
    "get-process", "get-service", "ipconfig", "systeminfo",
    "query", "inventory", "/query", "os get", "computersystem",
    "softwareprotectionplatform", "windowsupdate",
)
# Tokens that identify the technique itself. Generic words such as "lsass"
# are intentionally absent: they show up in normal process-access noise.
HIGH_SIGNAL = (
    "ntds.dit", "comsvcs", "mimikatz", "sekurlsa", "rubeus", "procdump",
    "dumpert", "esentutl", "vssadmin", "wbadmin", "bcdedit", "psexec",
    "psexesvc", "msbuild.exe", "net user", "net1.exe", "wsmprovhost",
    "schtasks", "excel.exe", "powerdump", "iertutil", "lsass.dmp",
    "minidump", "reg save", "wmic.exe", "wmic ", "shadowcopy",
)
NOISY_SOURCES = {
    "svchost.exe", "csrss.exe", "services.exe", "lsass.exe",
    "wininit.exe", "winlogon.exe", "conhost.exe",
}


def _download(url, dest: Path):
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 0:
        return dest.read_bytes()
    req = urllib.request.Request(url, headers={"User-Agent": "triagemate-dataset"})
    with urllib.request.urlopen(req, timeout=90) as resp:
        data = resp.read()
    if data.startswith(b"version https://git-lfs"):
        raise RuntimeError("git-lfs pointer, not file contents")
    dest.write_bytes(data)
    return data


def _iter_json_events(raw: bytes):
    raw = raw.strip()
    if not raw:
        return
    if raw[:1] == b"[":
        data = json.loads(raw)
        for ev in data:
            if isinstance(ev, dict):
                yield ev
        return
    for line in raw.splitlines():
        line = line.strip()
        if not line or line[:1] not in (b"{", "{"):
            continue
        if isinstance(line, bytes):
            try:
                line = line.decode("utf-8")
            except UnicodeDecodeError:
                continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(ev, dict):
            yield ev


def _blob(ev: dict) -> str:
    keys = (
        "CommandLine", "ParentCommandLine", "Image", "ParentImage",
        "SourceImage", "TargetImage", "Message", "ServiceName",
        "ServiceFileName", "NewProcessName", "ScriptBlockText",
        "TargetUserName", "PipeName", "Query",
    )
    return " ".join(str(ev.get(k, "")) for k in keys).lower()


def _basename(path_value) -> str:
    return str(path_value or "").replace("/", "\\").split("\\")[-1].lower()


def _slim(ev: dict) -> str:
    keep = (
        "EventID", "Channel", "Hostname", "Image", "CommandLine",
        "ParentImage", "ParentCommandLine", "SourceImage", "TargetImage",
        "GrantedAccess", "User", "AccountName", "TargetUserName",
        "LogonType", "ServiceName", "ServiceFileName", "Message",
        "NewProcessName", "ScriptBlockText",
    )
    out = {}
    for key in keep:
        val = ev.get(key)
        if val not in (None, "", "-"):
            text = str(val)
            if len(text) > 500:
                text = text[:500]
            out[key] = text
    return json.dumps(out)


def _host(ev):
    return ev.get("Hostname") or ev.get("Computer") or ev.get("host") or "unknown"


def _user(ev):
    for key in ("User", "AccountName", "TargetUserName", "SubjectUserName"):
        val = ev.get(key)
        if val and val not in ("-", "unknown"):
            return str(val)
    return "unknown"


def _timestamp(ev):
    for key in ("UtcTime", "EventTime", "@timestamp", "TimeCreated"):
        if ev.get(key):
            return str(ev[key])
    return "unknown"


def _channel(ev):
    return ev.get("Channel") or ev.get("log_source") or "unknown"


def _evidence(ev: dict):
    """Return technique tokens actually present in this event, or []."""
    cmd = str(ev.get("CommandLine") or "").strip()
    if cmd.isdigit():
        return []
    fields = " ".join(str(ev.get(k) or "") for k in (
        "CommandLine", "ParentCommandLine", "Image", "SourceImage", "TargetImage",
        "ScriptBlockText", "ServiceFileName", "ServiceName", "NewProcessName",
        "PipeName", "Message",
    )).lower()
    hits = [token for token in HIGH_SIGNAL if token in fields]
    eid = str(ev.get("EventID") or ev.get("EventCode") or "")
    source = _basename(ev.get("SourceImage") or ev.get("Image"))
    target = _basename(ev.get("TargetImage"))
    if eid == "10" and target == "lsass.exe" and source in {"taskmgr.exe", "procdump.exe", "rundll32.exe"}:
        hits.append("taskmgr")
    if not hits:
        return []
    if source in NOISY_SOURCES and eid not in ("1", "4688", "4104", "800", "7045"):
        return []
    if eid == "10":
        if target != "lsass.exe":
            return []
        if source in NOISY_SOURCES:
            return []
    return hits


def _is_benign(ev) -> bool:
    if str(ev.get("EventID")) not in ("1", "4688"):
        return False
    image = _basename(ev.get("Image") or ev.get("NewProcessName"))
    if image not in BENIGN_IMAGES or image == "lsass.exe":
        return False
    text = _blob(ev)
    if any(token in text for token in ATTACK_TOKENS):
        return False
    if _basename(ev.get("ParentImage")) in FP_IMAGES and "temp" in text:
        return False
    return True


def _is_false_positive(ev) -> bool:
    if str(ev.get("EventID")) not in ("1", "4688", "4104"):
        return False
    image = _basename(ev.get("Image") or ev.get("NewProcessName"))
    text = _blob(ev)
    if image not in FP_IMAGES:
        return False
    if any(token in text for token in ATTACK_TOKENS) or any(token in text for token in HIGH_SIGNAL):
        return False
    return any(hint in text for hint in FP_SAFE_HINTS)


def _rule_name(kind: str, ev: dict, filename: str) -> str:
    text = _blob(ev)
    if kind == "benign":
        return "Signed system process started"
    if kind == "false_positive":
        image = _basename(ev.get("Image") or ev.get("NewProcessName"))
        if image == "schtasks.exe":
            return "Scheduled task host activity"
        if image == "wmic.exe":
            return "WMI inventory query"
        if image == "sc.exe":
            return "Service control query"
        return "Administrative PowerShell"
    mapping = (
        ("comsvcs", "LSASS memory dump via comsvcs.dll"),
        ("mimikatz", "Mimikatz credential dump"),
        ("sekurlsa", "Mimikatz LSASS credential dump"),
        ("ntdsutil", "NTDS.dit dump via ntdsutil"),
        ("ntds", "NTDS.dit credential dump"),
        ("esentutl", "SAM hive copy via esentutl"),
        ("rubeus", "Rubeus Kerberos ticket request"),
        ("dsgetncchanges", "DCSync replication request"),
        ("dcsync", "DCSync replication request"),
        ("psexec", "PsExec remote service execution"),
        ("msbuild", "Remote MSBuild execution over WMI"),
        ("wmic", "Remote WMI process creation"),
        ("wmiprvse", "WMI process execution"),
        ("wsmprovhost", "PowerShell remoting session"),
        ("winrm", "WinRM remote command"),
        ("schtasks", "Scheduled task created or changed"),
        ("ntds.dit", "NTDS.dit dump via volume shadow copy"),
        ("powerdump", "SAM hive access via PowerDump"),
        ("vssadmin", "Volume shadow copies deleted" if "delete" in text else "Volume shadow copy created"),
        ("wbadmin", "Backup catalog deleted"),
        ("bcdedit", "Boot recovery disabled"),
        ("bitlocker", "Suspicious BitLocker command"),
        ("taskmgr", "LSASS access from Task Manager"),
        ("excel", "DCOM Excel remote execution"),
        ("adfs", "Remote ADFS configuration export"),
        ("net user", "Remote local account creation"),
    )
    for token, name in mapping:
        if token in text:
            return name
    return filename.replace(".zip", "").replace(".log", "").replace("_", " ")


def _mitre_hint(rule_name: str, category: str):
    name = rule_name.lower()
    if category in ("benign", "false_positive"):
        return None
    if "bitlocker" in name or "ransom" in name or "encrypt" in name:
        return "T1486"
    if "shadow" in name or "backup" in name or "recovery" in name or "bcdedit" in name:
        return "T1490"
    if "dcsync" in name:
        return "T1003.006"
    if "ntds" in name:
        return "T1003.003"
    if "sam " in name or name.startswith("sam"):
        return "T1003.002"
    if "lsass" in name or "mimikatz" in name:
        return "T1003.001"
    if "rubeus" in name or "kerberos" in name:
        return "T1558.001"
    if "wmi" in name or "msbuild" in name:
        return "T1047"
    if "remoting" in name or "winrm" in name:
        return "T1021.006"
    if "scheduled task" in name:
        return "T1053.005"
    if "dcom" in name or "excel" in name:
        return "T1021.003"
    if "psexec" in name or "service" in name or "smb" in name:
        return "T1021.002"
    if "adfs" in name:
        return "T1021"
    if category == "ransomware":
        return "T1486"
    if category == "credential_attack":
        return "T1003"
    if category == "lateral_movement":
        return "T1021"
    return None


def _priority(category: str, rule_name: str) -> str:
    if category == "ransomware":
        return "Critical"
    if category == "credential_attack":
        if "rubeus" in rule_name.lower():
            return "High"
        return "Critical"
    if category == "lateral_movement":
        return "High"
    return "Low"


def _make_alert(alert_id, ev, kind, category, source, filename):
    rule = _rule_name(kind, ev, filename)
    alert = {
        "alert_id": alert_id,
        "timestamp": _timestamp(ev),
        "rule_name": rule,
        "vendor_severity": "critical" if category in ("credential_attack", "ransomware") else (
            "high" if category == "lateral_movement" else "low"
        ),
        "log_source": _channel(ev),
        "host": {"name": _host(ev)},
        "user": {"name": _user(ev)},
        "source": {"ip": None},
        "destination": {"ip": None},
        "raw_log": _slim(ev),
        "mitre_hint": _mitre_hint(rule, category),
        "data_source": source,
    }
    if kind == "false_positive":
        alert["fp_rationale"] = (
            "Real background process from this recording. The command is an "
            "admin or maintenance action and does not include a credential "
            "dump, remote payload, or ransomware tool."
        )
    label = {
        "alert_id": alert_id,
        "label_category": category,
        "label_priority": _priority(category, rule),
    }
    return alert, label


def _pick_otrf(events, filename):
    preferred = {"1", "4688", "4104", "800", "7045", "4663", "11"}

    def rank(ev):
        hits = _evidence(ev)
        eid = str(ev.get("EventID") or "")
        return (len(hits), eid in preferred)

    evidenced = [ev for ev in events if _evidence(ev)]
    evidenced.sort(key=rank, reverse=True)
    attack = evidenced[0] if evidenced else None
    follow = None
    if attack is not None:
        attack_eid = str(attack.get("EventID"))
        attack_cmd = str(attack.get("CommandLine") or "")
        for ev in evidenced[1:]:
            if str(ev.get("EventID")) != attack_eid or str(ev.get("CommandLine") or "") != attack_cmd:
                follow = ev
                break
    benign = next((ev for ev in events if _is_benign(ev)), None)
    fp = next((ev for ev in events if _is_false_positive(ev) and ev is not attack and ev is not follow), None)
    return attack, follow, benign, fp


def _load_existing():
    alerts, labels = [], {}
    if ALERTS_PATH.exists():
        for line in ALERTS_PATH.read_text(encoding="utf-8").splitlines():
            if line.strip():
                alerts.append(json.loads(line))
    if LABELS_PATH.exists():
        rows = LABELS_PATH.read_text(encoding="utf-8").splitlines()
        for row in rows[1:]:
            if not row.strip():
                continue
            alert_id, category, priority = row.split(",")
            labels[alert_id] = {"alert_id": alert_id, "label_category": category, "label_priority": priority}
    return alerts, labels


def _next_num(alerts, prefix):
    best = 0
    for alert in alerts:
        aid = alert["alert_id"]
        if not aid.startswith(prefix):
            continue
        tail = aid[len(prefix):]
        if tail.isdigit():
            best = max(best, int(tail))
    return best + 1


def expand_otrf(alerts):
    added = []
    n_attack = _next_num(alerts, "OTRF-")
    # OTRF-001 style only. BEN and FP use their own prefixes, so skip those.
    n_attack = max(
        (int(a["alert_id"].split("-")[1]) for a in alerts
         if a["alert_id"].startswith("OTRF-") and a["alert_id"].split("-")[1].isdigit()),
        default=0,
    ) + 1
    n_ben = _next_num(alerts, "OTRF-BEN-")
    n_fp = _next_num(alerts, "OTRF-FP-")
    for tactic, filename in NEW_OTRF:
        rel = f"datasets/atomic/windows/{tactic}/host/{filename}"
        url = OTRF_RAW + rel
        dest = CACHE / filename
        print(f"OTRF {filename}")
        try:
            raw = _download(url, dest)
            zf = zipfile.ZipFile(io.BytesIO(raw))
            member = max(zf.namelist(), key=lambda name: zf.getinfo(name).file_size)
            events = list(_iter_json_events(zf.read(member)))
        except Exception as exc:
            print(f"  skip: {type(exc).__name__}: {exc}")
            continue
        if not events:
            print("  skip: no events")
            continue
        attack, follow, benign, fp = _pick_otrf(events, filename)
        source = f"https://github.com/OTRF/Security-Datasets :: {rel}"
        category = "credential_attack" if tactic == "credential_access" else "lateral_movement"
        batch = []
        if attack is not None:
            batch.append(_make_alert(f"OTRF-{n_attack:03d}", attack, "attack", category, source, filename))
            n_attack += 1
        if follow is not None:
            batch.append(_make_alert(f"OTRF-{n_attack:03d}", follow, "attack", category, source, filename))
            n_attack += 1
        if benign is not None:
            note = source + " (benign background event)"
            batch.append(_make_alert(f"OTRF-BEN-{n_ben:03d}", benign, "benign", "benign", note, filename))
            n_ben += 1
        if fp is not None:
            note = source + " (benign background event, team-labelled false positive)"
            batch.append(_make_alert(f"OTRF-FP-{n_fp:03d}", fp, "false_positive", "false_positive", note, filename))
            n_fp += 1
        print(f"  events={len(events)} kept={len(batch)}")
        added.extend(batch)
    return added


def _splunk_events(text: str, path: str):
    """Pull technique events out of a Splunk sample log."""
    if text.lstrip().startswith("{"):
        events = list(_iter_json_events(text.encode("utf-8", errors="ignore")))
    else:
        events = _parse_splunk_blocks(text)
    kept = []
    seen = set()
    for ev in events:
        if "EventID" not in ev and ev.get("EventCode"):
            ev["EventID"] = ev["EventCode"]
        ev.setdefault("Hostname", ev.get("ComputerName") or "attack-range")
        ev.setdefault("Channel", ev.get("LogName") or "WinEventLog")
        ev.setdefault("UtcTime", ev.get("TimeCreated") or "unknown")
        if not ev.get("CommandLine"):
            message = ev.get("Message") or ""
            ev["CommandLine"] = message[:500]
        hits = _evidence(ev)
        if not hits:
            continue
        key = (ev.get("EventID"), hits[0], str(ev.get("CommandLine"))[:120])
        if key in seen:
            continue
        seen.add(key)
        kept.append(ev)
        if len(kept) >= 2:
            break
    return kept


def _parse_splunk_blocks(text: str):
    """Splunk's exported logs are blank-line-separated Key=value records."""
    blocks, current = [], []
    for line in text.splitlines():
        if not line.strip():
            if current:
                blocks.append(current)
                current = []
            continue
        current.append(line)
    if current:
        blocks.append(current)
    events = []
    for lines in blocks:
        ev, message_key = {}, None
        for line in lines:
            if message_key and "=" not in line[:40]:
                ev[message_key] += "\n" + line
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            if " " in key or len(key) > 40:
                if message_key:
                    ev[message_key] += "\n" + line
                continue
            ev[key] = value
            message_key = key if key in ("Message", "ScriptBlockText") else None
        if ev.get("EventCode") or ev.get("EventID") or ev.get("Message"):
            events.append(ev)
    return events


def expand_splunk(alerts):
    added = []
    n = max(
        (int(a["alert_id"].split("-")[1]) for a in alerts if a["alert_id"].startswith("SPLK-")),
        default=0,
    ) + 1
    seen_snips = set()
    for rel in NEW_SPLUNK:
        url = SPLUNK_RAW + rel
        dest = CACHE / rel.replace("/", "__")
        print(f"Splunk {rel}")
        try:
            data = _download(url, dest)
            text = data.decode("utf-8", errors="replace")
        except Exception as exc:
            print(f"  skip: {type(exc).__name__}: {exc}")
            continue
        if "git-lfs" in text[:200]:
            print("  skip: git-lfs")
            continue
        events = _splunk_events(text, rel)
        if not events:
            print("  skip: no technique line")
            continue
        ev = events[0]
        snip = _blob(ev)[:240]
        if snip in seen_snips:
            print("  skip: duplicate snippet")
            continue
        seen_snips.add(snip)
        tech = "T1486" if "/T1486/" in rel else "T1490"
        source = f"https://github.com/splunk/attack_data :: {rel}"
        alert, label = _make_alert(f"SPLK-{n:03d}", ev, "attack", "ransomware", source, rel.split("/")[-1])
        alert["mitre_hint"] = tech
        label["label_priority"] = "Critical"
        alert["vendor_severity"] = "critical"
        added.append((alert, label))
        n += 1
        print(f"  kept {alert['rule_name']}")
    return added


def _load_generator():
    path = DATA / "generate_alerts.py"
    spec = importlib.util.spec_from_file_location("generate_alerts", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def expand_synthetic(alerts, labels_by_id):
    """Fill categories that are still short of TARGETS. Real rows stay."""
    counts = Counter(labels_by_id[a["alert_id"]]["label_category"] for a in alerts if a["alert_id"] in labels_by_id)
    gen = _load_generator()
    makers = {
        "benign": gen.make_benign,
        "false_positive": gen.make_false_positive,
        "credential_attack": gen.make_credential_attack,
        "lateral_movement": gen.make_lateral_movement,
        "ransomware": gen.make_ransomware,
    }
    random.seed(42)
    added = []
    n = 1
    for category, maker in makers.items():
        need = max(0, TARGETS[category] - counts[category])
        for _ in range(need):
            row = maker()
            event = gen.to_siem_event({
                **row,
                "alert_id": f"SYN-{n:04d}",
                "timestamp": f"2026-10-01T08:{n % 60:02d}:00",
            })
            event["alert_id"] = f"SYN-{n:04d}"
            event["mitre_hint"] = _mitre_hint(event["rule_name"], category)
            event["data_source"] = "synthetic :: data/generate_alerts.py seed=42 (documentation IPs only)"
            if category == "false_positive":
                event["fp_rationale"] = (
                    "Synthetic admin, scanner, or mistyped-password activity. "
                    "It is labelled false_positive because the generator built it "
                    "as legitimate noise rather than an attack."
                )
            label = {
                "alert_id": event["alert_id"],
                "label_category": category,
                "label_priority": row["label_priority"],
            }
            added.append((event, label))
            n += 1
        print(f"synthetic {category}: +{need}")
    return added


def _is_expanded(alert: dict) -> bool:
    source = alert.get("data_source") or ""
    if source.startswith("synthetic ::"):
        return True
    if alert["alert_id"].startswith("SYN-"):
        return True
    new_names = {name for _tactic, name in NEW_OTRF}
    new_names.update(path.split("/")[-1] for path in NEW_SPLUNK)
    return any(name in source for name in new_names)


def main():
    alerts, labels = _load_existing()
    original = [a for a in alerts if not _is_expanded(a)]
    print(f"keeping {len(original)} original alerts")
    fresh = []
    fresh.extend(expand_otrf(original))
    current_ids = original + [a for a, _l in fresh]
    fresh.extend(expand_splunk(current_ids))
    merged = list(original)
    label_map = {aid: lab for aid, lab in labels.items() if any(a["alert_id"] == aid for a in original)}
    for alert, label in fresh:
        merged.append(alert)
        label_map[alert["alert_id"]] = label
    synthetic = expand_synthetic(merged, label_map)
    for alert, label in synthetic:
        merged.append(alert)
        label_map[alert["alert_id"]] = label

    missing = [a["alert_id"] for a in merged if a["alert_id"] not in label_map]
    if missing:
        raise SystemExit(f"missing labels for {missing[:5]}")

    with ALERTS_PATH.open("w", encoding="utf-8") as handle:
        for alert in merged:
            handle.write(json.dumps(alert) + "\n")
    with LABELS_PATH.open("w", encoding="utf-8", newline="") as handle:
        handle.write("alert_id,label_category,label_priority\n")
        for alert in merged:
            lab = label_map[alert["alert_id"]]
            handle.write(f"{lab['alert_id']},{lab['label_category']},{lab['label_priority']}\n")

    counts = Counter(label_map[a["alert_id"]]["label_category"] for a in merged)
    origins = Counter()
    for alert in merged:
        src = alert.get("data_source") or ""
        if src.startswith("synthetic"):
            origins["synthetic"] += 1
        elif "splunk/attack_data" in src:
            origins["splunk"] += 1
        else:
            origins["otrf"] += 1
    print(f"\nWrote {len(merged)} alerts")
    print("categories", dict(counts))
    print("origins", dict(origins))


if __name__ == "__main__":
    main()
