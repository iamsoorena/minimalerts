#!/usr/bin/env python3
import argparse
import json
import os
import re
import shutil
import smtplib
import socket
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage

try:
    from ippanel import Client
except Exception:
    Client = None


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.environ.get("MONITOR_CONFIG_PATH", os.path.join(BASE_DIR, "config.json"))
STATE_PATH = os.environ.get("MONITOR_STATE_PATH", os.path.join(BASE_DIR, "state.json"))
PROC_PATH = os.environ.get("MONITOR_PROC_PATH", "/proc")
ROOT_PATH = os.environ.get("MONITOR_ROOT_PATH", "/")


def parse_sample_window_sec():
    raw = os.environ.get("MONITOR_SAMPLE_WINDOW_SEC", "5")
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        return 5.0


SAMPLE_WINDOW_SEC = parse_sample_window_sec()


def now_utc_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except Exception as exc:
        print(f"[{now_utc_iso()}] failed to load {path}: {exc}")
        return default


def save_json(path, data):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def read_proc_stat_cpu():
    with open(os.path.join(PROC_PATH, "stat"), "r", encoding="utf-8") as f:
        first = f.readline().strip()
    parts = first.split()
    if not parts or parts[0] != "cpu":
        raise RuntimeError("unexpected /proc/stat format")
    vals = [int(x) for x in parts[1:11]]
    keys = [
        "user",
        "nice",
        "system",
        "idle",
        "iowait",
        "irq",
        "softirq",
        "steal",
        "guest",
        "guest_nice",
    ]
    return dict(zip(keys, vals))


def read_mem_available_mb():
    with open(os.path.join(PROC_PATH, "meminfo"), "r", encoding="utf-8") as f:
        txt = f.read()
    m = re.search(r"^MemAvailable:\s+(\d+)\s+kB$", txt, re.MULTILINE)
    if not m:
        return None
    return int(m.group(1)) // 1024


def read_mem_total_mb():
    with open(os.path.join(PROC_PATH, "meminfo"), "r", encoding="utf-8") as f:
        txt = f.read()
    m = re.search(r"^MemTotal:\s+(\d+)\s+kB$", txt, re.MULTILINE)
    if not m:
        return None
    return int(m.group(1)) // 1024


def read_load1():
    with open(os.path.join(PROC_PATH, "loadavg"), "r", encoding="utf-8") as f:
        return float(f.read().split()[0])


def read_pswpout():
    with open(os.path.join(PROC_PATH, "vmstat"), "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("pswpout "):
                return int(line.split()[1])
    return None


def read_root_disk_used_pct():
    total, used, _free = shutil.disk_usage(ROOT_PATH)
    if total <= 0:
        return None
    return (used * 100.0) / total


def read_root_inode_used_pct():
    s = os.statvfs(ROOT_PATH)
    if s.f_files <= 0:
        return None
    used = s.f_files - s.f_ffree
    return (used * 100.0) / s.f_files


def service_active(service):
    unit = service if service.endswith(".service") else f"{service}.service"
    try:
        p = subprocess.run(
            ["systemctl", "is-active", unit],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        # systemctl is unavailable in some environments (e.g. containers)
        return None
    return p.stdout.strip() == "active"


def fetch_ipinfo_summary():
    try:
        req = urllib.request.Request(
            "https://ipinfo.io/json",
            headers={"User-Agent": "minimalerts/1.0"},
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.load(resp)
    except (urllib.error.URLError, TimeoutError, ValueError, OSError):
        return None

    fields = ["ip", "city", "region", "country", "org"]
    parts = [f"{key}={data.get(key)}" for key in fields if data.get(key)]
    if not parts:
        return None
    return " | ".join(parts)


def resolve_server_label(cfg):
    configured = cfg.get("server_name")
    if isinstance(configured, str) and configured.strip():
        return configured.strip()

    ipinfo = fetch_ipinfo_summary()
    if ipinfo:
        return f"{socket.gethostname()} ({ipinfo})"
    return socket.gethostname()


def read_pid1_comm():
    try:
        with open(os.path.join(PROC_PATH, "1", "comm"), "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return None


def send_email(cfg, subject, body):
    email_cfg = cfg.get("email", {})
    sender = email_cfg.get("host_user")
    password = email_cfg.get("host_password")
    recipients = email_cfg.get("recipients", [])
    smtp_host = email_cfg.get("smtp_host", "smtp.gmail.com")
    smtp_port = int(email_cfg.get("smtp_port", 587))

    if not sender or not password or not recipients:
        raise RuntimeError("email config missing sender/password/recipients")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)

    with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as s:
        s.starttls()
        s.login(sender, password)
        s.send_message(msg)


def normalize_phone(phone):
    digits = re.sub(r"\D", "", phone or "")
    if digits.startswith("98"):
        return digits
    if digits.startswith("0"):
        return "98" + digits[1:]
    if digits.startswith("9"):
        return "98" + digits
    raise ValueError(f"unsupported phone format: {phone}")


def send_sms(cfg, code):
    if Client is None:
        raise RuntimeError("ippanel package is not installed")

    sms_cfg = cfg.get("sms", {})
    api_key = sms_cfg.get("api_key")
    sender = sms_cfg.get("sender_number")
    pattern_code = sms_cfg.get("pattern_code")
    recipients = sms_cfg.get("recipients", [])

    if not api_key or not sender or not pattern_code or not recipients:
        raise RuntimeError("sms config missing api_key/sender/pattern/recipients")

    client = Client(api_key)
    pattern_values = {"verification-code": str(code)}

    errors = []
    for phone in recipients:
        try:
            dest = normalize_phone(phone)
            client.send_pattern(pattern_code, sender, dest, pattern_values)
        except Exception as exc:
            errors.append(f"{phone}: {exc}")

    if errors:
        raise RuntimeError("sms send errors: " + " | ".join(errors))


def send_notifications(cfg, subject, body, sms_code):
    errors = []
    try:
        send_email(cfg, subject, body)
    except Exception as exc:
        errors.append(f"email failed: {exc}")

    # Check if SMS is enabled before attempting to send
    if cfg.get("sms", {}).get("enabled", False):
        try:
            send_sms(cfg, sms_code)
        except Exception as exc:
            errors.append(f"sms failed: {exc}")

    return errors


def evaluate(cfg, metrics):
    t = cfg.get("thresholds", {})
    reasons = []

    iowait_limit = float(t.get("iowait_percent", 20))
    steal_limit = float(t.get("steal_percent", 10))
    swapout_limit = float(t.get("swap_out_per_sec", 40))
    mem_used_pct_limit = float(t.get("mem_used_percent", 85))
    cpu_busy_limit = float(t.get("cpu_busy_percent", 90))
    load_limit = float(t.get("load1_per_cpu", 2.0))
    disk_used_limit = float(t.get("disk_used_percent", 90))
    inode_used_limit = float(t.get("inode_used_percent", 90))

    if metrics.get("iowait_pct") is not None and metrics["iowait_pct"] >= iowait_limit:
        reasons.append(f"iowait high ({metrics['iowait_pct']:.2f}% >= {iowait_limit}%)")
    if metrics.get("steal_pct") is not None and metrics["steal_pct"] >= steal_limit:
        reasons.append(f"steal high ({metrics['steal_pct']:.2f}% >= {steal_limit}%)")
    if metrics.get("swap_out_per_sec") is not None and metrics["swap_out_per_sec"] >= swapout_limit:
        reasons.append(
            f"swap out high ({metrics['swap_out_per_sec']:.2f}/s >= {swapout_limit}/s)"
        )
    if metrics.get("mem_used_pct") is not None and metrics["mem_used_pct"] >= mem_used_pct_limit:
        reasons.append(
            f"RAM usage high ({metrics['mem_used_pct']:.2f}% >= {mem_used_pct_limit}%)"
        )
    if metrics.get("cpu_busy_pct") is not None and metrics["cpu_busy_pct"] >= cpu_busy_limit:
        reasons.append(
            f"CPU usage high ({metrics['cpu_busy_pct']:.2f}% >= {cpu_busy_limit}%)"
        )
    if metrics.get("load1_per_cpu") is not None and metrics["load1_per_cpu"] >= load_limit:
        reasons.append(
            f"load per cpu high ({metrics['load1_per_cpu']:.2f} >= {load_limit})"
        )
    if metrics.get("disk_used_pct") is not None and metrics["disk_used_pct"] >= disk_used_limit:
        reasons.append(
            f"disk usage high ({metrics['disk_used_pct']:.2f}% >= {disk_used_limit}%)"
        )
    if metrics.get("inode_used_pct") is not None and metrics["inode_used_pct"] >= inode_used_limit:
        reasons.append(
            f"inode usage high ({metrics['inode_used_pct']:.2f}% >= {inode_used_limit}%)"
        )

    for svc, is_active in metrics.get("service_active", {}).items():
        if is_active is False:
            reasons.append(f"service down ({svc})")

    return reasons


def build_alert(hostname, reasons, metrics):
    lines = [
        f"Server health alert on {hostname}",
        f"Time (UTC): {now_utc_iso()}",
        "",
        "Reasons:",
    ]
    for r in reasons:
        lines.append(f"- {r}")

    lines += [
        "",
        "Metrics:",
        f"- iowait_pct: {metrics.get('iowait_pct')}",
        f"- steal_pct: {metrics.get('steal_pct')}",
        f"- swap_out_per_sec: {metrics.get('swap_out_per_sec')}",
        f"- mem_available_mb: {metrics.get('mem_available_mb')}",
        f"- mem_total_mb: {metrics.get('mem_total_mb')}",
        f"- mem_used_mb: {metrics.get('mem_used_mb')}",
        f"- mem_used_pct: {metrics.get('mem_used_pct')}",
        f"- cpu_busy_pct: {metrics.get('cpu_busy_pct')}",
        f"- load1: {metrics.get('load1')}",
        f"- cpu_count: {metrics.get('cpu_count')}",
        f"- load1_per_cpu: {metrics.get('load1_per_cpu')}",
        f"- disk_used_pct: {metrics.get('disk_used_pct')}",
        f"- inode_used_pct: {metrics.get('inode_used_pct')}",
        f"- services: {metrics.get('service_active')}",
    ]
    return "\n".join(lines)


def build_recovery_message(hostname, metrics):
    return (
        f"Server recovery notice on {hostname}\n"
        f"Time (UTC): {now_utc_iso()}\n\n"
        "The host has returned to healthy state after a previous alert.\n\n"
        "Current quick metrics:\n"
        f"- cpu_busy_pct: {metrics.get('cpu_busy_pct')}\n"
        f"- iowait_pct: {metrics.get('iowait_pct')}\n"
        f"- steal_pct: {metrics.get('steal_pct')}\n"
        f"- mem_used_pct: {metrics.get('mem_used_pct')}\n"
        f"- disk_used_pct: {metrics.get('disk_used_pct')}\n"
        f"- load1_per_cpu: {metrics.get('load1_per_cpu')}\n"
        f"- services: {metrics.get('service_active')}\n"
    )


def collect_metrics(cfg):
    """Collect metrics over a sampling window to smooth out transient spikes.

    CPU, IOWait, Steal, and Swap are computed as deltas across the window.
    Memory is sampled at the start, middle, and end; the median is used.
    Load (already kernel-averaged), disk, and inode are read once.
    """
    window = SAMPLE_WINDOW_SEC
    half = window / 2.0

    # --- t=0: start of sampling window ---
    cpu_start = read_proc_stat_cpu()
    pswpout_start = read_pswpout()
    mem_samples = [read_mem_available_mb()]

    if half > 0:
        time.sleep(half)

    # --- t=window/2: midpoint sample ---
    mem_samples.append(read_mem_available_mb())

    if half > 0:
        time.sleep(half)

    # --- t=window: end of sampling window ---
    cpu_end = read_proc_stat_cpu()
    pswpout_end = read_pswpout()
    mem_samples.append(read_mem_available_mb())

    # CPU metrics: delta over the sampling window
    iowait_pct = None
    steal_pct = None
    cpu_busy_pct = None

    total_start = sum(cpu_start.values())
    total_end = sum(cpu_end.values())
    delta_total = total_end - total_start
    if delta_total > 0:
        iowait_pct = (cpu_end["iowait"] - cpu_start["iowait"]) * 100.0 / delta_total
        steal_pct = (cpu_end["steal"] - cpu_start["steal"]) * 100.0 / delta_total
        delta_idle = (cpu_end["idle"] - cpu_start["idle"]) + (cpu_end["iowait"] - cpu_start["iowait"])
        cpu_busy_pct = ((delta_total - delta_idle) * 100.0) / delta_total

    # Swap rate over the sampling window
    swap_out_per_sec = None
    if pswpout_start is not None and pswpout_end is not None and window > 0:
        swap_out_per_sec = (pswpout_end - pswpout_start) / window

    # Memory: use median of samples to resist transient spikes
    mem_total = read_mem_total_mb()
    valid_mem = [m for m in mem_samples if m is not None]
    mem_avail = int(statistics.median(valid_mem)) if valid_mem else None

    mem_used_mb = None
    mem_used_pct = None
    if mem_total is not None and mem_avail is not None:
        mem_used_mb = max(mem_total - mem_avail, 0)
        if mem_total > 0:
            mem_used_pct = (mem_used_mb * 100.0) / mem_total

    # Load, disk, inode: single read (stable or already kernel-averaged)
    load1 = read_load1()
    cpu_count = os.cpu_count() or 1
    disk_used_pct = read_root_disk_used_pct()
    inode_used_pct = read_root_inode_used_pct()

    services = {}
    for svc in cfg.get("services", ["ssh", "docker"]):
        services[svc] = service_active(svc)

    metrics = {
        "iowait_pct": round(iowait_pct, 2) if iowait_pct is not None else None,
        "steal_pct": round(steal_pct, 2) if steal_pct is not None else None,
        "cpu_busy_pct": round(cpu_busy_pct, 2) if cpu_busy_pct is not None else None,
        "swap_out_per_sec": round(swap_out_per_sec, 2) if swap_out_per_sec is not None else None,
        "mem_available_mb": mem_avail,
        "mem_total_mb": mem_total,
        "mem_used_mb": mem_used_mb,
        "mem_used_pct": round(mem_used_pct, 2) if mem_used_pct is not None else None,
        "load1": load1,
        "cpu_count": cpu_count,
        "load1_per_cpu": round(load1 / max(cpu_count, 1), 3),
        "disk_used_pct": round(disk_used_pct, 2) if disk_used_pct is not None else None,
        "inode_used_pct": round(inode_used_pct, 2) if inode_used_pct is not None else None,
        "service_active": services,
    }
    return metrics


def run_once():
    cfg = load_json(CONFIG_PATH, {})
    if not cfg:
        print(f"[{now_utc_iso()}] missing config at {CONFIG_PATH}")
        return 2

    state = load_json(
        STATE_PATH,
        {
            "breach_streak": 0,
            "last_alert_ts": 0,
            "incident_open": False,
        },
    )

    now_ts = time.time()
    metrics = collect_metrics(cfg)

    reasons = evaluate(cfg, metrics)
    if reasons:
        state["breach_streak"] = int(state.get("breach_streak", 0)) + 1
    else:
        state["breach_streak"] = 0

    consecutive = int(cfg.get("consecutive_failures", 3))
    cooldown = int(cfg.get("cooldown_minutes", 20)) * 60
    should_alert = (
        len(reasons) > 0
        and state["breach_streak"] >= consecutive
        and (now_ts - float(state.get("last_alert_ts", 0))) >= cooldown
    )

    server_label = resolve_server_label(cfg)
    if should_alert:
        subject = f"[ALERT] {server_label} health issue detected"
        body = build_alert(server_label, reasons, metrics)
        delivery_errors = send_notifications(cfg, subject, body, int(now_ts) % 1000000)

        if delivery_errors:
            print(f"[{now_utc_iso()}] ALERT trigger with delivery issues: {'; '.join(delivery_errors)}")
        else:
            print(f"[{now_utc_iso()}] ALERT sent successfully")
        state["last_alert_ts"] = now_ts
        state["incident_open"] = True
    else:
        if reasons:
            print(
                f"[{now_utc_iso()}] breach detected (streak {state['breach_streak']}/{consecutive}), waiting for confirmation: {reasons}"
            )
        else:
            if state.get("incident_open") and bool(cfg.get("notify_recovery", True)):
                recovery_subject = f"[RECOVERY] {server_label} health recovered"
                recovery_body = build_recovery_message(server_label, metrics)
                recovery_errors = send_notifications(
                    cfg, recovery_subject, recovery_body, int(now_ts) % 1000000
                )
                if recovery_errors:
                    print(
                        f"[{now_utc_iso()}] recovery notify had delivery issues: {'; '.join(recovery_errors)}"
                    )
                else:
                    print(f"[{now_utc_iso()}] recovery notification sent")
            state["incident_open"] = False
            print(f"[{now_utc_iso()}] healthy")

    # Clean up legacy state fields no longer needed (metrics are now
    # computed within a sampling window, not from inter-run deltas).
    for key in ("last_cpu", "last_pswpout", "last_ts"):
        state.pop(key, None)
    save_json(STATE_PATH, state)
    return 0


def main():
    parser = argparse.ArgumentParser(description="Server health monitor")
    parser.add_argument("--run-once", action="store_true", help="run a single check")
    parser.add_argument("--test-alert", action="store_true", help="send a test alert immediately")
    parser.add_argument("--test-email", action="store_true", help="send a test email only")
    parser.add_argument("--self-test", action="store_true", help="collect metrics and print evaluation without sending notifications")
    parser.add_argument("--verify-host", action="store_true", help="print host-view diagnostics for Docker/namespace setup")
    args = parser.parse_args()

    cfg = load_json(CONFIG_PATH, {})
    if args.test_email:
        server_label = resolve_server_label(cfg)
        subject = f"[TEST] {server_label} monitor email test"
        body = (
            f"This is an email-only test alert from {server_label} at {now_utc_iso()}.\n"
            "If you received this, email configuration is correct."
        )
        try:
            send_email(cfg, subject, body)
        except Exception as exc:
            print(f"[{now_utc_iso()}] test email failed: {exc}")
            return 1
        print(f"[{now_utc_iso()}] test email sent")
        return 0

    if args.test_alert:
        server_label = resolve_server_label(cfg)
        subject = f"[TEST] {server_label} monitor alert channel test"
        body = (
            f"This is a test alert from {server_label} at {now_utc_iso()}.\n"
            "If you received this, email channel is configured correctly."
        )
        errors = send_notifications(cfg, subject, body, int(time.time()) % 1000000)
        if errors:
            print(f"[{now_utc_iso()}] test alert partial/failed: {'; '.join(errors)}")
            return 1
        print(f"[{now_utc_iso()}] test alert sent")
        return 0

    if args.self_test:
        metrics = collect_metrics(cfg)
        reasons = evaluate(cfg, metrics)
        print(
            json.dumps(
                {
                    "server_label": resolve_server_label(cfg),
                    "time_utc": now_utc_iso(),
                    "metrics": metrics,
                    "reasons": reasons,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if args.verify_host:
        metrics = collect_metrics(cfg)
        in_container = os.path.exists("/.dockerenv")
        pid1_comm = read_pid1_comm()
        warnings = []
        if in_container and ROOT_PATH == "/":
            warnings.append("ROOT_PATH is '/': disk/inode metrics likely reflect container filesystem, not host.")
        if in_container and pid1_comm and pid1_comm not in ("systemd", "init"):
            warnings.append(
                f"PID namespace may not be host (pid1='{pid1_comm}'). CPU/RAM/load might be container-scoped."
            )
        print(
            json.dumps(
                {
                    "time_utc": now_utc_iso(),
                    "server_label": resolve_server_label(cfg),
                    "in_container": in_container,
                    "monitor_paths": {
                        "proc_path": PROC_PATH,
                        "root_path": ROOT_PATH,
                    },
                    "pid1_comm": pid1_comm,
                    "metrics": metrics,
                    "warnings": warnings,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if args.run_once:
        return run_once()

    return run_once()


if __name__ == "__main__":
    sys.exit(main())
