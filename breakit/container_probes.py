"""In-container isolation probes executed from within tenant containers (red/blue).

SECURITY: Architecture §10 - Probes N1..N4, F1..F3, P1..P5.
Every probe is a REAL attempt (real socket connections, real filesystem writes,
real ctypes syscalls). Only standard library used.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import socket
import sys


def probe_n1(role: str) -> dict:
    """N1: Resolve forbidden hostnames (must fail)."""
    desc = f"From {role}: resolve other services (DNS)"
    forbidden = ["model", "model-red", "model-blue", "logger", "verifier"]
    if role == "red":
        forbidden.append("blue")
    else:
        forbidden.append("red")

    resolved = []
    for host in forbidden:
        try:
            socket.getaddrinfo(host, 80, socket.AF_INET)
            resolved.append(host)
        except socket.gaierror:
            pass
        except Exception:
            pass

    if resolved:
        return {
            "passed": False,
            "observed": f"Resolution succeeded for forbidden host(s): {', '.join(resolved)}",
            "expected": "Resolution fails for all forbidden services",
            "description": desc,
        }
    return {
        "passed": True,
        "observed": f"All {len(forbidden)} forbidden hostnames failed to resolve (gaierror)",
        "expected": "Resolution fails for all forbidden services",
        "description": desc,
    }


def probe_n2(role: str, targets: list) -> dict:
    """N2: Real TCP connect (2s timeout) to target IPs of other services on all networks."""
    desc = f"From {role}: TCP connect to other service IPs"
    connected = []
    checked_count = 0
    for item in targets:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            ip, port = str(item[0]), int(item[1])
        else:
            continue
        checked_count += 1
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect((ip, port))
            connected.append(f"{ip}:{port}")
        except (socket.timeout, OSError):
            pass
        finally:
            s.close()

    if connected:
        return {
            "passed": False,
            "observed": f"Connected to forbidden targets: {', '.join(connected)}",
            "expected": "All TCP connections fail",
            "description": desc,
        }
    return {
        "passed": True,
        "observed": f"All {checked_count} forbidden TCP connects failed (timeout/unreachable)",
        "expected": "All TCP connections fail",
        "description": desc,
    }


def probe_n3(role: str) -> dict:
    """N3: Connect to 1.1.1.1:443 (must fail)."""
    desc = f"From {role}: connect to 1.1.1.1:443"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect(("1.1.1.1", 443))
        s.close()
        return {
            "passed": False,
            "observed": "Connected to 1.1.1.1:443 (outbound internet access permitted)",
            "expected": "Connect fails (internal network, no internet)",
            "description": desc,
        }
    except (socket.timeout, OSError) as e:
        s.close()
        return {
            "passed": True,
            "observed": f"Connect to 1.1.1.1:443 failed as expected ({type(e).__name__})",
            "expected": "Connect fails (internal network, no internet)",
            "description": desc,
        }


def probe_n4(role: str) -> dict:
    """N4: Exactly one non-loopback interface; scan own /24 for open ports (gateway only)."""
    desc = f"From {role}: exactly one non-loopback interface; scan own /24 for open ports"
    try:
        ifaces = [iface for iface in os.listdir("/sys/class/net") if iface != "lo"]
    except Exception as e:
        return {
            "passed": False,
            "observed": f"Failed to list network interfaces: {e}",
            "expected": "Exactly 1 non-loopback interface",
            "description": desc,
        }

    if len(ifaces) != 1:
        return {
            "passed": False,
            "observed": f"Found {len(ifaces)} non-loopback interfaces: {ifaces}",
            "expected": "Exactly 1 non-loopback interface",
            "description": desc,
        }

    iface = ifaces[0]
    own_ip = None
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("172.255.255.255", 1))
        candidate = s.getsockname()[0]
        if candidate and not candidate.startswith("127."):
            own_ip = candidate
    except Exception:
        pass
    finally:
        s.close()

    if not own_ip:
        try:
            import fcntl
            import struct

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            own_ip = socket.inet_ntoa(
                fcntl.ioctl(
                    s.fileno(),
                    0x8915,  # SIOCGIFADDR
                    struct.pack("256s", iface[:15].encode("utf-8")),
                )[20:24]
            )
            s.close()
        except Exception:
            pass

    if not own_ip:
        return {
            "passed": False,
            "observed": f"Could not determine IP for interface {iface}",
            "expected": "1 interface with valid IP",
            "description": desc,
        }

    parts = own_ip.split(".")
    subnet_prefix = f"{parts[0]}.{parts[1]}.{parts[2]}."

    import select

    ports_to_check = [8000, 8001, 8002, 8080, 80, 443]
    open_targets: list[str] = []

    # Scan each port across the /24 subnet using non-blocking poll (respects pids_limit and RLIMIT_NOFILE)
    for p in ports_to_check:
        poller = select.poll()
        sock_map: dict[int, tuple[socket.socket, str]] = {}
        for i in range(1, 255):
            ip = f"{subnet_prefix}{i}"
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            try:
                s.connect((ip, p))
            except (BlockingIOError, OSError):
                pass
            poller.register(s, select.POLLOUT | select.POLLERR | select.POLLHUP)
            sock_map[s.fileno()] = (s, ip)

        events = poller.poll(200)
        for fd, event in events:
            s, ip = sock_map[fd]
            if event & select.POLLOUT:
                err = s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if err == 0:
                    open_targets.append(f"{ip}:{p}")
        for s, _ in sock_map.values():
            s.close()

    # External open targets (excluding tenant container's own health port)
    external_open = [t for t in open_targets if not t.startswith(f"{own_ip}:")]

    # In a hardened tenant network, ONLY the gateway port (8000) is open
    if len(external_open) == 1 and external_open[0].endswith(":8000"):
        return {
            "passed": True,
            "observed": f"1 iface ({iface}); only gateway port open in /24: {external_open[0]}",
            "expected": "Only gateway's port is open",
            "description": desc,
        }
    return {
        "passed": False,
        "observed": f"1 iface ({iface}); open targets: {external_open} (all: {open_targets})",
        "expected": "Only gateway's port is open",
        "description": desc,
    }


def probe_f1(role: str) -> dict:
    """F1: Other tenant data, log volume and docker.sock absent."""
    desc = f"From {role}: other tenant data, log volume and docker.sock absent"
    forbidden = ["/app/log-data", "/log-data", "/var/run/docker.sock"]
    if role == "red":
        forbidden.extend(["/data/blue", "/data/bundles"])
    else:
        forbidden.extend(["/data/red", "/data/pool.jsonl"])

    found = [p for p in forbidden if os.path.exists(p)]
    if found:
        return {
            "passed": False,
            "observed": f"Found forbidden paths: {', '.join(found)}",
            "expected": "All forbidden paths absent",
            "description": desc,
        }
    return {
        "passed": True,
        "observed": f"All forbidden paths absent ({len(forbidden)} paths verified absent)",
        "expected": "All forbidden paths absent",
        "description": desc,
    }


def probe_f2(role: str) -> dict:
    """F2: Write to / and /app fails (read-only); /tmp works."""
    desc = f"From {role}: write to / and /app fails; /tmp works"
    root_failed = False
    try:
        with open("/breakit_probe.tmp", "w") as f:
            f.write("test")
    except OSError:
        root_failed = True

    app_failed = False
    try:
        with open("/app/breakit_probe.tmp", "w") as f:
            f.write("test")
    except OSError:
        app_failed = True

    tmp_ok = False
    try:
        path = "/tmp/breakit_probe.tmp"
        with open(path, "w") as f:
            f.write("test_ok")
        with open(path, "r") as f:
            if f.read() == "test_ok":
                tmp_ok = True
        os.remove(path)
    except Exception:
        tmp_ok = False

    if root_failed and app_failed and tmp_ok:
        return {
            "passed": True,
            "observed": "Root and /app writes failed (read-only); /tmp writable",
            "expected": "Root and /app writes fail; /tmp writable",
            "description": desc,
        }
    return {
        "passed": False,
        "observed": f"root_blocked={root_failed}, app_blocked={app_failed}, tmp_writable={tmp_ok}",
        "expected": "Root and /app writes fail; /tmp writable",
        "description": desc,
    }


def probe_f3(role: str) -> dict:
    """F3: List /run/secrets - only own secret present."""
    desc = f"From {role}: list /run/secrets"
    expected = [f"{role}_token"]
    try:
        secrets = sorted(os.listdir("/run/secrets"))
    except Exception as e:
        return {
            "passed": False,
            "observed": f"Failed to list /run/secrets: {e}",
            "expected": f"Only {expected}",
            "description": desc,
        }
    if secrets == expected:
        return {
            "passed": True,
            "observed": f"Only own secret present: {secrets}",
            "expected": f"Only {expected}",
            "description": desc,
        }
    return {
        "passed": False,
        "observed": f"Unexpected secrets in /run/secrets: {secrets}",
        "expected": f"Only {expected}",
        "description": desc,
    }


def probe_p1(role: str) -> dict:
    """P1: Effective uid is not 0."""
    desc = f"From {role}: effective uid not 0"
    uid = os.geteuid()
    if uid != 0:
        return {
            "passed": True,
            "observed": f"Effective UID is {uid} (non-root)",
            "expected": "Not 0",
            "description": desc,
        }
    return {
        "passed": False,
        "observed": "Effective UID is 0 (root)",
        "expected": "Not 0",
        "description": desc,
    }


def probe_p2(role: str) -> dict:
    """P2: CapEff in /proc/self/status is all zero."""
    desc = f"From {role}: CapEff in /proc/self/status all zero"
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("CapEff:"):
                    val_str = line.split()[1].strip()
                    val = int(val_str, 16)
                    if val == 0:
                        return {
                            "passed": True,
                            "observed": f"CapEff is 0 ({val_str})",
                            "expected": "All zero",
                            "description": desc,
                        }
                    return {
                        "passed": False,
                        "observed": f"CapEff is non-zero: {val_str}",
                        "expected": "All zero",
                        "description": desc,
                    }
        return {
            "passed": False,
            "observed": "CapEff not found in /proc/self/status",
            "expected": "All zero",
            "description": desc,
        }
    except Exception as e:
        return {
            "passed": False,
            "observed": f"Error reading /proc/self/status: {e}",
            "expected": "All zero",
            "description": desc,
        }


def probe_p3(role: str) -> dict:
    """P3: NoNewPrivs in /proc/self/status is 1."""
    desc = f"From {role}: NoNewPrivs in /proc/self/status is 1"
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("NoNewPrivs:"):
                    val = int(line.split()[1].strip())
                    if val == 1:
                        return {
                            "passed": True,
                            "observed": "NoNewPrivs is 1",
                            "expected": "1",
                            "description": desc,
                        }
                    return {
                        "passed": False,
                        "observed": f"NoNewPrivs is {val}",
                        "expected": "1",
                        "description": desc,
                    }
        return {
            "passed": False,
            "observed": "NoNewPrivs not found in /proc/self/status",
            "expected": "1",
            "description": desc,
        }
    except Exception as e:
        return {
            "passed": False,
            "observed": f"Error reading /proc/self/status: {e}",
            "expected": "1",
            "description": desc,
        }


def probe_p4(role: str) -> dict:
    """P4: Seccomp in /proc/self/status is 2."""
    desc = f"From {role}: Seccomp in /proc/self/status is 2 (filter active)"
    try:
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith("Seccomp:"):
                    val = int(line.split()[1].strip())
                    if val == 2:
                        return {
                            "passed": True,
                            "observed": "Seccomp is 2 (filter active)",
                            "expected": "2 (filter active)",
                            "description": desc,
                        }
                    return {
                        "passed": False,
                        "observed": f"Seccomp is {val}",
                        "expected": "2 (filter active)",
                        "description": desc,
                    }
        return {
            "passed": False,
            "observed": "Seccomp not found in /proc/self/status",
            "expected": "2 (filter active)",
            "description": desc,
        }
    except Exception as e:
        return {
            "passed": False,
            "observed": f"Error reading /proc/self/status: {e}",
            "expected": "2 (filter active)",
            "description": desc,
        }


def probe_p5(role: str) -> dict:
    """P5: unshare and mount attempts via ctypes (must fail with EPERM)."""
    desc = f"From {role}: unshare and mount attempts (ctypes)"
    import ctypes
    import errno

    libc = ctypes.CDLL(None, use_errno=True)

    CLONE_NEWUSER = 0x10000000
    rc1 = libc.unshare(CLONE_NEWUSER)
    err1 = ctypes.get_errno()

    rc2 = libc.mount(b"none", b"/tmp", b"tmpfs", 0, None)
    err2 = ctypes.get_errno()

    unshare_blocked = rc1 == -1 and err1 == errno.EPERM
    mount_blocked = rc2 == -1 and err2 in (errno.EPERM, errno.EACCES)

    if unshare_blocked and mount_blocked:
        return {
            "passed": True,
            "observed": f"unshare rc={rc1} errno={err1} (EPERM); mount rc={rc2} errno={err2} ({errno.errorcode.get(err2, err2)})",
            "expected": "EPERM",
            "description": desc,
        }
    return {
        "passed": False,
        "observed": f"unshare rc={rc1} errno={err1}; mount rc={rc2} errno={err2}",
        "expected": "EPERM",
        "description": desc,
    }


def run_all(role: str, targets: list) -> dict:
    return {
        "N1": probe_n1(role),
        "N2": probe_n2(role, targets),
        "N3": probe_n3(role),
        "N4": probe_n4(role),
        "F1": probe_f1(role),
        "F2": probe_f2(role),
        "F3": probe_f3(role),
        "P1": probe_p1(role),
        "P2": probe_p2(role),
        "P3": probe_p3(role),
        "P4": probe_p4(role),
        "P5": probe_p5(role),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Container isolation probes")
    parser.add_argument("--role", choices=["red", "blue"], required=True)
    parser.add_argument("--targets", default="[]", help="JSON string of [ip, port] targets for N2")
    parser.add_argument("--probe", default="all", help="Specific probe ID or 'all'")
    args = parser.parse_args()

    try:
        targets = json.loads(args.targets)
    except Exception:
        targets = []

    if args.probe == "all":
        results = run_all(args.role, targets)
        print(json.dumps(results))
    elif args.probe == "N1":
        print(json.dumps(probe_n1(args.role)))
    elif args.probe == "N2":
        print(json.dumps(probe_n2(args.role, targets)))
    elif args.probe == "N3":
        print(json.dumps(probe_n3(args.role)))
    elif args.probe == "N4":
        print(json.dumps(probe_n4(args.role)))
    elif args.probe == "F1":
        print(json.dumps(probe_f1(args.role)))
    elif args.probe == "F2":
        print(json.dumps(probe_f2(args.role)))
    elif args.probe == "F3":
        print(json.dumps(probe_f3(args.role)))
    elif args.probe == "P1":
        print(json.dumps(probe_p1(args.role)))
    elif args.probe == "P2":
        print(json.dumps(probe_p2(args.role)))
    elif args.probe == "P3":
        print(json.dumps(probe_p3(args.role)))
    elif args.probe == "P4":
        print(json.dumps(probe_p4(args.role)))
    elif args.probe == "P5":
        print(json.dumps(probe_p5(args.role)))
    else:
        sys.stderr.write(f"Unknown probe: {args.probe}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
