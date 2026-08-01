#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
asn123 — 从 ASN 拉取 IP，masscan 多端口扫描，检测 Cloudflare 反代节点
用法: python3 run.py AS209242 [AS3214 ...]
支持多端口扫描: python3 run.py AS209242 -p 443,8443,2053-2096
"""
import sys, os, subprocess, json, urllib.request, multiprocessing, socket, time, re
from pathlib import Path
from datetime import datetime

# ── 自适应硬件 ──
def detect_hardware():
    cpu = multiprocessing.cpu_count()
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if "MemAvailable" in line:
                    mem_mb = int(line.split()[1]) // 1024
                    break
    except:
        mem_mb = 512
    return cpu, mem_mb


# ── 智能 masscan 速率探测 ──
def probe_masscan_rate():
    """实测网卡发包上限，返回最优速率"""
    iface = None
    try:
        r = subprocess.run(["ip", "-4", "route", "get", "1.1.1.1"],
                           capture_output=True, text=True, timeout=5)
        m = __import__("re").search(r"dev\s+(\S+)", r.stdout)
        if m:
            iface = m.group(1)
    except Exception:
        pass
    if not iface:
        for name in ["eth0", "ens3", "enp0s3", "enp1s0", "ens5"]:
            if os.path.exists(f"/sys/class/net/{name}/statistics/tx_packets"):
                iface = name
                break
    if not iface:
        cores = multiprocessing.cpu_count()
        return max(1000, min(cores * 1000, 16000))

    cidrs = [a for a in sys.argv[1:] if not a.startswith("--") and "/" in a]
    if not cidrs:
        cidrs = ["1.1.1.0/24", "8.8.8.0/24", "9.9.9.0/24"]
    sample = cidrs[:50]
    tmp_cidr = "/tmp/.masscan_rate_test"
    with open(tmp_cidr, "w") as f:
        f.write("\n".join(sample))

    best_rate = 2000
    test_rate = 1000
    max_test = 200000
    probe_sec = 8

    while test_rate <= max_test:
        try:
            with open(f"/sys/class/net/{iface}/statistics/tx_packets") as f:
                tx_before = int(f.read().strip())
        except Exception:
            break

        proc = subprocess.Popen(
            ["masscan", "-iL", tmp_cidr, "-p", "443",
             "--rate", str(test_rate), "-oX", "/dev/null"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(probe_sec)
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            pass

        try:
            with open(f"/sys/class/net/{iface}/statistics/tx_packets") as f:
                tx_after = int(f.read().strip())
        except Exception:
            break

        actual_pps = (tx_after - tx_before) / probe_sec
        ratio = actual_pps / test_rate

        if ratio >= 0.7:
            best_rate = test_rate
            test_rate *= 2
        elif ratio >= 0.3:
            best_rate = max(2000, int(actual_pps * 0.8))
            break
        else:
            break

    try:
        os.remove(tmp_cidr)
    except Exception:
        pass
    return best_rate


CPU_CORES, RAM_MB = detect_hardware()
MASSCAN_RATE    = probe_masscan_rate()
CF_SCANNER_CONC = max(200, min(CPU_CORES * 100, 500))
API_CONCURRENT  = min(CPU_CORES * 16, 32)
API_CHUNK       = 2000 if RAM_MB < 1024 else 5000

print(f"  硬件: {CPU_CORES}核 {RAM_MB}MB → masscan {MASSCAN_RATE}pps cf-scanner {CF_SCANNER_CONC}c API {API_CONCURRENT}c")

# ── 获取公网 IP (NAT/Docker 环境兼容) ──
def get_public_ip():
    """获取公网出口 IP，HTTP API → DNS 多重兜底，局域网也能正确获取"""
    apis = [
        ("https://api.ipify.org", 5),
        ("https://api-ipv4.ip.sb/ip", 5),
        ("https://ifconfig.me/ip", 5),
        ("https://icanhazip.com", 5),
    ]
    for url, timeout in apis:
        try:
            return urllib.request.urlopen(url, timeout=timeout).read().decode("utf-8").strip()
        except Exception:
            continue
    dns_queries = [
        (["dig", "+short", "myip.opendns.com", "@resolver1.opendns.com"], 5),
        (["dig", "TXT", "+short", "o-o.myaddr.l.google.com", "@ns1.google.com"], 5),
        (["dig", "+short", "whoami.akamai.net", "@ns1-1.akamaitech.net"], 5),
    ]
    for cmd, timeout in dns_queries:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            out = r.stdout.strip().strip('"')
            if out and "." in out and out.count(".") == 3:
                parts = out.split(".")
                if all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    return out
        except Exception:
            continue
    return "127.0.0.1"

def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass
    return "127.0.0.1"

def detect_isp():
    ip = get_public_ip()
    print(f"\n  本机公网 IP: {ip}")
    if ip == "127.0.0.1":
        print("  (无法获取公网 IP，请检查网络连接，跳过运营商检测)")
        return ip, "", ""
    try:
        token = None
        token_file = Path("/root/.ipinfo_token")
        if token_file.is_file():
            token = token_file.read_text().strip()
        url = f"https://ipinfo.io/{ip}/json"
        if token:
            url += f"?token={token}"
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read())
            country = data.get("country", "")
            org = data.get("org", "")
            city = data.get("city", "")
            if country == "CN":
                isp = org.split(" ", 1)[-1] if org else "未知"
                print(f"  地区: {city}, {country}  🇨🇳  运营商: {isp}")
            else:
                isp = org
                print(f"  地区: {city}, {country}  机构: {org}")
            return ip, country, isp
    except Exception as e:
        print(f"  (无法获取详情: {e})")
    return ip, "", ""

GLOBAL_IP, GLOBAL_COUNTRY, GLOBAL_ISP = detect_isp()

if GLOBAL_COUNTRY in ("CN", "") and MASSCAN_RATE > 8000:
    print(f"  ⚠ 国内运营商链路，masscan 速率从 {MASSCAN_RATE}pps 降至 8000pps")
    MASSCAN_RATE = 8000

BASE      = Path(__file__).parent.resolve()
CF_SCANNER = BASE / "cf-scanner"
VERIFY_PY  = BASE / "verify.py"
API_URL    = "https://api.090227.xyz/check"

if CF_SCANNER.is_file():
    CF_SCANNER.chmod(0o755)

def fetch_prefixes(asns):
    cidrs = []
    for asn in asns:
        url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
        try:
            with urllib.request.urlopen(url, timeout=15) as resp:
                data = json.loads(resp.read())
                count = 0
                for p in data["data"]["prefixes"]:
                    if ":" not in p["prefix"]:
                        cidrs.append(p["prefix"])
                        count += 1
                print(f"  AS{asn} → {count} 个 IPv4 CIDR")
        except Exception as e:
            print(f"  AS{asn} → 失败: {e}")
    cidr_file = BASE / "cidrs.txt"
    cidr_file.write_text("\n".join(cidrs))
    print(f"  共 {len(cidrs)} 个 CIDR")
    return cidrs

def is_cidr(s):
    return "/" in s or re.match(r"^\d+\.\d+\.\d+\.\d+$", s)

def write_manual_cidrs(cidrs):
    cidr_file = BASE / "cidrs.txt"
    cidr_file.write_text("\n".join(cidrs))
    print(f"  手动 CIDR → {len(cidrs)} 个 CIDR")

with open(BASE / "ports.txt") as f:
    _default_ports = [l.strip() for l in f if l.strip() and not l.startswith("#")]
DEFAULT_PORTS = ",".join(_default_ports)

def parse_ports(port_str):
    """解析端口字符串: 443 或 8443-8550 或 443,8443,2053-2096"""
    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if not part:
            continue
        try:
            if '-' in part:
                a, b = part.split('-', 1)
                pa, pb = int(a), int(b)
                if pa < 1 or pb > 65535 or pa > pb:
                    continue
                ports.update(str(p) for p in range(pa, pb + 1))
            elif part.isdigit():
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(part)
        except ValueError:
            continue
    return ",".join(sorted(ports, key=int)) if ports else ""

def run_masscan(ports_str=None):
    ports = ports_str if ports_str else DEFAULT_PORTS
    if not ports or ports == ",":
        ports = DEFAULT_PORTS
    result_file = BASE / "masscan_result.txt"
    ip_file = BASE / "cidrs.txt"
    if result_file.exists():
        if os.geteuid() == 0:
            result_file.unlink()
        else:
            subprocess.run(["sudo", "rm", "-f", str(result_file)], check=False)
    sudo = [] if os.geteuid() == 0 else ["sudo"]
    cmd = sudo + [
        "masscan", "-iL", str(ip_file),
        "-p", ports,
        "--rate", str(MASSCAN_RATE),
        "-oL", str(result_file),
        "--wait", "5"
    ]
    print(f"  扫描端口: {ports}")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                            text=True, bufsize=1)
    bar_width = 30
    last_pct = -1
    stderr_lines = []
    for line in proc.stderr:
        stderr_lines.append(line)
        m = re.search(r"(\d+\.?\d*)%\s*done", line)
        if m:
            pct = min(float(m.group(1)), 100)
            if abs(pct - last_pct) >= 0.5:
                filled = int(bar_width * pct / 100)
                bar = "█" * filled + "░" * (bar_width - filled)
                sys.stderr.write(f"\r  [{bar}] {pct:.1f}%")
                sys.stderr.flush()
                last_pct = pct
    proc.wait()
    if proc.returncode == 0:
        sys.stderr.write(f"\r  [{'█' * bar_width}] 100.0%\n")
        sys.stderr.flush()
    else:
        sys.stderr.write("\n")
        sys.stderr.flush()
        stderr_text = "".join(stderr_lines)
        if "permission denied" in stderr_text.lower() or "init: failed" in stderr_text.lower():
            print("  ❌ masscan 需要 raw socket 权限，NAT 容器/部分 VPS 不支持")
            print("  → 请换到 KVM VPS 或物理机运行")
        raise subprocess.CalledProcessError(proc.returncode, cmd)
    if os.geteuid() != 0:
        uid = os.getuid()
        gid = os.getgid()
        subprocess.run(["sudo", "chown", f"{uid}:{gid}", str(result_file)], check=False)
    total = 0
    tmp_file = result_file.with_suffix(".tmp")
    with open(result_file) as src, open(tmp_file, "w") as dst:
        for line in src:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.strip().split()
            if len(parts) >= 4 and parts[0] == "open":
                dst.write(f"{parts[3]}:{parts[2]}\n")
                total += 1
    tmp_file.replace(result_file)
    print(f"  开放端口: {total}")
    return total

def cf_scan():
    new_file = BASE / "masscan_result.txt"
    hits_file = BASE / "cf_hits.txt"
    if new_file.stat().st_size == 0:
        print("  无开放端口，跳过")
        return 0
    if not os.access(CF_SCANNER, os.X_OK):
        os.chmod(CF_SCANNER, 0o755)
    proc = subprocess.Popen(
        [str(CF_SCANNER), "-i", str(new_file), "-o", str(hits_file), "-c", str(CF_SCANNER_CONC)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
    )
    bar_width = 30
    last_pct = -1
    for line in proc.stdout:
        m = re.search(r"Scanned\s+\d+/(\d+)\s+\((\d+\.?\d*)%\)", line)
        if m:
            pct = min(float(m.group(2)), 100)
            if abs(pct - last_pct) >= 0.5:
                filled = int(bar_width * pct / 100)
                bar = "█" * filled + "░" * (bar_width - filled)
                sys.stderr.write(f"\r  [{bar}] {pct:.1f}%")
                sys.stderr.flush()
                last_pct = pct
    proc.wait()
    if proc.returncode == 0:
        sys.stderr.write(f"\r  [{'█' * bar_width}] 100.0%\n")
        sys.stderr.flush()
    else:
        sys.stderr.write("\n")
        sys.stderr.flush()
        raise subprocess.CalledProcessError(proc.returncode, proc.args)
    hits = sum(1 for _ in open(hits_file))
    print(f"  CF 节点: {hits}")
    return hits

def api_verify():
    hits_file = BASE / "cf_hits.txt"
    verified_file = BASE / "verified.txt"
    if not hits_file.exists() or hits_file.stat().st_size == 0:
        print("  无 CF 节点，跳过")
        return 0
    subprocess.run([
        "python3", str(VERIFY_PY),
        "--input", str(hits_file),
        "--output", str(verified_file),
        "--api", API_URL,
        "--chunk", str(API_CHUNK),
        "--concurrent", str(API_CONCURRENT)
    ], check=True)
    passed = sum(1 for _ in open(verified_file))
    print(f"  精筛通过: {passed}")
    return passed

def output_csv(asns):
    verified_file = BASE / "verified.txt"
    if not verified_file.exists() or verified_file.stat().st_size == 0:
        print("  无结果")
        return
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    asn_tag = "_".join(asns)
    output = BASE / f"output_{asn_tag}_{ts}.csv"
    lines = []
    with open(verified_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("IP地址"):
                continue
            if line.count(",") >= 8:
                lines.append(line)
    with open(output, "w") as f:
        f.write("IP地址,端口,TLS,数据中心,地区,城市,网络延迟,下载速度,ASN\n")
        for line in lines:
            f.write(line + "\n")
    print(f"\n  结果: {len(lines)} 条 → {output.name}")
    lan_ip = get_lan_ip()
    port = 8899
    import socket
    def _port_free(p):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(1)
            return sock.connect_ex(('127.0.0.1', p)) != 0
        finally:
            sock.close()
    def _kill_port(p):
        import signal
        try:
            out = subprocess.run(["ss", "-tlnp", f"sport = :{p}"],
                                 capture_output=True, text=True, timeout=5)
            for line in out.stdout.split("\n"):
                if f":{p}" in line and "users:" in line:
                    m = __import__("re").search(r"pid=(\d+)", line)
                    if m:
                        os.kill(int(m.group(1)), signal.SIGTERM)
                        time.sleep(0.5)
                        return True
        except:
            pass
        return False
    if not _port_free(port):
        print(f"  端口 {port} 被占用，尝试释放...")
        if _kill_port(port) and _port_free(port):
            print(f"  已释放端口 {port}")
        else:
            while not _port_free(port) and port < 9900:
                port += 1
            if port >= 9900:
                print(f"\n  ⚠️  找不到可用端口，跳过下载服务")
                print(f"  📄 结果文件: {output}")
                return
    _http_server = None
    try:
        print(f"\n  📥 下载链接 (按回车关闭):")
        print(f"  http://{lan_ip}:{port}/{output.name}  (本机)")
        public_ip = get_public_ip()
        if public_ip != "127.0.0.1" and public_ip != lan_ip:
            print(f"  http://{public_ip}:{port}/{output.name}  (公网)")
        print()
        _http_server = subprocess.Popen(
            ["python3", "-m", "http.server", str(port), "--directory", str(BASE)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        input()
    except (EOFError, KeyboardInterrupt):
        pass
    finally:
        if _http_server and _http_server.poll() is None:
            _http_server.terminate()
            _http_server.wait()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        try:
            raw = input("  输入 ASN 或 CIDR (逗号分隔): ").strip()
        except (EOFError, KeyboardInterrupt):
            try:
                with open("/dev/tty") as tty:
                    os.dup2(tty.fileno(), 0)
                raw = input("  输入 ASN 或 CIDR (逗号分隔): ").strip()
            except:
                print(f"\n  请在终端运行: cd {BASE} && python3 run.py\n")
                sys.exit(0)
        if not raw:
            print("用法: asn123 AS209242  或  asn123 103.21.244.0/24")
            print("  多端口: asn123 AS209242 -p 443,8443,2053-2096")
            print("  ssh 断线不杀: screen -S scan → asn123 AS209242 → Ctrl+A D")
            sys.exit(1)
        items = [a.strip() for a in raw.replace("，", ",").split(",") if a.strip()]
    else:
        args = sys.argv[1:]
        i = 0
        items = []
        while i < len(args):
            if args[i] == "-p":
                i += 2
            else:
                items.append(args[i])
                i += 1
        if not items:
            print("用法: asn123 AS209242 或 asn123 103.21.244.0/24 或混合")
            print("  多端口: asn123 AS209242 -p 443,8443,2053-2096")
            print("  ssh 断线不杀: screen -S scan → asn123 AS209242 → Ctrl+A D")
            sys.exit(1)
    asns = []
    manual_cidrs = []
    for item in items:
        item = item.strip().replace("AS", "").replace("as", "")
        if is_cidr(item):
            manual_cidrs.append(item)
        elif item.isdigit():
            asns.append(item)
        else:
            print(f"  ⚠ 无法识别: {item}，已跳过")
    if asns:
        print(f"  ASN: {', '.join(f'AS{a}' for a in asns)}")
    if manual_cidrs:
        print(f"  CIDR: {', '.join(manual_cidrs)}")
    if not asns and not manual_cidrs:
        print("用法: asn123 AS209242 或 asn123 103.21.244.0/24")
        sys.exit(1)
    print()
    scan_ports = DEFAULT_PORTS
    if len(sys.argv) < 2:
        print(f"  默认端口: {DEFAULT_PORTS}")
        try:
            port_input = input("  回车使用默认，或输入自定义端口 (如 80 或 1-1000 或 80,443,8000-9000): ").strip()
        except (EOFError, KeyboardInterrupt):
            port_input = ""
        if port_input:
            parsed = parse_ports(port_input)
            if parsed:
                scan_ports = parsed
                print(f"  扫描端口: {scan_ports}")
    else:
        for i, arg in enumerate(sys.argv[1:], 1):
            if arg == "-p" and i < len(sys.argv) - 1:
                scan_ports = parse_ports(sys.argv[i+1])
                print(f"  自定义端口: {scan_ports}")
                break
    # 扫描流程（无测速，5步完成）
    steps = []
    if asns:
        steps.append(("1/5 ASN→CIDR", lambda: fetch_prefixes(asns)))
    if manual_cidrs:
        label = "1/5 CIDR→文件" if not asns else "1/5 +CIDR"
        steps.append((label, lambda: write_manual_cidrs(manual_cidrs)))
    steps += [
        ("2/5 masscan多端口", lambda: run_masscan(scan_ports)),
        ("3/5 cf-scanner", cf_scan),
        ("4/5 API精筛", api_verify),
        ("5/5 输出结果", lambda: output_csv(asns if asns else ["CIDR"])),
    ]
    for label, fn in steps:
        print(f"\n  [{label}]")
        try:
            fn()
        except Exception as e:
            print(f"  ❌ 失败: {e}")
            sys.exit(1)
    print()
    print("  ───")
    print("  用法: asn123 AS209242 或 asn123 103.21.244.0/24 或混合")
    print("  多端口: asn123 AS209242 -p 443,8443,2053-2096")
    print("  SSH 断线不杀: screen -S scan → asn123 AS209242 → Ctrl+A D")
    print("  恢复: screen -r scan")
    print("\n✓ 完成\n")
