import pyshark
import joblib
import pandas as pd
import ssl
import socket
import hashlib
import logging
import json
import os
import time
import threading
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend

print("=" * 65)
print("  MITM NIDS — Monitoring Win10 (192.168.10.10)")
print("=" * 65)

logging.basicConfig(
    filename="nids.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

stats = {
    "normal": 0,
    "suspicious": 0,
    "mitm": 0,
    "skipped": 0,
    "error": 0,
}

try:
    model = joblib.load("mitm_model.pkl")
    le_dict = joblib.load("label_encoders.pkl")
    FEATURE_COLS = joblib.load("model_features.pkl")
    print("[+] ML model loaded OK")
except Exception as e:
    print(f"[!] Không load được model: {e}")
    exit()

INTERFACE = "ens37"
VICTIM_IP = "192.168.10.10"
ATTACKER_IP = "192.168.10.20"
UBUNTU_MAC = "00:0c:29:6a:41:c9"
KALI_MAC = "00:0c:29:19:f2:6a"
MITMPROXY_PORT = 8080
MITMPROXY_PROBE_PORTS = [8080, 8081]

ARP_RESET_TIMEOUT = 30
CACHE_TTL = 300
TOFU_FILE = "tofu_store.json"

DOMAIN_REPEAT_INTERVAL = 5

LOCAL_TEST_DOMAINS = [
    "fakebank.local",
    "huit.maravo.vn",
]

IGNORE_KEYWORDS = [
    "ads", "doubleclick", "googlesyndication", "analytics",
    "tracking", "telemetry", "gstatic", "windowsupdate",
    "bing", "ocsp", "crl", "pki", "safebrowsing"
]

TRUSTED_CA = [
    "digicert", "let's encrypt", "google trust services",
    "sectigo", "globalsign", "comodo", "entrust", "amazon",
    "cloudflare", "microsoft", "apple", "geotrust",
    "thawte", "godaddy", "usertrust"
]

BLACKLIST_ISSUER = [
    "mitmproxy", "ettercap", "burp", "fiddler",
    "charles", "bettercap", "evil", "hacker",
    "test ca", "unknown ca"
]

arp_poison_state = {
    "active": False,
    "last_seen": 0.0,
    "count": 0,
}

arp_lock = threading.Lock()


def update_arp_state():
    with arp_lock:
        arp_poison_state["active"] = True
        arp_poison_state["last_seen"] = time.time()
        arp_poison_state["count"] += 1


def is_arp_active():
    with arp_lock:
        if not arp_poison_state["active"]:
            return False

        if time.time() - arp_poison_state["last_seen"] > ARP_RESET_TIMEOUT:
            arp_poison_state["active"] = False
            print(f"\n  [ARP] State reset sau {ARP_RESET_TIMEOUT}s")
            return False

        return True


_cert_cache = {}


def cache_get(key):
    e = _cert_cache.get(key)
    if e and (time.time() - e["ts"]) < CACHE_TTL:
        return e["cert_info"], e["fp"]
    return None, None


def cache_set(key, cert_info, fp):
    _cert_cache[key] = {
        "cert_info": cert_info,
        "fp": fp,
        "ts": time.time()
    }


def tofu_load():
    if os.path.exists(TOFU_FILE):
        try:
            with open(TOFU_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def tofu_save(store):
    try:
        with open(TOFU_FILE, "w") as f:
            json.dump(store, f, indent=2)
    except Exception:
        pass


tofu_store = tofu_load()
print(f"[+] TOFU store: {len(tofu_store)} domains")


def tofu_check(domain, fp, issuer):
    if domain not in tofu_store:
        tofu_store[domain] = {
            "fp": fp,
            "issuer": issuer,
            "seen": 1,
            "first_seen": datetime.now().isoformat()
        }
        tofu_save(tofu_store)
        return "new"

    entry = tofu_store[domain]
    entry["seen"] = entry.get("seen", 0) + 1

    if entry["fp"] != fp:
        entry["fp"] = fp
        entry["issuer"] = issuer
        tofu_save(tofu_store)
        return "mismatch"

    if entry.get("issuer") != issuer:
        entry["issuer"] = issuer
        tofu_save(tofu_store)
        return "issuer_change"

    tofu_save(tofu_store)
    return "match"


def normalize_mac(mac):
    return ":".join(p.zfill(2) for p in str(mac).lower().split(":"))


def is_local_test_domain(domain):
    if not domain:
        return False
    domain = domain.lower().strip()
    return domain in LOCAL_TEST_DOMAINS or domain.endswith(".local")


def should_ignore(domain):
    if not domain or domain == "Unknown":
        return True

    if is_local_test_domain(domain):
        return False

    return any(x in domain for x in IGNORE_KEYWORDS)


def is_blacklisted(issuer):
    issuer_l = str(issuer).lower()
    return any(b in issuer_l for b in BLACKLIST_ISSUER)


def is_trusted_ca(issuer):
    issuer_l = str(issuer).lower()

    if is_blacklisted(issuer_l):
        return 0

    return int(any(ca in issuer_l for ca in TRUSTED_CA))


def is_self_signed(cert):
    try:
        return cert.issuer == cert.subject
    except Exception:
        return False


def get_fp(der):
    return hashlib.sha256(der).hexdigest()


def safe_encode(col, value):
    le = le_dict.get(col)

    if le is None:
        return 0

    try:
        return int(le.transform([str(value)])[0])
    except ValueError:
        return -1


def fetch_cert_direct(host, sni, timeout=5):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der, default_backend())
                return cert, get_fp(der)

    except Exception:
        return None, None


def fetch_cert_via_proxy(domain, timeout=4):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for port in MITMPROXY_PROBE_PORTS:
        try:
            sock = socket.create_connection((ATTACKER_IP, port), timeout=timeout)

            req = (
                f"CONNECT {domain}:443 HTTP/1.1\r\n"
                f"Host: {domain}:443\r\n\r\n"
            )

            sock.sendall(req.encode())

            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk

            if b"200" not in resp:
                sock.close()
                continue

            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der, default_backend())
                return cert, get_fp(der), port

        except Exception:
            continue

    return None, None, None


def parse_cert(cert):
    try:
        attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)

        if attrs:
            issuer = str(attrs[0].value)
        else:
            cn = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            issuer = str(cn[0].value) if cn else "Unknown"

        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
        validity_days = (na - nb).days
        is_expired = int(datetime.now(timezone.utc) > na)

        try:
            sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "Unknown"
        except Exception:
            sig_alg = "Unknown"

        try:
            pub = cert.public_key()
            ktype = type(pub).__name__.upper()

            if "RSA" in ktype:
                key_type, key_length = "RSA", pub.key_size
            elif "EC" in ktype or "ELLIPTIC" in ktype:
                key_type, key_length = "EC", pub.key_size
            elif "DSA" in ktype:
                key_type, key_length = "DSA", pub.key_size
            else:
                key_type, key_length = "Unknown", 0

        except Exception:
            key_type, key_length = "Unknown", 0

        try:
            cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            has_san = 1
        except x509.ExtensionNotFound:
            has_san = 0

        version = {
            0: "v1",
            1: "v2",
            2: "v3"
        }.get(cert.version.value, "v3")

        return {
            "issuer": issuer,
            "validity_days": validity_days,
            "is_trusted_ca": is_trusted_ca(issuer),
            "sig_alg": sig_alg,
            "key_length": key_length,
            "key_type": key_type,
            "has_san": has_san,
            "version": version,
            "is_expired": is_expired,
            "self_signed": is_self_signed(cert),
        }

    except Exception:
        return None


def ml_predict(cert_info):
    row = {
        "Issuer_enc": safe_encode("Issuer", cert_info["issuer"]),
        "Signature_Algorithm_enc": safe_encode("Signature_Algorithm", cert_info["sig_alg"]),
        "Public_Key_Type_enc": safe_encode("Public_Key_Type", cert_info["key_type"]),
        "Version_enc": safe_encode("Version", cert_info["version"]),
        "Validity_Days": cert_info["validity_days"],
        "Is_Trusted_CA": cert_info["is_trusted_ca"],
        "Key_Length": cert_info["key_length"],
        "Has_SAN": cert_info["has_san"],
        "Is_Expired": cert_info["is_expired"],
    }

    df = pd.DataFrame([row]).reindex(columns=FEATURE_COLS, fill_value=0)

    pred = model.predict(df)[0]
    proba = model.predict_proba(df)[0]

    return int(pred), round(max(proba) * 100, 1)


def compute_score(
    cert_real_info,
    fp_real,
    cert_proxy_info,
    fp_proxy,
    domain,
    tofu_result,
    arp_monitor_active,
    dst_mac_is_kali
):
    score = 0
    reasons = []

    eval_cert = cert_proxy_info if cert_proxy_info else cert_real_info
    local_lab_domain = is_local_test_domain(domain)

    is_lab_self_signed = (
        local_lab_domain
        and eval_cert.get("self_signed") is True
        and not cert_proxy_info
        and not arp_monitor_active
    )

    if dst_mac_is_kali:
        if is_lab_self_signed:
            score += 15
            reasons.append("[+15] Local lab traffic tới Kali server")
        else:
            score += 60
            reasons.append("[+60] ⚠ dst MAC = Kali's MAC → traffic route về attacker")

    if arp_monitor_active:
        score += 30
        reasons.append(f"[+30] ARP poison active (count={arp_poison_state['count']})")

    if cert_proxy_info and is_blacklisted(cert_proxy_info["issuer"]):
        score += 80
        reasons.append(f"[+80] ⚠ Blacklisted issuer proxy: '{cert_proxy_info['issuer']}'")

    elif fp_proxy and fp_real and fp_proxy != fp_real:
        score += 75
        reasons.append("[+75] ⚠ Cert MISMATCH: proxy ≠ real server")

    elif is_blacklisted(cert_real_info["issuer"]):
        score += 80
        reasons.append(f"[+80] ⚠ Blacklisted issuer direct: '{cert_real_info['issuer']}'")

    if eval_cert.get("self_signed"):
        score += 40
        reasons.append("[+40] Self-signed certificate")

    if eval_cert["is_trusted_ca"] == 0 and not is_blacklisted(eval_cert["issuer"]):
        if is_lab_self_signed:
            score += 10
            reasons.append(f"[+10] Local lab untrusted issuer: '{eval_cert['issuer']}'")
        else:
            score += 30
            reasons.append(f"[+30] Untrusted issuer: '{eval_cert['issuer']}'")

    if eval_cert["is_expired"]:
        score += 15
        reasons.append("[+15] Certificate expired")

    if eval_cert["has_san"] == 0:
        score += 15
        reasons.append("[+15] No SAN extension")

    if eval_cert["key_type"] == "RSA" and eval_cert["key_length"] < 2048:
        score += 10
        reasons.append(f"[+10] Weak RSA key: {eval_cert['key_length']} bit")

    if eval_cert["validity_days"] > 825 or eval_cert["validity_days"] < 1:
        score += 10
        reasons.append(f"[+10] Abnormal validity: {eval_cert['validity_days']} days")

    if tofu_result == "mismatch":
        if is_lab_self_signed:
            score += 5
            reasons.append("[+5] TOFU changed on local lab domain")
        else:
            score += 25
            reasons.append("[+25] TOFU: Fingerprint CHANGED vs history")

    elif tofu_result == "issuer_change":
        score += 15
        reasons.append("[+15] TOFU: Issuer changed vs history")

    ml_pred, ml_conf = ml_predict(eval_cert)

    if ml_pred == 1:
        if is_lab_self_signed:
            score += 5
            reasons.append(f"[+5] ML model flagged lab cert ({ml_conf}%)")
        else:
            score += 20
            reasons.append(f"[+20] ML model: MITM ({ml_conf}%)")
    else:
        reasons.append(f"[   ] ML model: Normal ({ml_conf}%)")

    if is_lab_self_signed:
        if score < 40:
            score = 50
            reasons.append("[ADJUST] Kịch bản 1 self-signed → nâng lên SUSPICIOUS")

        elif score >= 80:
            old_score = score
            score = 65
            reasons.append(
                f"[ADJUST] Kịch bản 1 self-signed lab → giữ SUSPICIOUS ({old_score} → {score})"
            )

    return score, reasons


def get_verdict(score):
    if score >= 80:
        return "🔴 MITM", "mitm"
    elif score >= 40:
        return "🟡 SUSPICIOUS", "suspicious"
    else:
        return "🟢 NORMAL", "normal"


def arp_monitor():
    print("[*] ARP Monitor started")

    try:
        arp_cap = pyshark.LiveCapture(
            interface=INTERFACE,
            bpf_filter="arp"
        )

        for pkt in arp_cap.sniff_continuously():
            try:
                if not hasattr(pkt, "arp"):
                    continue

                opcode = str(pkt.arp.opcode)
                src_mac = normalize_mac(pkt.arp.src_hw_mac)
                src_ip = str(pkt.arp.src_proto_ipv4)
                dst_ip = str(pkt.arp.dst_proto_ipv4)
                kali_n = normalize_mac(KALI_MAC)

                if opcode == "2" and src_mac == kali_n:
                    if src_ip == VICTIM_IP or dst_ip == VICTIM_IP:
                        update_arp_state()
                        c = arp_poison_state["count"]

                        if c % 20 == 1:
                            print(f"\n  ⚠ [ARP POISON] Kali→Win10 | count={c}")
                            logging.warning(
                                f"ARP_POISON | kali={src_mac} | victim={VICTIM_IP} | count={c}"
                            )

            except Exception:
                pass

    except Exception as e:
        print(f"[!] ARP Monitor error: {e}")


arp_thread = threading.Thread(target=arp_monitor, daemon=True)
arp_thread.start()


# Domain thường dùng cooldown, domain .local thì bắt mọi lần refresh
seen_domains = {}


def analyze_packet(packet):
    try:
        if not hasattr(packet, "tls"):
            return

        if not hasattr(packet, "ip"):
            return

        src_ip = packet.ip.src
        dst_ip = packet.ip.dst

        if src_ip != VICTIM_IP:
            return

        tls = packet.tls
        time_str = packet.sniff_time.strftime("%Y-%m-%d %H:%M:%S")

        src_mac = "unknown"
        dst_mac = "unknown"
        dst_mac_is_kali = False

        try:
            if hasattr(packet, "eth"):
                src_mac = normalize_mac(packet.eth.src)
                dst_mac = normalize_mac(packet.eth.dst)

                if dst_mac == normalize_mac(KALI_MAC):
                    dst_mac_is_kali = True

        except Exception:
            pass

        arp_monitor_active = is_arp_active()

        domain = None

        try:
            domain = tls.get_field_value("tls.handshake.extensions_server_name")
        except Exception:
            pass

        if not domain:
            stats["skipped"] += 1
            return

        domain = domain.lower().strip()

        if should_ignore(domain):
            stats["skipped"] += 1
            return

        if not is_local_test_domain(domain):
            now = time.time()
            last_seen = seen_domains.get(domain, 0)

            if now - last_seen < DOMAIN_REPEAT_INTERVAL:
                return

            seen_domains[domain] = now

        cert_real_info, fp_real = cache_get(domain)
        from_cache = cert_real_info is not None

        if not from_cache:
            cert_real, fp_real = fetch_cert_direct(dst_ip, domain)
            if cert_real is None:
                cert_real, fp_real = fetch_cert_direct(domain, domain)

            if cert_real is None:
                print(f"\n[!] Không lấy được certificate của {domain} qua domain/IP {dst_ip}")
                stats["skipped"] += 1
                return

            cert_real_info = parse_cert(cert_real)

            if cert_real_info is None:
                stats["skipped"] += 1
                return

            cache_set(domain, cert_real_info, fp_real)

        cert_proxy, fp_proxy, proxy_port_used = fetch_cert_via_proxy(domain)
        cert_proxy_info = parse_cert(cert_proxy) if cert_proxy else None
        proxy_ok = cert_proxy_info is not None

        tofu_fp = fp_proxy if fp_proxy else fp_real
        tofu_issuer = cert_proxy_info["issuer"] if cert_proxy_info else cert_real_info["issuer"]
        tofu_result = tofu_check(domain, tofu_fp, tofu_issuer)

        score, reasons = compute_score(
            cert_real_info=cert_real_info,
            fp_real=fp_real,
            cert_proxy_info=cert_proxy_info,
            fp_proxy=fp_proxy,
            domain=domain,
            tofu_result=tofu_result,
            arp_monitor_active=arp_monitor_active,
            dst_mac_is_kali=dst_mac_is_kali,
        )

        verdict_label, verdict_key = get_verdict(score)

        print("\n" + "=" * 65)
        print(f"  {verdict_label}  |  Score: {score}  |  {time_str}")
        print(f"  Win10 ({src_ip}) → {dst_ip}")

        print(
            f"  src MAC: {src_mac}  dst MAC: {dst_mac}"
            + ("  ← KALI MAC!" if dst_mac_is_kali else "")
        )

        print(f"  Domain        : {domain}")
        print(f"  Issuer (real) : {cert_real_info['issuer']}")

        if proxy_ok:
            diff = "✗ DIFFERENT ← MITM!" if fp_proxy != fp_real else "✓ same"
            print(
        f"  Issuer (proxy): {cert_proxy_info['issuer']}  "
        f"[{diff}] via port {proxy_port_used}"
    )
        else:
            ports = ",".join(str(p) for p in MITMPROXY_PROBE_PORTS)
            print(f"  Issuer (proxy): N/A mitmproxy ports [{ports}] not reachable")

        print(
            f"  Validity      : {cert_real_info['validity_days']}d  "
            f"Key: {cert_real_info['key_type']} {cert_real_info['key_length']}bit  "
            f"SelfSigned: {cert_real_info['self_signed']}  "
            f"TOFU: {tofu_result}  Cache: {'hit' if from_cache else 'miss'}"
        )

        print()
        print("  Signals:")

        for r in reasons:
            print(f"    {r}")

        print("-" * 65)

        if verdict_key == "mitm":
            print(f"  >>> ⚠️  MITM ATTACK DETECTED  (score={score}) <<<")
            stats["mitm"] += 1

            logging.warning(
                f"MITM | score={score} | domain={domain} | "
                f"issuer_real={cert_real_info['issuer']} | "
                f"issuer_proxy={cert_proxy_info['issuer'] if cert_proxy_info else 'N/A'} | "
                f"dst_kali={dst_mac_is_kali} | arp={arp_monitor_active} | "
                f"tofu={tofu_result} | src={src_ip} dst={dst_ip}"
            )

        elif verdict_key == "suspicious":
            print(f"  >>> 🟡 SUSPICIOUS  (score={score})")
            stats["suspicious"] += 1

            logging.warning(
                f"SUSPICIOUS | score={score} | domain={domain} | "
                f"issuer_real={cert_real_info['issuer']} | "
                f"self_signed={cert_real_info['self_signed']} | "
                f"dst_kali={dst_mac_is_kali} | arp={arp_monitor_active} | "
                f"tofu={tofu_result} | src={src_ip} dst={dst_ip}"
            )

        else:
            print(f"  [OK] Normal Traffic  (score={score})")
            stats["normal"] += 1

            logging.info(
                f"OK | score={score} | domain={domain} | "
                f"issuer={cert_real_info['issuer']} | src={src_ip}"
            )

    except AttributeError:
        stats["error"] += 1

    except KeyError:
        stats["error"] += 1

    except Exception as e:
        stats["error"] += 1
        print(f"[!] Error: {e}")


print(f"\n[*] Giám sát      : VICTIM_IP = {VICTIM_IP} (Win10 ONLY)")
print(f"[*] Attacker IP   : {ATTACKER_IP}  MAC: {KALI_MAC}")
print(f"[*] Mitmproxy     : {ATTACKER_IP}:{MITMPROXY_PORT}")
print(f"[*] ARP reset     : {ARP_RESET_TIMEOUT}s")
print(f"[*] Domain repeat : normal={DOMAIN_REPEAT_INTERVAL}s | local=always")
print(f"[*] Verdict       : MITM≥80 | SUSP≥40 | OK<40")
print(f"[*] TOFU file     : {TOFU_FILE}")
print(f"[*] Log           : nids.log")
print(f"[*] Nhấn Ctrl+C để dừng\n")

capture = pyshark.LiveCapture(
    interface=INTERFACE,
    bpf_filter=f"tcp port 443 and src host {VICTIM_IP}"
)

try:
    capture.apply_on_packets(analyze_packet)

except KeyboardInterrupt:
    print("\n" + "=" * 65)
    print("  THỐNG KÊ PHIÊN")
    print("=" * 65)
    print(f"  🟢 Normal          : {stats['normal']}")
    print(f"  🟡 Suspicious      : {stats['suspicious']}")
    print(f"  🔴 MITM Detected   : {stats['mitm']}")
    print(f"  ⏭  Skipped         : {stats['skipped']}")
    print(f"  ❌ Errors          : {stats['error']}")
    print(f"  📦 TOFU domains    : {len(tofu_store)}")
    print(f"  🔍 ARP count       : {arp_poison_state['count']}")

    total = stats["mitm"] + stats["normal"] + stats["suspicious"]

    if total > 0:
        print(f"  📊 Suspicious rate : {stats['suspicious'] / total * 100:.1f}%")
        print(f"  📊 MITM rate       : {stats['mitm'] / total * 100:.1f}%")

    print("=" * 65)
    print("[*] Stop.")