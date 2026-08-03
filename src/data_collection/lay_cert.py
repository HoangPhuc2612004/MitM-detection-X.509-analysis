import ssl
import socket
import pandas as pd
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.hazmat.primitives import hashes 

# Danh sách CA tin cậy
TRUSTED_CA = [
    "digicert", "let's encrypt", "google trust services",
    "sectigo", "globalsign", "comodo", "entrust",
    "amazon", "cloudflare", "microsoft", "apple",
    "geotrust", "thawte", "godaddy", "usertrust"
]

def is_trusted_ca(issuer):
    return int(any(ca in str(issuer).lower() for ca in TRUSTED_CA))

def get_cert_from_domain(domain):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der, default_backend())

                # 1. Issuer
                issuer_attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
                if issuer_attrs:
                    issuer = issuer_attrs[0].value
                else:
                    cn_attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                    issuer = cn_attrs[0].value if cn_attrs else "Unknown"

                # 2. Validity_Days
                nb = cert.not_valid_before
                na = cert.not_valid_after
                validity_days = (na - nb).days

                # 3. Signature Algorithm
                sig_algo = cert.signature_algorithm_oid._name

                # 4 & 5. Public Key Type & Length
                public_key = cert.public_key()
                if isinstance(public_key, rsa.RSAPublicKey):
                    pk_type = "RSA"
                    key_length = public_key.key_size
                elif isinstance(public_key, ec.EllipticCurvePublicKey):
                    pk_type = "EC"
                    key_length = public_key.curve.key_size
                elif isinstance(public_key, dsa.DSAPublicKey):
                    pk_type = "DSA"
                    key_length = public_key.key_size
                else:
                    pk_type = "Unknown"
                    key_length = 0

                # 6. Has SAN (Subject Alternative Name)
                try:
                    ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    has_san = 1
                except x509.ExtensionNotFound:
                    has_san = 0

                # 7. Version
                version = cert.version.name

                # 8. Is Expired
                is_expired = 1 if na < datetime.now() else 0

                # 9. Fingerprint (SHA256)
                fingerprint = cert.fingerprint(hashes.SHA256()).hex()

                return {
                    "Domain": domain,
                    "Fingerprint": fingerprint,
                    "Issuer": issuer,
                    "Validity_Days": validity_days,
                    "Is_Trusted_CA": is_trusted_ca(issuer),
                    "Signature_Algorithm": sig_algo,
                    "Key_Length": key_length,
                    "Public_Key_Type": pk_type,
                    "Has_SAN": has_san,
                    "Version": version,
                    "Is_Expired": is_expired,
                    "label": 1  
                }
    except Exception:
        return None

def main():
    print("[*] Đang cào dữ liệu chứng chỉ (12 Features) từ domain.txt...")
    my_data = []
    try:
        with open("domain.txt", "r") as f:
            domains = [line.strip() for line in f if line.strip()]

        for domain in domains:
            cert_data = get_cert_from_domain(domain)
            if cert_data:
                my_data.append(cert_data)
                print(f"  -> OK: {domain} | {cert_data['Issuer']} | {cert_data['Signature_Algorithm']} | {cert_data['Key_Length']} bit")
            else:
                print(f"  -> Lỗi kết nối: {domain}")
    except FileNotFoundError:
        print("[!] Lỗi: Không tìm thấy file domain.txt")

    df_mine = pd.DataFrame(my_data)
    print(f"\n[+] Thu thập thành công {len(df_mine)} mẫu.")
    
    # Lưu file Dataset với tên mới để dễ phân biệt
    df_mine.to_csv("dataset_gia.csv", index=False)
    print("[OK] Đã lưu vào dataset_gia.csv")

if __name__ == "__main__":
    main()
