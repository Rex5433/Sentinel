"""Prepare the shared workspace TLS files and launch its HTTPS listener."""

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import ssl
import subprocess
from tempfile import TemporaryDirectory
import time
from urllib.request import HTTPSHandler, ProxyHandler, build_opener

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .shared_hosting import SharedHosting


def create_tls(store, host, *, folder=None):
    folder = folder or store / "tls"
    cert, key, ca = (folder / name for name in ("server.pem", "server.key", "sentinel-team-ca.cer"))
    files = (cert, key, ca)
    if any(path.exists() for path in files):
        if not all(path.is_file() for path in files):
            raise ValueError(f"TLS files are incomplete. Review the files in {folder}.")
        leaf = x509.load_pem_x509_certificate(cert.read_bytes())
        if host not in leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress):
            raise ValueError(f"The shared IP changed. Move the TLS folder at {folder} aside and restart to issue a certificate for {host}.")
        if leaf.not_valid_after_utc <= datetime.now(timezone.utc):
            raise ValueError(f"The HTTPS certificate expired. Move {folder} aside and restart to issue a replacement.")
        return files
    if folder.exists():
        raise ValueError(f"The TLS folder {folder} already exists. Review it before issuing a certificate.")

    now = datetime.now(timezone.utc)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Sentinel V6 team at {host}")])
    ca_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(2))

    def builder(name, signing_key):
        return (x509.CertificateBuilder().subject_name(name).issuer_name(ca_name).public_key(signing_key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
                .not_valid_after(now + timedelta(days=90)))

    root = (builder(ca_name, ca_key).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
            .sign(ca_key, hashes.SHA256()))
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, str(host))])
    leaf = (builder(leaf_name, leaf_key).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(host)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    # Store the signed leaf and the public trust certificate. Discard the CA signing key.
    folder.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with TemporaryDirectory(prefix="tls-stage-", dir=store) as stage:
        staged = Path(stage) / "tls"
        staged.mkdir(mode=0o700)
        (staged / cert.name).write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        (staged / ca.name).write_bytes(root.public_bytes(serialization.Encoding.DER))
        with os.fdopen(os.open(staged / key.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as out:
            out.write(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
        staged.rename(folder)
    return files


def prepare_https(store, settings, environment):
    legacy = store / "tls"
    folder = legacy / str(settings.host)
    if (legacy / "server.pem").is_file() and not folder.exists():
        leaf = x509.load_pem_x509_certificate((legacy / "server.pem").read_bytes())
        if settings.host in leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.IPAddress):
            folder = legacy
    cert, key, ca = create_tls(store, settings.host, folder=folder)
    root_certificate = x509.load_der_x509_certificate(ca.read_bytes())
    fingerprint = root_certificate.fingerprint(hashes.SHA256()).hex().upper()
    env = dict(environment, SENTINEL_SHARED_HOST=str(settings.host), SENTINEL_SHARED_NETWORK=str(settings.network),
               SENTINEL_SHARED_PORT=str(settings.port), SENTINEL_SYNTHETIC_REHEARSAL="0")
    trust = ssl.create_default_context(cadata=root_certificate.public_bytes(serialization.Encoding.PEM).decode())
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=trust))
    return cert, key, ca, fingerprint, env, opener


def shared_health(opener, origin, store, version):
    from hashlib import sha256

    try:
        with opener.open(origin + "/health", timeout=.5) as response:
            health = json.load(response)
        identity = sha256(str(store.resolve()).encode("utf-8")).hexdigest()[:16]
        return (health.get("ui_version") == version and health.get("status") == "ok"
                and health.get("instance_id") == identity and health.get("authentication_required") is True)
    except (OSError, ValueError, AttributeError):
        return False


def start(executable, root, args, stop_process):
    settings = SharedHosting.parse(args.shared, args.subnet, args.port)
    store = Path(os.environ["SENTINEL_STORAGE_DIR"])
    cert, key, ca, fingerprint, env, opener = prepare_https(store, settings, os.environ)
    print(f"Team HTTPS URL: {settings.origin}/\nAllowed network: {settings.network}", flush=True)
    print(f"Public trust certificate: {ca}\nSHA-256 certificate fingerprint: {fingerprint}", flush=True)
    command = [str(executable), "-m", "uvicorn", "app.main:app", "--host", str(settings.host),
               "--port", str(settings.port), "--ssl-certfile", str(cert), "--ssl-keyfile", str(key),
               "--no-proxy-headers", "--no-access-log"]
    process = subprocess.Popen(command, cwd=root, env=env)
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and process.poll() is None:
            if shared_health(opener, settings.origin, store, "sentinel-v6"):
                break
            time.sleep(.2)
        else:
            raise RuntimeError("Shared Sentinel could not start. Check the selected IP, port, and server output above.")
        print("Shared Sentinel is ready. Open the HTTPS URL after trusting the public certificate.", flush=True)
        if args.smoke_test:
            return 0
        print("Press Ctrl+C to stop shared Sentinel.", flush=True)
        return process.wait()
    except KeyboardInterrupt:
        # Both processes receive the console interrupt. Let Uvicorn flush live archives.
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            pass
        return 0
    finally:
        stop_process(process)
