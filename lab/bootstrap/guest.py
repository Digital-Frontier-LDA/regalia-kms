"""Early-boot experiment client; stdout is a credential pipe, never a log."""

import json
import http.client
import os
import sys
from pathlib import Path

STAGE = "imports"


def main():
    global STAGE
    from lab import derive_credential, run, tpm_refused
    from network import address, exchange
    from peer import BootSession, Refusal, qualification
    os.umask(0o077)
    fixture = json.loads(Path("/bootstrap/fixture.json").read_text())
    STAGE = "startup"
    startup = run("tpm2_startup", "-c", required=False)
    if startup.returncode:
        tpm_refused(startup, 0x100)
    current = Path("/tmp/current.pcr")
    run("tpm2_pcrread", "sha256:7", "-o", current, "-Q")
    print("REGALIA_PCR7_" + current.read_bytes().hex(), file=sys.stderr)
    if fixture.get("survey"):
        print("REGALIA_MEASUREMENT_SURVEY_COMPLETE", file=sys.stderr)
        return
    if fixture.get("tamper_pcr"):
        run("tpm2_pcrextend", "7:sha256=" + os.urandom(32).hex())
        run("tpm2_pcrread", "sha256:7", "-o", current, "-Q")
        print("REGALIA_PCR7_" + current.read_bytes().hex(), file=sys.stderr)
    STAGE = "unseal"
    checked = run("tpm2_unseal", "-c", "0x81010005", "-p", "pcr:sha256:7", required=False)
    if checked.returncode:
        tpm_refused(checked, 0x99D)
        print("REGALIA_UNSEAL_POLICY_REFUSED", file=sys.stderr)
        raise Refusal()
    local = checked.stdout
    wg = run("tpm2_unseal", "-c", "0x81010004", "-p", "pcr:sha256:7").stdout
    STAGE = "wireguard_create"
    run("ip", "link", "add", "wg-bootstrap", "type", "wireguard")
    run("ip", "address", "add", "10.77.91.1/24", "dev", "wg-bootstrap")
    STAGE = "wireguard_key"
    run("wg", "set", "wg-bootstrap", "listen-port", "51821", "private-key", "/dev/stdin", data=wg)
    STAGE = "wireguard_peers"
    for peer, pin in fixture["peers"].items():
        run("wg", "set", "wg-bootstrap", "peer", pin["wg_public"], "allowed-ips", address(peer) + "/32",
            "endpoint", address(peer, "underlay") + ":51820")
    run("ip", "link", "set", "wg-bootstrap", "up")
    session = BootSession({peer: bytes.fromhex(pin["signing_public"]) for peer, pin in fixture["peers"].items()})
    session_id = os.urandom(16).hex()
    STAGE = "peer_exchange"
    for peer in fixture["selected"]:
        try:
            challenge = exchange(address(peer), 8443, {"op": "challenge", "node_id": "A"}, timeout=8)
            if challenge["manifest_epoch"] != fixture["epoch"] or challenge["peer_id"] != peer:
                raise Refusal()
            request = session.request(challenge, session_id)
            message, signature = Path("/tmp/quote.msg"), Path("/tmp/quote.sig")
            run("tpm2_quote", "-c", "0x81010002", "-l", "sha256:7", "-g", "sha256", "-Q",
                "-q", qualification(request).hex(), "-m", message, "-s", signature)
            response = exchange(address(peer), 8443, {"op": "authorize", "request": request,
                                "quote": message.read_bytes().hex(), "signature": signature.read_bytes().hex()}, timeout=8)
            credential = derive_credential(local, session.open(response), peer)
            print("REGALIA_PEER_AUTHORIZED_" + peer, file=sys.stderr)
            sys.stdout.buffer.write(credential)
            return
        except Refusal as refusal:
            if refusal.code == "DENIED":
                print("REGALIA_PEER_DENIED_" + peer, file=sys.stderr)
            continue
        except (OSError, http.client.HTTPException):
            continue
    raise Refusal()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"REGALIA_BOOTSTRAP_REFUSED_{STAGE}_{type(error).__name__}", file=sys.stderr)
        raise SystemExit(1)
