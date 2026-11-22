"""Qualify the real Rust consumer using accepted, hash-pinned server fixtures.

Uses only the Python standard library. Provider/browser responsibilities remain in
the server's fixture; every Hubuum operation under test uses the public Rust SDK.
Only sanitized results are retained. Disposable secrets remain under fixture.root.
"""
import argparse
import hashlib
import importlib
import json
from pathlib import Path
import selectors
import subprocess
import sys
import time


REPO = Path(__file__).resolve().parents[3]
SOURCE = json.loads((REPO / "openapi/authentication-project-source.json").read_text())


def definition(fixture, profile):
    if profile != "oauth":
        return {
            "issuer": fixture.issuer, "client_id": "hubuum",
            "client_authentication": "client_secret_basic", "scopes": ["openid", "profile", "email"],
            "signing_algorithms": ["RS256"], "retain_refresh_tokens": True,
            "membership": {"mode": "provider_groups", "refresh_interval_seconds": 5,
                           "max_stale_seconds": 15, "claim_source": profile,
                           "claim_pointer": "/groups", "key_mode": "full_path"},
            "admission": {"mode": "provision_without_grants"},
        }
    return {
        "profile": "json_user", "authorization_endpoint": fixture.provider_origin + "/authorize",
        "token_endpoint": f"https://host.docker.internal:{fixture.provider_port}/token",
        "profile_endpoint": f"https://host.docker.internal:{fixture.provider_port}/account",
        "client_id": "fixture", "client_authentication": "client_secret_basic", "scopes": ["identity"],
        "subject_pointer": "/account/key", "subject_type": "string", "name_pointer": "/account/display",
        "profile_headers": {"x-profile-version": "2"},
        "membership": {"mode": "provider_groups", "claim_source": "profile", "claim_pointer": "/roles",
                       "key_mode": "immutable_id", "refresh_interval_seconds": 5, "max_stale_seconds": 15},
        "admission": {"mode": "provision_without_grants"},
    }


def counts(fixture):
    return {table: int(fixture.sql(f"SELECT count(*) FROM {table}")) for table in (
        "users", "principals", "group_memberships", "group_membership_sources",
        "auth_sessions", "auth_upstream_credentials")}


def consumer(fixture, binary, mode, profile, results):
    config = fixture.root / "sdk-input.json"
    config.write_text(json.dumps({
        "origin": fixture.origin, "ca_file": str(fixture.root / "mount/ca.pem"),
        "local_password": fixture.local_password, "client_secret": fixture.client_secret,
        "kind": "oauth" if profile == "oauth" else "oidc", "definition": definition(fixture, profile),
    }))
    config.chmod(0o600)
    preview = None
    with (fixture.root / "consumer.stderr").open("w") as stderr:
        process = subprocess.Popen([str(binary), mode, str(config)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=stderr, bufsize=0)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        complete = False
        deadline = time.monotonic() + 300
        try:
            while time.monotonic() < deadline:
                if not selector.select(timeout=min(45, max(0, deadline - time.monotonic()))):
                    raise RuntimeError("Consumer exceeded bounded progress interval")
                line = process.stdout.readline()
                if not line:
                    break
                event = json.loads(line)
                kind = event["event"]
                if kind == "provider":
                    fixture.provider_id = event["id"]
                    if profile != "oauth":
                        client = fixture.provider_api("/clients?clientId=hubuum")[0]
                        client["redirectUris"] = [fixture.origin + "/api/v1/auth/callbacks/" + fixture.provider_id]
                        fixture.provider_api("/clients/" + client["id"], client, method="PUT")
                    preview = counts(fixture)
                elif kind == "browser":
                    fixture.authorize(event)
                elif kind == "preview_completed":
                    if preview is None or preview != counts(fixture):
                        raise RuntimeError("Native SDK preview changed identity/session counts")
                    results.append("candidate preview leaves six identity/session tables unchanged")
                    preview = None
                elif kind == "passed":
                    results.append(event["check"])
                    print(f"{profile}/{mode}: {event['check']}", flush=True)
                    continue
                elif kind == "stage":
                    print(f"{profile}/{mode}: {event['stage']}", flush=True)
                    continue
                elif kind == "failure":
                    results.append({"failure": event})
                    raise RuntimeError("Native SDK operation failed")
                elif kind == "complete":
                    complete = True
                    break
                else:
                    raise RuntimeError("Unexpected consumer event")
                process.stdin.write(b"continue\n")
                process.stdin.flush()
            if not complete or process.wait(timeout=15) != 0:
                raise RuntimeError("Native SDK qualification failed")
            return results
        finally:
            selector.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=15)
            process.stdin.close()
            process.stdout.close()
            config.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server-source", required=True, type=Path)
    parser.add_argument("--image", required=True)
    parser.add_argument("--consumer", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--profile", choices=("id_token", "userinfo", "oauth"), required=True)
    args = parser.parse_args()
    source = args.server_source.resolve()
    server_commit = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if server_commit != SOURCE["accepted_server_source"]:
        raise RuntimeError("Server fixture checkout is not the accepted source")
    for relative, expected in SOURCE["source_live_fixture_sha256"].items():
        if hashlib.sha256((source / relative).read_bytes()).hexdigest() != expected:
            raise RuntimeError("Server fixture source differs from accepted candidate")
    image = json.loads(subprocess.check_output(["docker", "image", "inspect", args.image], text=True))[0]
    digests = {entry.split("@")[-1] for entry in image.get("RepoDigests", [])}
    qualified = next((pin for pin in SOURCE["qualified_server_images"] if image["Id"] in
                      (pin.get("docker_image_id"), pin["manifest"], pin["config"])
                      or pin["manifest"] in digests), None)
    if qualified is None:
        raise RuntimeError("Server image is not a qualified immutable candidate")
    sys.path.insert(0, str(source / "tests/python"))
    module = importlib.import_module("integration.oauth" if args.profile == "oauth" else "integration.keycloak")

    class Fixture(module.Fixture):
        def env(self, name, values):
            if name == "server":
                values["HUBUUM_SESSION_ACCESS_SECONDS"] = "30"
            return super().env(name, values)

    if args.profile == "oauth":
        fixture = Fixture(args.image, args.evidence, 48479, 48480)
    else:
        fixture = Fixture(args.image, args.evidence, 48477, 48478, args.profile)
    report = {"profile": args.profile, "source": SOURCE, "server_image": qualified,
              "consumer_sha256": hashlib.sha256(args.consumer.read_bytes()).hexdigest(),
              "sdk_source_commit": subprocess.check_output(["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True).strip(),
              "sdk_source_dirty": bool(subprocess.check_output(["git", "-C", str(REPO), "status", "--porcelain"], text=True)),
              "modes": {}, "passed": False}
    try:
        fixture.start()
        identity_path = args.evidence / "images.json"
        identity = json.loads(identity_path.read_text())
        identity.pop("source_commit", None)
        identity.pop("source_dirty", None)
        identity["server_source_commit"] = server_commit
        identity["sdk_source_commit"] = report["sdk_source_commit"]
        identity["sdk_source_dirty"] = report["sdk_source_dirty"]
        identity_path.write_text(json.dumps(identity, indent=2) + "\n")
        for mode in ("async", "blocking"):
            report["modes"][mode] = []
            consumer(fixture, args.consumer.resolve(), mode, args.profile, report["modes"][mode])
        report["passed"] = True
    finally:
        fixture.cleanup()
        args.evidence.mkdir(parents=True, exist_ok=True)
        (args.evidence / "sdk-qualification.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    # Do not echo provider response bodies, private fixture paths or credentials.
    try:
        raise SystemExit(main())
    except Exception:
        print("Native authentication qualification failed; sanitized partial report retained.", file=sys.stderr)
        raise SystemExit(1) from None
