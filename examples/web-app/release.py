#!/usr/bin/env python3
"""Step 6: release the site. Run as the deployer, after `. ./use.sh deployer`.

1. Huawei's Python SDK reads the database's address from RDS.
2. The site's files are rendered with it into site/.
3. The OBS SDK for Python uploads them to the bucket, under
   releases/<version>/ and current/, and checks that OBS encrypted each
   object with the stack's KMS key.

    python release.py v1
"""
import json
import os
import pathlib
import subprocess
import sys
from urllib.parse import urlparse

from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkcore.http.http_config import HttpConfig
from huaweicloudsdkrds.v3 import ListInstancesRequest, RdsClient
from huaweicloudsdkrds.v3.region.rds_region import RdsRegion
from obs import ObsClient, PutObjectHeader

REGION = os.environ.get("HW_REGION_NAME", "ap-southeast-1")
HERE = pathlib.Path(__file__).resolve().parent


def tf_output(name):
    """Reads an output of the stack (infra/) or of IAM (iam/)."""
    module = "iam" if name == "project_id" else "infra"
    return subprocess.run(["terraform", f"-chdir={HERE / module}", "output", "-raw", name],
                          check=True, capture_output=True, text=True).stdout


def rds_client(project_id):
    """The Python SDK keeps RDS's real endpoint and goes through WeiStack,
    an HTTPS proxy on the -lan port."""
    proxy = urlparse(os.environ["WEISTACK"])
    config = HttpConfig.get_default_config()
    config.proxy_protocol, config.proxy_host, config.proxy_port = proxy.scheme, proxy.hostname, proxy.port
    config.ssl_ca_cert = os.environ["REQUESTS_CA_BUNDLE"]  # the system bundle, with WeiStack's CA
    credentials = BasicCredentials(os.environ["HW_ACCESS_KEY"], os.environ["HW_SECRET_KEY"], project_id)
    return (RdsClient.new_builder().with_credentials(credentials)
            .with_region(RdsRegion.value_of(REGION)).with_http_config(config).build())


def obs_client():
    """The OBS SDK cannot use an HTTPS proxy, so it calls OBS's own host
    name on the -lan port, which the workstation resolves to the cloud
    machine (README, step 2)."""
    port = urlparse(os.environ["WEISTACK"]).port
    return ObsClient(
        access_key_id=os.environ["HW_ACCESS_KEY"],
        secret_access_key=os.environ["HW_SECRET_KEY"],
        server=f"https://obs.{REGION}.myhuaweicloud.com:{port}",
        ssl_verify=os.environ["REQUESTS_CA_BUNDLE"],
        path_style=True,
        signature="obs",
        is_signature_negotiation=False,
    )


def main():
    version = sys.argv[1] if len(sys.argv) > 1 else "v1"
    project_id, db_id, bucket = tf_output("project_id"), tf_output("db_id"), tf_output("bucket")
    key_id = tf_output("kms_key_id")

    db = rds_client(project_id).list_instances(ListInstancesRequest(id=db_id)).instances[0]
    print(f"database {db.name}: {db.status} at {db.private_ips[0]}:{db.port}")

    site = HERE / "site"
    site.mkdir(exist_ok=True)
    (site / "config.json").write_text(json.dumps(
        {"version": version, "db_host": db.private_ips[0], "db_port": db.port}, indent=2) + "\n")
    (site / "index.html").write_text(
        f"<!doctype html><title>web-app</title><h1>web-app {version}</h1>\n")

    client = obs_client()
    try:
        for f in sorted(site.iterdir()):
            for key in (f"releases/{version}/{f.name}", f"current/{f.name}"):
                resp = client.putFile(bucket, key, str(f), headers=PutObjectHeader(contentType=None))
                if resp.status >= 300:
                    sys.exit(f"upload of {key} failed: {resp.status} {resp.errorCode} {resp.errorMessage}")
                meta = client.getObjectMetadata(bucket, key)
                encryption = (meta.body.sseKms, meta.body.sseKmsKey) if meta.status < 300 else None
                # With path-style addressing the SDK signs S3-style, and OBS
                # answers in that dialect: "aws:kms" rather than "kms".
                if not encryption or encryption[0] not in ("kms", "aws:kms") or key_id not in (encryption[1] or ""):
                    sys.exit(f"{key} is not encrypted with the stack's key: {encryption}")
                print(f"uploaded {key} (KMS-encrypted)")
    finally:
        client.close()


if __name__ == "__main__":
    main()
