#!/usr/bin/env python3
"""Steps 6 and 7: the application reads its API token, and the deployer
rotates it. Huawei's Python SDK (CSMS) goes through WeiStack, an HTTPS
proxy on the -lan port, with CSMS's real endpoint.

    . ./use.sh app;      python app/api_token.py read
    . ./use.sh deployer; python app/api_token.py rotate

`read` prints which version the app got and a fingerprint of the token,
never the token itself: an app should not log its secrets either.
"""
import hashlib
import os
import pathlib
import secrets
import subprocess
import sys
from urllib.parse import urlparse

from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkcore.exceptions.exceptions import ClientRequestException
from huaweicloudsdkcore.http.http_config import HttpConfig
from huaweicloudsdkcsms.v1 import (CreateSecretVersionRequest, CreateSecretVersionRequestBody,
                                   CsmsClient, ShowSecretStageRequest, ShowSecretVersionRequest)
from huaweicloudsdkcsms.v1.region.csms_region import CsmsRegion

REGION = os.environ.get("HW_REGION_NAME", "ap-southeast-1")
HERE = pathlib.Path(__file__).resolve().parent.parent


def tf_output(name):
    """Reads an output of the stack (infra/) or of IAM (iam/)."""
    module = "iam" if name == "project_id" else "infra"
    return subprocess.run(["terraform", f"-chdir={HERE / module}", "output", "-raw", name],
                          check=True, capture_output=True, text=True).stdout


def csms_client(project_id):
    proxy = urlparse(os.environ["WEISTACK"])
    config = HttpConfig.get_default_config()
    config.proxy_protocol, config.proxy_host, config.proxy_port = proxy.scheme, proxy.hostname, proxy.port
    config.ssl_ca_cert = os.environ["REQUESTS_CA_BUNDLE"]  # the system bundle, with WeiStack's CA
    credentials = BasicCredentials(os.environ["HW_ACCESS_KEY"], os.environ["HW_SECRET_KEY"], project_id)
    return (CsmsClient.new_builder().with_credentials(credentials)
            .with_region(CsmsRegion.value_of(REGION)).with_http_config(config).build())


def fingerprint(token):
    return hashlib.sha256(token.encode()).hexdigest()[:12]


def read(client, name):
    """What the app does at start: read the current version (SYSCURRENT,
    which "latest" names)."""
    version = client.show_secret_version(ShowSecretVersionRequest(secret_name=name, version_id="latest")).version
    meta = version.version_metadata
    print(f"{name}: version {meta.id} ({', '.join(meta.version_stages)}), token sha256 {fingerprint(version.secret_string)}…")


def rotate(client, name):
    """A new version becomes SYSCURRENT; the one before it stays readable
    as SYSPREVIOUS, so instances still holding it keep working until they
    restart."""
    before = client.show_secret_stage(ShowSecretStageRequest(secret_name=name, stage_name="SYSCURRENT")).stage.version_id
    body = CreateSecretVersionRequestBody(secret_string=secrets.token_urlsafe(30))
    created = client.create_secret_version(CreateSecretVersionRequest(secret_name=name, body=body)).version_metadata
    previous = client.show_secret_stage(ShowSecretStageRequest(secret_name=name, stage_name="SYSPREVIOUS")).stage.version_id
    print(f"{name}: rotated {before} -> {created.id}; SYSPREVIOUS is {previous}")
    if previous != before:
        sys.exit(f"SYSPREVIOUS is {previous}, want {before}")


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "read"
    client = csms_client(tf_output("project_id"))
    name = tf_output("secret_name")
    try:
        {"read": read, "rotate": rotate}[action](client, name)
    except ClientRequestException as e:
        # The error's code and message, as Huawei Cloud would return them.
        sys.exit(f"{action}: {e.status_code} {e.error_code}: {e.error_msg}")


if __name__ == "__main__":
    main()
