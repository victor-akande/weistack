# CSMS secrets (default csms/default key with tags, and customer KMS key with
# binary payload), a custom version stage, and CSMS data sources.

variable "csms_secret_text" {
  type        = string
  sensitive   = true
  description = "Plaintext value of the default-key CSMS secret. run.sh generates one per run."
}

variable "csms_binary_payload" {
  type        = string
  sensitive   = true
  description = "Raw payload Base64-encoded for the KMS-key CSMS secret. run.sh generates one per run."
}

resource "huaweicloud_csms_secret" "text" {
  name        = "tf-csms-text"
  secret_text = var.csms_secret_text
  description = "Text secret encrypted with csms/default"

  tags = {
    env     = "test"
    service = "csms"
  }
}

resource "huaweicloud_csms_secret" "binary" {
  name          = "tf-csms-binary"
  secret_binary = base64encode(var.csms_binary_payload)
  kms_key_id    = huaweicloud_kms_key.app.id
  description   = "Binary secret encrypted with the scenario KMS key"
}

resource "huaweicloud_csms_secret_version_state" "deployed" {
  secret_name = huaweicloud_csms_secret.text.name
  name        = "deployed"
  version_id  = "v1"
}

data "huaweicloud_csms_secrets" "all" {
  depends_on = [
    huaweicloud_csms_secret.text,
    huaweicloud_csms_secret.binary,
  ]
}

data "huaweicloud_csms_secret_version" "text" {
  secret_name = huaweicloud_csms_secret.text.name

  depends_on = [
    huaweicloud_csms_secret.text,
    huaweicloud_csms_secret_version_state.deployed,
  ]
}

output "csms" {
  value = {
    text_status         = huaweicloud_csms_secret.text.status
    text_default_key    = huaweicloud_csms_secret.text.kms_key_id != "" && huaweicloud_csms_secret.text.kms_key_id != huaweicloud_kms_key.app.id
    text_latest_version = huaweicloud_csms_secret.text.latest_version
    binary_status       = huaweicloud_csms_secret.binary.status
    binary_kms_match    = huaweicloud_csms_secret.binary.kms_key_id == huaweicloud_kms_key.app.id
    stage_name          = huaweicloud_csms_secret_version_state.deployed.name
    stage_version_id    = huaweicloud_csms_secret_version_state.deployed.version_id
    secrets_count       = length(data.huaweicloud_csms_secrets.all.secrets)
    read_version        = data.huaweicloud_csms_secret_version.text.version
    version_text_match  = nonsensitive(data.huaweicloud_csms_secret_version.text.secret_text) == nonsensitive(var.csms_secret_text)
  }
}
