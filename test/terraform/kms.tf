# A KMS key with rotation and tags, and a data key made with it.

resource "huaweicloud_kms_key" "app" {
  key_alias         = "tf-app"
  key_description   = "Encrypts the app's data"
  pending_days      = "7"
  rotation_enabled  = true
  rotation_interval = 180

  tags = {
    env = "test"
  }
}

data "huaweicloud_kms_data_key" "app" {
  key_id         = huaweicloud_kms_key.app.id
  datakey_length = "512"
}

output "kms" {
  value = {
    key_state      = huaweicloud_kms_key.app.key_state
    rotation       = huaweicloud_kms_key.app.rotation_enabled
    data_key_chars = length(nonsensitive(data.huaweicloud_kms_data_key.app.plain_text))
  }
}
