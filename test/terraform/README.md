# Terraform scenario

`run.sh` checks WeiStack against the Huawei Cloud Terraform provider the way
a user would drive it. The provider keeps Huawei Cloud's real endpoints and
reaches WeiStack only through `HTTPS_PROXY`. Passthrough is off, so a
request for anything WeiStack does not emulate fails instead of reaching
the real cloud.

1. `terraform apply` creates a VPC, subnet, security group and rule, an ECS
   server, an OBS bucket and an RDS MySQL instance, and the outputs show
   them in their final states.
2. A second `terraform plan` must find no changes. This catches every read
   that disagrees with what was written.
3. `terraform destroy` deletes everything, and the emulator must hold
   nothing but what outlives a project's resources in the cloud: job
   history, public images and the default security group.

```bash
make test-terraform
```

It needs `terraform` (1.6 or later), `go`, `curl` and `python3`. Set
`WEISTACK_BIN` to test an existing binary instead of building one, and
`TF_PLUGIN_CACHE_DIR` to avoid downloading the provider on every run.

`main.tf` doubles as an example of the provider configuration WeiStack
needs; see the comments in its `provider` block.
