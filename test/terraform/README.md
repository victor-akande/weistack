# Terraform scenario

`run.sh` checks WeiStack against the Huawei Cloud Terraform provider the way
a user would drive it. The provider keeps Huawei Cloud's real endpoints and
reaches WeiStack only through `HTTPS_PROXY`. Passthrough is off, so a
request for anything WeiStack does not emulate fails instead of reaching
the real cloud.

1. `terraform apply` creates a VPC, subnet, security group and rule, an ECS
   server, an OBS bucket and an RDS MySQL instance (`main.tf`), and IAM
   resources through both of IAM's APIs (`iam.tf`):
   - classic IAM: a user, a group and its members, a custom role, the
     group's grants for one project, all projects, global services and
     the default enterprise project, a user's enterprise project grant,
     and an access key;
   - IAM 5.0: a user, a group and its members, an identity policy attached
     to both, and an access key.

   The outputs show them in their final states. The provider is given no
   domain ID: it finds the account through IAM.
2. A second `terraform plan` must find no changes. This catches every read
   that disagrees with what was written.
3. `terraform destroy` deletes everything, and the emulator must hold
   nothing but what outlives a project's resources in the cloud: job
   history, public images, the default security group, and the account's
   projects and root user.

```bash
make test-terraform
```

It needs `terraform` (1.6 or later), `go`, `curl` and `python3`. Set
`WEISTACK_BIN` to test an existing binary instead of building one, and
`TF_PLUGIN_CACHE_DIR` to avoid downloading the provider on every run.

`main.tf` doubles as an example of the provider configuration WeiStack
needs; see the comments in its `provider` block.
