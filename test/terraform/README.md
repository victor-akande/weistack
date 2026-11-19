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
     to both, and an access key;
   - KMS (`kms.tf`): a key with rotation and tags, a grant and a data key;
     the bucket, the server's data disk and the RDS storage are encrypted
     with the key;
   - agencies (`agencies.tf`): a classic agency for a cloud service, one
     for a second account (the partner, which `run.sh` adds through the
     admin API first), and a trust agency both accounts may assume.

   The outputs show them in their final states. The provider is given no
   domain ID: it finds the account through IAM.
2. The partner assumes the agencies with the provider's `assume_role`
   (`assume/main.tf`): once through classic IAM (`domain_name`), once
   through STS (`domain_id`), and reads the scenario's VPC with each set
   of temporary credentials.
3. The IAM 5.0 user signs with its own key (`restricted/main.tf`). Its
   policy allows OBS and VPC reads, and it reads the scenario's VPC. With
   `-iam=enforce`, creating a VPC and listing ECS servers must both be
   denied with `Policy doesn't allow <action> to be performed.`
4. A second `terraform plan` must find no changes. This catches every read
   that disagrees with what was written.
5. `terraform destroy` deletes everything, and the emulator must hold
   nothing but what outlives a project's resources in the cloud: job
   history, public images, the default security group, and the accounts'
   projects and root users.

```bash
make test-terraform
```

To run it with credentials enforced (`-iam=enforce`), set
`WEISTACK_TF_IAM=enforce`. Terraform then signs with the administrator's
keys, which `run.sh` gets from `weistack credentials`; CI runs it both
ways.

```bash
WEISTACK_TF_IAM=enforce make test-terraform
```

It needs `terraform` (1.6 or later), `go`, `curl` and `python3`. Set
`WEISTACK_BIN` to test an existing binary instead of building one, and
`TF_PLUGIN_CACHE_DIR` to avoid downloading the provider on every run.

`main.tf` doubles as an example of the provider configuration WeiStack
needs; see the comments in its `provider` block.
