# Vector into AWS

![Tfsec](https://github.com/nlamirault/terraform-aws-vector/workflows/Tfsec/badge.svg)

## Usage

```hcl
module "vector" {
  source  = "nlamirault/vector/aws"
  version = "1.0.0"

  project = var.project

  namespace       = var.namespace
  service_account = var.service_accounttags = var.tags

  tags = var.tags
}
```

and variables :

```hcl
project = "foo-prod"

region = "europe-west1"

##############################################################################
# External DNS

namespace       = "dns"
service_account = "vector"
```

## Documentation

<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Requirements

| Name | Version |
|------|---------|
| terraform | >= 1.0.0 |
| aws | >= 3.28.0 |

## Providers

| Name | Version |
|------|---------|
| aws | >= 3.28.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| vector | terraform-aws-modules/s3-bucket/aws | 2.11.1 |
| vector_log | terraform-aws-modules/s3-bucket/aws | 2.11.1 |
| vector_role | terraform-aws-modules/iam/aws//modules/iam-assumable-role-with-oidc | 4.7.0 |

## Resources

| Name |
|------|
| [aws_eks_cluster](https://registry.terraform.io/providers/hashicorp/aws/3.28.0/docs/data-sources/eks_cluster) |
| [aws_iam_policy](https://registry.terraform.io/providers/hashicorp/aws/3.28.0/docs/resources/iam_policy) |
| [aws_iam_policy_document](https://registry.terraform.io/providers/hashicorp/aws/3.28.0/docs/data-sources/iam_policy_document) |
| [aws_kms_alias](https://registry.terraform.io/providers/hashicorp/aws/3.28.0/docs/resources/kms_alias) |
| [aws_kms_key](https://registry.terraform.io/providers/hashicorp/aws/3.28.0/docs/resources/kms_key) |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| cluster\_name | Name of the EKS cluster | `string` | n/a | yes |
| deletion\_window\_in\_days | Duration in days after which the key is deleted after destruction of the resource, must be between 7 and 30 days | `number` | `30` | no |
| enable\_kms | Enable custom KMS key | `bool` | n/a | yes |
| namespace | The Kubernetes namespace | `string` | n/a | yes |
| service\_account | The Kubernetes service account | `string` | n/a | yes |
| tags | Tags for VPC | `map(string)` | <pre>{<br>  "made-by": "terraform"<br>}</pre> | no |

## Outputs

| Name | Description |
|------|-------------|
| role\_arn | Role ARN for Vector |
<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
