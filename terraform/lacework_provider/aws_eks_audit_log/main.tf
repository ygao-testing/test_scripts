provider "lacework" {
}

provider "aws" {
  region  = "us-east-2"
}

module "aws_eks_audit_log" {
  source  = "lacework/eks-audit-log/aws"
  version = "~> 1.1"

  cloudwatch_regions = ["us-east-2"]
  cluster_names      = ["rb_lw_test"]
}
