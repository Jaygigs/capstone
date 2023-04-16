provider "aws" {
  

    # create an iAM user on aws to get an authentication
    # to prevent misuse of aws access key and secret key we provide 
    profile = var.ec2_profile
    region = var.ec2_region
  
}
resource "aws_instance" "ec2_instance" {
    ami = var.ec2_ami
    count = var.ec2_count
    key_name = aws_key_pair.ec2_keys.key_name
    instance_type = var.ec2_instance_type
    security_groups = ["${var.ec2_sg}"]
    subnet_id = element(var.ec2_subnet_id,count.index)  #element(list, index)
    tags = {
      "Name" = "${var.ec2_tags}-${count.index+1 }"
    }
   
  
}
resource "aws_key_pair" "ec2_keys" {
  key_name = "couragekey1"
  public_key = file("${path.module}/public_key")

  
}


resource "aws_eks_cluster" "capstone" {
  name     = "capstone"
  role_arn = aws_iam_role.capstone-role.arn

  vpc_config {
    subnet_ids = var.ec2_subnet_id
    
    }

  depends_on = [
    aws_iam_role_policy_attachment.capstone-role-AmazonEKSClusterPolicy,
    aws_iam_role_policy_attachment.capstone-role-AmazonEKSVPCResourceController,
  ]
}


resource "aws_iam_role" "capstone-role" {
  name = "eks-cluster-role1"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "capstone-role-AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.capstone-role.name
}

resource "aws_iam_role_policy_attachment" "capstone-role-AmazonEKSVPCResourceController" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
  role       = aws_iam_role.capstone-role.name
}

data "tls_certificate" "ekstls" {
  url = aws_eks_cluster.capstone.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eksopidc" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.ekstls.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.capstone.identity[0].oidc[0].issuer
}

data "aws_iam_policy_document" "eksdoc_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eksopidc.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:aws-node"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.eksopidc.arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "clusterworkers" {
   name = "eks-cluster-worker-role"

  assume_role_policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:DescribeInstances",
                "ec2:DescribeInstanceTypes",
                "ec2:DescribeRouteTables",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeVolumes",
                "ec2:DescribeVolumesModifications",
                "ec2:DescribeVpcs",
                "eks:DescribeCluster"
            ],
            "Resource": "*"
        }
    ]
}
POLICY
}

resource "aws_iam_role" "ecr" {
   name = "eks-cluster-reporeadonly-role"

  assume_role_policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:GetRepositoryPolicy",
                "ecr:DescribeRepositories",
                "ecr:ListImages",
                "ecr:DescribeImages",
                "ecr:BatchGetImage",
                "ecr:GetLifecyclePolicy",
                "ecr:GetLifecyclePolicyPreview",
                "ecr:ListTagsForResource",
                "ecr:DescribeImageScanFindings"
            ],
            "Resource": "*"
        }
    ]
}
POLICY
}

resource "aws_eks_node_group" "capstone_node" {
  cluster_name    = aws_eks_cluster.capstone.name
  node_group_name = "clusternodes"
  node_role_arn   = aws_iam_role.capstone_node.arn
  subnet_ids      = var.ec2_subnet_id
  scaling_config {
    desired_size = 3
    max_size     = 3
    min_size     = 3
  }

  update_config {
    max_unavailable = 2
  }

  depends_on = [
    aws_iam_role_policy_attachment.capstone-node-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.capstone-node-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.capstone-node-AmazonEC2ContainerRegistryReadOnly,
  ]
}



resource "aws_iam_role" "capstone_node" {
  name = "capstone_role"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "capstone-node-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.clusterworkers.name
}

resource "aws_iam_role_policy_attachment" "capstone-node-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.capstone_node.name
}

 resource "aws_iam_role_policy_attachment" "capstone-node-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.ecr.name
 }

resource "aws_s3_bucket" "tf_state_bucket" {

    bucket = "cee-tf-state-bucket"

}

resource "aws_dynamodb_table" "tf_state_lock"{
    name = "cee-tf-state-lock"
    hash_key = "LockID"
    billing_mode = "PROVISIONED"
    read_capacity = 20
    write_capacity = 20
    attribute{
        name = "LockID"
        type = "S"
    }
}

#terraform{
#    backend "s3"{
#        bucket = "cee-tf-state-bucket"
#        key = "terraform.tfstate"
#        region = "us-east-1"
#        dynamodb_table = "tf-state-lock"
#        encrypt = true
#    }
#}