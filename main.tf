provider "aws" {
    region = var.aws_region
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = "my-vpc"
  cidr = "10.0.0.0/16"

  azs             = var.aws_azs
  private_subnets = var.vpc_private_subnets
  public_subnets  = var.vpc_public_subnets

  enable_nat_gateway = true
  single_nat_gateway = true
  one_nat_gateway_per_az = false

  tags = {
    Terraform = "true"
    Environment = "dev"
  }
}

resource "aws_instance" "consul_server" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t2.micro"
  key_name               = aws_key_pair.server_key.key_name
  count                  = 3

  vpc_security_group_ids = [module.consul-servers-sg.this_security_group_id]
  subnet_id              = module.vpc.public_subnets[0]
  iam_instance_profile   = aws_iam_instance_profile.consul-join.name
  
  tags = {
    Name = "consul-server${count.index + 1}"
    consul_server = true
  }
  user_data              = file("user-data-server.sh")

  connection {
    type = "ssh"
    host = "self.public_ip"
    private_key = tls_private_key.server_key.private_key_pem
    user = "ubuntu"
  }
}
resource "aws_instance" "app_server" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t2.micro"
  key_name               = aws_key_pair.server_key.key_name
  count                  = 1

  vpc_security_group_ids = [module.app-servers-sg.this_security_group_id]
  
  subnet_id              = module.vpc.public_subnets[0]
  iam_instance_profile   = aws_iam_instance_profile.consul-join.name
  
  tags = {
    Name = "app-server${count.index + 1}"
    consul_server = true
  }
  user_data              = file("consul-agent.sh")

  connection {
    type = "ssh"
    host = "self.public_ip"
    private_key = tls_private_key.server_key.private_key_pem
    user = "ubuntu"
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

module "consul-servers-sg" {
  source = "terraform-aws-modules/security-group/aws//modules/consul"

  name        = "consul-servers-sg"
  description = "Allow ssh & consul inbound traffic"
  vpc_id      = module.vpc.vpc_id

  ingress_cidr_blocks      = [module.vpc.vpc_cidr_block]
  
  ingress_with_cidr_blocks = [
    {
      rule        = "ssh-tcp"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      rule        = "consul-webui-tcp"
      cidr_blocks = "0.0.0.0/0"
    }
  ]
  egress_rules      = ["all-all"]
}

module "app-servers-sg" {
  source = "terraform-aws-modules/security-group/aws//modules/http-80"

  name        = "app-servers-sg"
  description = "Allow web inbound traffic"
  vpc_id      = module.vpc.vpc_id

  ingress_cidr_blocks      = ["0.0.0.0/0"]
  
  ingress_with_cidr_blocks = [
    {
      rule        = "consul-webui-tcp"
      cidr_blocks = "0.0.0.0/0"
    },
    {
      rule        = "ssh-tcp"
      cidr_blocks = "0.0.0.0/0"
    }    
  ]
  
  egress_rules      = ["all-all"]
}

#Monitoring Security Group
resource "aws_security_group" "monitor_sg" {
  name        = "monitor_sg_1"
  description = "Security group for monitoring server"
  vpc_id      = module.vpc.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow ICMP from control host IP
  ingress {
    from_port   = 8
    to_port     = 0
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow all SSH External
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow all traffic to HTTP port 3000
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Allow all traffic to HTTP port 9090
  ingress {
    from_port   = 9090
    to_port     = 9090
    protocol    = "TCP"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Allocate the EC2 monitoring instance
resource "aws_instance" "monitor" {
  count         = 1
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.monitor_instance_type

  subnet_id              = module.vpc.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.monitor_sg.id]
  key_name               = aws_key_pair.server_key.key_name

  associate_public_ip_address = true

  tags = {
    Owner = var.owner
    Name  = "Monitor-${count.index}"
  }
}

# Create an IAM role for the auto-join
resource "aws_iam_role" "consul-join" {
  name               = "hw-consul-join"
  assume_role_policy = file("${path.module}/templates/policies/assume-role.json")
}

# Create the policy
resource "aws_iam_policy" "consul-join" {
  name        = "hw-consul-join"
  description = "Allows Consul nodes to describe instances for joining."
  policy      = file("${path.module}/templates/policies/describe-instances.json")
}

#  the policy
resource "aws_iam_policy_attachment" "consul-join" {
  name       = "hw-consul-join"
  roles      = ["${aws_iam_role.consul-join.name}"]
  policy_arn = aws_iam_policy.consul-join.arn
}

# Create the instance profile
resource "aws_iam_instance_profile" "consul-join" {
  name  = "hw-consul-join"
  role = aws_iam_role.consul-join.name
}
