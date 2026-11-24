# ATAYLAB XATO QILINGAN TEST FAYLI. Haqiqiy muhitda ishlatmang!
# Har bir xato GT-identifikatori bilan belgilangan (ground_truth.csv).

provider "aws" {
  region     = "eu-central-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"                     # TF-01
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" # TF-01
}

resource "aws_s3_bucket" "tf02_bucket" {
  bucket = "diss-test-insecure-bucket" # TF-03..TF-06: shifrlash, versiyalash, jurnallash, public access block yo'q
}

resource "aws_s3_bucket_acl" "tf02_bucket_acl" {
  bucket = aws_s3_bucket.tf02_bucket.id
  acl    = "public-read" # TF-02
}

resource "aws_security_group" "tf07_ssh_open" {
  name        = "tf07-ssh-open"
  description = "test"
  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # TF-07
  }
}

resource "aws_security_group" "tf08_rdp_open" {
  name        = "tf08-rdp-open"
  description = "test"
  ingress {
    description = "rdp"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # TF-08
  }
}

resource "aws_db_instance" "tf09_rds" {
  identifier              = "diss-insecure-db"
  engine                  = "mysql"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "admin"
  password                = "SuperSecret123!" # TF-12
  publicly_accessible     = true              # TF-09
  storage_encrypted       = false             # TF-10
  backup_retention_period = 0                 # TF-11
  skip_final_snapshot     = true
}

resource "aws_ebs_volume" "tf13_ebs" {
  availability_zone = "eu-central-1a"
  size              = 10
  encrypted         = false # TF-13
}

resource "aws_instance" "tf14_ec2" {
  ami                         = "ami-12345678"
  instance_type               = "t3.micro"
  associate_public_ip_address = true # TF-15
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional" # TF-14 (IMDSv1)
  }
}

resource "aws_iam_policy" "tf16_admin_policy" {
  name = "diss-admin-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*" # TF-16
      Resource = "*"
    }]
  })
}

resource "aws_kms_key" "tf17_kms" {
  description         = "test key"
  enable_key_rotation = false # TF-17
}

resource "aws_cloudtrail" "tf18_trail" {
  name                       = "diss-trail"
  s3_bucket_name             = aws_s3_bucket.tf02_bucket.id
  enable_log_file_validation = false # TF-18
  is_multi_region_trail      = true
  # TF-19: kms_key_id yo'q (jurnallar KMS bilan shifrlanmagan)
}

resource "aws_lb_listener" "tf20_http" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:eu-central-1:111122223333:loadbalancer/app/diss/1234567890"
  port              = 80
  protocol          = "HTTP" # TF-20
  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:eu-central-1:111122223333:targetgroup/diss/1234567890"
  }
}
