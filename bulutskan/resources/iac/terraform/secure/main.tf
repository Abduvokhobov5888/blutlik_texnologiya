# XAVFSIZ SOZLANGAN TEST FAYLI (soxta musbat natijalarni o'lchash uchun).

variable "db_password" {
  type      = string
  sensitive = true
}

provider "aws" {
  region = "eu-central-1"
}

resource "aws_kms_key" "sec17_kms" {
  description         = "secure key"
  enable_key_rotation = true
}

resource "aws_s3_bucket" "sec02_bucket" {
  bucket = "diss-test-secure-bucket"
}

resource "aws_s3_bucket_acl" "sec02_bucket_acl" {
  bucket = aws_s3_bucket.sec02_bucket.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "sec02_bucket_pab" {
  bucket                  = aws_s3_bucket.sec02_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sec02_bucket_sse" {
  bucket = aws_s3_bucket.sec02_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.sec17_kms.arn
    }
  }
}

resource "aws_s3_bucket_versioning" "sec02_bucket_versioning" {
  bucket = aws_s3_bucket.sec02_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket" "sec02_log_bucket" {
  bucket = "diss-test-secure-log-bucket"
}

resource "aws_s3_bucket_public_access_block" "sec02_log_pab" {
  bucket                  = aws_s3_bucket.sec02_log_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "sec02_log_sse" {
  bucket = aws_s3_bucket.sec02_log_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.sec17_kms.arn
    }
  }
}

resource "aws_s3_bucket_versioning" "sec02_log_versioning" {
  bucket = aws_s3_bucket.sec02_log_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "sec02_bucket_logging" {
  bucket        = aws_s3_bucket.sec02_bucket.id
  target_bucket = aws_s3_bucket.sec02_log_bucket.id
  target_prefix = "log/"
}

resource "aws_security_group" "sec07_ssh" {
  name        = "sec07-ssh-internal"
  description = "ssh from internal network only"
  ingress {
    description = "ssh"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_security_group" "sec08_rdp" {
  name        = "sec08-rdp-internal"
  description = "rdp from internal network only"
  ingress {
    description = "rdp"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}

resource "aws_db_instance" "sec09_rds" {
  identifier              = "diss-secure-db"
  engine                  = "mysql"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "admin"
  password                = var.db_password
  publicly_accessible     = false
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.sec17_kms.arn
  backup_retention_period = 7
  skip_final_snapshot     = false
}

resource "aws_ebs_volume" "sec13_ebs" {
  availability_zone = "eu-central-1a"
  size              = 10
  encrypted         = true
  kms_key_id        = aws_kms_key.sec17_kms.arn
}

resource "aws_instance" "sec14_ec2" {
  ami                         = "ami-12345678"
  instance_type               = "t3.micro"
  associate_public_ip_address = false
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
}

resource "aws_iam_policy" "sec16_policy" {
  name = "diss-readonly-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::diss-test-secure-bucket/*"
    }]
  })
}

resource "aws_cloudtrail" "sec18_trail" {
  name                       = "diss-secure-trail"
  s3_bucket_name             = aws_s3_bucket.sec02_log_bucket.id
  enable_log_file_validation = true
  is_multi_region_trail      = true
  kms_key_id                 = aws_kms_key.sec17_kms.arn
}

resource "aws_lb_listener" "sec20_https" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:eu-central-1:111122223333:loadbalancer/app/diss/1234567890"
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = "arn:aws:acm:eu-central-1:111122223333:certificate/12345678-1234-1234-1234-123456789012"
  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:eu-central-1:111122223333:targetgroup/diss/1234567890"
  }
}
