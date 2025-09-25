# Terraform Infrastructure as Code for MPEG Video API
# Assessment 2 - All AWS Services Deployment

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Configure AWS Provider
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "CAB432-Assessment2"
      Environment = var.environment
      Owner       = var.student_username
      Purpose     = "assessment-2"
    }
  }
}

# Variables
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ap-southeast-2"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "student_username" {
  description = "Student username (e.g., n11538082)"
  type        = string
}

variable "app_name" {
  description = "Application name"
  type        = string
  default     = "mpeg-video-api"
}

variable "domain_name" {
  description = "Custom domain name"
  type        = string
  default     = "cab432.com"
}

# Data sources
data "aws_caller_identity" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

# ===========================================
# S3 BUCKET FOR VIDEO STORAGE
# ===========================================
resource "aws_s3_bucket" "video_storage" {
  bucket = "${var.student_username}-${var.app_name}-videos"
  
  tags = {
    Name        = "MPEG Video Storage"
    DataType    = "Unstructured-VideoFiles"
    Assessment  = "2-ObjectStorage"
  }
}

resource "aws_s3_bucket_versioning" "video_storage_versioning" {
  bucket = aws_s3_bucket.video_storage.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "video_storage_encryption" {
  bucket = aws_s3_bucket.video_storage.id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_cors_configuration" "video_storage_cors" {
  bucket = aws_s3_bucket.video_storage.id

  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["GET", "PUT", "POST", "DELETE", "HEAD"]
    allowed_origins = ["*"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3000
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "video_storage_lifecycle" {
  bucket = aws_s3_bucket.video_storage.id

  rule {
    id     = "cleanup_old_versions"
    status = "Enabled"

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# ===========================================
# RDS POSTGRESQL DATABASE
# ===========================================
resource "aws_db_subnet_group" "main" {
  name       = "${var.app_name}-db-subnet-group"
  subnet_ids = [aws_subnet.private_1.id, aws_subnet.private_2.id]

  tags = {
    Name = "${var.app_name} DB subnet group"
  }
}

resource "aws_security_group" "rds" {
  name_prefix = "${var.app_name}-rds-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.app_name} RDS Security Group"
  }
}

resource "aws_db_instance" "postgresql" {
  identifier     = "${var.student_username}-${var.app_name}-db"
  engine         = "postgres"
  engine_version = "15.4"
  instance_class = "db.t3.micro"
  
  allocated_storage     = 20
  max_allocated_storage = 100
  storage_type          = "gp2"
  storage_encrypted     = true
  
  db_name  = "cohort_2025"
  username = "s323"
  password = "vNo7jHx2HU1q" # In production, use AWS Secrets Manager
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "mon:04:00-mon:05:00"
  
  skip_final_snapshot = true
  deletion_protection = false
  
  tags = {
    Name         = "${var.app_name} PostgreSQL Database"
    DataType     = "Structured-ACID-Financial"
    Assessment   = "2-SQLDatabase"
    purpose      = "assessment-2"
    qut-username = "${var.student_username}@qut.edu.au"
  }
}

# ===========================================
# COGNITO USER POOL
# ===========================================
resource "aws_cognito_user_pool" "main" {
  name = "${var.app_name}-user-pool"

  password_policy {
    minimum_length    = 8
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
    require_uppercase = true
  }

  auto_verified_attributes = ["email"]
  
  verification_message_template {
    default_email_option = "CONFIRM_WITH_CODE"
    email_subject        = "MPEG Video API - Verify your account"
    email_message        = "Your confirmation code is {####}"
  }

  email_configuration {
    email_sending_account = "COGNITO_DEFAULT"
  }

  schema {
    attribute_data_type = "String"
    name                = "email"
    required            = true
    mutable             = true
  }

  tags = {
    Name       = "${var.app_name} User Pool"
    Assessment = "2-Authentication"
  }
}

resource "aws_cognito_user_pool_client" "main" {
  name         = "${var.app_name}-client"
  user_pool_id = aws_cognito_user_pool.main.id

  generate_secret = false
  
  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH"
  ]

  supported_identity_providers = ["COGNITO"]

  callback_urls = [
    "http://localhost:3000/callback",
    "https://${var.student_username}-${replace(var.app_name, "_", "-")}.${var.domain_name}/callback"
  ]

  logout_urls = [
    "http://localhost:3000/logout",
    "https://${var.student_username}-${replace(var.app_name, "_", "-")}.${var.domain_name}/logout"
  ]
}

# ===========================================
# VPC AND NETWORKING
# ===========================================
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.app_name} VPC"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.app_name} Internet Gateway"
  }
}

resource "aws_subnet" "public_1" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.app_name} Public Subnet 1"
  }
}

resource "aws_subnet" "public_2" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.app_name} Public Subnet 2"
  }
}

resource "aws_subnet" "private_1" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "${var.app_name} Private Subnet 1"
  }
}

resource "aws_subnet" "private_2" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "${var.app_name} Private Subnet 2"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.app_name} Public Route Table"
  }
}

resource "aws_route_table_association" "public_1" {
  subnet_id      = aws_subnet.public_1.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_2" {
  subnet_id      = aws_subnet.public_2.id
  route_table_id = aws_route_table.public.id
}

# ===========================================
# SECURITY GROUPS
# ===========================================
resource "aws_security_group" "app" {
  name_prefix = "${var.app_name}-app-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.app_name} Application Security Group"
  }
}

# ===========================================
# PARAMETER STORE PARAMETERS
# ===========================================
resource "aws_ssm_parameter" "app_url" {
  name  = "/${var.app_name}/app-url"
  type  = "String"
  value = "https://${var.student_username}-${replace(var.app_name, "_", "-")}.${var.domain_name}"

  tags = {
    Name       = "Application URL"
    Assessment = "2-ParameterStore"
  }
}

resource "aws_ssm_parameter" "external_api_url" {
  name  = "/${var.app_name}/external-api-url"
  type  = "String"
  value = "https://www.omdbapi.com/"

  tags = {
    Name       = "External API URL"
    Assessment = "2-ParameterStore"
  }
}

resource "aws_ssm_parameter" "s3_bucket_name" {
  name  = "/${var.app_name}/s3-bucket-name"
  type  = "String"
  value = aws_s3_bucket.video_storage.bucket

  tags = {
    Name       = "S3 Bucket Name"
    Assessment = "2-ParameterStore"
  }
}

resource "aws_ssm_parameter" "database_host" {
  name  = "/${var.app_name}/database-host"
  type  = "String"
  value = aws_db_instance.postgresql.address

  tags = {
    Name       = "Database Host"
    Assessment = "2-ParameterStore"
  }
}

# ===========================================
# SECRETS MANAGER SECRETS
# ===========================================
resource "aws_secretsmanager_secret" "database_credentials" {
  name                    = "${var.app_name}-database-credentials"
  description             = "Database credentials for MPEG Video API"
  recovery_window_in_days = 0

  tags = {
    Name       = "Database Credentials"
    Assessment = "2-SecretsManager"
  }
}

resource "aws_secretsmanager_secret_version" "database_credentials" {
  secret_id = aws_secretsmanager_secret.database_credentials.id
  secret_string = jsonencode({
    username = aws_db_instance.postgresql.username
    password = aws_db_instance.postgresql.password
    host     = aws_db_instance.postgresql.address
    port     = aws_db_instance.postgresql.port
    dbname   = aws_db_instance.postgresql.db_name
  })
}

resource "aws_secretsmanager_secret" "jwt_secret" {
  name                    = "${var.app_name}-jwt-secret"
  description             = "JWT secret key for token signing"
  recovery_window_in_days = 0

  tags = {
    Name       = "JWT Secret"
    Assessment = "2-SecretsManager"
  }
}

resource "aws_secretsmanager_secret_version" "jwt_secret" {
  secret_id = aws_secretsmanager_secret.jwt_secret.id
  secret_string = jsonencode({
    jwt_secret = "your-super-secret-jwt-key-for-assessment2-${random_string.jwt_suffix.result}"
  })
}

resource "aws_secretsmanager_secret" "external_api_keys" {
  name                    = "${var.app_name}-external-api-keys"
  description             = "External API keys for movie database"
  recovery_window_in_days = 0

  tags = {
    Name       = "External API Keys"
    Assessment = "2-SecretsManager"
  }
}

resource "aws_secretsmanager_secret_version" "external_api_keys" {
  secret_id = aws_secretsmanager_secret.external_api_keys.id
  secret_string = jsonencode({
    omdb_api_key = "trilogy"
    youtube_api_key = "demo-key-for-assessment"
  })
}

resource "random_string" "jwt_suffix" {
  length  = 8
  special = false
}

# ===========================================
# ELASTICACHE REDIS (IN-MEMORY CACHE)
# ===========================================
resource "aws_elasticache_subnet_group" "main" {
  name       = "${var.app_name}-cache-subnet"
  subnet_ids = [aws_subnet.private_1.id, aws_subnet.private_2.id]

  tags = {
    Name = "${var.app_name} Cache Subnet Group"
  }
}

resource "aws_security_group" "redis" {
  name_prefix = "${var.app_name}-redis-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.app_name} Redis Security Group"
  }
}

resource "aws_elasticache_replication_group" "main" {
  replication_group_id         = "${var.student_username}-${var.app_name}-cache"
  description                  = "Redis cache for MPEG Video API"
  
  port               = 6379
  parameter_group_name = "default.redis7"
  node_type          = "cache.t3.micro"
  num_cache_clusters = 1
  
  subnet_group_name  = aws_elasticache_subnet_group.main.name
  security_group_ids = [aws_security_group.redis.id]
  
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  
  tags = {
    Name        = "${var.app_name} Redis Cache"
    Assessment  = "2-InMemoryCache"
    DataType    = "Cache-VideoMetadata"
  }
}

# ===========================================
# ROUTE53 DNS RECORD
# ===========================================
data "aws_route53_zone" "main" {
  name = var.domain_name
}

resource "aws_route53_record" "app" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "${var.student_username}-${replace(var.app_name, "_", "-")}.${var.domain_name}"
  type    = "CNAME"
  ttl     = 300
  records = [aws_instance.app.public_dns]

  depends_on = [aws_instance.app]

  tags = {
    Name       = "${var.app_name} DNS Record"
    Assessment = "2-Route53DNS"
  }
}

# ===========================================
# EC2 INSTANCE
# ===========================================
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_key_pair" "app" {
  key_name   = "${var.app_name}-key"
  public_key = tls_private_key.app.public_key_openssh

  tags = {
    Name = "${var.app_name} Key Pair"
  }
}

resource "tls_private_key" "app" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "local_file" "private_key" {
  content         = tls_private_key.app.private_key_pem
  filename        = "${var.app_name}-key.pem"
  file_permission = "0600"
}

resource "aws_iam_role" "ec2_role" {
  name = "${var.app_name}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "ec2_policy" {
  name = "${var.app_name}-ec2-policy"
  role = aws_iam_role.ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          "s3:GetObjectVersion"
        ]
        Resource = [
          aws_s3_bucket.video_storage.arn,
          "${aws_s3_bucket.video_storage.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "cognito-idp:*"
        ]
        Resource = aws_cognito_user_pool.main.arn
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/${var.app_name}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          aws_secretsmanager_secret.database_credentials.arn,
          aws_secretsmanager_secret.jwt_secret.arn,
          aws_secretsmanager_secret.external_api_keys.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "elasticache:Describe*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "${var.app_name}-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

resource "aws_instance" "app" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.medium"
  key_name               = aws_key_pair.app.key_name
  vpc_security_group_ids = [aws_security_group.app.id]
  subnet_id              = aws_subnet.public_1.id
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

  user_data = base64encode(templatefile("${path.module}/user-data.sh", {
    s3_bucket_name         = aws_s3_bucket.video_storage.bucket
    cognito_user_pool_id   = aws_cognito_user_pool.main.id
    cognito_client_id      = aws_cognito_user_pool_client.main.id
    rds_hostname           = aws_db_instance.postgresql.address
    rds_port               = aws_db_instance.postgresql.port
    rds_username           = aws_db_instance.postgresql.username
    rds_password           = aws_db_instance.postgresql.password
    rds_db_name            = aws_db_instance.postgresql.db_name
    redis_endpoint         = aws_elasticache_replication_group.main.primary_endpoint
    app_name               = var.app_name
    aws_region             = var.aws_region
  }))

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
  }

  tags = {
    Name        = "${var.app_name} Application Server"
    Assessment  = "2-EC2-Deployment"
  }
}

# ===========================================
# OUTPUTS
# ===========================================
output "s3_bucket_name" {
  description = "Name of the S3 bucket for video storage"
  value       = aws_s3_bucket.video_storage.bucket
}

output "rds_endpoint" {
  description = "RDS PostgreSQL endpoint"
  value       = aws_db_instance.postgresql.address
  sensitive   = true
}

output "cognito_user_pool_id" {
  description = "Cognito User Pool ID"
  value       = aws_cognito_user_pool.main.id
}

output "cognito_client_id" {
  description = "Cognito User Pool Client ID"
  value       = aws_cognito_user_pool_client.main.id
}

output "redis_endpoint" {
  description = "Redis cache endpoint"
  value       = aws_elasticache_replication_group.main.primary_endpoint
}

output "application_url" {
  description = "Application URL"
  value       = "https://${aws_route53_record.app.name}"
}

output "ec2_public_ip" {
  description = "EC2 instance public IP"
  value       = aws_instance.app.public_ip
}

output "ec2_ssh_command" {
  description = "SSH command to connect to EC2 instance"
  value       = "ssh -i ${local_file.private_key.filename} ec2-user@${aws_instance.app.public_ip}"
}