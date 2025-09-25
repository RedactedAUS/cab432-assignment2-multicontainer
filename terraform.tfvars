# terraform.tfvars
# Final configuration for Assessment 2 deployment

# Required: Your QUT student usernames
student_username = "n11538082"
partner_username = "n11310375"

# AWS Configuration
aws_region = "ap-southeast-2"
environment = "production"

# Application Configuration
app_name = "mpeg-video-api"
domain_name = "cab432.com"

# The following will be automatically generated:
# - S3 bucket name: n11538082-mpeg-video-api-videos
# - RDS instance identifier: n11538082-mpeg-video-api-db
# - Cognito user pool name: mpeg-video-api-user-pool
# - Redis cluster name: n11538082-mpeg-video-api-cache
# - Route53 subdomain: n11538082-mpeg-video-api.cab432.com
# - EC2 instance name: mpeg-video-api Application Server