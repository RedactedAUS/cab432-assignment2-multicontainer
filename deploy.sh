#!/bin/bash

# AWS Deployment Script for MPEG Video Processing API

set -e  # Exit on any error

# Configuration
APP_NAME="mpeg-video-api"
AWS_REGION="ap-southeast-2"
ECR_REPOSITORY_URI=""
EC2_INSTANCE_ID=""
KEY_FILE="~/.ssh/cab432-key.pem"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper function for colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI not found. Please install AWS CLI."
        exit 1
    fi
    
    if ! command -v docker &> /dev/null; then
        print_error "Docker not found. Please install Docker."
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "AWS credentials not configured. Run 'aws configure'."
        exit 1
    fi
    
    print_success "Prerequisites check completed"
}

# Get or create ECR repository
setup_ecr() {
    print_status "Setting up ECR repository..."
    
    # Try to describe the repository first
    if aws ecr describe-repositories --repository-names $APP_NAME --region $AWS_REGION &> /dev/null; then
        print_status "ECR repository already exists"
    else
        print_status "Creating ECR repository..."
        aws ecr create-repository --repository-name $APP_NAME --region $AWS_REGION
        print_success "ECR repository created"
    fi
    
    # Get repository URI
    ECR_REPOSITORY_URI=$(aws ecr describe-repositories --repository-names $APP_NAME --region $AWS_REGION --query 'repositories[0].repositoryUri' --output text)
    print_success "ECR repository URI: $ECR_REPOSITORY_URI"
}

# Build and push Docker image
build_and_push() {
    print_status "Building Docker image..."
    
    # Get ECR login token
    aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $ECR_REPOSITORY_URI
    
    # Build the image
    docker build -t $APP_NAME .
    
    # Tag for ECR
    docker tag $APP_NAME:latest $ECR_REPOSITORY_URI:latest
    docker tag $APP_NAME:latest $ECR_REPOSITORY_URI:$(date +%Y%m%d-%H%M%S)
    
    # Push to ECR
    print_status "Pushing to ECR..."
    docker push $ECR_REPOSITORY_URI:latest
    docker push $ECR_REPOSITORY_URI:$(date +%Y%m%d-%H%M%S)
    
    print_success "Image pushed to ECR successfully"
}

# Create EC2 instance if not exists
create_ec2_instance() {
    print_status "Setting up EC2 instance..."
    
    if [ -z "$EC2_INSTANCE_ID" ]; then
        print_status "Creating new EC2 instance..."
        
        # Create key pair if it doesn't exist
        if ! aws ec2 describe-key-pairs --key-names cab432-key --region $AWS_REGION &> /dev/null; then
            aws ec2 create-key-pair --key-name cab432-key --region $AWS_REGION --query 'KeyMaterial' --output text > ~/.ssh/cab432-key.pem
            chmod 400 ~/.ssh/cab432-key.pem
            print_success "Key pair created"
        fi
        
        # Create security group if it doesn't exist
        if ! aws ec2 describe-security-groups --filters "Name=group-name,Values=mpeg-api-sg" --region $AWS_REGION &> /dev/null; then
            SECURITY_GROUP_ID=$(aws ec2 create-security-group --group-name mpeg-api-sg --description "MPEG API Security Group" --region $AWS_REGION --query 'GroupId' --output text)
            
            # Add rules
            aws ec2 authorize-security-group-ingress --group-id $SECURITY_GROUP_ID --protocol tcp --port 22 --cidr 0.0.0.0/0 --region $AWS_REGION
            aws ec2 authorize-security-group-ingress --group-id $SECURITY_GROUP_ID --protocol tcp --port 80 --cidr 0.0.0.0/0 --region $AWS_REGION
            aws ec2 authorize-security-group-ingress --group-id $SECURITY_GROUP_ID --protocol tcp --port 3000 --cidr 0.0.0.0/0 --region $AWS_REGION
            
            print_success "Security group created"
        else
            SECURITY_GROUP_ID=$(aws ec2 describe-security-groups --filters "Name=group-name,Values=mpeg-api-sg" --region $AWS_REGION --query 'SecurityGroups[0].GroupId' --output text)
        fi
        
        # Launch instance
        EC2_INSTANCE_ID=$(aws ec2 run-instances \
            --image-id ami-0c02fb55956c7d316 \
            --count 1 \
            --instance-type t3.medium \
            --key-name cab432-key \
            --security-group-ids $SECURITY_GROUP_ID \
            --region $AWS_REGION \
            --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=MPEG-API-Server},{Key=Project,Value=CAB432}]' \
            --user-data file://user-data.sh \
            --query 'Instances[0].InstanceId' \
            --output text)
        
        print_success "EC2 instance created: $EC2_INSTANCE_ID"
        
        # Wait for instance to be running
        print_status "Waiting for instance to be running..."
        aws ec2 wait instance-running --instance-ids $EC2_INSTANCE_ID --region $AWS_REGION
        print_success "Instance is now running"
    else
        print_status "Using existing EC2 instance: $EC2_INSTANCE_ID"
    fi
    
    # Get instance public IP
    PUBLIC_IP=$(aws ec2 describe-instances --instance-ids $EC2_INSTANCE_ID --region $AWS_REGION --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
    print_success "Instance public IP: $PUBLIC_IP"
}

# Create user data script for EC2
create_user_data() {
    cat > user-data.sh << 'EOF'
#!/bin/bash
yum update -y
yum install -y docker

# Start Docker service
systemctl start docker
systemctl enable docker

# Add ec2-user to docker group
usermod -a -G docker ec2-user

# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
./aws/install

# Create application directories
mkdir -p /opt/mpeg-api/{uploads,processed,data}
chown -R ec2-user:ec2-user /opt/mpeg-api

# Create systemd service
cat > /etc/systemd/system/mpeg-api.service << 'EOL'
[Unit]
Description=MPEG Video Processing API
After=docker.service
Requires=docker.service

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/opt/mpeg-api
ExecStartPre=-/usr/bin/docker stop mpeg-api
ExecStartPre=-/usr/bin/docker rm mpeg-api
ExecStart=/usr/bin/docker run --name mpeg-api -p 3000:3000 -v /opt/mpeg-api/uploads:/app/uploads -v /opt/mpeg-api/processed:/app/processed -v /opt/mpeg-api/data:/app/data --env NODE_ENV=production [ECR_URI]:latest
ExecStop=/usr/bin/docker stop mpeg-api
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOL

systemctl daemon-reload
EOF
}

# Deploy to EC2
deploy_to_ec2() {
    print_status "Deploying to EC2 instance..."
    
    # Get instance public IP
    PUBLIC_IP=$(aws ec2 describe-instances --instance-ids $EC2_INSTANCE_ID --region $AWS_REGION --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
    
    if [ "$PUBLIC_IP" = "None" ] || [ -z "$PUBLIC_IP" ]; then
        print_error "Could not get public IP for instance"
        exit 1
    fi
    
    print_status "Connecting to EC2 instance at $PUBLIC_IP"
    
    # Wait for SSH to be available
    while ! ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i $KEY_FILE ec2-user@$PUBLIC_IP 'echo "SSH Ready"' &> /dev/null; do
        print_status "Waiting for SSH to be ready..."
        sleep 10
    done
    
    # Deploy application
    ssh -o StrictHostKeyChecking=no -i $KEY_FILE ec2-user@$PUBLIC_IP << EOF
        # Configure AWS CLI for ECR access
        aws configure set region $AWS_REGION
        
        # Login to ECR
        aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $ECR_REPOSITORY_URI
        
        # Pull latest image
        docker pull $ECR_REPOSITORY_URI:latest
        
        # Stop existing container if running
        docker stop mpeg-api 2>/dev/null || true
        docker rm mpeg-api 2>/dev/null || true
        
        # Run new container
        docker run -d \\
            --name mpeg-api \\
            -p 3000:3000 \\
            -v /opt/mpeg-api/uploads:/app/uploads \\
            -v /opt/mpeg-api/processed:/app/processed \\
            -v /opt/mpeg-api/data:/app/data \\
            --env NODE_ENV=production \\
            --restart unless-stopped \\
            $ECR_REPOSITORY_URI:latest
        
        # Check if container is running
        sleep 5
        if docker ps | grep mpeg-api; then
            echo "Container is running successfully"
        else
            echo "Container failed to start"
            docker logs mpeg-api
            exit 1
        fi
EOF
    
    print_success "Deployment completed successfully!"
    print_success "Application is available at: http://$PUBLIC_IP:3000"
}

# Health check
health_check() {
    print_status "Performing health check..."
    
    PUBLIC_IP=$(aws ec2 describe-instances --instance-ids $EC2_INSTANCE_ID --region $AWS_REGION --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
    
    # Wait for application to start
    sleep 30
    
    # Check health endpoint
    for i in {1..10}; do
        if curl -f http://$PUBLIC_IP:3000/api/health &> /dev/null; then
            print_success "Health check passed!"
            return 0
        else
            print_status "Health check attempt $i/10 failed, retrying in 10 seconds..."
            sleep 10
        fi
    done
    
    print_error "Health check failed after 10 attempts"
    return 1
}

# Cleanup function
cleanup() {
    print_status "Cleaning up temporary files..."
    rm -f user-data.sh
}

# Main execution
main() {
    print_status "Starting MPEG Video API deployment to AWS"
    
    # Check if we're in the right directory
    if [ ! -f "package.json" ] || [ ! -f "Dockerfile" ]; then
        print_error "Please run this script from the application root directory"
        exit 1
    fi
    
    # Create user data script
    create_user_data
    
    # Run deployment steps
    check_prerequisites
    setup_ecr
    build_and_push
    create_ec2_instance
    deploy_to_ec2
    
    if health_check; then
        print_success "ðŸŽ‰ Deployment completed successfully!"
        print_success "ðŸŒ Application URL: http://$PUBLIC_IP:3000"
        print_success "ðŸ“Š Health Check: http://$PUBLIC_IP:3000/api/health"
        print_success "ðŸ”§ SSH Access: ssh -i $KEY_FILE ec2-user@$PUBLIC_IP"
    else
        print_error "Deployment completed but health check failed"
        exit 1
    fi
    
    cleanup
}

# Handle script interruption
trap cleanup EXIT

# Run main function
main "$@"
