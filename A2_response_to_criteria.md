Assignment 2 - Cloud Services Exercises - Response to Criteria
================================================

Instructions
------------------------------------------------
- Keep this file named A2_response_to_criteria.md, do not change the name
- Upload this file along with your code in the root directory of your project
- Upload this file in the current Markdown format (.md extension)
- Do not delete or rearrange sections.  If you did not attempt a criterion, leave it blank
- Text inside [ ] like [eg. S3 ] are examples and should be removed


Overview
------------------------------------------------

- **Name:** Dante Pollach  
- **Student number:** n11538082
- **Partner name (if applicable):** Allen Saji
- **Application name:** MPEG Video Processing Platform
- **Two line description:** A cloud-native video processing platform that enables users to upload, transcode, and manage video files. Implements comprehensive AWS services including S3, RDS, DynamoDB, ElastiCache, Cognito, and more for a fully stateless, scalable architecture.
- **EC2 instance name or ID:** i-0a242b49ab788f159 [a2-multicontainer-Dante and Allen V2]

------------------------------------------------

### Core - First data persistence service

- **AWS service name:**  S3
- **What data is being stored?:** Video files (raw uploads and transcoded outputs)
- **Why is this service suited to this data?:** S3 is optimized for large binary objects and supports direct client uploads via pre-signed URLs
- **Why is are the other services used not suitable for this data?:** RDS has size limitations for BLOBs, DynamoDB has 400KB item limit making it unsuitable for video files
- **Bucket/instance/table name:** cab432-n11538082-videos
- **Video timestamp:** 00:32 
- **Relevant files:** index.js (upload endpoint lines 1500-1700)
    -

### Core - Second data persistence service

- **AWS service name:** PostgreSQL RDS
- **What data is being stored?:** User accounts, video metadata, processing jobs, and relational data
- **Why is this service suited to this data?:** Relational data with complex relationships between users, videos, and jobs
- **Why is are the other services used not suitable for this data?:** S3 cannot handle relational queries, DynamoDB lacks complex join capabilities needed for user-video-job relationships
- **Bucket/instance/table name:** database-1-instance-1.ce2haupt2cta.ap-southeast-2.rds.amazonaws.com
- **Video timestamp:** 01:06
- **Relevant files:** index.js (lines 200-300 - database initialization)
                      index.js (createDatabaseTables function)
    -

### Third data service

- **AWS service name:**  DynamoDB
- **What data is being stored?:** User sessions with TTL-based expiration
- **Why is this service suited to this data?:** NoSQL structure perfect for session data, automatic TTL cleanup, serverless scaling
- **Why is are the other services used not suitable for this data?:** RDS overhead unnecessary for simple key-value sessions, S3 not suitable for frequently accessed small data
- **Bucket/instance/table name:** n11538082-video-sessions
- **Video timestamp:** 1:38
- **Relevant files:** index.js (DynamoDBSessionManager object)
    -

### S3 Pre-signed URLs

- **S3 Bucket names:** cab432-n11538082-videos
- **Video timestamp:** 1:58
- **Relevant files:** index.js (lines 1100-1200 - pre-signed URL generation in videos endpoint)
    -

### In-memory cache

- **ElastiCache instance name:** a2-allen-dante
- **What data is being cached?:** Video lists, analytics data, user session data
- **Why is this data likely to be accessed frequently?:** Video lists and analytics are accessed on every page load, caching reduces database load
- **Video timestamp:** 2:22
- **Relevant files:**
    index.js (CacheManager object)
    index.js (initializeMemcached function)
    index.js (videos endpoint with cache check)
    -

### Core - Statelessness

- **What data is stored within your application that is not stored in cloud data services?:** Only temporary FFmpeg processing files in /tmp during transcoding
- **Why is this data not considered persistent state?:** Files are deleted immediately after processing, can be recreated from source S3 files
- **How does your application ensure data consistency if the app suddenly stops?:** All state in cloud services, processing jobs tracked in RDS with status updates, S3 files persist independently
- **Relevant files:**
    index.js (transcode endpoint - temp file handling)
    Dockerfile (no persistent volumes)
    -

### Graceful handling of persistent connections

- **Type of persistent connection and use:** 
- **Method for handling lost connections:** 
- **Relevant files:**
    -


### Core - Authentication with Cognito

- **User pool name:**User pool - 5xfdp0
- **How are authentication tokens handled by the client?:** JWT tokens stored in localStorage, sent as Bearer tokens in Authorization headers
- **Video timestamp:** 4:09 
- **Relevant files:**
    cognito-auth.js
    cognito-routes.js
    public/index.html (Cognito login handlers)
    -

### Cognito multi-factor authentication

- **What factors are used for authentication:** tired to implement
- **Video timestamp:**
- **Relevant files:**
    cognito-auth.js (setupMFA, verifyMFASetup functions)
    cognito-routes.js (MFA routes)
    -

### Cognito federated identities

- **Identity providers used:**
- **Video timestamp:**
- **Relevant files:**
    -

### Cognito groups

- **How are groups used to set permissions?:** [eg. 'admin' users can delete and ban other users]
- **Video timestamp:**
- **Relevant files:**
    -

### Core - DNS with Route53

- **Subdomain**: n11538082-mpeg-video.cab432.com
- **Video timestamp:** 5:06

### Parameter store

- **Parameter names:** 
- **Video timestamp:**
- **Relevant files:**
    -

### Secrets manager

- **Secrets names:** 
- **Video timestamp:**
- **Relevant files:**
    -

### Infrastructure as code

- **Technology used:** AWS CDK (TypeScript)
- **Services deployed:** VPC, RDS PostgreSQL, S3 Bucket, ElastiCache Memcached, DynamoDB, Secrets Manager, Parameter Store, IAM roles, Security Groups
- **Video timestamp:** was mentioned in criteria to not address it in the video
- **Relevant files:**
    infrastructure/lib/mpeg-video-api-stack.ts
    infrastructure/app.ts
    -

### Other (with prior approval only)

- **Description:**
- **Video timestamp:**
- **Relevant files:**
    -

### Other (with prior permission only)

- **Description:**
- **Video timestamp:**
- **Relevant files:**
    -
