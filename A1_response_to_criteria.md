Assignment 1 - REST API Project - Response to Criteria
================================================

Overview
------------------------------------------------

- **Name:** Dante Pollach
- **Student number:** n11538082
- **Application name:** MPEG Video Processing API
- **Two line description:** This REST API provides video upload, transcoding, and management capabilities.
  Advanced video processing with CPU-intensive FFmpeg transcoding and multi-core load testing.

Core criteria
------------------------------------------------

### Containerise the app

- **ECR Repository name:** n11538082-mpeg-video-api
- **Video timestamp:** 0:22
- **Relevant files:**
    - Dockerfile
    - package.json

### Deploy the container

- **EC2 instance ID:** i-0876ff5fd7e6fb706
- **Video timestamp:** 1:06

### User login

- **One line description:** JWT-based authentication with bcrypt password hashing and role-based access control.
- **Video timestamp:** 1:22
- **Relevant files:**
    - index.js

### REST API

- **One line description:** Express.js REST API with video upload, transcoding, download, and admin management endpoints.
- **Video timestamp:** 1:36
- **Relevant files:**
    - index.js

### Data types

- **One line description:** SQLite3 database for structured metadata and local filesystem for unstructured video files.
- **Video timestamp:** 2:13
- **Relevant files:**
    - index.js

#### First kind

- **One line description:** Video metadata, user accounts, processing jobs, and analytics stored in relational database.
- **Type:** Structured
- **Rationale:** Requires ACID properties, relationships, and complex queries for user management and job tracking.
- **Video timestamp:** 2:13
- **Relevant files:**
    - index.js

#### Second kind

- **One line description:** Video files stored as binary data in local filesystem directories.
- **Type:** Unstructured
- **Rationale:** Large binary video files don't fit well in relational databases and require file streaming.
- **Video timestamp:** 2:13
- **Relevant files:**
  - index.js

### CPU intensive task

- **One line description:** FFmpeg video transcoding with CPU-intensive filters (noise reduction, unsharp masking, color correction).
- **Video timestamp:** 3:55
- **Relevant files:**
    - index.js

### CPU load testing

- **One line description:** Multi-core mathematical operations and array processing for sustained 5-minute CPU load testing.
- **Video timestamp:** 4:15-5:00
- **Relevant files:**
    - index.js

Additional criteria
------------------------------------------------

### Extensive REST API features

- **One line description:** Comprehensive HTTP status codes, pagination, filtering, rate limiting, and proper file streaming.
- **Video timestamp:** Throughout video
- **Relevant files:**
    - index.js

### External API(s)

- **One line description:** Mock video recommendation API integration simulating YouTube Data API.
- **Video timestamp:** Not demonstrated in video
- **Relevant files:**
    - index.js

### Additional types of data

- **One line description:** Processing job tracking, video analytics, system metrics, and extracted video metadata.
- **Video timestamp:** 2:13
- **Relevant files:**
    - index.js

### Custom processing

- **One line description:** Not attempted
- **Video timestamp:**
- **Relevant files:**
    - 

### Infrastructure as code

- **One line description:** Not attempted
- **Video timestamp:**
- **Relevant files:**
    - 

### Web client

- **One line description:** Complete responsive web interface with authentication, video management, and admin features.
- **Video timestamp:** Throughout video
- **Relevant files:**
    - index.html

### Upon request

- **One line description:** Not attempted
- **Video timestamp:**
- **Relevant files:**
    -