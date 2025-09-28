# ProxyApiExplorer - Proxy API Explorer

## 🎯 Program Overview

ProxyApiExplorer is a simple proxy monitoring and API analysis tool specifically designed to explore, analyze, and record API traffic through proxies.

ProxyApiExplorer, a simple tool using proxy to find website or sth's api.

## ✨ Main Features

- 🔍 **API Request Monitoring**: Real-time monitoring of all HTTP/HTTPS requests through proxy
- 📊 **Smart Pattern Recognition**: Automatically identifies API patterns and extracts path parameters
- 📝 **Multi-format Reports**: Generates analysis reports in JSON, Markdown, and API documentation formats
- 🔧 **Request Modification**: Intercepts and modifies requests, supports real-time editing of URLs, headers, and request bodies
- 🌐 **Web Modification Interface**: Provides a user-friendly web interface for request modification operations
- 🔐 **User Authentication System**: Complete login authentication to protect secure access to management interface
- 👤 **User Management**: Supports modifying username and password, session management
- 🛡️ **Security Masking**: Automatically masks sensitive information (passwords, tokens, etc.)
- 🚀 **High Performance**: Supports high-concurrency request processing
- 📱 **Cross-platform**: Supports Windows, Linux, macOS, and ARM architectures

## 🆕 Request Modification Feature

### Feature Description
ProxyApiExplorer now supports **real-time request interception and modification**! When this feature is enabled, the program will:

1. **Intercept Matching Requests** - Intercept specific requests based on configured rules
2. **Pause Request Processing** - Wait for user modifications through the web interface
3. **Provide Modification Interface** - Offer a user-friendly modification interface in the browser
4. **Send Modified Requests** - Send the modified request after user confirmation

### Use Cases
- 🧪 **API Testing**: Modify request parameters to test different scenarios
- 🐛 **Debug Analysis**: Modify request content for troubleshooting
- 🔒 **Security Testing**: Test API security and boundary conditions
- 📚 **Learning Research**: Understand API working principles and parameter effects

### Quick Experience
```bash
# Run demo version (intercepts all POST requests)
go run ProxyApiExplorer.go

# Access modification interface (login required)
http://localhost:8889
```

## 🔐 User Authentication Feature

### Security Features
ProxyApiExplorer now has a complete user authentication system to ensure only authorized users can access the management interface:

- 🔒 **Login Authentication**: Beautiful login interface with username and password verification
- 🍪 **Session Management**: Secure cookie sessions with 24-hour automatic expiration
- 👤 **User Management**: Supports modifying username and password
- 🛡️ **Configuration Protection**: Configuration files are protected and cannot be accessed directly via HTTP
- 🚪 **Auto Logout**: Supports manual logout and automatic expiration

### Default Login Information
- **Username**: `admin`
- **Password**: `admin`
- **Management Interface**: `http://localhost:8889`

### First-time Usage Steps
1. **Start Program**: Run `go run ProxyApiExplorer.go`
2. **Access Interface**: Open `http://localhost:8889`
3. **Login System**: Use default username `admin` and password `admin`
4. **Change Password**: Visit user management page (`/user`) to change default password
5. **Start Using**: Enjoy all features, now protected by security

### Feature Pages
- 🏠 **Main Interface** (`/`): Request modification and monitoring interface
- ⚙️ **Configuration Management** (`/config`): Real-time configuration modification
- 📊 **Raw Data** (`/data`): Data management and download
- 👤 **User Management** (`/user`): Modify username and password
- 🚪 **Logout** (`/logout`): Secure system exit

### Security Mechanisms
- **Session Protection**: Uses HTTP-only cookies to prevent XSS attacks
- **Configuration Protection**: Configuration files protected by dedicated protection server to prevent direct access
- **Auto Renewal**: Active user sessions automatically extended for 24 hours
- **Forced Login**: All management functions require valid sessions

### Port Description
- **8888**: Proxy server port
- **8889**: Management interface port (requires login authentication)
- **8890**: Configuration file protection service port

### Troubleshooting
**Forgot Password**:
1. Stop the program
2. Delete the `ProxyApiExplorer_config.json` file
3. Restart the program, it will restore default `admin/admin`

**Cannot Login**:
- Ensure the program is running
- Check if port 8889 is occupied
- Clear browser cookies and retry

## 🚀 Quick Start

### Method 1: Double-click Start (Recommended)
```
Start ProxyApiExplorer.bat
```

### Method 2: Command Line Start
```cmd
chcp 65001
ProxyApiExplorer.exe
```

### Method 3: PowerShell Start
```powershell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
.\ProxyApiExplorer.exe
```

### Method 4: Docker Deployment (Recommended for Server/Raspberry Pi)

#### 🐳 Docker Quick Deployment

**1. Create Dockerfile**
```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY ProxyApiExplorer.go .

# Build Go program
RUN go mod init proxy-explorer && \
    go build -o proxy-explorer ProxyApiExplorer.go

FROM alpine:latest

# Install necessary packages
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

# Copy compiled program
COPY --from=builder /app/proxy-explorer .

# Create configuration and report directories
RUN mkdir -p /root/api_explorer_reports

# Expose ports
EXPOSE 8888
EXPOSE 8889
# Start program
CMD ["./proxy-explorer"]
```

**2. Build Docker Image**
```bash
# Build image
docker build -t proxy-api-explorer .

# Or use multi-platform build (supports ARM64, suitable for Raspberry Pi)
docker buildx build --platform linux/amd64,linux/arm64 -t proxy-api-explorer .
```

**3. Run Docker Container**
```bash
# Basic run
docker run -d \
  --name proxy-explorer \
  -p 8888:8888 \
  -v $(pwd)/reports:/root/api_explorer_reports \
  proxy-api-explorer

# Run with custom configuration
docker run -d \
  --name proxy-explorer \
  -p 8888:8888 \
  -p 8889:8889 \
  -v $(pwd)/config:/root/config \
  -v $(pwd)/reports:/root/api_explorer_reports \
  proxy-api-explorer

# View logs
docker logs -f proxy-explorer
```

#### 🍓 Raspberry Pi Deployment Example

**1. Deploy on Raspberry Pi**
```bash
# Clone or upload code to Raspberry Pi
scp ProxyApiExplorer.go pi@192.168.1.100:~/

# SSH connect to Raspberry Pi
ssh pi@192.168.1.100

# Build and run
docker build -t proxy-explorer .
docker run -d \
  --name proxy-explorer \
  --restart unless-stopped \
  -p 8888:8888 \
  -p 8889:8889 \
  -v /home/pi/proxy-reports:/root/api_explorer_reports \
  proxy-explorer
```

**2. LAN Device Proxy Configuration**

Set HTTP proxy on PC/mobile devices in LAN:
- **Proxy Address**: `192.168.1.100` (Raspberry Pi IP)
- **Port**: `8888`
- **Proxy Type**: HTTP proxy

**Windows Proxy Settings**:
```
Settings → Network & Internet → Proxy → Manual proxy setup
Address: 192.168.1.100
Port: 8888
```

**macOS Proxy Settings**:
```
System Preferences → Network → Advanced → Proxies → Web Proxy (HTTP)
Server: 192.168.1.100
Port: 8888
```

#### 🔧 Docker Compose Deployment

Create `docker-compose.yml`:
```yaml
version: '3.8'

services:
  proxy-explorer:
    build: .
    container_name: proxy-api-explorer
    ports:
      - "8888:8888"
      - "8889:8889"
    volumes:
      - ./reports:/root/api_explorer_reports
      - ./config:/root/config
    restart: unless-stopped
    environment:
      - TZ=Asia/Shanghai
    networks:
      - proxy-network

networks:
  proxy-network:
    driver: bridge
```

Run commands:
```bash
# Start service
docker-compose up -d

# View logs
docker-compose logs -f

# Stop service
docker-compose down
```

#### 📱 Mobile Device Proxy Configuration

**Android Devices**:
1. Settings → WLAN → Long press connected WiFi → Modify network
2. Advanced options → Proxy → Manual
3. Hostname: `192.168.1.100`, Port: `8888`

**iOS Devices**:
1. Settings → WiFi → Tap (i) icon of connected WiFi
2. Configure Proxy → Manual
3. Server: `192.168.1.100`, Port: `8888`

#### 🛡️ Docker Security Configuration

**1. Limit Container Privileges**
```bash
docker run -d \
  --name proxy-explorer \
  --user 1000:1000 \
  --read-only \
  --tmpfs /tmp \
  -p 8888:8888 \
  -p 8889:8889 \
  -v $(pwd)/reports:/root/api_explorer_reports \
  proxy-api-explorer
```

**2. Network Isolation**
```bash
# Create custom network
docker network create proxy-net

# Run in custom network
docker run -d \
  --name proxy-explorer \
  --network proxy-net \
  -p 8888:8888 \
  -p 8889:8889 \
  proxy-api-explorer
```

#### 📊 Monitoring and Maintenance

**View Container Status**:
```bash
# View running status
docker ps

# View resource usage
docker stats proxy-explorer

# View detailed information
docker inspect proxy-explorer
```

**Backup and Recovery**:
```bash
# Backup report data
docker cp proxy-explorer:/root/api_explorer_reports ./backup/

# Clean old data
docker exec proxy-explorer rm -rf /root/api_explorer_reports/*
```

## ⚙️ Configuration File

Edit `ProxyApiExplorer_config.json` to customize settings:

```json
{
  "port": 8888,                    // Proxy port
  "output_dir": "api_explorer_reports", // Report output directory
  "max_requests": 10000,           // Maximum requests
  "target_hosts": [],              // Target hosts (empty = all)
  "capture_body": false,           // Whether to capture request body
  "max_body_size": 1048576,        // Maximum body size
  "enable_modify": false,          // Enable request modification feature
  "modify_port": 8889,             // Modification interface port
  "username": "admin",             // Management interface username
  "password": "admin",             // Management interface password
  "intercept_rules": [             // Intercept rules (regular expressions)
    "POST.*api/login",             // Intercept login requests
    "PUT.*api/users/.*"            // Intercept user update requests
  ]
}
```

### 🔐 User Authentication Configuration

- **username**: Management interface login username (default: admin)
- **password**: Management interface login password (default: admin)
- **modify_port**: Management interface port, all management functions require access through this port and login

**Security Recommendations**:
- Change default username and password immediately after first use
- Password should be at least 4 characters, including letters and numbers
- Change password regularly to ensure security
- Do not use overly simple passwords in configuration files

### 🔧 Request Modification Configuration

- **enable_modify**: Whether to enable request modification feature
- **modify_port**: Port number for web modification interface
- **intercept_rules**: Array of intercept rules, supports regular expression matching
  - Format: `"HTTP_METHOD hostname/path"`
  - Example: `"POST api.example.com/login"` matches login requests
  - Example: `".*api/users/.*"` matches all user-related APIs

### 📝 Intercept Rules Examples

```json
{
  "intercept_rules": [
    "POST.*",                      // Intercept all POST requests
    ".*api/.*",                    // Intercept all requests containing api
    "PUT.*users.*",                // Intercept user update requests
    "DELETE.*",                    // Intercept all DELETE requests
    ".*login.*|.*auth.*"           // Intercept login and auth related requests
  ]
}
```

## ⚙️ Web Configuration Management Feature

### 🌐 Real-time Configuration Interface
Visit `http://localhost:8889/config` for real-time configuration management:

**📊 Real-time Statistics Panel**:
- Number of pending requests
- Current proxy port status
- Modification interface port status
- Number of configured filter rules

**🔧 Configuration Management Features**:
- **Basic Configuration**: Proxy port, modification interface port, feature switches
- **Filter Configuration**: Target hosts, intercept rules, filter keywords
- **Sensitive Information**: Custom sensitive parameter and header lists
- **Advanced Configuration**: Maximum requests, output directory, etc.

### 💡 Smart Filtering Mechanism

**Target Host Filtering**:
```
example.com
api.example.com
192.168.1.100
```

**Intercept Rules** (supports regular expressions):
```
POST.*api/login          # Intercept login requests
PUT.*api/users/.*        # Intercept user update requests
DELETE.*                 # Intercept all DELETE requests
```

**Filter Keywords** (only process URLs containing keywords):
```
api
login
user
admin
```

### 🔄 Configuration Operations

- **💾 Save Configuration**: One-click save to `ProxyApiExplorer_config.json`
- **🔄 Reload**: Reload settings from configuration file
- **🔄 Reset Default**: Restore to program default configuration
- **⚡ Immediate Effect**: Configuration changes take effect without restarting the program

### 🎯 Use Cases

**Dynamic Debugging**:
- When there are too many requests, set target hosts to only process specific domains
- Use keyword filtering to focus only on requests containing "api"
- Adjust intercept rules in real-time to focus on specific types of requests

**Team Collaboration**:
- Quickly share configuration files
- Unify team sensitive parameter settings
- Adjust filtering strategies according to project needs

### 🔒 Sensitive Parameter Configuration

The program supports custom sensitive parameter and header lists for masking in logs and reports:

```json
{
  "sensitive_params": [
    "password", "pwd", "passwd", "pass",
    "token", "access_token", "refresh_token", "jwt",
    "key", "api_key", "apikey", "secret_key",
    "secret", "client_secret", "app_secret",
    "auth", "authorization", "authenticate",
    "session", "sessionid", "session_id",
    "credit_card", "card_number", "cvv", "ssn",
    "phone", "email"
  ],
  "sensitive_headers": [
    "authorization", "x-api-key", "x-auth-token",
    "cookie", "x-access-token", "x-refresh-token",
    "x-session-token", "x-csrf-token", "x-xsrf-token",
    "authentication", "x-authentication", "bearer"
  ]
}
```

**Sensitive Parameter Configuration Description**:
- **sensitive_params**: List of sensitive request parameters, will be displayed as `***` in logs when matched
- **sensitive_headers**: List of sensitive HTTP headers, will be displayed as `***` in logs when matched
- Matching method: Case-insensitive substring matching
- If configured as empty array, program will use built-in default sensitive word list
- Supports adding custom sensitive words, such as company-specific parameter names

**Use Cases**:
- 🔐 **Security Audit**: Prevent sensitive information leakage to log files
- 📊 **Compliance Requirements**: Meet data protection regulation requirements
- 🛡️ **Privacy Protection**: Protect user privacy data
- 📝 **Team Collaboration**: Safely share API debugging logs

## 📊 Generated Reports

The program generates the following in the `api_explorer_reports` directory:

1. **JSON Reports** - Complete data for program processing
2. **Markdown Reports** - Human-readable analysis reports
3. **API Documentation** - Automatically generated interface documentation

## 🔧 Usage Steps

1. **Start Program**: Run `Start ProxyApiExplorer.bat`
2. **Set Proxy**: Set application proxy to `localhost:8888`
3. **Use Application**: Use your application normally
4. **Stop Monitoring**: Press `Ctrl+C` to stop and generate reports

## 🛡️ Security Features

- Automatically masks sensitive information (passwords, tokens, etc.)
- Smart memory management to prevent overflow
- Thread-safe concurrent processing
- Smart binary content filtering

## 📈 Analysis Features

- **API Pattern Recognition**: Automatically identifies patterns like `/users/{id}`
- **Performance Analysis**: Response time and error rate statistics
- **Traffic Analysis**: Host, method, and status code distribution
- **Parameter Analysis**: Query parameter usage frequency

## 🎨 Special Features

### Smart Pattern Recognition
- Numeric ID: `/users/123` → `/users/{id}`
- UUID: `/items/uuid-string` → `/items/{uuid}`
- Token: `/auth/long-token` → `/auth/{token}`
- Timestamp: `/logs/1640995200` → `/logs/{timestamp}`

### Multi-language Interface
- Chinese and English bilingual display
- UTF-8 encoding support
- Windows console compatibility

### Flexible Configuration
- JSON configuration file
- Runtime parameter adjustment
- Multiple startup methods

## 🔍 Troubleshooting

### Port Occupied
Modify the `port` value in the configuration file

### Insufficient Memory
Reduce `max_requests` or disable `capture_body`

### Cannot Connect
Check firewall and network settings

## 📝 Update History

### v3.0 - User Authentication Version (Latest)
- 🔐 **Added User Authentication System**: Complete login authentication to protect management interface
- 👤 **User Management Feature**: Supports modifying username and password
- 🍪 **Session Management**: Secure cookie sessions with 24-hour automatic expiration
- 🛡️ **Configuration File Protection**: Prevents configuration files from being directly accessed externally
- 🚪 **Login Logout**: Beautiful login interface and secure logout functionality
- 🔒 **Default Security**: Default username and password are admin/admin, recommended to change after first use
- 🌐 **Unified Navigation**: All pages have unified navigation bar with user management and logout links

### v2.0 - ProxyApiExplorer
- Fixed all compilation issues
- Optimized Chinese display
- Improved configuration system

### v1.0 - Original Version
- Basic proxy functionality
- API pattern recognition
- Simple report generation

---
