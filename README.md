# ProxyApiExplorer - 代理API探索器

## 🎯 程序简介

ProxyApiExplorer 是一个简单的代理监控和API分析工具，专门用于探索、分析和记录通过代理的API流量。

ProxyApiExplorer ,a simple tool using proxy to find website or sth's api.

## ✨ 主要特性

- 🔍 **API请求监控**: 实时监控所有通过代理的HTTP/HTTPS请求
- 📊 **智能模式识别**: 自动识别API模式，提取路径参数
- 📝 **多格式报告**: 生成JSON、Markdown和API文档格式的分析报告
- 🔧 **请求修改功能**: 拦截并修改请求，支持实时编辑URL、头部、请求体
- 🌐 **Web修改界面**: 提供友好的Web界面进行请求修改操作
- 🛡️ **安全脱敏**: 自动脱敏敏感信息（密码、令牌等）
- 🚀 **高性能**: 支持高并发请求处理
- 📱 **跨平台**: 支持Windows、Linux、macOS和ARM架构

## 🆕 请求修改功能

### 功能说明
ProxyApiExplorer 现在支持**实时拦截和修改请求**功能！当启用此功能时，程序会：

1. **拦截匹配的请求** - 根据配置的规则拦截特定请求
2. **暂停请求处理** - 等待用户通过Web界面进行修改
3. **提供修改界面** - 在浏览器中提供友好的修改界面
4. **发送修改后请求** - 用户确认后发送修改后的请求

### 使用场景
- 🧪 **API测试**: 修改请求参数测试不同场景
- 🐛 **调试分析**: 修改请求内容进行问题排查
- 🔒 **安全测试**: 测试API的安全性和边界条件
- 📚 **学习研究**: 了解API的工作原理和参数影响

### 快速体验
```bash
# 运行演示版本（拦截所有POST请求）
go run ProxyApiExplorer_Demo.go

# 访问修改界面
http://localhost:8889
```
## 🚀 快速开始

### 方法1：双击启动（推荐）
```
启动ProxyApiExplorer.bat
```

### 方法2：命令行启动
```cmd
chcp 65001
ProxyApiExplorer.exe
```

### 方法3：PowerShell启动
```powershell
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
.\ProxyApiExplorer.exe
```

### 方法4：Docker部署（推荐用于服务器/树莓派）

#### 🐳 Docker快速部署

**1. 创建Dockerfile**
```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY ProxyApiExplorer.go .

# 构建Go程序
RUN go mod init proxy-explorer && \
    go build -o proxy-explorer ProxyApiExplorer.go

FROM alpine:latest

# 安装必要的包
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

# 复制编译好的程序
COPY --from=builder /app/proxy-explorer .

# 创建配置目录和报告目录
RUN mkdir -p /root/api_explorer_reports

# 暴露端口
EXPOSE 8888

# 启动程序
CMD ["./proxy-explorer"]
```

**2. 构建Docker镜像**
```bash
# 构建镜像
docker build -t proxy-api-explorer .

# 或者使用多平台构建（支持ARM64，适用于树莓派）
docker buildx build --platform linux/amd64,linux/arm64 -t proxy-api-explorer .
```

**3. 运行Docker容器**
```bash
# 基本运行
docker run -d \
  --name proxy-explorer \
  -p 8888:8888 \
  -v $(pwd)/reports:/root/api_explorer_reports \
  proxy-api-explorer

# 带自定义配置运行
docker run -d \
  --name proxy-explorer \
  -p 8888:8888 \
  -v $(pwd)/config:/root/config \
  -v $(pwd)/reports:/root/api_explorer_reports \
  proxy-api-explorer

# 查看日志
docker logs -f proxy-explorer
```

#### 🍓 树莓派部署示例

**1. 在树莓派上部署**
```bash
# 克隆或上传代码到树莓派
scp ProxyApiExplorer.go pi@192.168.1.100:~/

# SSH连接到树莓派
ssh pi@192.168.1.100

# 构建并运行
docker build -t proxy-explorer .
docker run -d \
  --name proxy-explorer \
  --restart unless-stopped \
  -p 8888:8888 \
  -v /home/pi/proxy-reports:/root/api_explorer_reports \
  proxy-explorer
```

**2. 局域网设备配置代理**

在局域网内的PC/手机上设置HTTP代理：
- **代理地址**: `192.168.1.100`（树莓派IP）
- **端口**: `8888`
- **代理类型**: HTTP代理

**Windows代理设置**:
```
设置 → 网络和Internet → 代理 → 手动设置代理
地址: 192.168.1.100
端口: 8888
```

**macOS代理设置**:
```
系统偏好设置 → 网络 → 高级 → 代理 → Web代理(HTTP)
服务器: 192.168.1.100
端口: 8888
```

#### 🔧 Docker Compose部署

创建 `docker-compose.yml`:
```yaml
version: '3.8'

services:
  proxy-explorer:
    build: .
    container_name: proxy-api-explorer
    ports:
      - "8888:8888"
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

运行命令:
```bash
# 启动服务
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

#### 📱 移动设备代理配置

**Android设备**:
1. 设置 → WLAN → 长按连接的WiFi → 修改网络
2. 高级选项 → 代理 → 手动
3. 主机名: `192.168.1.100`，端口: `8888`

**iOS设备**:
1. 设置 → WiFi → 点击已连接WiFi的(i)图标
2. 配置代理 → 手动
3. 服务器: `192.168.1.100`，端口: `8888`

#### 🛡️ Docker安全配置

**1. 限制容器权限**
```bash
docker run -d \
  --name proxy-explorer \
  --user 1000:1000 \
  --read-only \
  --tmpfs /tmp \
  -p 8888:8888 \
  -v $(pwd)/reports:/root/api_explorer_reports \
  proxy-api-explorer
```

**2. 网络隔离**
```bash
# 创建自定义网络
docker network create proxy-net

# 在自定义网络中运行
docker run -d \
  --name proxy-explorer \
  --network proxy-net \
  -p 8888:8888 \
  proxy-api-explorer
```

#### 📊 监控和维护

**查看容器状态**:
```bash
# 查看运行状态
docker ps

# 查看资源使用
docker stats proxy-explorer

# 查看详细信息
docker inspect proxy-explorer
```

**备份和恢复**:
```bash
# 备份报告数据
docker cp proxy-explorer:/root/api_explorer_reports ./backup/

# 清理旧数据
docker exec proxy-explorer rm -rf /root/api_explorer_reports/*
```

## ⚙️ 配置文件

编辑 `ProxyApiExplorer_config.json` 来自定义设置：

```json
{
  "port": 8888,                    // 代理端口
  "output_dir": "api_explorer_reports", // 报告输出目录
  "max_requests": 10000,           // 最大请求数
  "target_hosts": [],              // 目标主机（空=全部）
  "capture_body": false,           // 是否捕获请求体
  "max_body_size": 1048576,        // 最大体大小
  "enable_modify": false,          // 启用请求修改功能
  "modify_port": 8889,             // 修改界面端口
  "intercept_rules": [             // 拦截规则（正则表达式）
    "POST.*api/login",             // 拦截登录请求
    "PUT.*api/users/.*"            // 拦截用户更新请求
  ]
}
```

### 🔧 请求修改配置说明

- **enable_modify**: 是否启用请求修改功能
- **modify_port**: Web修改界面的端口号
- **intercept_rules**: 拦截规则数组，支持正则表达式匹配
  - 格式：`"HTTP方法 主机名路径"`
  - 示例：`"POST api.example.com/login"` 匹配登录请求
  - 示例：`".*api/users/.*"` 匹配所有用户相关API

### 📝 拦截规则示例

```json
{
  "intercept_rules": [
    "POST.*",                      // 拦截所有POST请求
    ".*api/.*",                    // 拦截所有包含api的请求
    "PUT.*users.*",                // 拦截用户更新请求
    "DELETE.*",                    // 拦截所有删除请求
    ".*login.*|.*auth.*"           // 拦截登录和认证相关请求
  ]
}
```

## ⚙️ Web配置管理功能

### 🌐 实时配置界面
访问 `http://localhost:8889/config` 可以进行实时配置管理：

**📊 实时统计面板**：
- 待处理请求数量
- 当前代理端口状态
- 修改界面端口状态
- 已配置的过滤规则数量

**🔧 配置管理功能**：
- **基础配置**: 代理端口、修改界面端口、功能开关
- **过滤配置**: 目标主机、拦截规则、过滤关键字
- **敏感信息**: 自定义敏感参数和头部列表
- **高级配置**: 最大请求数、输出目录等

### 💡 智能过滤机制

**目标主机过滤**：
```
example.com
api.example.com
192.168.1.100
```

**拦截规则**（支持正则表达式）：
```
POST.*api/login          # 拦截登录请求
PUT.*api/users/.*        # 拦截用户更新请求
DELETE.*                 # 拦截所有删除请求
```

**过滤关键字**（URL包含关键字才处理）：
```
api
login
user
admin
```

### 🔄 配置操作

- **💾 保存配置**: 一键保存到 `ProxyApiExplorer_config.json`
- **🔄 重新加载**: 从配置文件重新加载设置
- **🔄 重置默认**: 恢复到程序默认配置
- **⚡ 立即生效**: 配置修改后无需重启程序

### 🎯 使用场景

**动态调试**：
- 请求太多时，设置目标主机只处理特定域名
- 使用关键字过滤只关注包含"api"的请求
- 实时调整拦截规则，专注特定类型的请求

**团队协作**：
- 快速分享配置文件
- 统一团队的敏感参数设置
- 根据项目需求调整过滤策略

### 🔒 敏感参数配置

程序支持自定义敏感参数和头部列表，用于在日志和报告中进行脱敏处理：

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

**敏感参数配置说明**：
- **sensitive_params**: 敏感请求参数列表，匹配时会在日志中显示为 `***`
- **sensitive_headers**: 敏感HTTP头部列表，匹配时会在日志中显示为 `***`
- 匹配方式：不区分大小写的子字符串匹配
- 如果配置为空数组，程序会使用内置的默认敏感词列表
- 支持添加自定义的敏感词，如公司特定的参数名称

**使用场景**：
- 🔐 **安全审计**: 防止敏感信息泄露到日志文件
- 📊 **合规要求**: 满足数据保护法规要求
- 🛡️ **隐私保护**: 保护用户隐私数据
- 📝 **团队协作**: 安全地分享API调试日志

## 📊 生成的报告

程序会在 `api_explorer_reports` 目录生成：

1. **JSON报告** - 完整数据，便于程序处理
2. **Markdown报告** - 人类可读的分析报告
3. **API文档** - 自动生成的接口文档

## 🔧 使用步骤

1. **启动程序**：运行 `启动ProxyApiExplorer.bat`
2. **设置代理**：将应用程序代理设为 `localhost:8888`
3. **使用应用**：正常使用你的应用程序
4. **停止监控**：按 `Ctrl+C` 停止并生成报告

## 🛡️ 安全特性

- 自动脱敏敏感信息（密码、令牌等）
- 智能内存管理，防止溢出
- 线程安全的并发处理
- 二进制内容智能过滤

## 📈 分析功能

- **API模式识别**：自动识别 `/users/{id}` 等模式
- **性能分析**：响应时间、错误率统计
- **流量分析**：主机、方法、状态码分布
- **参数分析**：查询参数使用频率

## 🎨 特色功能

### 智能模式识别
- 数字ID: `/users/123` → `/users/{id}`
- UUID: `/items/uuid-string` → `/items/{uuid}`
- 令牌: `/auth/long-token` → `/auth/{token}`
- 时间戳: `/logs/1640995200` → `/logs/{timestamp}`

### 多语言界面
- 中英文双语显示
- UTF-8编码支持
- Windows控制台兼容

### 灵活配置
- JSON配置文件
- 运行时参数调整
- 多种启动方式

## 🔍 故障排除


### 端口占用
修改配置文件中的 `port` 值

### 内存不足
减少 `max_requests` 或禁用 `capture_body`

### 无法连接
检查防火墙和网络设置

## 📝 更新历史

### v2.0 - ProxyApiExplorer
- 修复所有编译问题
- 优化中文显示
- 完善配置系统

### v1.0 - 原版
- 基础代理功能
- API模式识别
- 简单报告生成

---
