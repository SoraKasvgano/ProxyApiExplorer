package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Config 配置结构（增强版）
type Config struct {
	Port             int      `json:"port"`
	EnableModify     bool     `json:"enable_modify"`
	ModifyPort       int      `json:"modify_port"`
	CaptureBody      bool     `json:"capture_body"`
	TargetHosts      []string `json:"target_hosts"`
	SensitiveParams  []string `json:"sensitive_params"`  // 敏感参数列表
	SensitiveHeaders []string `json:"sensitive_headers"` // 敏感头部列表
	InterceptRules   []string `json:"intercept_rules"`   // 拦截规则
	FilterKeywords   []string `json:"filter_keywords"`   // 过滤关键字
	MaxRequests      int      `json:"max_requests"`      // 最大请求数
	OutputDir        string   `json:"output_dir"`        // 输出目录
	Username         string   `json:"username"`          // 用户名
	Password         string   `json:"password"`          // 密码
}

// ModifyRequest 待修改的请求
type ModifyRequest struct {
	ID        string            `json:"id"`
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers"`
	Body      string            `json:"body"`
	Timestamp time.Time         `json:"timestamp"`
	Status    string            `json:"status"` // pending, modified, sent, cancelled
}

// ModifyResponse 修改请求的响应
type ModifyResponse struct {
	Action string                 `json:"action"` // send_original, send_modified, cancel
	Data   map[string]interface{} `json:"data,omitempty"`
}

// APIData 存储API请求和响应数据
type APIData struct {
	Timestamp       string            `json:"timestamp"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	Host            string            `json:"host"`
	Path            string            `json:"path"`
	Query           string            `json:"query"`
	RequestHeaders  map[string]string `json:"request_headers"`
	RequestBody     string            `json:"request_body,omitempty"`
	ResponseStatus  int               `json:"response_status"`
	ResponseHeaders map[string]string `json:"response_headers"`
	ResponseBody    string            `json:"response_body,omitempty"`
}

// Session 会话信息
type Session struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ProxyMonitor 代理监控器（简化版）
type ProxyMonitor struct {
	config         *Config
	mutex          sync.RWMutex
	requestCount   int64
	pendingReqs    map[string]*ModifyRequest      // 待修改的请求
	modifyChannels map[string]chan ModifyResponse // 修改响应通道
	modifyMutex    sync.RWMutex
	sessions       map[string]*Session // 会话管理
	sessionMutex   sync.RWMutex
}

// NewProxyMonitor 创建新的代理监控器
func NewProxyMonitor(config *Config) *ProxyMonitor {
	return &ProxyMonitor{
		config:         config,
		pendingReqs:    make(map[string]*ModifyRequest),
		modifyChannels: make(map[string]chan ModifyResponse),
		sessions:       make(map[string]*Session),
	}
}

// Start 启动代理服务器
func (pm *ProxyMonitor) Start() error {
	// 启动修改界面服务器
	go pm.startModifyServer()

	// 启动代理服务器
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", pm.config.Port),
		Handler: http.HandlerFunc(pm.handleRequest),
	}

	// 优雅关闭
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		fmt.Println("\n正在关闭服务器...")
		server.Close()
	}()

	fmt.Printf("代理服务器启动: http://localhost:%d\n", pm.config.Port)
	fmt.Printf("修改界面: http://localhost:%d\n", pm.config.ModifyPort)
	fmt.Printf("配置管理: http://localhost:%d/config\n", pm.config.ModifyPort)
	fmt.Printf("原始数据: http://localhost:%d/data\n", pm.config.ModifyPort)

	return server.ListenAndServe()
}

// handleRequest 处理代理请求（简化版）
func (pm *ProxyMonitor) handleRequest(w http.ResponseWriter, r *http.Request) {
	// 读取请求体
	var requestBody string
	if pm.config.CaptureBody && r.Body != nil {
		bodyBytes, _ := io.ReadAll(r.Body)
		requestBody = string(bodyBytes)
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// 检查是否需要拦截
	if pm.shouldIntercept(r.Method, r.URL.String()) {
		modifyReq := pm.createModifyRequest(r, requestBody)

		modifyResp, err := pm.waitForModification(modifyReq)
		if err != nil {
			fmt.Printf("警告: %v，使用原始请求\n", err)
		} else if modifyResp.Action == "cancel" {
			http.Error(w, "请求已取消", http.StatusBadRequest)
			return
		} else if modifyResp.Action == "send_modified" {
			// 使用修改后的请求
			if reqData, ok := modifyResp.Data["request"].(map[string]interface{}); ok {
				newMethod := reqData["method"].(string)
				newURL := reqData["url"].(string)
				newBody := ""
				if body, exists := reqData["body"]; exists && body != nil {
					newBody = body.(string)
				}

				var bodyReader io.Reader
				if newBody != "" {
					bodyReader = strings.NewReader(newBody)
				}

				newReq, err := http.NewRequest(newMethod, newURL, bodyReader)
				if err == nil {
					// 复制头部
					if headers, exists := reqData["headers"]; exists {
						if headerMap, ok := headers.(map[string]interface{}); ok {
							for key, value := range headerMap {
								if strValue, ok := value.(string); ok {
									newReq.Header.Set(key, strValue)
								}
							}
						}
					}
					r = newReq
				}
			}
		}
	}

	// 构建目标URL
	targetURL := "https://" + r.Host + r.URL.Path
	if r.URL.RawQuery != "" {
		targetURL += "?" + r.URL.RawQuery
	}

	// 创建新请求
	proxyReq, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		http.Error(w, "创建请求失败", http.StatusInternalServerError)
		return
	}

	// 复制头部
	for name, values := range r.Header {
		for _, value := range values {
			proxyReq.Header.Add(name, value)
		}
	}

	// 发送请求
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "请求失败: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// 读取响应体用于保存
	var responseBody string
	if pm.config.CaptureBody {
		bodyBytes, _ := io.ReadAll(resp.Body)
		responseBody = string(bodyBytes)
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// 保存API数据到文件
	pm.saveAPIData(r, resp, requestBody, responseBody)

	// 复制响应头
	for name, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	fmt.Printf("代理请求: %s %s -> %d\n", r.Method, r.URL.String(), resp.StatusCode)
}

// saveAPIData 保存API数据到文件
func (pm *ProxyMonitor) saveAPIData(req *http.Request, resp *http.Response, requestBody, responseBody string) {
	// 创建输出目录
	if err := os.MkdirAll(pm.config.OutputDir, 0755); err != nil {
		fmt.Printf("创建输出目录失败: %v\n", err)
		return
	}

	// 构建API数据
	apiData := APIData{
		Timestamp:       time.Now().Format("2006-01-02 15:04:05"),
		Method:          req.Method,
		URL:             req.URL.String(),
		Host:            req.Host,
		Path:            req.URL.Path,
		Query:           req.URL.RawQuery,
		RequestHeaders:  make(map[string]string),
		RequestBody:     requestBody,
		ResponseStatus:  resp.StatusCode,
		ResponseHeaders: make(map[string]string),
		ResponseBody:    responseBody,
	}

	// 复制请求头
	for name, values := range req.Header {
		if len(values) > 0 {
			apiData.RequestHeaders[name] = values[0]
		}
	}

	// 复制响应头
	for name, values := range resp.Header {
		if len(values) > 0 {
			apiData.ResponseHeaders[name] = values[0]
		}
	}

	// 生成文件名
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_%s_%s.json", timestamp, req.Method, sanitizeFilename(req.Host))
	filepath := fmt.Sprintf("%s/%s", pm.config.OutputDir, filename)

	// 保存到文件
	jsonData, err := json.MarshalIndent(apiData, "", "  ")
	if err != nil {
		fmt.Printf("序列化API数据失败: %v\n", err)
		return
	}

	if err := os.WriteFile(filepath, jsonData, 0644); err != nil {
		fmt.Printf("保存API数据失败: %v\n", err)
		return
	}

	fmt.Printf("API数据已保存: %s\n", filepath)
}

// sanitizeFilename 清理文件名中的非法字符
func sanitizeFilename(filename string) string {
	// 替换非法字符
	filename = strings.ReplaceAll(filename, ":", "_")
	filename = strings.ReplaceAll(filename, "/", "_")
	filename = strings.ReplaceAll(filename, "\\", "_")
	filename = strings.ReplaceAll(filename, "?", "_")
	filename = strings.ReplaceAll(filename, "*", "_")
	filename = strings.ReplaceAll(filename, "<", "_")
	filename = strings.ReplaceAll(filename, ">", "_")
	filename = strings.ReplaceAll(filename, "|", "_")
	filename = strings.ReplaceAll(filename, "\"", "_")
	return filename
}

// generateSessionID 生成会话ID
func (pm *ProxyMonitor) generateSessionID() string {
	return fmt.Sprintf("session_%d_%d", time.Now().UnixNano(), time.Now().Unix())
}

// createSession 创建新会话
func (pm *ProxyMonitor) createSession(username string) *Session {
	pm.sessionMutex.Lock()
	defer pm.sessionMutex.Unlock()

	session := &Session{
		ID:        pm.generateSessionID(),
		Username:  username,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24小时过期
	}

	pm.sessions[session.ID] = session
	return session
}

// validateSession 验证会话
func (pm *ProxyMonitor) validateSession(sessionID string) *Session {
	pm.sessionMutex.RLock()
	defer pm.sessionMutex.RUnlock()

	session, exists := pm.sessions[sessionID]
	if !exists {
		return nil
	}

	if time.Now().After(session.ExpiresAt) {
		delete(pm.sessions, sessionID)
		return nil
	}

	return session
}

// deleteSession 删除会话
func (pm *ProxyMonitor) deleteSession(sessionID string) {
	pm.sessionMutex.Lock()
	defer pm.sessionMutex.Unlock()
	delete(pm.sessions, sessionID)
}

// requireAuth 认证中间件
func (pm *ProxyMonitor) requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 检查会话cookie
		cookie, err := r.Cookie("session_id")
		if err != nil {
			pm.redirectToLogin(w, r)
			return
		}

		session := pm.validateSession(cookie.Value)
		if session == nil {
			pm.redirectToLogin(w, r)
			return
		}

		// 续期会话
		session.ExpiresAt = time.Now().Add(24 * time.Hour)
		handler(w, r)
	}
}

// redirectToLogin 重定向到登录页面
func (pm *ProxyMonitor) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleLogin 处理登录页面
func (pm *ProxyMonitor) handleLogin(w http.ResponseWriter, r *http.Request) {
	// 检查是否已经登录
	if cookie, err := r.Cookie("session_id"); err == nil {
		if session := pm.validateSession(cookie.Value); session != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}

	html := `<!DOCTYPE html>
<html>
<head>
    <title>登录 - ProxyApiExplorer</title>
    <meta charset="UTF-8">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0; 
            padding: 0; 
            height: 100vh; 
            display: flex; 
            justify-content: center; 
            align-items: center; 
        }
        .login-container { 
            background: white; 
            padding: 40px; 
            border-radius: 10px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.3); 
            width: 100%; 
            max-width: 400px; 
        }
        .login-header { 
            text-align: center; 
            margin-bottom: 30px; 
        }
        .login-header h1 { 
            color: #333; 
            margin-bottom: 10px; 
        }
        .login-header p { 
            color: #666; 
            margin: 0; 
        }
        .form-group { 
            margin-bottom: 20px; 
        }
        .form-group label { 
            display: block; 
            margin-bottom: 5px; 
            font-weight: bold; 
            color: #333; 
        }
        .form-group input { 
            width: 100%; 
            padding: 12px; 
            border: 1px solid #ddd; 
            border-radius: 5px; 
            box-sizing: border-box; 
            font-size: 16px; 
        }
        .form-group input:focus { 
            outline: none; 
            border-color: #007bff; 
            box-shadow: 0 0 5px rgba(0,123,255,0.3); 
        }
        .btn { 
            width: 100%; 
            padding: 12px; 
            background: #007bff; 
            color: white; 
            border: none; 
            border-radius: 5px; 
            font-size: 16px; 
            cursor: pointer; 
            transition: background 0.3s; 
        }
        .btn:hover { 
            background: #0056b3; 
        }
        .alert { 
            padding: 15px; 
            margin-bottom: 20px; 
            border-radius: 5px; 
            display: none; 
        }
        .alert-danger { 
            background: #f8d7da; 
            color: #721c24; 
            border: 1px solid #f5c6cb; 
        }
        .alert-success { 
            background: #d4edda; 
            color: #155724; 
            border: 1px solid #c3e6cb; 
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>ProxyApiExplorer</h1>
            <p>请登录以访问管理界面</p>
        </div>
        
        <div id="alert" class="alert alert-danger"></div>
        
        <form id="loginForm">
            <div class="form-group">
                <label for="username">用户名:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">密码:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn">登录</button>
        </form>
    </div>

    <script>
        function showAlert(message, type) {
            const alert = document.getElementById('alert');
            alert.className = 'alert alert-' + type;
            alert.textContent = message;
            alert.style.display = 'block';
            setTimeout(() => {
                alert.style.display = 'none';
            }, 5000);
        }

        document.getElementById('loginForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            })
            .then(response => {
                if (response.ok) {
                    showAlert('登录成功，正在跳转...', 'success');
                    setTimeout(() => {
                        window.location.href = '/';
                    }, 1000);
                } else {
                    return response.text().then(text => {
                        throw new Error(text);
                    });
                }
            })
            .catch(error => {
                showAlert('登录失败: ' + error.message, 'danger');
            });
        });
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleLoginAPI 处理登录API
func (pm *ProxyMonitor) handleLoginAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "方法不允许", http.StatusMethodNotAllowed)
		return
	}

	var loginReq struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&loginReq); err != nil {
		http.Error(w, "请求格式错误", http.StatusBadRequest)
		return
	}

	// 验证用户名和密码
	if loginReq.Username != pm.config.Username || loginReq.Password != pm.config.Password {
		http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
		return
	}

	// 创建会话
	session := pm.createSession(loginReq.Username)

	// 设置会话cookie
	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    session.ID,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // 在生产环境中应该设置为true
		SameSite: http.SameSiteStrictMode,
		Expires:  session.ExpiresAt,
	}
	http.SetCookie(w, cookie)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("登录成功"))
}

// handleLogout 处理注销
func (pm *ProxyMonitor) handleLogout(w http.ResponseWriter, r *http.Request) {
	// 获取会话cookie
	if cookie, err := r.Cookie("session_id"); err == nil {
		pm.deleteSession(cookie.Value)
	}

	// 清除cookie
	cookie := &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	}
	http.SetCookie(w, cookie)

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// handleUserManagement 处理用户管理页面
func (pm *ProxyMonitor) handleUserManagement(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>用户管理 - ProxyApiExplorer</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .nav { margin-bottom: 20px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #007bff; }
        .nav a:hover { text-decoration: underline; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .btn { padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; margin-right: 10px; }
        .btn-primary { background: #007bff; color: white; }
        .btn-danger { background: #dc3545; color: white; }
        .btn:hover { opacity: 0.8; }
        .current-user { background: #e9ecef; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .alert { padding: 15px; margin: 20px 0; border-radius: 5px; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-danger { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/">修改界面</a>
            <a href="/config">配置管理</a>
            <a href="/data">原始数据</a>
            <a href="/user">用户管理</a>
            <a href="/logout">注销</a>
        </div>
        
        <div class="header">
            <h1>用户管理</h1>
            <p>修改登录用户名和密码</p>
        </div>

        <div class="current-user">
            <h3>当前用户信息</h3>
            <p><strong>用户名:</strong> <span id="current-username">admin</span></p>
            <p><strong>会话状态:</strong> <span style="color: green;">已登录</span></p>
        </div>

        <form id="userForm">
            <div class="form-group">
                <label for="new_username">新用户名:</label>
                <input type="text" id="new_username" name="new_username" required>
            </div>
            <div class="form-group">
                <label for="new_password">新密码:</label>
                <input type="password" id="new_password" name="new_password" required>
            </div>
            <div class="form-group">
                <label for="confirm_password">确认密码:</label>
                <input type="password" id="confirm_password" name="confirm_password" required>
            </div>
            <div style="text-align: center; margin-top: 30px;">
                <button type="submit" class="btn btn-primary">更新用户信息</button>
                <button type="button" class="btn btn-danger" onclick="confirmLogout()">注销登录</button>
            </div>
        </form>
    </div>

    <script>
        function showAlert(message, type) {
            const alertDiv = document.createElement('div');
            alertDiv.className = 'alert alert-' + type;
            alertDiv.textContent = message;
            document.querySelector('.container').insertBefore(alertDiv, document.querySelector('.current-user'));
            setTimeout(() => alertDiv.remove(), 5000);
        }

        function loadCurrentUser() {
            fetch('/api/user')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('current-username').textContent = data.username;
                    document.getElementById('new_username').value = data.username;
                })
                .catch(error => {
                    showAlert('加载用户信息失败: ' + error.message, 'danger');
                });
        }

        function confirmLogout() {
            if (confirm('确定要注销登录吗？')) {
                window.location.href = '/logout';
            }
        }

        document.getElementById('userForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const newUsername = document.getElementById('new_username').value;
            const newPassword = document.getElementById('new_password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            
            if (newPassword !== confirmPassword) {
                showAlert('两次输入的密码不一致', 'danger');
                return;
            }
            
            if (newPassword.length < 4) {
                showAlert('密码长度至少4位', 'danger');
                return;
            }

            fetch('/api/user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    username: newUsername, 
                    password: newPassword 
                })
            })
            .then(response => {
                if (response.ok) {
                    showAlert('用户信息更新成功，请重新登录', 'success');
                    setTimeout(() => {
                        window.location.href = '/logout';
                    }, 2000);
                } else {
                    return response.text().then(text => {
                        throw new Error(text);
                    });
                }
            })
            .catch(error => {
                showAlert('更新失败: ' + error.message, 'danger');
            });
        });

        // 页面加载时获取当前用户信息
        window.onload = loadCurrentUser;
    </script>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleUserAPI 处理用户API
func (pm *ProxyMonitor) handleUserAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		// 返回当前用户信息
		response := map[string]string{
			"username": pm.config.Username,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else if r.Method == "POST" {
		// 更新用户信息
		var userReq struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := json.NewDecoder(r.Body).Decode(&userReq); err != nil {
			http.Error(w, "请求格式错误", http.StatusBadRequest)
			return
		}

		if userReq.Username == "" || userReq.Password == "" {
			http.Error(w, "用户名和密码不能为空", http.StatusBadRequest)
			return
		}

		if len(userReq.Password) < 4 {
			http.Error(w, "密码长度至少4位", http.StatusBadRequest)
			return
		}

		// 更新配置
		pm.config.Username = userReq.Username
		pm.config.Password = userReq.Password

		// 保存配置到文件
		if err := pm.saveConfig(); err != nil {
			http.Error(w, "保存配置失败", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("用户信息更新成功"))
	}
}

// startModifyServer 启动修改界面服务器
func (pm *ProxyMonitor) startModifyServer() {
	if !pm.config.EnableModify {
		return
	}

	mux := http.NewServeMux()

	// 公开路由（不需要认证）
	mux.HandleFunc("/login", pm.handleLogin)
	mux.HandleFunc("/api/login", pm.handleLoginAPI)
	mux.HandleFunc("/logout", pm.handleLogout)

	// 受保护的路由（需要认证）
	mux.HandleFunc("/", pm.requireAuth(pm.handleModifyUI))
	mux.HandleFunc("/api/pending", pm.requireAuth(pm.handleGetPending))
	mux.HandleFunc("/api/modify", pm.requireAuth(pm.handleModifyRequest))
	mux.HandleFunc("/api/config", pm.requireAuth(pm.handleConfigAPI))
	mux.HandleFunc("/config", pm.requireAuth(pm.handleConfigUI))
	mux.HandleFunc("/data", pm.requireAuth(pm.handleDataManagement))
	mux.HandleFunc("/user", pm.requireAuth(pm.handleUserManagement))
	mux.HandleFunc("/api/user", pm.requireAuth(pm.handleUserAPI))

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", pm.config.ModifyPort),
		Handler: mux,
	}

	go func() {
		fmt.Printf("修改界面: http://localhost:%d\n", pm.config.ModifyPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("修改界面服务器错误: %v", err)
		}
	}()
}

// handleDataManagement 处理原始数据管理页面
func (pm *ProxyMonitor) handleDataManagement(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		action := r.FormValue("action")
		switch action {
		case "download":
			pm.handleDownloadData(w, r)
			return
		case "clear":
			pm.handleClearData(w, r)
			return
		}
	}

	// 获取文件统计信息
	files, err := os.ReadDir(pm.config.OutputDir)
	if err != nil {
		files = []os.DirEntry{}
	}

	var totalSize int64
	var fileCount int
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			fileCount++
			if info, err := file.Info(); err == nil {
				totalSize += info.Size()
			}
		}
	}

	html := `<!DOCTYPE html>
<html>
<head>
    <title>原始数据管理 - ProxyApiExplorer</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #007bff; }
        .stat-label { color: #666; margin-top: 5px; }
        .actions { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .action-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }
        .btn { padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; text-decoration: none; display: inline-block; }
        .btn-primary { background: #007bff; color: white; }
        .btn-danger { background: #dc3545; color: white; }
        .btn:hover { opacity: 0.8; }
        .nav { margin-bottom: 20px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #007bff; }
        .nav a:hover { text-decoration: underline; }
        .alert { padding: 15px; margin: 20px 0; border-radius: 5px; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-danger { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/">修改界面</a>
            <a href="/config">配置管理</a>
            <a href="/data">原始数据</a>
            <a href="/user">用户管理</a>
            <a href="/logout">注销</a>
        </div>
        
        <div class="header">
            <h1>原始数据管理</h1>
            <p>管理代理抓取的API原始数据</p>
        </div>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">` + fmt.Sprintf("%d", fileCount) + `</div>
                <div class="stat-label">API文件数量</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">` + formatFileSize(totalSize) + `</div>
                <div class="stat-label">总文件大小</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">` + pm.config.OutputDir + `</div>
                <div class="stat-label">输出目录</div>
            </div>
        </div>

        <div class="actions">
            <div class="action-card">
                <h3>打包下载</h3>
                <p>将所有API数据文件打包为ZIP文件下载</p>
                <form method="post" style="display: inline;">
                    <input type="hidden" name="action" value="download">
                    <button type="submit" class="btn btn-primary">下载数据包</button>
                </form>
            </div>
            <div class="action-card">
                <h3>清空数据</h3>
                <p>删除所有已保存的API数据文件</p>
                <form method="post" style="display: inline;" onsubmit="return confirm('确定要删除所有数据吗？此操作不可恢复！')">
                    <input type="hidden" name="action" value="clear">
                    <button type="submit" class="btn btn-danger">清空数据</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

// handleDownloadData 处理数据打包下载
func (pm *ProxyMonitor) handleDownloadData(w http.ResponseWriter, r *http.Request) {
	// 创建临时ZIP文件
	zipFilename := fmt.Sprintf("api_data_%s.zip", time.Now().Format("20060102_150405"))
	zipPath := fmt.Sprintf("%s/%s", pm.config.OutputDir, zipFilename)

	zipFile, err := os.Create(zipPath)
	if err != nil {
		http.Error(w, "创建ZIP文件失败", http.StatusInternalServerError)
		return
	}
	defer zipFile.Close()
	defer os.Remove(zipPath) // 下载后删除临时文件

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// 添加所有JSON文件到ZIP
	files, err := os.ReadDir(pm.config.OutputDir)
	if err != nil {
		http.Error(w, "读取目录失败", http.StatusInternalServerError)
		return
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			filePath := fmt.Sprintf("%s/%s", pm.config.OutputDir, file.Name())
			if err := addFileToZip(zipWriter, filePath, file.Name()); err != nil {
				fmt.Printf("添加文件到ZIP失败: %v\n", err)
			}
		}
	}

	zipWriter.Close()
	zipFile.Close()

	// 发送ZIP文件
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", zipFilename))

	zipData, err := os.ReadFile(zipPath)
	if err != nil {
		http.Error(w, "读取ZIP文件失败", http.StatusInternalServerError)
		return
	}

	w.Write(zipData)
}

// handleClearData 处理清空数据
func (pm *ProxyMonitor) handleClearData(w http.ResponseWriter, r *http.Request) {
	files, err := os.ReadDir(pm.config.OutputDir)
	if err != nil {
		http.Error(w, "读取目录失败", http.StatusInternalServerError)
		return
	}

	deletedCount := 0
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			filePath := fmt.Sprintf("%s/%s", pm.config.OutputDir, file.Name())
			if err := os.Remove(filePath); err == nil {
				deletedCount++
			}
		}
	}

	// 重定向回数据管理页面
	http.Redirect(w, r, "/data?cleared="+fmt.Sprintf("%d", deletedCount), http.StatusSeeOther)
}

// addFileToZip 添加文件到ZIP
func addFileToZip(zipWriter *zip.Writer, filePath, fileName string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer, err := zipWriter.Create(fileName)
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, file)
	return err
}

// formatFileSize 格式化文件大小
func formatFileSize(size int64) string {
	if size < 1024 {
		return fmt.Sprintf("%d B", size)
	} else if size < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	} else if size < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
	} else {
		return fmt.Sprintf("%.1f GB", float64(size)/(1024*1024*1024))
	}
}

// shouldIntercept 判断是否应该拦截此请求
func (pm *ProxyMonitor) shouldIntercept(method, url string) bool {
	// 简单示例：拦截所有POST请求
	return pm.config.EnableModify && method == "POST"
}

// 其他必要的方法（从原文件复制）
func (pm *ProxyMonitor) createModifyRequest(r *http.Request, body string) *ModifyRequest {
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	headers := make(map[string]string)
	for name, values := range r.Header {
		if len(values) > 0 {
			headers[name] = values[0]
		}
	}

	return &ModifyRequest{
		ID:        id,
		Method:    r.Method,
		URL:       r.URL.String(),
		Headers:   headers,
		Body:      body,
		Timestamp: time.Now(),
		Status:    "pending",
	}
}

func (pm *ProxyMonitor) waitForModification(req *ModifyRequest) (ModifyResponse, error) {
	pm.modifyMutex.Lock()
	pm.pendingReqs[req.ID] = req
	pm.modifyChannels[req.ID] = make(chan ModifyResponse, 1)
	pm.modifyMutex.Unlock()

	// 等待修改响应，超时时间30秒
	select {
	case resp := <-pm.modifyChannels[req.ID]:
		pm.modifyMutex.Lock()
		delete(pm.pendingReqs, req.ID)
		delete(pm.modifyChannels, req.ID)
		pm.modifyMutex.Unlock()
		return resp, nil
	case <-time.After(30 * time.Second):
		pm.modifyMutex.Lock()
		delete(pm.pendingReqs, req.ID)
		delete(pm.modifyChannels, req.ID)
		pm.modifyMutex.Unlock()
		return ModifyResponse{Action: "send_original"}, fmt.Errorf("修改请求超时")
	}
}

// handleModifyUI 处理修改界面
func (pm *ProxyMonitor) handleModifyUI(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>请求修改界面 - ProxyApiExplorer</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .nav { margin-bottom: 20px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #007bff; }
        .nav a:hover { text-decoration: underline; }
        .status { background: #e9ecef; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .pending-requests { margin-bottom: 30px; }
        .request-item { border: 1px solid #ddd; border-radius: 5px; margin-bottom: 15px; padding: 15px; background: #f8f9fa; }
        .request-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .request-method { padding: 3px 8px; border-radius: 3px; color: white; font-weight: bold; }
        .method-GET { background: #28a745; }
        .method-POST { background: #007bff; }
        .method-PUT { background: #ffc107; color: black; }
        .method-DELETE { background: #dc3545; }
        .request-url { font-family: monospace; word-break: break-all; }
        .request-details { display: none; margin-top: 15px; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input, .form-group textarea { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .form-group textarea { height: 100px; resize: vertical; font-family: monospace; }
        .headers-container { max-height: 200px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; border-radius: 4px; background: #f8f9fa; }
        .header-item { display: flex; margin-bottom: 5px; }
        .header-item input { margin-right: 10px; }
        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; margin-right: 10px; }
        .btn-primary { background: #007bff; color: white; }
        .btn-success { background: #28a745; color: white; }
        .btn-warning { background: #ffc107; color: black; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-secondary { background: #6c757d; color: white; }
        .btn:hover { opacity: 0.8; }
        .alert { padding: 15px; margin: 20px 0; border-radius: 5px; }
        .alert-info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-warning { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
        .no-requests { text-align: center; color: #6c757d; padding: 40px; }
        .timestamp { color: #6c757d; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/">修改界面</a>
            <a href="/config">配置管理</a>
            <a href="/data">原始数据</a>
            <a href="/user">用户管理</a>
            <a href="/logout">注销</a>
        </div>
        
        <div class="header">
            <h1>请求修改界面</h1>
            <p>拦截、修改和重发HTTP请求</p>
        </div>

        <div class="status">
            <h3>状态信息</h3>
            <p><strong>拦截状态:</strong> <span id="intercept-status">等待中...</span></p>
            <p><strong>待处理请求:</strong> <span id="pending-count">0</span></p>
            <p><strong>最后更新:</strong> <span id="last-update">-</span></p>
        </div>

        <div class="pending-requests">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                <h3>待处理请求</h3>
                <button onclick="manualRefresh()" class="btn btn-secondary">手动刷新</button>
            </div>
            <div id="requests-container">
                <div class="no-requests">
                    <p>暂无待处理的请求</p>
                    <p>当有符合拦截规则的请求时，会在这里显示</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        let pendingRequests = {};
        let expandedRequests = new Set(); // 记录展开的请求
        let editingRequests = new Set();  // 记录正在编辑的请求
        let refreshPaused = false;        // 刷新暂停标志

        function showAlert(message, type) {
            const alertDiv = document.createElement('div');
            alertDiv.className = 'alert alert-' + type;
            alertDiv.textContent = message;
            document.querySelector('.container').insertBefore(alertDiv, document.querySelector('.status'));
            setTimeout(() => alertDiv.remove(), 5000);
        }

        function formatTimestamp(timestamp) {
            return new Date(timestamp).toLocaleString('zh-CN');
        }

        function toggleDetails(id) {
            const details = document.getElementById('details-' + id);
            const btn = document.getElementById('toggle-' + id);
            if (details.style.display === 'none') {
                details.style.display = 'block';
                btn.textContent = '隐藏详情';
                expandedRequests.add(id);
            } else {
                details.style.display = 'none';
                btn.textContent = '显示详情';
                expandedRequests.delete(id);
                editingRequests.delete(id);
            }
        }

        // 监听输入框变化，标记为正在编辑
        function markAsEditing(id) {
            editingRequests.add(id);
            // 暂停刷新5秒
            refreshPaused = true;
            setTimeout(() => {
                refreshPaused = false;
            }, 5000);
        }

        // 检查请求是否正在被编辑
        function isRequestBeingEdited(id) {
            return editingRequests.has(id);
        }

        function addHeaderField(containerId) {
            const container = document.getElementById(containerId);
            const requestId = containerId.replace('headers-', '');
            const headerItem = document.createElement('div');
            headerItem.className = 'header-item';
            headerItem.innerHTML = '<input type="text" placeholder="Header名称" style="flex: 1;" oninput="markAsEditing(\'' + requestId + '\')"><input type="text" placeholder="Header值" style="flex: 2;" oninput="markAsEditing(\'' + requestId + '\')"><button type="button" onclick="this.parentElement.remove()" class="btn btn-danger" style="margin-left: 10px;">删除</button>';
            container.appendChild(headerItem);
            markAsEditing(requestId); // 添加头部字段也算编辑操作
        }

        function sendRequest(id, action) {
            const request = pendingRequests[id];
            if (!request) {
                showAlert('请求不存在', 'warning');
                return;
            }

            let requestData = { action: action };

            if (action === 'send_modified') {
                // 收集修改后的数据
                const method = document.getElementById('method-' + id).value;
                const url = document.getElementById('url-' + id).value;
                const body = document.getElementById('body-' + id).value;
                
                // 收集头部
                const headers = {};
                const headerItems = document.querySelectorAll('#headers-' + id + ' .header-item');
                headerItems.forEach(item => {
                    const inputs = item.querySelectorAll('input');
                    if (inputs.length === 2 && inputs[0].value && inputs[1].value) {
                        headers[inputs[0].value] = inputs[1].value;
                    }
                });

                requestData.data = {
                    request: { method, url, headers, body }
                };
            }

            fetch('/api/modify?id=' + id, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(requestData)
            })
            .then(response => {
                if (response.ok) {
                    showAlert('请求已处理', 'success');
                    delete pendingRequests[id];
                    loadPendingRequests();
                } else {
                    showAlert('处理请求失败', 'warning');
                }
            })
            .catch(error => {
                showAlert('处理请求失败: ' + error.message, 'warning');
            });
        }

        function renderRequest(request) {
            const methodClass = 'method-' + request.method;
            const timestamp = formatTimestamp(request.timestamp);
            
            let headersHtml = '';
            Object.entries(request.headers || {}).forEach(([key, value]) => {
                headersHtml += '<div class="header-item"><input type="text" value="' + key + '" style="flex: 1;" oninput="markAsEditing(\'' + request.id + '\')"><input type="text" value="' + value + '" style="flex: 2;" oninput="markAsEditing(\'' + request.id + '\')"><button type="button" onclick="this.parentElement.remove()" class="btn btn-danger" style="margin-left: 10px;">删除</button></div>';
            });

            return '<div class="request-item">' +
                '<div class="request-header">' +
                    '<div>' +
                        '<span class="request-method ' + methodClass + '">' + request.method + '</span>' +
                        '<span class="timestamp">' + timestamp + '</span>' +
                    '</div>' +
                    '<button type="button" id="toggle-' + request.id + '" class="btn btn-secondary" onclick="toggleDetails(\'' + request.id + '\')">显示详情</button>' +
                '</div>' +
                '<div class="request-url">' + request.url + '</div>' +
                '<div id="details-' + request.id + '" class="request-details">' +
                    '<div class="form-group">' +
                        '<label>请求方法:</label>' +
                        '<input type="text" id="method-' + request.id + '" value="' + request.method + '" oninput="markAsEditing(\'' + request.id + '\')">' +
                    '</div>' +
                    '<div class="form-group">' +
                        '<label>请求URL:</label>' +
                        '<input type="text" id="url-' + request.id + '" value="' + request.url + '" oninput="markAsEditing(\'' + request.id + '\')">' +
                    '</div>' +
                    '<div class="form-group">' +
                        '<label>请求头部:</label>' +
                        '<div id="headers-' + request.id + '" class="headers-container">' + headersHtml + '</div>' +
                        '<button type="button" onclick="addHeaderField(\'headers-' + request.id + '\')" class="btn btn-secondary" style="margin-top: 10px;">添加头部</button>' +
                    '</div>' +
                    '<div class="form-group">' +
                        '<label>请求正文:</label>' +
                        '<textarea id="body-' + request.id + '" oninput="markAsEditing(\'' + request.id + '\')">' + (request.body || '') + '</textarea>' +
                    '</div>' +
                    '<div style="text-align: center; margin-top: 20px;">' +
                        '<button onclick="sendRequest(\'' + request.id + '\', \'send_original\')" class="btn btn-success">发送原始请求</button>' +
                        '<button onclick="sendRequest(\'' + request.id + '\', \'send_modified\')" class="btn btn-primary">发送修改请求</button>' +
                        '<button onclick="sendRequest(\'' + request.id + '\', \'cancel\')" class="btn btn-danger">取消请求</button>' +
                    '</div>' +
                '</div>' +
            '</div>';
        }

        function loadPendingRequests() {
            // 如果刷新被暂停，跳过本次刷新
            if (refreshPaused) {
                return;
            }

            fetch('/api/pending')
                .then(response => response.json())
                .then(requests => {
                    const container = document.getElementById('requests-container');
                    const pendingCount = document.getElementById('pending-count');
                    const lastUpdate = document.getElementById('last-update');
                    const interceptStatus = document.getElementById('intercept-status');

                    pendingCount.textContent = requests.length;
                    lastUpdate.textContent = new Date().toLocaleString('zh-CN');
                    interceptStatus.textContent = requests.length > 0 ? '有待处理请求' : '等待拦截请求';

                    if (requests.length === 0) {
                        container.innerHTML = '<div class="no-requests"><p>暂无待处理的请求</p><p>当有符合拦截规则的请求时，会在这里显示</p></div>';
                        pendingRequests = {};
                        expandedRequests.clear();
                        editingRequests.clear();
                    } else {
                        // 检查是否有正在编辑的请求
                        let hasEditingRequests = false;
                        requests.forEach(request => {
                            if (isRequestBeingEdited(request.id)) {
                                hasEditingRequests = true;
                            }
                        });

                        // 如果有正在编辑的请求，延迟刷新
                        if (hasEditingRequests) {
                            console.log('检测到正在编辑的请求，延迟刷新...');
                            return;
                        }

                        let html = '';
                        requests.forEach(request => {
                            pendingRequests[request.id] = request;
                            html += renderRequest(request);
                        });
                        container.innerHTML = html;

                        // 恢复之前展开的请求状态
                        expandedRequests.forEach(id => {
                            const details = document.getElementById('details-' + id);
                            const btn = document.getElementById('toggle-' + id);
                            if (details && btn) {
                                details.style.display = 'block';
                                btn.textContent = '隐藏详情';
                            }
                        });
                    }
                })
                .catch(error => {
                    console.error('加载待处理请求失败:', error);
                });
        }

        // 定期刷新待处理请求 - 增加刷新间隔到5秒
        setInterval(loadPendingRequests, 5000);
        
        // 手动刷新函数
        function manualRefresh() {
            refreshPaused = false;
            editingRequests.clear();
            loadPendingRequests();
            showAlert('已手动刷新', 'success');
        }
        
        // 页面加载时立即加载
        window.onload = loadPendingRequests;
    </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func (pm *ProxyMonitor) handleGetPending(w http.ResponseWriter, r *http.Request) {
	pm.modifyMutex.RLock()
	defer pm.modifyMutex.RUnlock()

	var pending []*ModifyRequest
	for _, req := range pm.pendingReqs {
		pending = append(pending, req)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pending)
}

func (pm *ProxyMonitor) handleModifyRequest(w http.ResponseWriter, r *http.Request) {
	var resp ModifyResponse
	if err := json.NewDecoder(r.Body).Decode(&resp); err != nil {
		http.Error(w, "解析请求失败", http.StatusBadRequest)
		return
	}

	id := r.URL.Query().Get("id")
	pm.modifyMutex.RLock()
	ch, exists := pm.modifyChannels[id]
	pm.modifyMutex.RUnlock()

	if exists {
		select {
		case ch <- resp:
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "发送响应失败", http.StatusInternalServerError)
		}
	} else {
		http.Error(w, "请求不存在", http.StatusNotFound)
	}
}

func (pm *ProxyMonitor) handleConfigUI(w http.ResponseWriter, r *http.Request) {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>配置管理 - ProxyApiExplorer</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .nav { margin-bottom: 20px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #007bff; }
        .nav a:hover { text-decoration: underline; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input, .form-group textarea, .form-group select { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .form-group textarea { height: 100px; resize: vertical; }
        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .btn { padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
        .btn-primary { background: #007bff; color: white; }
        .btn-secondary { background: #6c757d; color: white; }
        .btn:hover { opacity: 0.8; }
        .status-info { background: #e9ecef; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .status-info h3 { margin-top: 0; }
        .alert { padding: 15px; margin: 20px 0; border-radius: 5px; }
        .alert-success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .alert-danger { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        .checkbox-group { display: flex; align-items: center; }
        .checkbox-group input[type="checkbox"] { width: auto; margin-right: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="/">修改界面</a>
            <a href="/config">配置管理</a>
            <a href="/data">原始数据</a>
            <a href="/user">用户管理</a>
            <a href="/logout">注销</a>
        </div>
        
        <div class="header">
            <h1>配置管理</h1>
            <p>实时修改代理服务器配置，无需重启</p>
        </div>

        <div class="status-info">
            <h3>当前状态</h3>
            <p><strong>代理端口:</strong> <span id="proxy-port">8888</span></p>
            <p><strong>修改端口:</strong> <span id="modify-port">8889</span></p>
            <p><strong>拦截规则数量:</strong> <span id="filter-count">0</span></p>
        </div>

        <form id="configForm">
            <div class="form-row">
                <div class="form-group">
                    <label>代理端口:</label>
                    <input type="number" id="port" min="1" max="65535" required>
                </div>
                <div class="form-group">
                    <label>修改界面端口:</label>
                    <input type="number" id="modify_port" min="1" max="65535" required>
                </div>
            </div>

            <div class="form-row">
                <div class="form-group checkbox-group">
                    <input type="checkbox" id="enable_modify">
                    <label for="enable_modify">启用请求修改功能</label>
                </div>
                <div class="form-group checkbox-group">
                    <input type="checkbox" id="capture_body">
                    <label for="capture_body">捕获请求/响应正文</label>
                </div>
            </div>

            <div class="form-group">
                <label>目标主机 (一行一个):</label>
                <textarea id="target_hosts" placeholder="example.com&#10;api.example.com"></textarea>
            </div>

            <div class="form-group">
                <label>拦截规则 (正则表达式，一行一个):</label>
                <textarea id="intercept_rules" placeholder="POST.*api/login&#10;PUT.*api/users/.*&#10;DELETE.*"></textarea>
            </div>

            <div class="form-group">
                <label>过滤关键字 (一行一个):</label>
                <textarea id="filter_keywords" placeholder="login&#10;register&#10;payment"></textarea>
            </div>

            <div class="form-group">
                <label>敏感参数 (一行一个):</label>
                <textarea id="sensitive_params" placeholder="password&#10;token&#10;key"></textarea>
            </div>

            <div class="form-group">
                <label>敏感头部 (一行一个):</label>
                <textarea id="sensitive_headers" placeholder="authorization&#10;x-api-key&#10;cookie"></textarea>
            </div>

            <div class="form-row">
                <div class="form-group">
                    <label>最大请求数:</label>
                    <input type="number" id="max_requests" min="1" required>
                </div>
                <div class="form-group">
                    <label>输出目录:</label>
                    <input type="text" id="output_dir" placeholder="api_explorer_reports">
                </div>
            </div>

            <div style="text-align: center; margin-top: 30px;">
                <button type="button" class="btn btn-secondary" onclick="loadConfig()">重新加载</button>
                <button type="submit" class="btn btn-primary">保存配置</button>
            </div>
        </form>
    </div>

    <script>
        function showAlert(message, type) {
            const alertDiv = document.createElement('div');
            alertDiv.className = 'alert alert-' + type;
            alertDiv.textContent = message;
            document.querySelector('.container').insertBefore(alertDiv, document.querySelector('.status-info'));
            setTimeout(() => alertDiv.remove(), 3000);
        }

        function loadConfig() {
            fetch('/api/config')
                .then(response => response.json())
                .then(config => {
                    document.getElementById('port').value = config.port || 8888;
                    document.getElementById('modify_port').value = config.modify_port || 8889;
                    document.getElementById('enable_modify').checked = config.enable_modify || false;
                    document.getElementById('capture_body').checked = config.capture_body || false;
                    document.getElementById('target_hosts').value = (config.target_hosts || []).join('\n');
                    document.getElementById('intercept_rules').value = (config.intercept_rules || []).join('\n');
                    document.getElementById('filter_keywords').value = (config.filter_keywords || []).join('\n');
                    document.getElementById('sensitive_params').value = (config.sensitive_params || []).join('\n');
                    document.getElementById('sensitive_headers').value = (config.sensitive_headers || []).join('\n');
                    document.getElementById('max_requests').value = config.max_requests || 10000;
                    document.getElementById('output_dir').value = config.output_dir || 'api_explorer_reports';
                    
                    document.getElementById('proxy-port').textContent = config.port || 8888;
                    document.getElementById('modify-port').textContent = config.modify_port || 8889;
                    document.getElementById('filter-count').textContent = (config.intercept_rules || []).length;
                    
                    showAlert('配置加载成功', 'success');
                })
                .catch(error => {
                    showAlert('加载配置失败: ' + error.message, 'danger');
                });
        }

        document.getElementById('configForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const config = {
                port: parseInt(document.getElementById('port').value),
                modify_port: parseInt(document.getElementById('modify_port').value),
                enable_modify: document.getElementById('enable_modify').checked,
                capture_body: document.getElementById('capture_body').checked,
                target_hosts: document.getElementById('target_hosts').value.split('\n').filter(h => h.trim()),
                intercept_rules: document.getElementById('intercept_rules').value.split('\n').filter(r => r.trim()),
                filter_keywords: document.getElementById('filter_keywords').value.split('\n').filter(k => k.trim()),
                sensitive_params: document.getElementById('sensitive_params').value.split('\n').filter(p => p.trim()),
                sensitive_headers: document.getElementById('sensitive_headers').value.split('\n').filter(h => h.trim()),
                max_requests: parseInt(document.getElementById('max_requests').value),
                output_dir: document.getElementById('output_dir').value || 'api_explorer_reports'
            };

            fetch('/api/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            })
            .then(response => {
                if (response.ok) {
                    showAlert('配置保存成功', 'success');
                    loadConfig(); // 重新加载以更新状态信息
                } else {
                    showAlert('保存配置失败', 'danger');
                }
            })
            .catch(error => {
                showAlert('保存配置失败: ' + error.message, 'danger');
            });
        });

        // 页面加载时自动加载配置
        window.onload = loadConfig;
    </script>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(html))
}

func (pm *ProxyMonitor) handleConfigAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(pm.config)
	} else if r.Method == "POST" {
		var newConfig Config
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			http.Error(w, "解析配置失败", http.StatusBadRequest)
			return
		}
		pm.config = &newConfig
		// 保存配置到文件
		pm.saveConfig()
		w.WriteHeader(http.StatusOK)
	}
}

// isSensitiveParam 判断是否为敏感参数（从配置文件读取）
func (pm *ProxyMonitor) isSensitiveParam(param string) bool {
	if len(pm.config.SensitiveParams) == 0 {
		// 默认敏感参数
		defaultParams := []string{"password", "token", "key", "secret", "auth", "session"}
		for _, sensitive := range defaultParams {
			if strings.Contains(strings.ToLower(param), sensitive) {
				return true
			}
		}
		return false
	}

	for _, sensitive := range pm.config.SensitiveParams {
		if strings.Contains(strings.ToLower(param), strings.ToLower(sensitive)) {
			return true
		}
	}
	return false
}

// loadConfig 加载配置文件（增强版，自动创建配置文件）
func loadConfig() *Config {
	config := &Config{}
	configFile := "ProxyApiExplorer_config.json"

	// 尝试读取配置文件
	if data, err := os.ReadFile(configFile); err == nil {
		if err := json.Unmarshal(data, config); err != nil {
			fmt.Printf("解析配置文件失败: %v\n", err)
		} else {
			fmt.Printf("配置文件加载成功: %s\n", configFile)
			// 确保必要的默认值
			if config.Port == 0 {
				config.Port = 8888
			}
			if config.ModifyPort == 0 {
				config.ModifyPort = 8889
			}
			if config.OutputDir == "" {
				config.OutputDir = "api_explorer_reports"
			}
			if config.MaxRequests == 0 {
				config.MaxRequests = 10000
			}
			if config.Username == "" {
				config.Username = "admin"
			}
			if config.Password == "" {
				config.Password = "admin"
			}
			return config
		}
	} else {
		fmt.Printf("配置文件不存在，将创建默认配置: %s\n", configFile)
	}

	// 创建默认配置
	config = &Config{
		Port:         8888,
		EnableModify: true,
		ModifyPort:   8889,
		CaptureBody:  true,
		TargetHosts:  []string{},
		SensitiveParams: []string{
			"password", "pwd", "passwd", "pass", "token", "access_token",
			"refresh_token", "jwt", "key", "api_key", "apikey", "secret_key",
			"secret", "client_secret", "app_secret", "auth", "authorization",
			"authenticate", "session", "sessionid", "session_id", "credit_card",
			"card_number", "cvv", "ssn", "phone", "email",
		},
		SensitiveHeaders: []string{
			"authorization", "x-api-key", "x-auth-token", "cookie",
			"x-access-token", "x-refresh-token", "x-session-token",
			"x-csrf-token", "x-xsrf-token", "authentication", "x-authentication", "bearer",
		},
		InterceptRules: []string{"POST.*"},
		FilterKeywords: []string{},
		MaxRequests:    10000,
		OutputDir:      "api_explorer_reports",
		Username:       "admin",
		Password:       "admin",
	}

	// 保存默认配置文件
	if configData, err := json.MarshalIndent(config, "", "  "); err == nil {
		if err := os.WriteFile(configFile, configData, 0644); err == nil {
			fmt.Printf("默认配置文件创建成功: %s\n", configFile)
		} else {
			fmt.Printf("创建默认配置文件失败: %v\n", err)
		}
	}

	return config
}

// saveConfig 保存配置文件
func (pm *ProxyMonitor) saveConfig() error {
	configData, err := json.MarshalIndent(pm.config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile("ProxyApiExplorer_config.json", configData, 0644)
}

func main() {
	fmt.Println("=== ProxyApiExplorer - 增强版用户认证功能 ===")

	config := loadConfig()
	monitor := NewProxyMonitor(config)

	// 启动配置文件保护服务器（阻止直接访问配置文件）
	go func() {
		configMux := http.NewServeMux()
		configMux.HandleFunc("/ProxyApiExplorer_config.json", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "访问被拒绝", http.StatusForbidden)
		})
		configMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			// 检查是否试图访问配置文件
			if strings.Contains(r.URL.Path, "config.json") {
				http.Error(w, "访问被拒绝", http.StatusForbidden)
				return
			}
			http.NotFound(w, r)
		})

		configServer := &http.Server{
			Addr:    ":8890", // 使用不同的端口来保护配置文件
			Handler: configMux,
		}

		fmt.Printf("配置文件保护服务: http://localhost:8890\n")
		if err := configServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("配置文件保护服务器错误: %v", err)
		}
	}()

	fmt.Printf("默认登录信息 - 用户名: %s, 密码: %s\n", config.Username, config.Password)
	fmt.Printf("请访问 http://localhost:%d 进行登录\n", config.ModifyPort)

	if err := monitor.Start(); err != nil && err != http.ErrServerClosed {
		log.Printf("服务器错误: %v", err)
	}

	fmt.Println("ProxyApiExplorer 已停止")
}
