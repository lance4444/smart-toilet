const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// 中間件設置
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// 用戶管理
const users = [
  { username: "admin", password: "admin12345", role: "admin" },
  { username: "user", password: "12345", role: "user" }
];

// 會話管理
let sessions = {};
let currentUser = "";
let currentRole = "";

// 馬桶狀態數據 (與ESP32相同結構)
let toiletStatus = {
  paperLow: false,
  trashFull: false,
  weightAlert: false,
  doorOpen: false,
  personDetected: false,
  peopleCount: 0,
  co2Level: 0,
  tvocLevel: 0,
  lastUpdate: 0,
  occupiedStartTime: 0,
  occupancyTimeout: false,
  occupiedDuration: 0,
  lastCloudUploadSuccess: true,
  lastCloudUploadTime: Date.now(),
  
  isOccupied() {
    return !this.doorOpen && this.personDetected;
  },
  
  resetAlerts() {
    this.paperLow = false;
    this.trashFull = false;
    this.weightAlert = false;
    this.personDetected = false;
    this.peopleCount = 0;
    this.co2Level = 0;
    this.tvocLevel = 0;
    this.occupiedStartTime = 0;
    this.occupancyTimeout = false;
    this.occupiedDuration = 0;
    console.log("🔄 All alerts and counters reset to normal state");
  },
  
  updateOccupancy() {
    const currentlyOccupied = this.isOccupied();
    
    if (currentlyOccupied) {
      if (this.occupiedStartTime === 0) {
        this.occupiedStartTime = Date.now();
        this.occupancyTimeout = false;
        console.log("🚻 Occupancy started");
      } else {
        this.occupiedDuration = Date.now() - this.occupiedStartTime;
        if (this.occupiedDuration > 10000 && !this.occupancyTimeout) {
          this.occupancyTimeout = true;
          console.log("⏰ Occupancy timeout detected! (simulating 30 minutes)");
        }
      }
    } else {
      if (this.occupiedStartTime !== 0) {
        console.log("🚻 Occupancy ended");
        this.occupiedStartTime = 0;
        this.occupancyTimeout = false;
        this.occupiedDuration = 0;
      }
    }
  },
  
  getOccupancyMessage() {
    if (!this.isOccupied()) {
      return "";
    }
    
    if (this.occupancyTimeout) {
      return "⚠️ Occupied for 30+ minutes!";
    } else if (this.occupiedStartTime > 0) {
      const seconds = Math.floor(this.occupiedDuration / 1000);
      return `🕐 Occupied for ${seconds} seconds`;
    }
    
    return "";
  },
  
  getStatusSummary() {
    return `Status Summary:
- Paper: ${this.paperLow ? "LOW" : "OK"}
- Trash: ${this.trashFull ? "FULL" : "OK"}  
- Weight: ${this.weightAlert ? "ALERT" : "OK"}
- Door: ${this.doorOpen ? "OPEN" : "CLOSED"}
- People: ${this.peopleCount}
- Occupied: ${this.isOccupied() ? "YES" : "NO"}
- CO2: ${this.co2Level}ppm
- TVOC: ${this.tvocLevel}ppb
${this.occupancyTimeout ? "- ⚠️ OCCUPANCY TIMEOUT!" : ""}`;
  }
};

// 輔助函數
function authenticateUser(username, password) {
  const user = users.find(u => u.username === username && u.password === password);
  if (user) {
    const sessionToken = "session_" + Date.now();
    sessions[sessionToken] = {
      username: user.username,
      role: user.role,
      timestamp: Date.now()
    };
    return sessionToken;
  }
  return null;
}

function isAuthenticated(req) {
  const sessionToken = req.headers.authorization || req.session?.token;
  return sessions[sessionToken] && sessions[sessionToken];
}

function isAdmin(req) {
  const session = isAuthenticated(req);
  return session && session.role === "admin";
}

// 中間件添加 cookie 解析
app.use((req, res, next) => {
  req.cookies = {};
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    cookieHeader.split(';').forEach(cookie => {
      const parts = cookie.trim().split('=');
      req.cookies[parts[0]] = parts[1];
    });
  }
  next();
});

// 設置 cookie 輔助函數
function setCookie(res, name, value, options = {}) {
  let cookieString = `${name}=${value}`;
  if (options.maxAge) cookieString += `; Max-Age=${options.maxAge}`;
  if (options.httpOnly) cookieString += `; HttpOnly`;
  if (options.secure) cookieString += `; Secure`;
  if (options.sameSite) cookieString += `; SameSite=${options.sameSite}`;
  res.setHeader('Set-Cookie', cookieString);
}

// 定期更新占用狀態
setInterval(() => {
  toiletStatus.updateOccupancy();
}, 1000);

// API路由 - 接收ESP32數據 (保持原有功能)
app.post('/api/sensor-data', (req, res) => {
  console.log('📡 Received sensor data:', req.body);
  
  // 更新狀態
  if (req.body.deviceId) {
    Object.assign(toiletStatus, req.body);
    toiletStatus.lastUpdate = Date.now();
    toiletStatus.updateOccupancy();
    
    console.log('✅ Status updated:', toiletStatus.getStatusSummary());
  }
  
  res.json({ 
    success: true, 
    message: 'Data received successfully',
    timestamp: Date.now()
  });
});

// 登入頁面
app.get('/login', (req, res) => {
  const error = req.query.error || '';
  res.send(getLoginHTML(error));
});

// 登入處理
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const sessionToken = authenticateUser(username, password);
  
  if (sessionToken) {
    setCookie(res, 'session', sessionToken, { maxAge: 86400 }); // 24小時
    res.writeHead(302, { 'Location': '/' });
    res.end();
  } else {
    res.writeHead(302, { 'Location': '/login?error=Invalid credentials! Please try again.' });
    res.end();
  }
});

// 登出
app.get('/logout', (req, res) => {
  const sessionToken = req.cookies?.session;
  if (sessionToken) {
    delete sessions[sessionToken];
  }
  setCookie(res, 'session', '', { maxAge: 0 });
  res.writeHead(302, { 'Location': '/login' });
  res.end();
});

// 主頁面
app.get('/', (req, res) => {
  const sessionToken = req.cookies?.session;
  const session = sessions[sessionToken];
  
  if (!session) {
    return res.redirect('/login');
  }
  
  res.send(getMainHTML(session));
});

// 狀態API
app.get('/status', (req, res) => {
  const sessionToken = req.cookies?.session;
  if (!sessions[sessionToken]) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  res.json({
    ...toiletStatus,
    occupied: toiletStatus.isOccupied(),
    occupancyMessage: toiletStatus.getOccupancyMessage(),
    cloudEnabled: true,
    lastCloudUploadSuccess: toiletStatus.lastCloudUploadSuccess,
    lastCloudUploadTime: toiletStatus.lastCloudUploadTime
  });
});

// 重置警報 (僅管理員)
app.get('/reset', (req, res) => {
  const sessionToken = req.cookies?.session;
  const session = sessions[sessionToken];
  
  if (!session) {
    return res.status(401).send('Unauthorized');
  }
  
  if (session.role !== 'admin') {
    return res.status(403).send('Access Denied - Admin Only');
  }
  
  toiletStatus.resetAlerts();
  console.log(`🔄 Alerts reset by ${session.username}`);
  res.send('Alerts reset');
});

// 測試數據 (僅管理員)
app.get('/test', (req, res) => {
  const sessionToken = req.cookies?.session;
  const session = sessions[sessionToken];
  
  if (!session) {
    return res.status(401).send('Unauthorized');
  }
  
  if (session.role !== 'admin') {
    return res.status(403).send('Access Denied - Admin Only');
  }
  
  // 生成測試數據
  toiletStatus.paperLow = true;
  toiletStatus.co2Level = 1200;
  toiletStatus.tvocLevel = 3000;
  toiletStatus.peopleCount = 2;
  toiletStatus.doorOpen = false;
  toiletStatus.personDetected = true;
  toiletStatus.lastUpdate = Date.now();
  toiletStatus.occupiedStartTime = Date.now() - 15000;
  toiletStatus.occupancyTimeout = true;
  
  console.log(`🧪 Generated test data by ${session.username}`);
  res.send('Test data generated');
});

// WiFi信息頁面 (僅管理員)
app.get('/wifi', (req, res) => {
  const sessionToken = req.cookies?.session;
  const session = sessions[sessionToken];
  
  if (!session) {
    return res.redirect('/login');
  }
  
  if (session.role !== 'admin') {
    return res.status(403).send('Access Denied - Admin Only');
  }
  
  res.send(getWiFiHTML());
});

// 雲端狀態頁面
app.get('/cloud', (req, res) => {
  const sessionToken = req.cookies?.session;
  const session = sessions[sessionToken];
  
  if (!session) {
    return res.redirect('/login');
  }
  
  res.send(getCloudHTML());
});

// 健康檢查端點
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    toiletStatus: toiletStatus.getStatusSummary()
  });
});

// HTML生成函數
function getLoginHTML(error = '') {
  return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>EEE4464 EA Project - Login</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Arial', sans-serif;
            background: linear-gradient(135deg, #f0f8f0 0%, #e8f5e8 100%);
            color: #2d5a2d; min-height: 100vh; display: flex;
            align-items: center; justify-content: center; padding: 20px;
        }
        .login-container {
            background: white; padding: 40px; border-radius: 15px;
            box-shadow: 0 4px 20px rgba(76, 175, 80, 0.15);
            border: 3px solid #4CAF50; max-width: 400px; width: 100%;
        }
        .header { text-align: center; margin-bottom: 30px; }
        .project-title {
            font-size: 14px; font-weight: bold; margin-bottom: 8px;
            letter-spacing: 1px; color: #4CAF50;
        }
        h1 { font-size: 1.8em; margin-bottom: 8px; color: #2d5a2d; }
        .subtitle { font-size: 14px; color: #666; }
        .form-group { margin-bottom: 20px; }
        label {
            display: block; margin-bottom: 5px; font-weight: bold; color: #2d5a2d;
        }
        input[type="text"], input[type="password"] {
            width: 100%; padding: 12px; border: 2px solid #ddd;
            border-radius: 8px; font-size: 16px;
            transition: border-color 0.3s ease;
        }
        input[type="text"]:focus, input[type="password"]:focus {
            outline: none; border-color: #4CAF50;
        }
        .btn {
            width: 100%; background: #4CAF50; border: none; color: white;
            padding: 12px; border-radius: 8px; cursor: pointer;
            font-size: 16px; font-weight: 600; transition: all 0.3s ease;
        }
        .btn:hover { background: #45a049; transform: translateY(-2px); }
        .error {
            color: #f44336; text-align: center; margin-bottom: 20px; font-weight: bold;
        }
        .demo-info {
            margin-top: 20px; padding: 15px; background: #f8fcf8;
            border-radius: 8px; border-left: 4px solid #4CAF50; font-size: 14px;
        }
        .demo-info h4 { margin-bottom: 8px; color: #2d5a2d; }
        .demo-info p { margin: 4px 0; color: #666; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="header">
            <div class="project-title">EEE4464 EA PROJECT</div>
            <h1>🚽 Smart Toilet Monitor</h1>
            <div class="subtitle">Please login to continue</div>
        </div>
        
        ${error ? `<div class='error'>${error}</div>` : ''}
        
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="btn">🔑 Login</button>
        </form>
        
        <div class="demo-info">
            <h4>📋 Demo Accounts:</h4>
            <p><strong>Admin:</strong> admin / admin12345</p>
            <p><strong>User:</strong> user / 12345</p>
        </div>
    </div>
</body>
</html>`;
}

function getMainHTML(session) {
  return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>EEE4464 EA Project - Smart Toilet Monitor</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        /* 與ESP32版本相同的CSS樣式 */
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Arial', sans-serif;
            background: linear-gradient(135deg, #f0f8f0 0%, #e8f5e8 100%);
            color: #2d5a2d; min-height: 100vh; padding: 15px;
        }
        .container {
            max-width: 1200px; margin: 0 auto; background: white;
            border-radius: 15px; box-shadow: 0 4px 20px rgba(76, 175, 80, 0.15);
            overflow: hidden; border: 3px solid #4CAF50;
        }
        .header {
            background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%);
            color: white; padding: 25px; text-align: center; position: relative;
        }
        .user-info {
            position: absolute; top: 15px; right: 20px;
            font-size: 12px; opacity: 0.9;
        }
        .logout-btn {
            background: rgba(255,255,255,0.2); border: 1px solid rgba(255,255,255,0.3);
            color: white; padding: 5px 10px; border-radius: 15px;
            text-decoration: none; font-size: 11px; margin-left: 10px;
            transition: background 0.3s ease;
        }
        .logout-btn:hover { background: rgba(255,255,255,0.3); }
        .project-title {
            font-size: 16px; font-weight: bold; margin-bottom: 10px; letter-spacing: 1px;
        }
        h1 { font-size: 2.2em; margin-bottom: 10px; }
        .subtitle { font-size: 16px; opacity: 0.9; }
        .content { padding: 25px; }
        .control-buttons {
            display: flex; justify-content: center; flex-wrap: wrap;
            gap: 12px; margin-bottom: 25px;
        }
        .btn {
            background: #4CAF50; border: none; color: white;
            padding: 12px 20px; border-radius: 20px; cursor: pointer;
            font-size: 14px; font-weight: 600; transition: all 0.3s ease;
            text-decoration: none; display: inline-flex;
            align-items: center; gap: 8px;
        }
        .btn:hover { background: #45a049; transform: translateY(-2px); }
        .occupied-indicator {
            font-size: 22px; font-weight: bold; text-align: center;
            padding: 22px; border-radius: 12px; margin-bottom: 25px; border: 2px solid;
        }
        .occupied-available {
            background: linear-gradient(135deg, #e8f5e8, #f0f9f0);
            border-color: #4CAF50; color: #2d5a2d;
        }
        .occupied-busy {
            background: linear-gradient(135deg, #ffebee, #fce4ec);
            border-color: #f44336; color: #c62828; animation: pulse 2s infinite;
        }
        .occupied-timeout {
            background: linear-gradient(135deg, #fff3e0, #ffe0b2);
            border-color: #ff9800; color: #e65100; animation: urgentPulse 1.5s infinite;
        }
        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(244, 67, 54, 0.7); }
            70% { box-shadow: 0 0 0 8px rgba(244, 67, 54, 0); }
            100% { box-shadow: 0 0 0 0 rgba(244, 67, 54, 0); }
        }
        @keyframes urgentPulse {
            0% { box-shadow: 0 0 0 0 rgba(255, 152, 0, 0.8); }
            50% { box-shadow: 0 0 0 10px rgba(255, 152, 0, 0); }
            100% { box-shadow: 0 0 0 0 rgba(255, 152, 0, 0); }
        }
        .occupancy-message {
            font-size: 16px; margin-top: 10px; padding: 10px;
            border-radius: 8px; background: rgba(255, 255, 255, 0.2);
        }
        .status-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 18px; margin-bottom: 25px;
        }
        .status-card {
            background: #f8fcf8; border: 2px solid #4CAF50;
            padding: 22px; border-radius: 12px; text-align: center;
            transition: all 0.3s ease;
        }
        .status-card:hover {
            transform: translateY(-3px); box-shadow: 0 6px 20px rgba(76, 175, 80, 0.2);
        }
        .status-card h3 {
            margin: 0 0 15px 0; font-size: 18px; color: #2d5a2d;
            display: flex; align-items: center; justify-content: center; gap: 10px;
        }
        .status-card p { margin: 0; font-size: 16px; font-weight: bold; }
        .card-icon { font-size: 28px; }
        .card-good { background: #f8fcf8; border-color: #4CAF50; color: #2d5a2d; }
        .card-warning { background: #fff8e1; border-color: #FF9800; color: #e65100; }
        .card-danger { background: #ffebee; border-color: #f44336; color: #c62828; }
        .card-info { background: #e3f2fd; border-color: #2196F3; color: #1565c0; }
        .last-update {
            text-align: center; color: #666; font-size: 14px;
            margin-top: 20px; padding: 15px; background: #f8f9fa;
            border-radius: 10px; border-left: 4px solid #4CAF50;
        }
        .status-value { font-size: 14px; margin-top: 8px; }
        .loading { color: #999; font-style: italic; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="user-info">
                Logged in as: <strong>${session.username}</strong> (${session.role})
                <a href="/logout" class="logout-btn">🚪 Logout</a>
            </div>
            <div class="project-title">EEE4464 EA PROJECT - CLOUD VERSION</div>
            <h1><span style="font-size: 1.2em;">🚽</span> Smart Toilet Monitoring System</h1>
            <div class="subtitle">Real-time Facility Management Dashboard</div>
        </div>
        
        <div class="content">
            <div class="control-buttons">
                ${session.role === 'admin' ? `
                <button class="btn" onclick="resetAlerts()">
                    <span>🔄</span> Reset Alerts
                </button>
                <button class="btn" onclick="generateTest()">
                    <span>🧪</span> Test Data
                </button>
                <button class="btn" onclick="window.open('/wifi', '_blank')">
                    <span>📶</span> Server Info
                </button>
                ` : ''}
                <button class="btn" onclick="location.reload()">
                    <span>♻️</span> Refresh
                </button>
                <button class="btn" onclick="window.open('/cloud', '_blank')">
                    <span>☁️</span> Cloud Status
                </button>
            </div>
            
            <div id="occupiedStatus" class="occupied-indicator occupied-available">
                🔄 Loading Status...
            </div>
            
            <div class="status-grid">
                <div id="paperCard" class="status-card card-good">
                    <h3><span class="card-icon">🧻</span> Toilet Paper</h3>
                    <p id="paperStatus" class="loading">Loading...</p>
                </div>
                
                <div id="trashCard" class="status-card card-good">
                    <h3><span class="card-icon">🗑️</span> Waste Bin</h3>
                    <p id="trashStatus" class="loading">Loading...</p>
                </div>
                
                <div id="peopleCard" class="status-card card-info">
                    <h3><span class="card-icon">👥</span> People Count</h3>
                    <p id="peopleCount" class="loading">Loading...</p>
                </div>
                
                <div id="doorCard" class="status-card card-good">
                    <h3><span class="card-icon">🚪</span> Toilet compartment</h3>
                    <p id="doorStatus" class="loading">Loading...</p>
                </div>
                
                <div id="airCard" class="status-card card-good">
                    <h3><span class="card-icon">🌬️</span> Air Quality</h3>
                    <p id="airStatus" class="loading">Loading...</p>
                    <div class="status-value" id="airDetails"></div>
                </div>
                
                <div id="weightCard" class="status-card card-good">
                    <h3><span class="card-icon">⚖️</span> Weight Sensor</h3>
                    <p id="weightStatus" class="loading">Loading...</p>
                </div>
            </div>
            
            <div class="last-update">
                <strong>⏰ Last Update:</strong> <span id="lastUpdate">Never</span>
            </div>
        </div>
    </div>

    <script>
        function updateStatus() {
            fetch('/status')
                .then(response => {
                    if (response.status === 401) {
                        window.location.href = '/login';
                        return;
                    }
                    return response.json();
                })
                .then(data => {
                    if (!data) return;
                    
                    const occupiedDiv = document.getElementById('occupiedStatus');
                    
                    if (data.occupancyTimeout) {
                        occupiedDiv.innerHTML = '⚠️ OCCUPANCY TIMEOUT!<div class="occupancy-message">' + data.occupancyMessage + '</div>';
                        occupiedDiv.className = 'occupied-indicator occupied-timeout';
                    } else if (data.occupied) {
                        let message = '🔴 OCCUPIED - In Use';
                        if (data.occupancyMessage) {
                            message += '<div class="occupancy-message">' + data.occupancyMessage + '</div>';
                        }
                        occupiedDiv.innerHTML = message;
                        occupiedDiv.className = 'occupied-indicator occupied-busy';
                    } else {
                        occupiedDiv.innerHTML = '🟢 AVAILABLE - Ready';
                        occupiedDiv.className = 'occupied-indicator occupied-available';
                    }
                    
                    updateCard('paperCard', 'paperStatus', data.paperLow, '⚠️ Paper Low!', '✅ Normal');
                    updateCard('trashCard', 'trashStatus', data.trashFull, '⚠️ Bin Full!', '✅ Normal');
                    updateCard('weightCard', 'weightStatus', data.weightAlert, '⚠️ Alert!', '✅ Normal');
                    
                    const peopleCard = document.getElementById('peopleCard');
                    peopleCard.className = 'status-card card-info';
                    document.getElementById('peopleCount').textContent = data.peopleCount + ' Person(s)';
                    
                    const doorCard = document.getElementById('doorCard');
                    const doorStatus = document.getElementById('doorStatus');
                    if (data.doorOpen) {
                        doorCard.className = 'status-card card-good';
                        doorStatus.textContent = '🔓 Open';
                    } else {
                        doorCard.className = 'status-card card-danger';
                        doorStatus.textContent = '🔒 Closed';
                    }
                    
                    const airCard = document.getElementById('airCard');
                    const airStatus = document.getElementById('airStatus');
                    const airDetails = document.getElementById('airDetails');
                    
                    if (data.co2Level > 2000 || data.tvocLevel > 5000) {
                        airCard.className = 'status-card card-danger';
                        airStatus.textContent = '⚠️ Poor';
                    } else if (data.co2Level > 1000 || data.tvocLevel > 2000) {
                        airCard.className = 'status-card card-warning';
                        airStatus.textContent = '⚡ Fair';
                    } else {
                        airCard.className = 'status-card card-good';
                        airStatus.textContent = '✅ Good';
                    }
                    
                    airDetails.textContent = \`CO₂: \${data.co2Level}ppm | TVOC: \${data.tvocLevel}ppb\`;
                    
                    document.getElementById('lastUpdate').textContent = new Date().toLocaleString();
                })
                .catch(error => {
                    console.error('Status fetch failed:', error);
                    document.getElementById('occupiedStatus').textContent = '❌ Connection Lost';
                    document.getElementById('occupiedStatus').className = 'occupied-indicator occupied-busy';
                });
        }
        
        function updateCard(cardId, statusId, isAlert, alertText, normalText) {
            const card = document.getElementById(cardId);
            const status = document.getElementById(statusId);
            if (isAlert) {
                card.className = 'status-card card-danger';
                status.textContent = alertText;
            } else {
                card.className = 'status-card card-good';
                status.textContent = normalText;
            }
        }
        
        function resetAlerts() {
            fetch('/reset')
                .then(response => {
                    if (response.status === 403) {
                        showNotification('❌ Access Denied - Admin Only!', 'error');
                        return;
                    }
                    if (response.ok) {
                        showNotification('✅ Alerts Reset!', 'success');
                        updateStatus();
                    } else {
                        showNotification('❌ Reset Failed!', 'error');
                    }
                });
        }
        
        function generateTest() {
            fetch('/test')
                .then(response => {
                    if (response.status === 403) {
                        showNotification('❌ Access Denied - Admin Only!', 'error');
                        return;
                    }
                    if (response.ok) {
                        showNotification('🧪 Test Data Generated!', 'success');
                        updateStatus();
                    } else {
                        showNotification('❌ Generation Failed!', 'error');
                    }
                });
        }
        
        function showNotification(message, type) {
            const notification = document.createElement('div');
            notification.textContent = message;
            notification.style.cssText = \`
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 12px 20px;
                border-radius: 8px;
                color: white;
                font-weight: bold;
                z-index: 1000;
                opacity: 0;
                transition: opacity 0.3s ease;
                max-width: 300px;
                \${type === 'success' ? 'background: #4CAF50;' : 'background: #f44336;'}
            \`;
            
            document.body.appendChild(notification);
            
            setTimeout(() => notification.style.opacity = '1', 100);
            setTimeout(() => {
                notification.style.opacity = '0';
                setTimeout(() => document.body.removeChild(notification), 300);
            }, 4000);
        }
        
        setInterval(updateStatus, 3000);
        updateStatus();
    </script>
</body>
</html>`;
}

function getWiFiHTML() {
  return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Server Information</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f0f8f0;
            color: #2d5a2d;
        }
        .container {
            max-width: 500px;
            margin: 0 auto;
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 5px solid #4CAF50;
        }
        h1 {
            color: #4CAF50;
            text-align: center;
            margin-bottom: 25px;
        }
        p {
            margin: 15px 0;
            padding: 10px;
            background: #f8fcf8;
            border-radius: 5px;
        }
        a {
            display: block;
            text-align: center;
            margin-top: 20px;
            padding: 12px 24px;
            background: #4CAF50;
            color: white;
            text-decoration: none;
            border-radius: 5px;
        }
        a:hover {
            background: #45a049;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 Server Information</h1>
        <p><strong>Status:</strong> Online (Cloud Server)</p>
        <p><strong>Platform:</strong> Render Cloud Platform</p>
        <p><strong>Server Type:</strong> Node.js Express</p>
        <p><strong>URL:</strong> ${process.env.RENDER_EXTERNAL_URL || 'https://your-app.onrender.com'}</p>
        <p><strong>Port:</strong> ${PORT}</p>
        <p><strong>Uptime:</strong> ${Math.floor(process.uptime())} seconds</p>
        <a href='/'>🔙 Back to Main</a>
    </div>
</body>
</html>`;
}

function getCloudHTML() {
  return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Cloud Status</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background: #f0f8f0; 
        }
        .container { 
            max-width: 600px; 
            margin: 0 auto; 
            background: white; 
            padding: 25px; 
            border-radius: 10px; 
        }
        h1 { 
            color: #4CAF50; 
            text-align: center; 
        }
        .status { 
            padding: 15px; 
            border-radius: 8px; 
            margin: 15px 0; 
            text-align: center; 
            font-weight: bold; 
        }
        .online { 
            background: #d4edda; 
            color: #155724; 
            border: 1px solid #c3e6cb; 
        }
        .btn { 
            padding: 10px 20px; 
            background: #4CAF50; 
            color: white; 
            border: none; 
            border-radius: 5px; 
            cursor: pointer; 
            margin: 5px; 
            text-decoration: none;
            display: inline-block;
        }
        .btn:hover { 
            background: #45a049; 
        }
        .info { 
            background: #f8f9fa; 
            padding: 15px; 
            border-radius: 5px; 
            margin: 15px 0; 
        }
        .center { text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>☁️ Cloud Status</h1>
        
        <div class="status online">
            🟢 Cloud Server ONLINE
        </div>
        
        <div class="info">
            <p><strong>Server URL:</strong> ${process.env.RENDER_EXTERNAL_URL || 'https://your-app.onrender.com'}</p>
            <p><strong>Platform:</strong> Render Cloud</p>
            <p><strong>Runtime:</strong> Node.js Express</p>
            <p><strong>Status:</strong> Running</p>
            <p><strong>Uptime:</strong> ${Math.floor(process.uptime())} seconds</p>
            <p><strong>Data Storage:</strong> In-Memory (Real-time)</p>
        </div>
        
        <div class="center">
            <a href="/" class="btn">🔙 Back to Main</a>
        </div>
    </div>
</body>
</html>`;
}

// 錯誤處理中間件
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: err.message 
  });
});

// 404 處理
app.use((req, res) => {
  res.status(404).send('404 - Page Not Found');
});

// 啟動服務器
app.listen(PORT, () => {
  console.log(`
🚽 Smart Toilet Cloud Server Started!
=====================================
🌐 Server URL: http://localhost:${PORT}
🎯 Environment: ${process.env.NODE_ENV || 'development'}
📡 API Endpoint: /api/sensor-data
🔑 Login Page: /login
📊 Health Check: /health

Demo Accounts:
👤 Admin: admin / admin12345
👤 User: user / 12345

Ready to receive data from ESP32! 🚀
`);
});

// 優雅關閉
process.on('SIGTERM', () => {
  console.log('🛑 Received SIGTERM, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('🛑 Received SIGINT, shutting down gracefully...');
  process.exit(0);
});
