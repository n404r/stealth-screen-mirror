package main

import (
	"context"
	_ "embed"
	"flag"
	"fmt"
	"image/jpeg"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/gorilla/websocket"
	"github.com/kbinani/screenshot"
)

//go:embed viewer.html
var viewerHTML []byte

// Runtime configuration (can be set via flags)
var (
	configFPS        = 60
	configQuality    = 85
	configMaxClients = 3
	configBuffer     = 2
)

var (
	clientCount  = 0
	clientMutex  sync.Mutex
	serverPort   int
	shutdownChan = make(chan bool, 1)
	shutdownCtx  context.Context
	cancelFunc   context.CancelFunc
	// Broadcast system for multi-client support
	clientsMap   = make(map[*websocket.Conn]chan []byte)
	clientsMutex sync.RWMutex
)

// WebSocket upgrader
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins (local network)
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 2 * 1024 * 1024, // 2MB write buffer for fast transmission
}

// Windows API for hiding console
var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	user32               = syscall.NewLazyDLL("user32.dll")
	procGetConsoleWindow = kernel32.NewProc("GetConsoleWindow")
	procShowWindow       = user32.NewProc("ShowWindow")
)

const SW_HIDE = 0

// Hide console window for stealth
func hideConsole() {
	if runtime.GOOS != "windows" {
		return
	}
	hwnd, _, _ := procGetConsoleWindow.Call()
	if hwnd != 0 {
		procShowWindow.Call(hwnd, SW_HIDE)
	}
}

// Capture screen continuously with delta encoding
func captureLoop(ctx context.Context) {
	// Check if display is available
	numDisplays := screenshot.NumActiveDisplays()
	if numDisplays == 0 {
		return
	}

	// Get primary display bounds
	bounds := screenshot.GetDisplayBounds(0)

	ticker := time.NewTicker(time.Second / time.Duration(configFPS))
	defer ticker.Stop()

	var prevFrame []byte
	keyFrameCounter := 0

	for {
		select {
		case <-ctx.Done():
			// Shutdown signal received, exit cleanly
			return
		case <-ticker.C:
			// Skip if no clients
			clientsMutex.RLock()
			if len(clientsMap) == 0 {
				clientsMutex.RUnlock()
				continue
			}
			clientsMutex.RUnlock()

			// Capture screen
			img, err := screenshot.CaptureRect(bounds)
			if err != nil {
				continue
			}

			// Encode to JPEG
			buf := getBuffer()
			err = jpeg.Encode(buf, img, &jpeg.Options{Quality: configQuality})
			if err != nil {
				putBuffer(buf)
				continue
			}

			currentFrame := buf.Bytes()

			// Send full keyframe every 60 frames or if first frame
			keyFrameCounter++
			if prevFrame == nil || keyFrameCounter >= 60 {
				// Broadcast to all clients
				broadcastFrame(currentFrame)
				prevFrame = make([]byte, len(currentFrame))
				copy(prevFrame, currentFrame)
				keyFrameCounter = 0
			} else {
				// Check if frames are significantly different
				diff := calculateDifference(prevFrame, currentFrame)

				// If >5% changed, broadcast frame
				if diff > 0.05 {
					broadcastFrame(currentFrame)
					copy(prevFrame, currentFrame)
				}
			}

			putBuffer(buf)
		}
	}
}

// Calculate difference percentage between two frames
func calculateDifference(prev, curr []byte) float64 {
	if len(prev) != len(curr) {
		return 1.0
	}

	minLen := len(prev)
	if len(curr) < minLen {
		minLen = len(curr)
	}

	// Ensure minimum 100 samples for accurate detection
	sampleSize := minLen / 1000 // Sample 0.1%
	if sampleSize < 100 {
		sampleSize = minLen
	}

	diff := 0
	for i := 0; i < sampleSize; i++ {
		idx := (i * minLen) / sampleSize
		if idx < minLen && prev[idx] != curr[idx] {
			diff++
		}
	}

	return float64(diff) / float64(sampleSize)
}

// Broadcast frame to all connected clients
func broadcastFrame(frame []byte) {
	clientsMutex.RLock()
	defer clientsMutex.RUnlock()

	// Make a copy for each client to avoid race conditions
	for _, clientChan := range clientsMap {
		frameCopy := make([]byte, len(frame))
		copy(frameCopy, frame)
		
		// Non-blocking send
		select {
		case clientChan <- frameCopy:
		default:
			// Client is slow, skip this frame
		}
	}
}

// Buffer pool for zero-allocation encoding
var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytesBuffer)
	},
}

type bytesBuffer struct {
	data []byte
}

func (b *bytesBuffer) Write(p []byte) (n int, err error) {
	b.data = append(b.data, p...)
	return len(p), nil
}

func (b *bytesBuffer) Bytes() []byte {
	return b.data
}

func (b *bytesBuffer) Reset() {
	b.data = b.data[:0]
}

func getBuffer() *bytesBuffer {
	buf := bufferPool.Get().(*bytesBuffer)
	buf.Reset()
	return buf
}

func putBuffer(buf *bytesBuffer) {
	if cap(buf.data) > 10*1024*1024 { // 10MB max pool size
		return
	}
	bufferPool.Put(buf)
}

// WebSocket stream handler
func wsStreamHandler(w http.ResponseWriter, r *http.Request) {
	clientsMutex.Lock()
	clientCount := len(clientsMap)
	if clientCount >= configMaxClients {
		clientsMutex.Unlock()
		http.Error(w, "Too many clients", http.StatusServiceUnavailable)
		return
	}
	clientsMutex.Unlock()

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.EnableWriteCompression(false)

	// Create dedicated channel for this client
	clientChan := make(chan []byte, configBuffer)

	// Register client
	clientsMutex.Lock()
	clientsMap[conn] = clientChan
	clientsMutex.Unlock()

	// Unregister on disconnect
	defer func() {
		clientsMutex.Lock()
		delete(clientsMap, conn)
		close(clientChan)
		clientsMutex.Unlock()
	}()

	// Send frames to this client
	for {
		select {
		case frame, ok := <-clientChan:
			if !ok {
				return
			}
			_ = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
			err = conn.WriteMessage(websocket.BinaryMessage, frame)
			if err != nil {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}

// Serve viewer HTML
func viewerHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Write(viewerHTML)
}

// Minimal logging middleware
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No logging in stealth mode
		next.ServeHTTP(w, r)
	})
}

func showHelp() {
	fmt.Println("\nScreen Mirror - Stealth Screen Sharing Tool")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println("\nUsage:")
	fmt.Println("  mirror.exe                - Show help")
	fmt.Println("  mirror.exe start [flags]  - Start the screen mirror server")
	fmt.Println("  mirror.exe stop           - Stop running server")
	fmt.Println("  mirror.exe status         - Show server status")
	fmt.Println("\nStart Flags:")
	fmt.Println("  -p PORT        Server port (default: 8080)")
	fmt.Println("  -fps FPS       Frames per second (default: 60, range: 10-120)")
	fmt.Println("  -q QUALITY     JPEG quality (default: 85, range: 1-100)")
	fmt.Println("  -clients N     Max concurrent viewers (default: 3, range: 1-10)")
	fmt.Println("  -buffer N      Frame buffer size (default: 2, range: 1-10)")
	fmt.Println("\nExamples:")
	fmt.Println("  mirror.exe start")
	fmt.Println("  mirror.exe start -p 9000")
	fmt.Println("  mirror.exe start -p 8080 -fps 30 -q 70 -clients 5")
	fmt.Println()
}

func isServerRunning() bool {
	exe, _ := os.Executable()
	exeName := filepath.Base(exe)
	exeDir := filepath.Dir(exe)

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	process32First := kernel32.NewProc("Process32FirstW")
	process32Next := kernel32.NewProc("Process32NextW")

	const TH32CS_SNAPPROCESS = 0x00000002
	handle, _, _ := createToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if handle == 0 {
		return false
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	var pe struct {
		Size              uint32
		CntUsage          uint32
		ProcessID         uint32
		DefaultHeapID     uintptr
		ModuleID          uint32
		CntThreads        uint32
		ParentProcessID   uint32
		PriorityClassBase int32
		Flags             uint32
		ExeFile           [260]uint16
	}
	pe.Size = uint32(unsafe.Sizeof(pe))

	ret, _, _ := process32First.Call(handle, uintptr(unsafe.Pointer(&pe)))
	if ret != 0 {
		for {
			procName := syscall.UTF16ToString(pe.ExeFile[:])
			if strings.EqualFold(procName, exeName) && pe.ProcessID != uint32(os.Getpid()) {
				procHandle, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE|syscall.PROCESS_QUERY_INFORMATION, false, pe.ProcessID)
				if err == nil {
					queryFullProcessImageName := kernel32.NewProc("QueryFullProcessImageNameW")
					buffer := make([]uint16, 260)
					size := uint32(len(buffer))
					ret, _, _ := queryFullProcessImageName.Call(
						uintptr(procHandle),
						0,
						uintptr(unsafe.Pointer(&buffer[0])),
						uintptr(unsafe.Pointer(&size)),
					)

					if ret > 0 {
						procPath := syscall.UTF16ToString(buffer[:])
						procDir := filepath.Dir(procPath)

						if strings.EqualFold(procDir, exeDir) {
							syscall.CloseHandle(procHandle)
							return true
						}
					}
					syscall.CloseHandle(procHandle)
				}
			}

			ret, _, _ = process32Next.Call(handle, uintptr(unsafe.Pointer(&pe)))
			if ret == 0 {
				break
			}
		}
	}

	return false
}

func main() {
	// No arguments = show help
	if len(os.Args) < 2 {
		showHelp()
		return
	}

	command := os.Args[1]

	// Handle help command
	if command == "--help" || command == "-h" || command == "help" {
		showHelp()
		return
	}

	// Handle status command
	if command == "status" {
		showStatus()
		return
	}

	// Handle stop command
	if command == "stop" {
		stopServer()
		return
	}

	// Handle daemon command (internal use)
	if command == "daemon" {
		if len(os.Args) < 3 {
			return
		}
		// Parse daemon arguments: daemon PORT FPS QUALITY CLIENTS BUFFER
		serverPort, _ = strconv.Atoi(os.Args[2])
		if len(os.Args) > 3 {
			configFPS, _ = strconv.Atoi(os.Args[3])
		}
		if len(os.Args) > 4 {
			configQuality, _ = strconv.Atoi(os.Args[4])
		}
		if len(os.Args) > 5 {
			configMaxClients, _ = strconv.Atoi(os.Args[5])
		}
		if len(os.Args) > 6 {
			configBuffer, _ = strconv.Atoi(os.Args[6])
		}
		// Frame channels created per-client in broadcast system
		runDaemon()
		return
	}

	// Handle start command with flags
	if command == "start" {
		// Check if server is already running
		if isServerRunning() {
			fmt.Println("✗ Error: Server is already running")
			fmt.Println("  Use 'mirror.exe stop' to stop it first, or 'mirror.exe status' to check status")
			return
		}

		startCmd := flag.NewFlagSet("start", flag.ExitOnError)
		port := startCmd.Int("p", 8080, "Server port")
		fps := startCmd.Int("fps", 60, "Frames per second (10-120)")
		quality := startCmd.Int("q", 85, "JPEG quality (1-100)")
		clients := startCmd.Int("clients", 3, "Max concurrent viewers (1-10)")
		buffer := startCmd.Int("buffer", 2, "Frame buffer size (1-10)")

		startCmd.Parse(os.Args[2:])

		// Validate inputs
		if *port < 1 || *port > 65535 {
			fmt.Println("Error: Port must be between 1 and 65535")
			return
		}
		if *fps < 10 || *fps > 120 {
			fmt.Println("Error: FPS must be between 10 and 120")
			return
		}
		if *quality < 1 || *quality > 100 {
			fmt.Println("Error: Quality must be between 1 and 100")
			return
		}
		if *clients < 1 || *clients > 10 {
			fmt.Println("Error: Max clients must be between 1 and 10")
			return
		}
		if *buffer < 1 || *buffer > 10 {
			fmt.Println("Error: Buffer size must be between 1 and 10")
			return
		}

		// Check if port is already in use
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			fmt.Printf("✗ Error: Port %d is already in use\n", *port)
			return
		}
		listener.Close()

		serverPort = *port
		configFPS = *fps
		configQuality = *quality
		configMaxClients = *clients
		configBuffer = *buffer

		// Start as background process
		exe, _ := os.Executable()

		// Create detached process with all parameters
		var sI syscall.StartupInfo
		var pI syscall.ProcessInformation

		argv, _ := syscall.UTF16PtrFromString(fmt.Sprintf(`"%s" daemon %d %d %d %d %d`, exe, serverPort, configFPS, configQuality, configMaxClients, configBuffer))
		createErr := syscall.CreateProcess(
			nil,
			argv,
			nil,
			nil,
			false,
			syscall.CREATE_NEW_PROCESS_GROUP|0x00000008, // DETACHED_PROCESS
			nil,
			nil,
			&sI,
			&pI,
		)

		if createErr != nil {
			fmt.Println("Failed to start background process")
			return
		}

		syscall.CloseHandle(pI.Process)
		syscall.CloseHandle(pI.Thread)

		// Wait a moment for daemon to start
		time.Sleep(2 * time.Second)

		// Display info
		fmt.Println()
		fmt.Printf("✓ Server started on port %d\n", serverPort)
		fmt.Printf("  FPS: %d | Quality: %d | Max Clients: %d | Buffer: %d\n", configFPS, configQuality, configMaxClients, configBuffer)
		fmt.Println()

		// Display IPs
		displayIPs := []string{}
		addrs, _ := net.InterfaceAddrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ip := ipnet.IP.String()
					if !strings.HasPrefix(ip, "169.254.") {
						displayIPs = append(displayIPs, ip)
					}
				}
			}
		}
		if len(displayIPs) > 0 {
			fmt.Println("Access URLs:")
			for _, ip := range displayIPs {
				fmt.Printf("  http://%s:%d\n", ip, serverPort)
			}
		} else {
			fmt.Printf("Access URL:\n  http://localhost:%d\n", serverPort)
		}
		fmt.Println()
		return
	}

	// Unknown command
	fmt.Printf("Unknown command: %s\n", command)
	fmt.Println("Use 'mirror.exe --help' for usage information")
}

func runDaemon() {
	// Hide console immediately
	hideConsole()

	// Set process priority to low (stealth mode)
	runtime.GOMAXPROCS(2) // Limit CPU cores

	// Initialize shutdown context
	shutdownCtx, cancelFunc = context.WithCancel(context.Background())

	// serverPort is already set by main() before spawning daemon

	// Create server
	mux := http.NewServeMux()
	mux.HandleFunc("/", viewerHandler)
	mux.HandleFunc("/ws", wsStreamHandler)

	addr := fmt.Sprintf("0.0.0.0:%d", serverPort)
	server := &http.Server{
		Addr:           addr,
		Handler:        loggingMiddleware(mux),
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   0,
		MaxHeaderBytes: 1 << 20,
		// Disable Nagle's algorithm for lower latency
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tcpConn, ok := c.(*net.TCPConn); ok {
				_ = tcpConn.SetNoDelay(true)
				_ = tcpConn.SetWriteBuffer(2 * 1024 * 1024) // 2MB buffer
			}
			return ctx
		},
	}

	// Start capture in background with context
	go captureLoop(shutdownCtx)

	// Start server in background
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Server failed
		}
	}()

	// Wait for shutdown signal
	<-shutdownChan
	
	// Cancel context to stop captureLoop
	cancelFunc()
	
	// Shutdown server gracefully
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

// Stop server command
func stopServer() {
	fmt.Println("Stopping Screen Mirror...")

	// Find and kill process by executable name
	exePath, _ := os.Executable()
	exeName := filepath.Base(exePath)
	exeDir := filepath.Dir(exePath)

	// Get all processes with same name
	if runtime.GOOS == "windows" {
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
		process32First := kernel32.NewProc("Process32FirstW")
		process32Next := kernel32.NewProc("Process32NextW")

		const TH32CS_SNAPPROCESS = 0x00000002

		handle, _, _ := snapshot.Call(TH32CS_SNAPPROCESS, 0)
		if handle == 0 {
			fmt.Println("✗ Failed to enumerate processes")
			return
		}
		defer syscall.CloseHandle(syscall.Handle(handle))

		type ProcessEntry32 struct {
			Size            uint32
			Usage           uint32
			ProcessID       uint32
			DefaultHeapID   uintptr
			ModuleID        uint32
			Threads         uint32
			ParentProcessID uint32
			PriClassBase    int32
			Flags           uint32
			ExeFile         [260]uint16
		}

		var pe ProcessEntry32
		pe.Size = uint32(unsafe.Sizeof(pe))

		ret, _, _ := process32First.Call(handle, uintptr(unsafe.Pointer(&pe)))
		if ret == 0 {
			fmt.Println("✗ No processes found")
			return
		}

		stopped := false
		for {
			procName := syscall.UTF16ToString(pe.ExeFile[:])

			// Check if this is our process
			if strings.EqualFold(procName, exeName) {
				// Get process handle
				procHandle, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE|syscall.PROCESS_QUERY_INFORMATION, false, pe.ProcessID)
				if err == nil {
					// Try to get executable path
					var buffer [syscall.MAX_PATH]uint16
					size := uint32(len(buffer))

					psapi := syscall.NewLazyDLL("psapi.dll")
					getModuleFileNameEx := psapi.NewProc("GetModuleFileNameExW")

					ret, _, _ := getModuleFileNameEx.Call(
						uintptr(procHandle),
						0,
						uintptr(unsafe.Pointer(&buffer[0])),
						uintptr(size),
					)

					if ret > 0 {
						procPath := syscall.UTF16ToString(buffer[:])
						procDir := filepath.Dir(procPath)

						// Kill only if in same directory
						if strings.EqualFold(procDir, exeDir) {
							syscall.TerminateProcess(procHandle, 0)
							fmt.Printf("✓ Stopped process PID: %d\n", pe.ProcessID)
							stopped = true
						}
					}

					syscall.CloseHandle(procHandle)
				}
			}

			ret, _, _ = process32Next.Call(handle, uintptr(unsafe.Pointer(&pe)))
			if ret == 0 {
				break
			}
		}

		if stopped {
			fmt.Println("✓ Server stopped")
		} else {
			fmt.Println("✗ No running server found")
		}
	}
}

// Show server status
func showStatus() {
	fmt.Println("\nScreen Mirror Status:")
	fmt.Println(strings.Repeat("=", 50))

	// Check if process is running
	exe, _ := os.Executable()
	exeName := filepath.Base(exe)
	exeDir := filepath.Dir(exe)

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	process32First := kernel32.NewProc("Process32FirstW")
	process32Next := kernel32.NewProc("Process32NextW")

	const TH32CS_SNAPPROCESS = 0x00000002
	handle, _, _ := createToolhelp32Snapshot.Call(TH32CS_SNAPPROCESS, 0)
	if handle == 0 {
		fmt.Println("✗ Cannot check process status")
		return
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	var pe struct {
		Size              uint32
		CntUsage          uint32
		ProcessID         uint32
		DefaultHeapID     uintptr
		ModuleID          uint32
		CntThreads        uint32
		ParentProcessID   uint32
		PriorityClassBase int32
		Flags             uint32
		ExeFile           [260]uint16
	}
	pe.Size = uint32(unsafe.Sizeof(pe))

	found := false
	ret, _, _ := process32First.Call(handle, uintptr(unsafe.Pointer(&pe)))
	if ret != 0 {
		for {
			procName := syscall.UTF16ToString(pe.ExeFile[:])
			if strings.EqualFold(procName, exeName) && pe.ProcessID != uint32(os.Getpid()) {
				procHandle, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE|syscall.PROCESS_QUERY_INFORMATION, false, pe.ProcessID)
				if err == nil {
					queryFullProcessImageName := kernel32.NewProc("QueryFullProcessImageNameW")
					buffer := make([]uint16, 260)
					size := uint32(len(buffer))
					ret, _, _ := queryFullProcessImageName.Call(
						uintptr(procHandle),
						0,
						uintptr(unsafe.Pointer(&buffer[0])),
						uintptr(unsafe.Pointer(&size)),
					)

					if ret > 0 {
						procPath := syscall.UTF16ToString(buffer[:])
						procDir := filepath.Dir(procPath)

						if strings.EqualFold(procDir, exeDir) {
							found = true
							fmt.Printf("✓ Server is running (PID: %d)\n", pe.ProcessID)
							syscall.CloseHandle(procHandle)
							break
						}
					}
					syscall.CloseHandle(procHandle)
				}
			}

			ret, _, _ = process32Next.Call(handle, uintptr(unsafe.Pointer(&pe)))
			if ret == 0 {
				break
			}
		}
	}

	if !found {
		fmt.Println("✗ Server is not running")
		fmt.Println("\nTo start the server, use: mirror.exe start")
	}

	fmt.Println()
}
