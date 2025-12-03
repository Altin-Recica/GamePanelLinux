package main

import (
	"bufio"
	"context"
	"archive/tar"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"compress/gzip"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed templates/*.html templates/partials/*.html
var templateFS embed.FS

type ServerType string

const (
	ServerRust      ServerType = "rust"
	ServerMinecraft ServerType = "minecraft"
)

type ConsoleBuffer struct {
	lines []string
	max   int
	mu    sync.Mutex
}

func NewConsoleBuffer(max int) *ConsoleBuffer {
	return &ConsoleBuffer{max: max}
}

func (b *ConsoleBuffer) Append(line string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return
	}
	b.lines = append(b.lines, line)
	if len(b.lines) > b.max {
		b.lines = b.lines[len(b.lines)-b.max:]
	}
}

func (b *ConsoleBuffer) Lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.lines))
	copy(out, b.lines)
	return out
}

type RustConfig struct {
	ServerName      string  `json:"server_name"`
	Description     string  `json:"description"`
	MaxPlayers      int     `json:"max_players"`
	Port            int     `json:"port"`
	Seed            string  `json:"seed"`
	WorldSize       int     `json:"world_size"`
	MapType         string  `json:"map_type"`
	EnableEAC       bool    `json:"enable_eac"`
	Secure          bool    `json:"secure"`
	Encryption      bool    `json:"encryption"` // when true, use strongest encryption level
	EnableRCON      bool    `json:"enable_rcon"`
	RconPort        int     `json:"rcon_port"`
	RconPassword    string  `json:"rcon_password"`
	LevelURL        string  `json:"level_url"`
	SaveInterval    int     `json:"save_interval"`
	PVEMode         bool    `json:"pve_mode"`
	DecayScale      float64 `json:"decay_scale"`
	CraftingSpeed   float64 `json:"crafting_speed"`
	ExtraLaunchArgs string  `json:"extra_launch_args"`
	ExtraServerCfg  string  `json:"extra_server_cfg"`
	BinaryPath      string  `json:"binary_path"`
	WorkingDir      string  `json:"working_dir"`
	Identity        string  `json:"identity"`
}

type MinecraftConfig struct {
	MOTD             string `json:"motd"`
	MaxPlayers       int    `json:"max_players"`
	Port             int    `json:"port"`
	LevelName        string `json:"level_name"`
	LevelSeed        string `json:"level_seed"`
	Gamemode         string `json:"gamemode"`
	Difficulty       string `json:"difficulty"`
	Hardcore         bool   `json:"hardcore"`
	PVP              bool   `json:"pvp"`
	AllowFlight      bool   `json:"allow_flight"`
	ViewDistance     int    `json:"view_distance"`
	SimulationDist   int    `json:"simulation_distance"`
	OnlineMode       bool   `json:"online_mode"`
	Whitelist        bool   `json:"whitelist"`
	EnableRCON       bool   `json:"enable_rcon"`
	RconPort         int    `json:"rcon_port"`
	RconPassword     string `json:"rcon_password"`
	MinRAM           string `json:"min_ram"`
	MaxRAM           string `json:"max_ram"`
	ExtraJVMArgs     string `json:"extra_jvm_args"`
	JarPath          string `json:"jar_path"`
	WorkingDir       string `json:"working_dir"`
	JavaPath         string `json:"java_path"`
}

type ServerConfig struct {
	ID         string           `json:"id"`
	Name       string           `json:"name"`
	Type       ServerType       `json:"type"`
	Rust       *RustConfig      `json:"rust,omitempty"`
	Minecraft  *MinecraftConfig `json:"minecraft,omitempty"`
	CreatedAt  time.Time        `json:"created_at"`
	LastUpdate time.Time        `json:"last_update"`
}

type ScheduleItem struct {
	ID        string     `json:"id"`
	ServerID  string     `json:"server_id"`
	Server    ServerType `json:"server"`
	Action    string     `json:"action"`
	Time      string     `json:"time"`
	Frequency string     `json:"frequency"` // daily or once
	NextRun   time.Time  `json:"next_run"`
}

type GameServer struct {
	Type      ServerType
	Cmd       *exec.Cmd
	Stdin     io.WriteCloser
	Console   *ConsoleBuffer
	Running   bool
	LastStart time.Time
	LastStop  time.Time
	mu        sync.Mutex
}

type Manager struct {
	dataDir       string
	registryPath  string
	scheduleURI   string
	servers       map[string]*GameServer
	registry      map[string]ServerConfig
	scheduler     *Scheduler
	mu            sync.Mutex
}

type Scheduler struct {
	path    string
	items   []ScheduleItem
	mu      sync.Mutex
	manager *Manager
	stop    chan struct{}
}

type App struct {
	manager    *Manager
	templates  *template.Template
	authSecret []byte
	password   string
}

func main() {
	dataDir, _ := filepath.Abs(filepath.Join(".", "data"))
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		log.Fatalf("failed to create data dir: %v", err)
	}

	password := os.Getenv("PANEL_PASSWORD")
	if password == "" {
		password = "admin"
		log.Println("PANEL_PASSWORD not set, using default 'admin'. Please change it.")
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		log.Fatalf("failed to generate secret: %v", err)
	}

	tmpl := template.Must(template.New("base").Funcs(template.FuncMap{
		"upper":       strings.ToUpper,
		"friendlyRun": friendlyRun,
		"formatTime":  func(t time.Time) string { return t.Format("Jan 2 15:04:05") },
		"dict": func(values ...any) map[string]any {
			if len(values)%2 != 0 {
				panic("dict expects even number of args")
			}
			m := make(map[string]any, len(values)/2)
			for i := 0; i < len(values); i += 2 {
				key, _ := values[i].(string)
				m[key] = values[i+1]
			}
			return m
		},
	}).ParseFS(templateFS, "templates/*.html", "templates/partials/*.html"))

	manager, err := NewManager(dataDir)
	if err != nil {
		log.Fatalf("failed to init manager: %v", err)
	}

	scheduler := NewScheduler(filepath.Join(dataDir, "schedules.json"), manager)
	manager.scheduler = scheduler
	scheduler.Start()

	app := &App{
		manager:    manager,
		templates:  tmpl,
		authSecret: secret,
		password:   password,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/login", app.handleLogin)
	mux.HandleFunc("/logout", app.handleLogout)
	mux.Handle("/", app.requireAuth(http.HandlerFunc(app.handleHome)))
	mux.Handle("/servers/create", app.requireAuth(http.HandlerFunc(app.handleCreateServer)))
	mux.Handle("/servers/", app.requireAuth(http.HandlerFunc(app.handleServerDispatch)))

	server := &http.Server{
		Addr:         ":6767",
		Handler:      logRequests(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	log.Println("Panel ready on http://localhost:6767")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func friendlyRun(s bool) string {
	if s {
		return "Running"
	}
	return "Stopped"
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic serving %s %s: %v", r.Method, r.URL.Path, rec)
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func NewManager(dataDir string) (*Manager, error) {
	m := &Manager{
		dataDir:       dataDir,
		scheduleURI:   filepath.Join(dataDir, "schedules.json"),
		registryPath:  filepath.Join(dataDir, "servers.json"),
		servers:       map[string]*GameServer{},
		registry:      map[string]ServerConfig{},
	}

	if err := m.loadRegistry(); err != nil {
		return nil, err
	}

	// create consoles
	for id, cfg := range m.registry {
		m.servers[id] = &GameServer{Type: cfg.Type, Console: NewConsoleBuffer(400)}
	}
	return m, nil
}

func (m *Manager) loadRegistry() error {
	var items []ServerConfig
	if err := readJSON(m.registryPath, &items); err != nil {
		items = []ServerConfig{}
	}
	m.registry = map[string]ServerConfig{}
	for _, it := range items {
		m.registry[it.ID] = it
	}
	_ = m.ensureDirs()
	return m.saveRegistry()
}

func (m *Manager) saveRegistry() error {
	var list []ServerConfig
	for _, v := range m.registry {
		list = append(list, v)
	}
	return writeJSON(m.registryPath, list)
}

func applyRustPaths(id string, cfg RustConfig) *RustConfig {
	base := filepath.Join("servers", id)
	_ = os.MkdirAll(base, 0755)
	cfg.WorkingDir = base
	cfg.BinaryPath = filepath.Join(base, "RustDedicated")
	cfg.Identity = id
	return &cfg
}

func applyMinecraftPaths(id string, cfg MinecraftConfig) *MinecraftConfig {
	base := filepath.Join("servers", id)
	_ = os.MkdirAll(base, 0755)
	cfg.WorkingDir = base
	cfg.JarPath = filepath.Join(base, "server.jar")
	return &cfg
}

func (m *Manager) ensureDirs() error {
	for id, cfg := range m.registry {
		updated := cfg
		switch cfg.Type {
		case ServerRust:
			if cfg.Rust != nil {
				updated.Rust = applyRustPaths(id, *cfg.Rust)
			}
		case ServerMinecraft:
			if cfg.Minecraft != nil {
				updated.Minecraft = applyMinecraftPaths(id, *cfg.Minecraft)
			}
		}
		m.registry[id] = updated
	}
	return nil
}

func defaultRustConfig() RustConfig {
	return RustConfig{
		ServerName:      "Rust Base",
		Description:     "Rust server managed by the panel",
		MaxPlayers:      50,
		Port:            28015,
		Seed:            "12345",
		WorldSize:       3500,
		MapType:         "Procedural Map",
		EnableEAC:       true,
		Secure:          true,
		Encryption:      true,
		EnableRCON:      true,
		RconPort:        28016,
		RconPassword:    "rustpass",
		LevelURL:        "",
		SaveInterval:    300,
		PVEMode:         false,
		DecayScale:      1.0,
		CraftingSpeed:   1.0,
		ExtraLaunchArgs: "",
		ExtraServerCfg:  "",
		BinaryPath:      "",
		WorkingDir:      "",
		Identity:        "",
	}
}

func defaultMinecraftConfig() MinecraftConfig {
	return MinecraftConfig{
		MOTD:           "Minecraft Server Panel",
		MaxPlayers:     20,
		Port:           25565,
		LevelName:      "world",
		LevelSeed:      "",
		Gamemode:       "survival",
		Difficulty:     "easy",
		Hardcore:       false,
		PVP:            true,
		AllowFlight:    false,
		ViewDistance:   10,
		SimulationDist: 10,
		OnlineMode:     true,
		Whitelist:      false,
		EnableRCON:     true,
		RconPort:       25575,
		RconPassword:   "changeme",
		MinRAM:         "1G",
		MaxRAM:         "2G",
		ExtraJVMArgs:   "",
		JarPath:        "",
		WorkingDir:     "",
		JavaPath:       "java",
	}
}

func readJSON(path string, v any) error {
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(content, v)
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	content, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, content, 0644)
}

func (m *Manager) ServerStatus(id string) (running bool, lastStart, lastStop time.Time) {
	s := m.servers[id]
	if s == nil {
		return false, time.Time{}, time.Time{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Running, s.LastStart, s.LastStop
}

func (m *Manager) StartServer(id string) error {
	cfg, ok := m.registry[id]
	if !ok {
		return errors.New("server not found")
	}
	if m.servers[id] == nil {
		return errors.New("server process entry missing")
	}
	switch cfg.Type {
	case ServerRust:
		return m.startRust(id, cfg)
	case ServerMinecraft:
		return m.startMinecraft(id, cfg)
	}
	return fmt.Errorf("unknown server type")
}

func (m *Manager) StopServer(id string) error {
	cfg, ok := m.registry[id]
	if !ok {
		return errors.New("server not found")
	}
	if m.servers[id] == nil {
		return errors.New("server process entry missing")
	}
	switch cfg.Type {
	case ServerRust:
		return m.stopServer(id, "quit")
	case ServerMinecraft:
		return m.stopServer(id, "stop")
	}
	return fmt.Errorf("unknown server")
}

func (m *Manager) RestartServer(id string) error {
	if err := m.StopServer(id); err != nil && !strings.Contains(err.Error(), "not running") {
		return err
	}
	time.Sleep(2 * time.Second)
	return m.StartServer(id)
}

func (m *Manager) SendCommand(id string, cmd string) error {
	s := m.servers[id]
	if s == nil {
		return errors.New("server not found")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.Running || s.Stdin == nil {
		return errors.New("server not running")
	}
	_, err := io.WriteString(s.Stdin, cmd+"\n")
	return err
}

func (m *Manager) EnsureSteamCMD() (string, error) {
	base := filepath.Join(m.dataDir, "steamcmd")
	baseAbs, _ := filepath.Abs(base)
	target := filepath.Join(baseAbs, "steamcmd.sh")
	if _, err := os.Stat(target); err == nil {
		return target, nil
	}
	if err := os.MkdirAll(baseAbs, 0755); err != nil {
		return "", err
	}
	url := "https://steamcdn-a.akamaihd.net/client/installer/steamcmd_linux.tar.gz"
	tmp := filepath.Join(baseAbs, "steamcmd_linux.tar.gz")
	if err := downloadFile(url, tmp, 2*time.Minute); err != nil {
		return "", err
	}
	if err := untarGz(tmp, baseAbs); err != nil {
		return "", err
	}
	_ = os.Chmod(target, 0755)
	return target, nil
}

func untarGz(archive, dest string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		target := filepath.Join(dest, hdr.Name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			out, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
			if err := os.Chmod(target, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		}
	}
	return nil
}

// Paper helpers
type paperProject struct {
	ProjectID string   `json:"project_id"`
	Versions  []string `json:"versions"`
}

type paperVersionInfo struct {
	ProjectID string `json:"project_id"`
	Version   string `json:"version"`
	Builds    []int  `json:"builds"`
}

type paperBuildInfo struct {
	ProjectID string                `json:"project_id"`
	Version   string                `json:"version"`
	Build     int                   `json:"build"`
	Time      string                `json:"time"`
	Changes   []any                 `json:"changes"`
	Downloads map[string]paperFile  `json:"downloads"`
}

type paperFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Purpur helpers
// Vanilla helpers
type vanillaManifest struct {
	Versions []struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	} `json:"versions"`
}

type vanillaVersionDetail struct {
	Downloads struct {
		Server struct {
			URL  string `json:"url"`
			Sha1 string `json:"sha1"`
			Size int64  `json:"size"`
		} `json:"server"`
	} `json:"downloads"`
}

func fetchPaperVersions() ([]string, error) {
	resp, err := http.Get("https://api.papermc.io/v2/projects/paper")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var p paperProject
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, err
	}
	// newest first
	for i, j := 0, len(p.Versions)-1; i < j; i, j = i+1, j-1 {
		p.Versions[i], p.Versions[j] = p.Versions[j], p.Versions[i]
	}
	return p.Versions, nil
}

func fetchPaperBuilds(version string) ([]int, error) {
	if version == "" {
		return nil, errors.New("version required")
	}
	resp, err := http.Get(fmt.Sprintf("https://api.papermc.io/v2/projects/paper/versions/%s", url.PathEscape(version)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var v paperVersionInfo
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, err
	}
	// newest first
	for i, j := 0, len(v.Builds)-1; i < j; i, j = i+1, j-1 {
		v.Builds[i], v.Builds[j] = v.Builds[j], v.Builds[i]
	}
	return v.Builds, nil
}

func fetchPaperBuildInfo(version string, build string) (*paperBuildInfo, error) {
	if version == "" || build == "" {
		return nil, errors.New("version and build required")
	}
	resp, err := http.Get(fmt.Sprintf("https://api.papermc.io/v2/projects/paper/versions/%s/builds/%s", url.PathEscape(version), url.PathEscape(build)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var b paperBuildInfo
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		return nil, err
	}
	return &b, nil
}

func (m *Manager) stopServer(id string, stopCommand string) error {
	s := m.servers[id]
	s.mu.Lock()
	if !s.Running {
		s.mu.Unlock()
		return errors.New("not running")
	}
	stdin := s.Stdin
	cmd := s.Cmd
	s.mu.Unlock()

	if stdin != nil {
		_, _ = io.WriteString(stdin, stopCommand+"\n")
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
	case err := <-done:
		if err != nil {
			return err
		}
	}

	s.mu.Lock()
	s.Running = false
	s.LastStop = time.Now()
	s.mu.Unlock()
	return nil
}

func (m *Manager) startRust(id string, serverCfg ServerConfig) error {
	cfg := *serverCfg.Rust
	s := m.servers[id]

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Running {
		return errors.New("rust already running")
	}

	workingDir, err := filepath.Abs(cfg.WorkingDir)
	if err != nil {
		return err
	}
	binaryPath := cfg.BinaryPath
	if !filepath.IsAbs(binaryPath) {
		binaryPath = filepath.Join(workingDir, filepath.Base(binaryPath))
	}

	if cfg.EnableEAC && !cfg.Secure {
		cfg.Secure = true // keep "secure" flag for UI; EAC implies secure intent
	}
	if cfg.EnableEAC && cfg.EnableRCON && cfg.RconPassword == "" {
		cfg.RconPassword = "changeme"
	}

	if err := m.writeRustConfig(cfg); err != nil {
		return err
	}

	if _, err := os.Stat(binaryPath); err != nil {
		return fmt.Errorf("rust binary missing at %s", binaryPath)
	}

	level := normalizeRustMapType(cfg.MapType)

	encLevel := "0"
	if cfg.Encryption || cfg.Secure || cfg.EnableEAC {
		encLevel = "2" // per Rust warning: 2 required for secure visibility
	}

	args := []string{
		"-batchmode",
		"+server.hostname", cfg.ServerName,
		"+server.description", cfg.Description,
		"+server.port", fmt.Sprint(cfg.Port),
		"+server.seed", cfg.Seed,
		"+server.worldsize", fmt.Sprint(cfg.WorldSize),
		"+server.level", level,
		"+server.maxplayers", fmt.Sprint(cfg.MaxPlayers),
		"+server.identity", cfg.Identity,
		"+server.saveinterval", fmt.Sprint(cfg.SaveInterval),
		"+server.encryption", encLevel,
		"+server.pve", boolToInt(cfg.PVEMode),
	}

	if cfg.EnableRCON {
		args = append(args,
			"+rcon.port", fmt.Sprint(cfg.RconPort),
			"+rcon.password", cfg.RconPassword,
			"+rcon.web", "1",
		)
	}

	if !cfg.EnableEAC {
		args = append(args, "-noeac")
	}

	if cfg.LevelURL != "" {
		args = append(args, "+server.levelurl", cfg.LevelURL)
	}

	if strings.TrimSpace(cfg.ExtraLaunchArgs) != "" {
		args = append(args, strings.Fields(cfg.ExtraLaunchArgs)...)
	}

	cmd := exec.Command(binaryPath, args...)
	cmd.Dir = workingDir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	s.Running = true
	s.LastStart = time.Now()
	s.Cmd = cmd
	s.Stdin = stdin

	go streamToBuffer(stdout, s.Console, "")
	go streamToBuffer(stderr, s.Console, "ERR")
	go func() {
		err := cmd.Wait()
		s.mu.Lock()
		s.Running = false
		s.LastStop = time.Now()
		if err != nil {
			s.Console.Append(fmt.Sprintf("process exited: %v", err))
		} else {
			s.Console.Append("process exited cleanly")
		}
		s.mu.Unlock()
	}()

	return nil
}

func (m *Manager) startMinecraft(id string, serverCfg ServerConfig) error {
	cfg := *serverCfg.Minecraft
	s := m.servers[id]

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Running {
		return errors.New("minecraft already running")
	}

	if err := m.writeMinecraftProperties(cfg); err != nil {
		return err
	}

	if err := os.MkdirAll(cfg.WorkingDir, 0755); err != nil {
		return err
	}
	workingDir, err := filepath.Abs(cfg.WorkingDir)
	if err != nil {
		return err
	}
	eulaPath := filepath.Join(workingDir, "eula.txt")
	if err := os.WriteFile(eulaPath, []byte("eula=true\n"), 0644); err != nil {
		return fmt.Errorf("writing eula.txt: %w", err)
	}
	jarPath := cfg.JarPath
	if !filepath.IsAbs(jarPath) {
		jarPath = filepath.Join(workingDir, filepath.Base(jarPath))
	}
	javaPath := cfg.JavaPath
	if p, err := exec.LookPath(javaPath); err == nil {
		javaPath = p
	} else {
		return fmt.Errorf("java runtime not found at %s", cfg.JavaPath)
	}
	if _, err := os.Stat(jarPath); err != nil {
		return fmt.Errorf("jar missing at %s", jarPath)
	}

	args := []string{
		fmt.Sprintf("-Xms%s", cfg.MinRAM),
		fmt.Sprintf("-Xmx%s", cfg.MaxRAM),
	}
	if strings.TrimSpace(cfg.ExtraJVMArgs) != "" {
		args = append(args, strings.Fields(cfg.ExtraJVMArgs)...)
	}
	args = append(args, "-jar", jarPath, "nogui")

	cmd := exec.Command(javaPath, args...)
	cmd.Dir = workingDir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	s.Running = true
	s.LastStart = time.Now()
	s.Cmd = cmd
	s.Stdin = stdin

	go streamToBuffer(stdout, s.Console, "")
	go streamToBuffer(stderr, s.Console, "ERR")
	go func() {
		err := cmd.Wait()
		s.mu.Lock()
		s.Running = false
		s.LastStop = time.Now()
		if err != nil {
			s.Console.Append(fmt.Sprintf("process exited: %v", err))
		} else {
			s.Console.Append("process exited cleanly")
		}
		s.mu.Unlock()
	}()

	return nil
}

func streamToBuffer(r io.Reader, buf *ConsoleBuffer, prefix string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := cleanAnsi(scanner.Text())
		if prefix != "" {
			line = fmt.Sprintf("[%s] %s", prefix, line)
		}
		buf.Append(line)
	}
	if err := scanner.Err(); err != nil {
		buf.Append(fmt.Sprintf("stream error: %v", err))
	}
}

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func cleanAnsi(s string) string {
	return ansiRegex.ReplaceAllString(s, "")
}

func boolToInt(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func (m *Manager) writeRustConfig(cfg RustConfig) error {
	if err := os.MkdirAll(cfg.WorkingDir, 0755); err != nil {
		return err
	}
	level := normalizeRustMapType(cfg.MapType)
	encLevel := "0"
	if cfg.Encryption || cfg.Secure || cfg.EnableEAC {
		encLevel = "2"
	}
	lines := []string{
		fmt.Sprintf(`server.hostname "%s"`, cfg.ServerName),
		fmt.Sprintf(`server.description "%s"`, cfg.Description),
		fmt.Sprintf("server.maxplayers %d", cfg.MaxPlayers),
		fmt.Sprintf("server.port %d", cfg.Port),
		fmt.Sprintf("server.seed %s", cfg.Seed),
		fmt.Sprintf("server.worldsize %d", cfg.WorldSize),
		fmt.Sprintf("server.level %s", level),
		fmt.Sprintf("server.identity %s", cfg.Identity),
		fmt.Sprintf("server.saveinterval %d", cfg.SaveInterval),
		fmt.Sprintf("server.encryption %s", encLevel),
		fmt.Sprintf("server.pve %t", cfg.PVEMode),
		fmt.Sprintf("decay.scale %.2f", cfg.DecayScale),
		fmt.Sprintf("crafting.scale %.2f", cfg.CraftingSpeed),
	}
	if cfg.LevelURL != "" {
		lines = append(lines, fmt.Sprintf("server.levelurl %s", cfg.LevelURL))
	}
	if cfg.EnableRCON {
		lines = append(lines,
			fmt.Sprintf("rcon.port %d", cfg.RconPort),
			fmt.Sprintf(`rcon.password "%s"`, cfg.RconPassword),
			"rcon.web 1",
		)
	}
	if strings.TrimSpace(cfg.ExtraServerCfg) != "" {
		lines = append(lines, cfg.ExtraServerCfg)
	}

	content := strings.Join(lines, "\n") + "\n"
	target := filepath.Join(cfg.WorkingDir, "server.cfg")
	return os.WriteFile(target, []byte(content), 0644)
}

func (m *Manager) writeMinecraftProperties(cfg MinecraftConfig) error {
	if err := os.MkdirAll(cfg.WorkingDir, 0755); err != nil {
		return err
	}
	pairs := map[string]string{
		"motd":                 cfg.MOTD,
		"max-players":          fmt.Sprint(cfg.MaxPlayers),
		"server-port":          fmt.Sprint(cfg.Port),
		"level-name":           cfg.LevelName,
		"level-seed":           cfg.LevelSeed,
		"gamemode":             strings.ToLower(cfg.Gamemode),
		"difficulty":           strings.ToLower(cfg.Difficulty),
		"hardcore":             strconv.FormatBool(cfg.Hardcore),
		"pvp":                  strconv.FormatBool(cfg.PVP),
		"allow-flight":         strconv.FormatBool(cfg.AllowFlight),
		"view-distance":        fmt.Sprint(cfg.ViewDistance),
		"simulation-distance":  fmt.Sprint(cfg.SimulationDist),
		"online-mode":          strconv.FormatBool(cfg.OnlineMode),
		"white-list":           strconv.FormatBool(cfg.Whitelist),
		"enable-rcon":          strconv.FormatBool(cfg.EnableRCON),
		"rcon.port":            fmt.Sprint(cfg.RconPort),
		"rcon.password":        cfg.RconPassword,
		"enable-query":         "false",
		"enable-command-block": "false",
	}

	var lines []string
	for k, v := range pairs {
		lines = append(lines, fmt.Sprintf("%s=%s", k, v))
	}
	content := strings.Join(lines, "\n") + "\n"
	target := filepath.Join(cfg.WorkingDir, "server.properties")
	return os.WriteFile(target, []byte(content), 0644)
}

func (m *Manager) PlayerCount(id string) (int, string, error) {
	cfg, ok := m.registry[id]
	if !ok {
		return 0, "", errors.New("server not found")
	}
	switch cfg.Type {
	case ServerRust:
		rc := cfg.Rust
		if rc == nil || !rc.EnableRCON {
			return 0, "", errors.New("RCON disabled")
		}
		addr := fmt.Sprintf("127.0.0.1:%d", rc.RconPort)
		out, err := queryRCON(addr, rc.RconPassword, "playerlist")
		if err != nil {
			return 0, "", err
		}
		return parsePlayerCount(out), out, nil
	case ServerMinecraft:
		mc := cfg.Minecraft
		if mc == nil || !mc.EnableRCON {
			return 0, "", errors.New("RCON disabled")
		}
		addr := fmt.Sprintf("127.0.0.1:%d", mc.RconPort)
		out, err := queryRCON(addr, mc.RconPassword, "list")
		if err != nil {
			return 0, "", err
		}
		return parsePlayerCount(out), out, nil
	default:
		return 0, "", fmt.Errorf("unknown server")
	}
}

// Source RCON implementation good enough for Rust and Minecraft.
func queryRCON(addr, password, command string) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	if err := sendRconPacket(conn, 3, password); err != nil {
		return "", err
	}
	if _, err := readRconPacket(conn); err != nil {
		return "", err
	}
	if err := sendRconPacket(conn, 2, command); err != nil {
		return "", err
	}
	resp, err := readRconPacket(conn)
	if err != nil {
		return "", err
	}
	return resp.Body, nil
}

type rconPacket struct {
	ID   int32
	Type int32
	Body string
}

func sendRconPacket(w io.Writer, packetType int32, body string) error {
	p := rconPacket{ID: 1, Type: packetType, Body: body}
	payload := append([]byte{}, int32ToBytes(p.ID)...)
	payload = append(payload, int32ToBytes(p.Type)...)
	payload = append(payload, []byte(p.Body)...)
	payload = append(payload, 0x00, 0x00)
	size := int32(len(payload))
	packet := append(int32ToBytes(size), payload...)
	_, err := w.Write(packet)
	return err
}

func readRconPacket(r io.Reader) (rconPacket, error) {
	var size int32
	if err := binaryRead(r, &size); err != nil {
		return rconPacket{}, err
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return rconPacket{}, err
	}
	id := bytesToInt32(buf[0:4])
	packetType := bytesToInt32(buf[4:8])
	body := string(buf[8 : len(buf)-2])
	if id == -1 {
		return rconPacket{}, errors.New("rcon auth failed")
	}
	return rconPacket{ID: id, Type: packetType, Body: body}, nil
}

func int32ToBytes(v int32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

func bytesToInt32(b []byte) int32 {
	return int32(b[0]) | int32(b[1])<<8 | int32(b[2])<<16 | int32(b[3])<<24
}

func binaryRead(r io.Reader, v *int32) error {
	buf := make([]byte, 4)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	*v = bytesToInt32(buf)
	return nil
}

func parsePlayerCount(out string) int {
	re := regexp.MustCompile(`(?i)(\d+)\s+player`)
	if m := re.FindStringSubmatch(out); len(m) == 2 {
		if n, err := strconv.Atoi(m[1]); err == nil {
			return n
		}
	}
	if strings.Contains(out, ":") {
		parts := strings.Split(out, ":")
		if len(parts) > 1 {
			players := strings.Split(strings.TrimSpace(parts[1]), ",")
			if len(players) == 1 && players[0] == "" {
				return 0
			}
			return len(players)
		}
	}
	return 0
}

// Scheduler
func NewScheduler(path string, manager *Manager) *Scheduler {
	s := &Scheduler{
		path:    path,
		manager: manager,
		stop:    make(chan struct{}),
	}
	_ = s.load()
	return s
}

func (s *Scheduler) Start() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for {
			select {
			case <-ticker.C:
				s.runDue()
			case <-s.stop:
				ticker.Stop()
				return
			}
		}
	}()
}

func (s *Scheduler) Stop() {
	close(s.stop)
}

func (s *Scheduler) runDue() {
	now := time.Now()
	s.mu.Lock()
	items := make([]ScheduleItem, 0, len(s.items))
	for _, item := range s.items {
		if item.NextRun.IsZero() {
			item.NextRun = nextRunFromClock(item.Time, now)
		}
		if !now.Before(item.NextRun) {
			go s.dispatch(item)
			if item.Frequency == "once" {
				continue
			}
			item.NextRun = nextRunFromClock(item.Time, now.Add(time.Minute))
		}
		items = append(items, item)
	}
	s.items = items
	s.mu.Unlock()
	_ = s.persist()
}

func (s *Scheduler) dispatch(item ScheduleItem) {
	switch strings.ToLower(item.Action) {
	case "restart":
		_ = s.manager.RestartServer(item.ServerID)
	case "start":
		_ = s.manager.StartServer(item.ServerID)
	case "stop":
		_ = s.manager.StopServer(item.ServerID)
	default:
		log.Printf("unknown action %s", item.Action)
	}
}

func (s *Scheduler) Add(serverID string, serverType ServerType, action, timeStr, frequency string) (ScheduleItem, error) {
	item := ScheduleItem{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		ServerID:  serverID,
		Server:    serverType,
		Action:    action,
		Time:      timeStr,
		Frequency: frequency,
		NextRun:   nextRunFromClock(timeStr, time.Now()),
	}
	s.mu.Lock()
	s.items = append(s.items, item)
	s.mu.Unlock()
	return item, s.persist()
}

func (s *Scheduler) Delete(id string) error {
	s.mu.Lock()
	var next []ScheduleItem
	for _, item := range s.items {
		if item.ID != id {
			next = append(next, item)
		}
	}
	s.items = next
	s.mu.Unlock()
	return s.persist()
}

func (s *Scheduler) List() []ScheduleItem {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ScheduleItem, len(s.items))
	copy(out, s.items)
	return out
}

func (s *Scheduler) ListFor(serverID string) []ScheduleItem {
	all := s.List()
	var filtered []ScheduleItem
	for _, it := range all {
		if it.ServerID == serverID {
			filtered = append(filtered, it)
		}
	}
	return filtered
}

func (s *Scheduler) persist() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeJSON(s.path, s.items)
}

func (s *Scheduler) load() error {
	var items []ScheduleItem
	if err := readJSON(s.path, &items); err != nil {
		return err
	}
	now := time.Now()
	for i, item := range items {
		if item.NextRun.IsZero() || now.After(item.NextRun) {
			items[i].NextRun = nextRunFromClock(item.Time, now)
		}
	}
	s.items = items
	return nil
}

func nextRunFromClock(clock string, now time.Time) time.Time {
	parts := strings.Split(clock, ":")
	if len(parts) != 2 {
		return now.Add(24 * time.Hour)
	}
	h, _ := strconv.Atoi(parts[0])
	m, _ := strconv.Atoi(parts[1])
	next := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next
}

// HTTP handlers and auth
func (a *App) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.isAuthed(r) {
			next.ServeHTTP(w, r)
			return
		}
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
}

func (a *App) isAuthed(r *http.Request) bool {
	c, err := r.Cookie("panel_auth")
	if err != nil {
		return false
	}
	expected := a.sign(a.password)
	return hmac.Equal([]byte(c.Value), []byte(expected))
}

func (a *App) sign(value string) string {
	mac := hmac.New(sha256.New, a.authSecret)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.FormValue("password") == a.password {
			http.SetCookie(w, &http.Cookie{
				Name:     "panel_auth",
				Value:    a.sign(a.password),
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				Expires:  time.Now().Add(24 * time.Hour),
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		a.render(w, "login.html", map[string]any{"Error": "Wrong password"})
		return
	}
	a.render(w, "login.html", nil)
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "panel_auth",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) handleHome(w http.ResponseWriter, r *http.Request) {
	var servers []ServerConfig
	for _, v := range a.manager.registry {
		servers = append(servers, v)
	}
	a.render(w, "servers.html", map[string]any{
		"Servers": servers,
	})
}

func (a *App) handleCreateServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := r.FormValue("name")
	typ := ServerType(strings.ToLower(r.FormValue("type")))
	id := fmt.Sprintf("%s-%d", typ, time.Now().UnixNano())
	cfg := ServerConfig{
		ID:         id,
		Name:       name,
		Type:       typ,
		CreatedAt:  time.Now(),
		LastUpdate: time.Now(),
	}
	switch typ {
	case ServerRust:
		cfg.Rust = applyRustPaths(id, defaultRustConfig())
	case ServerMinecraft:
		cfg.Minecraft = applyMinecraftPaths(id, defaultMinecraftConfig())
	default:
		http.Error(w, "unknown type", http.StatusBadRequest)
		return
	}
	a.manager.mu.Lock()
	a.manager.registry[id] = cfg
	a.manager.servers[id] = &GameServer{Type: typ, Console: NewConsoleBuffer(400)}
	a.manager.mu.Unlock()
	_ = a.manager.saveRegistry()
	http.Redirect(w, r, "/servers/"+id, http.StatusSeeOther)
}

func (a *App) handleServerDispatch(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/servers/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	rest := parts[1:]
	if len(rest) == 0 || rest[0] == "" {
		a.handleServerPage(w, r, id)
		return
	}
	switch rest[0] {
	case "action":
		a.handleServerAction(w, r, id, rest[1:])
	case "console":
		a.handleConsole(w, r, id)
	case "command":
		a.handleCommand(w, r, id)
	case "config":
		a.handleConfig(w, r, id)
	case "playercount":
		a.handlePlayerCount(w, r, id)
	case "schedules":
		a.handleSchedules(w, r, id)
	case "schedule":
		if len(rest) > 1 {
			a.handleScheduleDelete(w, r, id, rest[1])
		} else {
			http.NotFound(w, r)
		}
	case "install":
		if len(rest) > 1 {
			a.handleInstall(w, r, id, rest[1])
		} else {
			http.NotFound(w, r)
		}
	case "paper":
		if len(rest) < 2 {
			http.NotFound(w, r)
			return
		}
		switch rest[1] {
		case "versions":
			a.handlePaperVersions(w, r, id)
		case "builds":
			a.handlePaperBuilds(w, r, id)
		default:
			http.NotFound(w, r)
		}
	case "folia":
		if len(rest) < 2 {
			http.NotFound(w, r)
			return
		}
		switch rest[1] {
		case "versions":
			a.handleFoliaVersions(w, r, id)
		case "builds":
			a.handleFoliaBuilds(w, r, id)
		default:
			http.NotFound(w, r)
		}
	case "spigot":
		if len(rest) >= 2 && rest[1] == "versions" {
			a.handleVanillaVersions(w, r, id) // reuse vanilla version list
		} else {
			http.NotFound(w, r)
		}
	case "vanilla":
		if len(rest) >= 2 && rest[1] == "versions" {
			a.handleVanillaVersions(w, r, id)
		} else {
			http.NotFound(w, r)
		}
	case "delete":
		a.handleDeleteServer(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

func (a *App) handleServerAction(w http.ResponseWriter, r *http.Request, id string, rest []string) {
	if r.Method != http.MethodPost || len(rest) == 0 {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	action := rest[0]

	var err error
	switch action {
	case "start":
		err = a.manager.StartServer(id)
	case "stop":
		err = a.manager.StopServer(id)
	case "restart":
		err = a.manager.RestartServer(id)
	default:
		http.NotFound(w, r)
		return
	}

	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	a.renderPartialServerCard(w, id, errMsg)
}

func (a *App) handleServerPage(w http.ResponseWriter, r *http.Request, id string) {
	cfg, ok := a.manager.registry[id]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if a.manager.servers[id] == nil {
		a.manager.mu.Lock()
		if a.manager.servers[id] == nil {
			a.manager.servers[id] = &GameServer{Type: cfg.Type, Console: NewConsoleBuffer(400)}
		}
		a.manager.mu.Unlock()
	}
	status := statusMap(a.manager, id)
	data := map[string]any{
		"Server":      cfg,
		"Status":      status,
		"Schedules":   a.manager.scheduler.ListFor(id),
		"HumanTimeNow": time.Now().Format("15:04"),
	}
	switch cfg.Type {
	case ServerRust:
		data["Rust"] = cfg.Rust
		data["ConsoleID"] = "rust-console"
		data["ConsoleLines"] = a.manager.servers[id].Console.Lines()
		a.render(w, "server_rust.html", data)
	case ServerMinecraft:
		data["Minecraft"] = cfg.Minecraft
		data["ConsoleID"] = "mc-console"
		data["ConsoleLines"] = a.manager.servers[id].Console.Lines()
		a.render(w, "server_minecraft.html", data)
	default:
		http.Error(w, "unknown server type", http.StatusInternalServerError)
	}
}

func (a *App) renderPartialServerCard(w http.ResponseWriter, id string, errMsg string) {
	cfg, ok := a.manager.registry[id]
	if !ok {
		http.NotFound(w, nil)
		return
	}
	switch cfg.Type {
	case ServerRust:
		a.render(w, "partials/server_rust_card.html", map[string]any{
			"Server":     cfg,
			"Rust":       cfg.Rust,
			"Status":     statusMap(a.manager, id),
			"Error":      errMsg,
		})
	case ServerMinecraft:
		a.render(w, "partials/server_minecraft_card.html", map[string]any{
			"Server":    cfg,
			"Minecraft": cfg.Minecraft,
			"Status":    statusMap(a.manager, id),
			"Error":     errMsg,
		})
	}
}

func statusMap(m *Manager, id string) map[string]any {
	running, start, stop := m.ServerStatus(id)
	return map[string]any{"Running": running, "LastStart": start, "LastStop": stop}
}

func (a *App) handleConsole(w http.ResponseWriter, r *http.Request, id string) {
	s := a.manager.servers[id]
	if s == nil {
		fmt.Fprint(w, "")
		return
	}
	lines := s.Console.Lines()
	a.render(w, "partials/console.html", map[string]any{"Lines": lines})
}

func (a *App) handleCommand(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	cmd := strings.TrimSpace(r.FormValue("command"))
	if cmd == "" {
		fmt.Fprint(w, `<div class="text-amber-500 text-sm">Empty command.</div>`)
		return
	}
	if err := a.manager.SendCommand(id, cmd); err != nil {
		fmt.Fprintf(w, `<div class="text-amber-500 text-sm">Command failed: %v</div>`, err)
		return
	}
	a.handleConsole(w, r, id)
}

func (a *App) handleConfig(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cfg, ok := a.manager.registry[id]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	var err error
	switch cfg.Type {
	case ServerRust:
		err = a.updateRustConfig(id, r)
	case ServerMinecraft:
		err = a.updateMinecraftConfig(id, r)
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `<div class="text-red-500 text-sm">%v</div>`, err)
		return
	}
	targetID := "rust-config-status"
	if cfg.Type == ServerMinecraft {
		targetID = "mc-config-status"
	}
	fmt.Fprintf(w, `<div id="%s" class="text-emerald-500 text-sm">Config saved.</div>`, targetID)
}

func (a *App) updateRustConfig(id string, r *http.Request) error {
	serverCfg := a.manager.registry[id]
	if serverCfg.Rust == nil {
		return errors.New("rust config missing")
	}
	cfg := *serverCfg.Rust
	cfg.ServerName = r.FormValue("server_name")
	cfg.Description = r.FormValue("description")
	cfg.MaxPlayers = toInt(r.FormValue("max_players"), cfg.MaxPlayers)
	cfg.Port = toInt(r.FormValue("port"), cfg.Port)
	cfg.Seed = r.FormValue("seed")
	cfg.WorldSize = toInt(r.FormValue("world_size"), cfg.WorldSize)
	cfg.MapType = r.FormValue("map_type")
	cfg.EnableEAC = r.FormValue("enable_eac") == "on"
	cfg.Secure = r.FormValue("secure") == "on"
	cfg.Encryption = r.FormValue("encryption") == "on"
	cfg.EnableRCON = r.FormValue("enable_rcon") == "on"
	cfg.RconPort = toInt(r.FormValue("rcon_port"), cfg.RconPort)
	cfg.RconPassword = r.FormValue("rcon_password")
	cfg.LevelURL = r.FormValue("level_url")
	cfg.SaveInterval = toInt(r.FormValue("save_interval"), cfg.SaveInterval)
	cfg.PVEMode = r.FormValue("pve_mode") == "on"
	cfg.DecayScale = toFloat(r.FormValue("decay_scale"), cfg.DecayScale)
	cfg.CraftingSpeed = toFloat(r.FormValue("crafting_speed"), cfg.CraftingSpeed)
	cfg.ExtraLaunchArgs = r.FormValue("extra_launch_args")
	cfg.ExtraServerCfg = r.FormValue("extra_server_cfg")
	cfg.BinaryPath = r.FormValue("binary_path")
	cfg.WorkingDir = r.FormValue("working_dir")
	cfg.Identity = r.FormValue("identity")
	if cfg.EnableEAC {
		cfg.Secure = true // EAC implies secure intent
	}

	newCfg := a.manager.registry[id]
	newCfg.Rust = &cfg
	newCfg.LastUpdate = time.Now()
	a.manager.registry[id] = newCfg
	if err := a.manager.saveRegistry(); err != nil {
		return err
	}
	return a.manager.writeRustConfig(cfg)
}

func (a *App) updateMinecraftConfig(id string, r *http.Request) error {
	serverCfg := a.manager.registry[id]
	if serverCfg.Minecraft == nil {
		return errors.New("minecraft config missing")
	}
	cfg := *serverCfg.Minecraft
	cfg.MOTD = r.FormValue("motd")
	cfg.MaxPlayers = toInt(r.FormValue("max_players"), cfg.MaxPlayers)
	cfg.Port = toInt(r.FormValue("port"), cfg.Port)
	cfg.LevelName = r.FormValue("level_name")
	cfg.LevelSeed = r.FormValue("level_seed")
	cfg.Gamemode = r.FormValue("gamemode")
	cfg.Difficulty = r.FormValue("difficulty")
	cfg.Hardcore = r.FormValue("hardcore") == "on"
	cfg.PVP = r.FormValue("pvp") == "on"
	cfg.AllowFlight = r.FormValue("allow_flight") == "on"
	cfg.ViewDistance = toInt(r.FormValue("view_distance"), cfg.ViewDistance)
	cfg.SimulationDist = toInt(r.FormValue("simulation_distance"), cfg.SimulationDist)
	cfg.OnlineMode = r.FormValue("online_mode") == "on"
	cfg.Whitelist = r.FormValue("whitelist") == "on"
	cfg.EnableRCON = r.FormValue("enable_rcon") == "on"
	cfg.RconPort = toInt(r.FormValue("rcon_port"), cfg.RconPort)
	cfg.RconPassword = r.FormValue("rcon_password")
	cfg.MinRAM = r.FormValue("min_ram")
	cfg.MaxRAM = r.FormValue("max_ram")
	cfg.ExtraJVMArgs = r.FormValue("extra_jvm_args")
	cfg.JarPath = r.FormValue("jar_path")
	cfg.WorkingDir = r.FormValue("working_dir")
	cfg.JavaPath = r.FormValue("java_path")

	newCfg := a.manager.registry[id]
	newCfg.Minecraft = &cfg
	newCfg.LastUpdate = time.Now()
	a.manager.registry[id] = newCfg
	if err := a.manager.saveRegistry(); err != nil {
		return err
	}
	return a.manager.writeMinecraftProperties(cfg)
}

func toInt(value string, fallback int) int {
	if v, err := strconv.Atoi(value); err == nil {
		return v
	}
	return fallback
}

func toFloat(value string, fallback float64) float64 {
	if v, err := strconv.ParseFloat(value, 64); err == nil {
		return v
	}
	return fallback
}

func normalizeRustMapType(m string) string {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case "procedural map", "procedural", "default", "proc":
		return "Procedural Map"
	case "barren":
		return "Barren"
	case "hapis", "hapis island", "hapisland":
		return "HapisIsland"
	default:
		return m
	}
}

func (m *Manager) InstallRust(id string, steamcmdPath string) (string, error) {
	cfg, ok := m.registry[id]
	if !ok || cfg.Rust == nil {
		return "", errors.New("server not found")
	}
	rc := cfg.Rust
	workingDirAbs, err := filepath.Abs(rc.WorkingDir)
	if err != nil {
		return "", err
	}
	if srv := m.servers[id]; srv != nil {
		srv.Console.Append("Installing Rust server via SteamCMD...")
	}
	if steamcmdPath == "" {
		path, err := m.EnsureSteamCMD()
		if err == nil {
			steamcmdPath = path
		} else {
			steamcmdPath = "steamcmd"
		}
	}
	if !filepath.IsAbs(steamcmdPath) {
		if p, err := filepath.Abs(steamcmdPath); err == nil {
			steamcmdPath = p
		}
	}
	if err := os.MkdirAll(workingDirAbs, 0755); err != nil {
		return "", err
	}
	args := []string{
		"+login", "anonymous",
		"+force_install_dir", workingDirAbs,
		"+app_update", "258550", "validate",
		"+quit",
	}
	cmd := exec.Command(steamcmdPath, args...)
	cmd.Dir = workingDirAbs
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", err
	}
	if srv := m.servers[id]; srv != nil {
		go streamToBuffer(stdout, srv.Console, "STEAM")
		go streamToBuffer(stderr, srv.Console, "STEAM")
	}
	err = cmd.Wait()
	msg := "SteamCMD run complete"
	if err != nil {
		return msg, fmt.Errorf("steamcmd error: %v", err)
	}
	binaryPath := rc.BinaryPath
	if binaryPath == "" {
		binaryPath = "RustDedicated"
	}
	if !filepath.IsAbs(binaryPath) {
		binaryPath = filepath.Join(workingDirAbs, filepath.Base(binaryPath))
	}
	if st, err := os.Stat(binaryPath); err == nil && !st.IsDir() {
		_ = os.Chmod(binaryPath, 0755)
	} else {
		found := ""
		_ = filepath.Walk(workingDirAbs, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			name := info.Name()
			if name == "RustDedicated" || name == "RustDedicated.exe" {
				found = path
				return io.EOF
			}
			return nil
		})
		if found != "" {
			binaryPath = found
			_ = os.Chmod(binaryPath, 0755)
		} else {
			return msg, fmt.Errorf("finished but binary still missing under %s", workingDirAbs)
		}
	}

	cfgCopy := m.registry[id]
	if cfgCopy.Rust != nil {
		cfgCopy.Rust.BinaryPath = binaryPath
		m.registry[id] = cfgCopy
		_ = m.saveRegistry()
	}
	if srv := m.servers[id]; srv != nil {
		srv.Console.Append("Installation done. You can adjust config and press Start.")
	}
	return "Installation done. You can adjust config and press Start.", nil
}

func (m *Manager) InstallMinecraft(id string, jarURL string) (string, error) {
	cfg, ok := m.registry[id]
	if !ok || cfg.Minecraft == nil {
		return "", errors.New("server not found")
	}
	mc := cfg.Minecraft
	if err := os.MkdirAll(mc.WorkingDir, 0755); err != nil {
		return "", err
	}
	if jarURL == "" {
		return "", errors.New("provide a jar URL to download (e.g. Paper/Purpur direct link) or use Paper selector")
	}
	tmp := mc.JarPath + ".download"
	if !filepath.IsAbs(tmp) {
		tmp = filepath.Join(mc.WorkingDir, filepath.Base(tmp))
	}
	jarPath := mc.JarPath
	if !filepath.IsAbs(jarPath) {
		jarPath = filepath.Join(mc.WorkingDir, filepath.Base(jarPath))
	}
	if err := downloadFile(jarURL, tmp, 15*time.Minute); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, jarPath); err != nil {
		return "", err
	}
	if srv := m.servers[id]; srv != nil {
		srv.Console.Append(fmt.Sprintf("Downloaded jar from %s", jarURL))
	}
	return "Jar downloaded", nil
}

func (m *Manager) InstallPaper(id, version, build string) (string, error) {
	cfg, ok := m.registry[id]
	if !ok || cfg.Minecraft == nil {
		return "", errors.New("server not found")
	}
	if version == "" || build == "" {
		return "", errors.New("select version and build")
	}
	mc := cfg.Minecraft
	if err := os.MkdirAll(mc.WorkingDir, 0755); err != nil {
		return "", err
	}

	info, err := fetchPaperBuildInfo(version, build)
	if err != nil {
		return "", err
	}
	download := info.Downloads["application"]
	filename := download.Name
	if filename == "" {
		filename = fmt.Sprintf("paper-%s-%s.jar", version, build)
	}
	downloadURL := fmt.Sprintf("https://api.papermc.io/v2/projects/paper/versions/%s/builds/%s/downloads/%s", url.PathEscape(version), url.PathEscape(build), filename)

	tmp := filepath.Join(mc.WorkingDir, filename+".download")
	jarPath := mc.JarPath
	if !filepath.IsAbs(jarPath) {
		jarPath = filepath.Join(mc.WorkingDir, filepath.Base(jarPath))
	}

	if err := downloadFile(downloadURL, tmp, 15*time.Minute); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, jarPath); err != nil {
		return "", err
	}
	if srv := m.servers[id]; srv != nil {
		srv.Console.Append(fmt.Sprintf("Downloaded Paper %s build %s", version, build))
	}
	return "Paper jar downloaded", nil
}

func (m *Manager) InstallFolia(id, version, build string) (string, error) {
	cfg, ok := m.registry[id]
	if !ok || cfg.Minecraft == nil {
		return "", errors.New("server not found")
	}
	if version == "" || build == "" {
		return "", errors.New("select version and build")
	}
	mc := cfg.Minecraft
	if err := os.MkdirAll(mc.WorkingDir, 0755); err != nil {
		return "", err
	}

	info, err := fetchFoliaBuildInfo(version, build)
	if err != nil {
		return "", err
	}
	download := info.Downloads["application"]
	filename := download.Name
	if filename == "" {
		filename = fmt.Sprintf("folia-%s-%s.jar", version, build)
	}
	downloadURL := fmt.Sprintf("https://api.papermc.io/v2/projects/folia/versions/%s/builds/%s/downloads/%s", url.PathEscape(version), url.PathEscape(build), filename)

	tmp := filepath.Join(mc.WorkingDir, filename+".download")
	jarPath := mc.JarPath
	if !filepath.IsAbs(jarPath) {
		jarPath = filepath.Join(mc.WorkingDir, filepath.Base(jarPath))
	}

	if err := downloadFile(downloadURL, tmp, 15*time.Minute); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, jarPath); err != nil {
		return "", err
	}
	if srv := m.servers[id]; srv != nil {
		srv.Console.Append(fmt.Sprintf("Downloaded Folia %s build %s", version, build))
	}
	return "Folia jar downloaded", nil
}

func (m *Manager) InstallVanilla(id, version string) (string, error) {
	cfg, ok := m.registry[id]
	if !ok || cfg.Minecraft == nil {
		return "", errors.New("server not found")
	}
	if version == "" {
		return "", errors.New("select version")
	}
	downloadURL, err := fetchVanillaServerURL(version)
	if err != nil {
		return "", err
	}
	mc := cfg.Minecraft
	if err := os.MkdirAll(mc.WorkingDir, 0755); err != nil {
		return "", err
	}
	tmp := mc.JarPath + ".download"
	if !filepath.IsAbs(tmp) {
		tmp = filepath.Join(mc.WorkingDir, filepath.Base(tmp))
	}
	jarPath := mc.JarPath
	if !filepath.IsAbs(jarPath) {
		jarPath = filepath.Join(mc.WorkingDir, filepath.Base(jarPath))
	}
	if err := downloadFile(downloadURL, tmp, 15*time.Minute); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, jarPath); err != nil {
		return "", err
	}
	if srv := m.servers[id]; srv != nil {
		srv.Console.Append(fmt.Sprintf("Downloaded Vanilla %s", version))
	}
	return "Vanilla jar downloaded", nil
}

func (m *Manager) InstallSpigot(id, version string) (string, error) {
	cfg, ok := m.registry[id]
	if !ok || cfg.Minecraft == nil {
		return "", errors.New("server not found")
	}
	if version == "" {
		return "", errors.New("select version")
	}
	mc := cfg.Minecraft
	if err := os.MkdirAll(mc.WorkingDir, 0755); err != nil {
		return "", err
	}
	tmp := mc.JarPath + ".download"
	if !filepath.IsAbs(tmp) {
		tmp = filepath.Join(mc.WorkingDir, filepath.Base(tmp))
	}
	jarPath := mc.JarPath
	if !filepath.IsAbs(jarPath) {
		jarPath = filepath.Join(mc.WorkingDir, filepath.Base(jarPath))
	}
	downloadURL := fmt.Sprintf("https://download.getbukkit.org/spigot/spigot-%s.jar", url.PathEscape(version))
	if err := downloadFile(downloadURL, tmp, 15*time.Minute); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, jarPath); err != nil {
		return "", err
	}
	if srv := m.servers[id]; srv != nil {
		srv.Console.Append(fmt.Sprintf("Downloaded Spigot %s", version))
	}
	return "Spigot jar downloaded", nil
}

func downloadFile(url, dest string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: %s", resp.Status)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func (a *App) handlePlayerCount(w http.ResponseWriter, r *http.Request, id string) {
	count, raw, err := a.manager.PlayerCount(id)
	if err != nil {
		return
	}
	fmt.Fprintf(w, `<div class="text-sm text-emerald-500">%d player(s) online</div><div class="text-xs text-slate-400">%s</div>`, count, template.HTMLEscapeString(raw))
}

func (a *App) handleSchedules(w http.ResponseWriter, r *http.Request, serverID string) {
	cfg, ok := a.manager.registry[serverID]
	if !ok {
		fmt.Fprint(w, "")
		return
	}
	switch r.Method {
	case http.MethodGet:
		a.render(w, "partials/schedule_list.html", map[string]any{"Schedules": a.manager.scheduler.ListFor(serverID)})
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		action := r.FormValue("action")
		timeStr := r.FormValue("time")
		freq := r.FormValue("frequency")
		if freq == "" {
			freq = "daily"
		}
		if action == "" {
			action = "restart"
		}
		if _, err := a.manager.scheduler.Add(serverID, cfg.Type, action, timeStr, freq); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, `<div class="text-red-500 text-sm">%v</div>`, err)
			return
		}
		a.render(w, "partials/schedule_list.html", map[string]any{"Schedules": a.manager.scheduler.ListFor(serverID)})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (a *App) handleScheduleDelete(w http.ResponseWriter, r *http.Request, serverID, schedID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := a.manager.scheduler.Delete(schedID); err != nil {
		log.Printf("schedule delete failed: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `<div class="text-red-500 text-sm">%v</div>`, err)
		return
	}
	a.render(w, "partials/schedule_list.html", map[string]any{"Schedules": a.manager.scheduler.ListFor(serverID)})
}

func (a *App) handleInstall(w http.ResponseWriter, r *http.Request, serverID string, installType string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := a.manager.registry[serverID]; !ok {
		fmt.Fprint(w, `<div class="text-amber-500 text-sm">Server not found.</div>`)
		return
	}
	switch installType {
	case "rust":
		// Auto-manage SteamCMD location; download if missing.
		msg, err := a.manager.InstallRust(serverID, "")
		if err != nil {
			fmt.Fprintf(w, `<div class="text-amber-500 text-sm">%v</div>`, err)
			return
		}
		fmt.Fprintf(w, `<div class="text-emerald-500 text-sm">%s</div>`, template.HTMLEscapeString(msg))
	case "minecraft":
		url := strings.TrimSpace(r.FormValue("jar_url"))
		msg, err := a.manager.InstallMinecraft(serverID, url)
		if err != nil {
			fmt.Fprintf(w, `<div class="text-amber-500 text-sm">%v</div>`, err)
			return
		}
		fmt.Fprintf(w, `<div class="text-emerald-500 text-sm">%s</div>`, template.HTMLEscapeString(msg))
	case "paper":
		version := strings.TrimSpace(r.FormValue("paper_version"))
		if version == "" {
			version = strings.TrimSpace(r.FormValue("mc_version"))
		}
		build := strings.TrimSpace(r.FormValue("paper_build"))
		if build == "" {
			build = strings.TrimSpace(r.FormValue("mc_build"))
		}
		msg, err := a.manager.InstallPaper(serverID, version, build)
		if err != nil {
			fmt.Fprintf(w, `<div class="text-amber-500 text-sm">%v</div>`, err)
			return
		}
		fmt.Fprintf(w, `<div class="text-emerald-500 text-sm">%s</div>`, template.HTMLEscapeString(msg))
	case "folia":
		version := strings.TrimSpace(r.FormValue("folia_version"))
		if version == "" {
			version = strings.TrimSpace(r.FormValue("mc_version"))
		}
		build := strings.TrimSpace(r.FormValue("folia_build"))
		if build == "" {
			build = strings.TrimSpace(r.FormValue("mc_build"))
		}
		msg, err := a.manager.InstallFolia(serverID, version, build)
		if err != nil {
			fmt.Fprintf(w, `<div class="text-amber-500 text-sm">%v</div>`, err)
			return
		}
		fmt.Fprintf(w, `<div class="text-emerald-500 text-sm">%s</div>`, template.HTMLEscapeString(msg))
	case "spigot":
		version := strings.TrimSpace(r.FormValue("spigot_version"))
		if version == "" {
			version = strings.TrimSpace(r.FormValue("mc_version"))
		}
		msg, err := a.manager.InstallSpigot(serverID, version)
		if err != nil {
			fmt.Fprintf(w, `<div class="text-amber-500 text-sm">%v</div>`, err)
			return
		}
		fmt.Fprintf(w, `<div class="text-emerald-500 text-sm">%s</div>`, template.HTMLEscapeString(msg))
	case "vanilla":
		version := strings.TrimSpace(r.FormValue("vanilla_version"))
		if version == "" {
			version = strings.TrimSpace(r.FormValue("mc_version"))
		}
		msg, err := a.manager.InstallVanilla(serverID, version)
		if err != nil {
			fmt.Fprintf(w, `<div class="text-amber-500 text-sm">%v</div>`, err)
			return
		}
		fmt.Fprintf(w, `<div class="text-emerald-500 text-sm">%s</div>`, template.HTMLEscapeString(msg))
	default:
		http.Error(w, "unknown installer", http.StatusBadRequest)
		return
	}
}

func (a *App) handleDeleteServer(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if srv := a.manager.servers[id]; srv != nil && srv.Running {
		_ = a.manager.StopServer(id)
	}
	a.manager.mu.Lock()
	delete(a.manager.registry, id)
	delete(a.manager.servers, id)
	a.manager.mu.Unlock()
	_ = a.manager.saveRegistry()
	_ = os.RemoveAll(filepath.Join("servers", id))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) handlePaperVersions(w http.ResponseWriter, r *http.Request, id string) {
	_, ok := a.manager.registry[id]
	if !ok {
		fmt.Fprint(w, "")
		return
	}
	versions, err := fetchPaperVersions()
	if err != nil {
		fmt.Fprintf(w, `<option disabled>Error: %v</option>`, err)
		return
	}
	var b strings.Builder
	for _, v := range versions {
		fmt.Fprintf(&b, `<option value="%s">%s</option>`, v, v)
	}
	fmt.Fprint(w, b.String())
}

func (a *App) handlePaperBuilds(w http.ResponseWriter, r *http.Request, id string) {
	_, ok := a.manager.registry[id]
	if !ok {
		fmt.Fprint(w, "")
		return
	}
	version := r.URL.Query().Get("version")
	builds, err := fetchPaperBuilds(version)
	if err != nil {
		fmt.Fprintf(w, `<option disabled>Error: %v</option>`, err)
		return
	}
	var b strings.Builder
	for _, bld := range builds {
		fmt.Fprintf(&b, `<option value="%d">%d</option>`, bld, bld)
	}
	fmt.Fprint(w, b.String())
}

func (a *App) handleFoliaVersions(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := a.manager.registry[id]; !ok {
		fmt.Fprint(w, "")
		return
	}
	versions, err := fetchFoliaVersions()
	if err != nil {
		fmt.Fprintf(w, `<option disabled>Error: %v</option>`, err)
		return
	}
	var b strings.Builder
	for _, v := range versions {
		fmt.Fprintf(&b, `<option value="%s">%s</option>`, v, v)
	}
	fmt.Fprint(w, b.String())
}

func (a *App) handleFoliaBuilds(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := a.manager.registry[id]; !ok {
		fmt.Fprint(w, "")
		return
	}
	version := r.URL.Query().Get("version")
	builds, err := fetchFoliaBuilds(version)
	if err != nil {
		fmt.Fprintf(w, `<option disabled>Error: %v</option>`, err)
		return
	}
	var b strings.Builder
	for _, bld := range builds {
		fmt.Fprintf(&b, `<option value="%d">%d</option>`, bld, bld)
	}
	fmt.Fprint(w, b.String())
}

func (a *App) handleVanillaVersions(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := a.manager.registry[id]; !ok {
		fmt.Fprint(w, "")
		return
	}
	versions, err := fetchVanillaVersions()
	if err != nil {
		fmt.Fprintf(w, `<option disabled>Error: %v</option>`, err)
		return
	}
	var b strings.Builder
	for _, v := range versions {
		fmt.Fprintf(&b, `<option value="%s">%s</option>`, v, v)
	}
	fmt.Fprint(w, b.String())
}

// Folia helpers (PaperMC project)
func fetchFoliaVersions() ([]string, error) {
	resp, err := http.Get("https://api.papermc.io/v2/projects/folia")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var p paperProject
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, err
	}
	for i, j := 0, len(p.Versions)-1; i < j; i, j = i+1, j-1 {
		p.Versions[i], p.Versions[j] = p.Versions[j], p.Versions[i]
	}
	return p.Versions, nil
}

func fetchFoliaBuilds(version string) ([]int, error) {
	if version == "" {
		return nil, errors.New("version required")
	}
	resp, err := http.Get(fmt.Sprintf("https://api.papermc.io/v2/projects/folia/versions/%s", url.PathEscape(version)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var v paperVersionInfo
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, err
	}
	for i, j := 0, len(v.Builds)-1; i < j; i, j = i+1, j-1 {
		v.Builds[i], v.Builds[j] = v.Builds[j], v.Builds[i]
	}
	return v.Builds, nil
}

func fetchFoliaBuildInfo(version, build string) (*paperBuildInfo, error) {
	if version == "" || build == "" {
		return nil, errors.New("version and build required")
	}
	resp, err := http.Get(fmt.Sprintf("https://api.papermc.io/v2/projects/folia/versions/%s/builds/%s", url.PathEscape(version), url.PathEscape(build)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var b paperBuildInfo
	if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
		return nil, err
	}
	return &b, nil
}

// Vanilla helpers
func fetchVanillaVersions() ([]string, error) {
	resp, err := http.Get("https://launchermeta.mojang.com/mc/game/version_manifest_v2.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var manifest vanillaManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return nil, err
	}
	var versions []string
	for _, v := range manifest.Versions {
		versions = append(versions, v.ID)
	}
	return versions, nil
}

func fetchVanillaServerURL(version string) (string, error) {
	resp, err := http.Get("https://launchermeta.mojang.com/mc/game/version_manifest_v2.json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var manifest vanillaManifest
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return "", err
	}
	var detailURL string
	for _, v := range manifest.Versions {
		if v.ID == version {
			detailURL = v.URL
			break
		}
	}
	if detailURL == "" {
		return "", errors.New("version not found")
	}
	dResp, err := http.Get(detailURL)
	if err != nil {
		return "", err
	}
	defer dResp.Body.Close()
	var detail vanillaVersionDetail
	if err := json.NewDecoder(dResp.Body).Decode(&detail); err != nil {
		return "", err
	}
	if detail.Downloads.Server.URL == "" {
		return "", errors.New("server jar not found for version")
	}
	return detail.Downloads.Server.URL, nil
}

func (a *App) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Cache-Control", "no-store")
	if err := a.templates.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
