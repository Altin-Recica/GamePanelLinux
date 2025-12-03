# Game Server Panel

## 📝 Description
Lightweight Go web panel to manage Rust and Minecraft servers: start/stop/restart, live consoles, config editors, installers (SteamCMD + Paper/Folia/Spigot/Vanilla), and simple scheduling.

## 🛠️ Tech Stack
- Go 1.25 (standard library HTTP server, embedded templates)
- HTMX + Tailwind via CDN
- SteamCMD for Rust installs/updates
- Java runtime (recommended 17+) for Minecraft JARs

## 🚀 How to Use
```bash
export PANEL_PASSWORD="change-me"
go run .

go build -o gamepanel .
./gamepanel
```
Open http://localhost:6767, log in, create a Rust or Minecraft server, use the installer buttons to download binaries/JARs, then start/stop/restart and manage configs/schedules from the UI.
