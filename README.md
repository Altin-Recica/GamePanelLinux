# Game Server Panel

## 📝 Description
Lightweight Go web panel to manage Rust and Minecraft servers: start/stop/restart, live consoles, server configuration, and simple scheduling.

## 🛠️ Tech Stack
- Go 1.25 (standard library HTTP server, embedded templates)
- HTMX + Tailwind via CDN
- SteamCMD for Rust installs/updates
- Java runtime (recommended 17+) for Minecraft JARs

## 🚀 How to Use
```bash
go build -o gamepanel .

export PANEL_PASSWORD="change-me" //Use this to set whatever password you want the default is admin if you dont run this
go run .
```
Open http://localhost:6767, log in, create a Rust or Minecraft server, use the installer buttons to download binaries/JARs, then start/stop/restart and manage configs/schedules from the UI.

Login:
<img width="1920" height="934" alt="Login" src="https://github.com/user-attachments/assets/39555120-49b3-4677-876a-44af12595886" />

Server list:
<img width="1918" height="930" alt="ServerList" src="https://github.com/user-attachments/assets/4dd31273-86be-4505-9ebc-49d012b8801e" />

Minecraft server dashboard:
<img width="1920" height="934" alt="ServerDashboard1" src="https://github.com/user-attachments/assets/59a21208-4a65-4fb0-8960-13b7dc15af76" />
<img width="1900" height="934" alt="ServerDashboard2" src="https://github.com/user-attachments/assets/c4fdc4ea-b529-4f2f-a075-ba24bf162a09" />

Rust server dashboard:
<img width="1911" height="935" alt="ServerDashboard2 5" src="https://github.com/user-attachments/assets/f19ddcc4-d6c5-4262-9cff-238ea4eda56e" />
<img width="1911" height="935" alt="ServerDashboard3" src="https://github.com/user-attachments/assets/16f27a15-7ea9-4971-9188-2e567b05bf4f" />
