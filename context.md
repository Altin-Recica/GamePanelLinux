# Game Panel – Project Context

## Overview
A lightweight game server control panel written in Go with HTMX + Tailwind UI. It runs as a single binary, no external JS authored. Supports multiple server instances (Rust and Minecraft), each with its own folder, config, console, scheduling, and installers.

## Current Capabilities
- **Auth**: Single password via `PANEL_PASSWORD` env; stored as signed cookie.
- **Multi-server**: Home `/` lists servers; you can create/delete Rust or Minecraft servers. Each server lives under `servers/{id}` with its own working dir and assets.
- **Per-server dashboard** (`/servers/{id}`):
  - Start/Stop/Restart
  - Live console (auto-scroll, ANSI stripped)
  - Commands input
  - Config editors (Rust → server.cfg + launch args; Minecraft → server.properties + JVM args)
  - Scheduling (start/stop/restart daily/once)
  - Installers:
    - Rust: SteamCMD (auto-downloads SteamCMD to `data/steamcmd` if path blank)
    - Minecraft: Direct jar URL downloader
    - Unified Minecraft picker: choose distro (Paper, Folia, Spigot, Vanilla), version (and build where applicable) and download to the server folder
- **Player count**: RCON-based for both games (silent fail if unreachable/disabled).
- **Path automation**: Working dir/binary/jar paths auto-set per server; no manual typing needed.
- **Delete server**: Stops if running, removes registry entry and `servers/{id}` folder.

## Notable Behaviors
- Minecraft first start auto-writes `eula=true` to avoid EULA failure.
- Paper/Folia versions/builds sorted newest → oldest.
- Consoles strip ANSI color codes and auto-scroll after updates.
- Missing/invalid polling endpoints return empty to reduce htmx console noise.
- Rust: `server.encryption` set to level 2 when secure/EAC implied; `-noeac` passed when EAC is disabled. Invalid `server.secure` arg removed. RCON password defaulted if empty when EAC on.
- No default servers are seeded; empty registry on fresh start.

## File/Dir Structure
- `main.go` – All backend logic: auth, registry, process mgmt, schedulers, installers, RCON, HTTP handlers, templates embedding.
- `templates/servers.html` – Server list + create form.
- `templates/server_rust.html`, `templates/server_minecraft.html` – Per-server dashboards.
- `templates/partials/*.html` – Reusable cards, console, schedule list.
- `data/servers.json` – Server registry; `data/schedules.json` – scheduler; `data/steamcmd` – auto-downloaded SteamCMD.
- `servers/{id}` – Per-server working dir (RustDedicated/binaries or server.jar, configs, eula.txt, etc.).
- `.gitignore` excludes runtime state (data/servers.json, data/schedules.json, data/steamcmd/, servers/, local config samples) and built binaries (gamepanel, gamepanel.exe).

## How to Run
```bash
PANEL_PASSWORD="admin" go run .
# open http://localhost:8080
```
Create a server → open its page → use installers (SteamCMD or Paper picker/direct URL) → Start.

## Remaining Nice-to-Haves
- Windows auto-download of SteamCMD (currently Linux-only).
- Auto-select latest version/build by default in pickers.
- More granular error display for htmx polling if desired.
