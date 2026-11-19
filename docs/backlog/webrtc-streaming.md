# WebRTC Window Streaming TODO

Goal: stream a captured desktop window to a mobile web app, then add a
bidirectional control channel for touch, pointer, keyboard, and app events.

## Examples

Start the built-in server for the primary screen and choose a free port:

```powershell
dist\win-x64\tanit-cli.exe video stream --server --input "screen:0" --port 0
```

Loopback-only smoke run that exits after one second and prints JSON:

```powershell
dist\win-x64\tanit-cli.exe video stream --server --input "screen:0" --bind 127.0.0.1 --port 0 --duration-ms 1000 --json
```

LAN/mobile run on a fixed port. Open the printed URL on the phone, replacing
`127.0.0.1` with the desktop machine's LAN IP if needed:

```powershell
dist\win-x64\tanit-cli.exe video stream --server --input "screen:0" --bind 0.0.0.0 --port 8787 --fps 30 --bitrate-kbps 8000 --token dev
```

For the temporary MJPEG preview, raise JPEG quality if text/details look soft.
This increases bandwidth and CPU:

```powershell
dist\win-x64\tanit-cli.exe video stream --server --input "screen:0" --bind 0.0.0.0 --port 8787 --fps 30 --mjpeg-quality 95 --token dev
```

## Cursor

```sh
tanit-cli.exe video stream --server --input "screen:1:rrect=1323,78,603,948" --bind 0.0.0.0 --port 8787 --fps 30 --bitrate-kbps 8000 --token dev

tanit-cli.exe --log-level trace video stream --server --input "screen:1:wintitle=*Cursor*:rrect=1323,78,603,948" --bind 0.0.0.0 --port 8787 --fps 30 --bitrate-kbps 8000 --token dev

tanit-cli.exe --log-level trace video stream --server --input "screen:1:wintitle=*Cursor*:rrect=1323,78,603,948" --bind 0.0.0.0 --mjpeg-quality 100 --port 8787 --fps 30 --bitrate-kbps 8000 --token dev
```

The bootstrap page displays the live HTTP MJPEG preview. Direct endpoints:

```powershell
start http://127.0.0.1:8787/mjpeg
start http://127.0.0.1:8787/snapshot.jpg
```

Fetch the server descriptor:

```powershell
Invoke-RestMethod http://127.0.0.1:8787/status
```

HTTP signaling mailbox for the upcoming WebRTC offer/answer/candidate exchange:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8787/signal -Headers @{"X-PM-Token"="dev"} -Body '{"type":"offer","sdp":"..."}' -ContentType 'application/json'
Invoke-RestMethod "http://127.0.0.1:8787/signal?token=dev&since=0&waitMs=1000"
```

Current HTTP control endpoint, using the token from the launch command:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8787/control -Headers @{"X-PM-Token"="dev"} -Body '{"kind":"ping"}' -ContentType 'application/json'
```

Normalized remote-control coordinates map into the selected capture rect
(`screen:0`, `screen:1`, `screen:0:hwnd=...`, etc.):

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8787/control -Headers @{"X-PM-Token"="dev"} -Body '{"action":"move","nx":0.5,"ny":0.5}' -ContentType 'application/json'
Invoke-RestMethod -Method Post http://127.0.0.1:8787/control -Headers @{"X-PM-Token"="dev"} -Body '{"action":"click","nx":0.5,"ny":0.5,"button":"left"}' -ContentType 'application/json'
```

Absolute desktop input actions also use the same endpoint and reuse
`assistant app-use` internals:

```powershell
Invoke-RestMethod -Method Post http://127.0.0.1:8787/control -Headers @{"X-PM-Token"="dev"} -Body '{"action":"move","x":100,"y":100}' -ContentType 'application/json'
Invoke-RestMethod -Method Post http://127.0.0.1:8787/control -Headers @{"X-PM-Token"="dev"} -Body '{"action":"click","x":100,"y":100,"button":"left"}' -ContentType 'application/json'
Invoke-RestMethod -Method Post http://127.0.0.1:8787/control -Headers @{"X-PM-Token"="dev"} -Body '{"action":"hotkey","keys":["ctrl","l"]}' -ContentType 'application/json'
```

Later, after `video info --screens` picks a window, use the same screen grammar:

```powershell
dist\win-x64\tanit-cli.exe video stream --server --input "screen:0:hwnd=123456" --port 8787 --open
```

## 1. Built-in Signaling Server

- [x] Add a small built-in signaling server that can run implicitly when window
      streaming starts.
- [x] Reuse the existing CLI/runtime patterns from `src/cli/pm_image_run.cpp`
      instead of creating a separate daemon shape first.
- [x] Serve a minimal mobile client page and an HTTP signaling placeholder:
      `/` for the client UI, `/status` for descriptor JSON, `/signal` for the
      next SDP/ICE implementation step.
- [x] Replace the `/signal` placeholder with a token-protected HTTP signaling
      mailbox: `POST /signal` stores messages, `GET /signal?since=N` polls them.
- [x] Keep the server LAN-friendly for the first pass: bind host/port options,
      print the mobile URL, and avoid cloud/NAT complexity.
- [x] Add a simple session token or pairing code before exposing input control.
- [ ] Decide whether the server is owned by the streaming command, reused from
      an app/IPC host, or later promoted into a broader service.

## 2. Streaming Library First

- [ ] Implement the core as library code under `src/video/streaming`.
- [ ] Define small interfaces before wiring command/UI surfaces:
      `WindowCaptureSource`, `VideoStreamEncoder`, `RealtimeTransport`, and
      `InputControlChannel`.
- [ ] On Windows, start with the existing WGC/D3D11 capture path in
      `src/session/recorder/pm_session_video_recorder.cpp`.
- [ ] For the first working stream, allow a Media Foundation H.264 path if it
      gets pixels to the browser fastest.
- [ ] Add an NVENC D3D11 encoder path after the transport works, using
      `packages/nvidia/Samples/AppEncode/AppEncD3D11` as the reference.
- [ ] Keep the packet-producing encoder separate from file-oriented
      `pm::video::VideoEncoder`; streaming needs H.264 access units, not MP4.
- [x] Add a first browser-visible video path using the existing capture source
      and JPEG encoder: `/mjpeg` live preview plus `/snapshot.jpg`.
- [x] Add `--mjpeg-quality` for the temporary MJPEG preview while WebRTC/H.264
      is pending.
- [ ] Plan cross-platform backend slots:
      Windows WGC/D3D11, macOS ScreenCaptureKit/VideoToolbox, Linux
      PipeWire/VAAPI/NVENC/software fallback.

## 3. CLI Exposure

- [x] Expose the prototype through `src/cli/pm_image_cmd_video.cpp`.
- [x] Add a command shape such as:
      `video stream --input "screen:0:hwnd=..." --server --port 0`.
- [x] Reuse `video info --screens` capture specs for window/monitor selection.
- [x] Add options for `--fps`, `--bitrate`, `--include-cursor`,
      `--bind`, `--port`, `--token`, and `--open`.
- [x] Print JSON status when `--json` is passed: URL, bind address, port,
      stream id, token/pairing status, selected encoder, selected capture source.
- [ ] Add cooperative stop/status subcommands if the stream can outlive the
      launching command, matching the `video record stop/status` pattern.
- [x] Decide whether `--server` means "start built-in signaling server" or
      whether server startup is implicit for `video stream`.

## 4. Mobile Web Client

- [x] Create `apps/remote` as a small React app, copying the app/build shape from
      `apps/xblox` where practical.
- [ ] Implement a first-page flow: connect to signaling, receive the WebRTC video
      track, show connection/ICE/codec stats, and reconnect cleanly.
- [x] Implement a temporary first-page flow that displays `/mjpeg` while WebRTC
      media is still pending.
- [x] Add client-side zoom controls for the temporary MJPEG preview.
- [x] Add an in-page fullscreen/theater toggle for the preview. This does not
      call browser fullscreen APIs or put Chrome itself in fullscreen.
- [x] Add a first `apps/remote` UI that drives HTTP control directly from the
      video surface: tap, drag, wheel, keyboard text, hotkeys, and pinch/zoom.
- [ ] Add a data channel for bidirectional messages.
- [x] Start with non-destructive HTTP controls: ping, pointer preview, text,
      and last-message logging.
- [x] Add explicit opt-in HTTP input actions for manual tests: move, click,
      drag, scroll, type, hotkey, key. These are temporary stand-ins for the
      WebRTC data channel and reuse `src/win/assistant/app_use.cpp`.
- [x] Map normalized remote coordinates (`nx`, `ny`) into the selected
      `screen:` capture rectangle before executing explicit input actions.
- [ ] Add interactive controls after pairing is reliable: touch-to-mouse,
      drag, wheel/gesture, keyboard text, hotkeys, and clipboard if desired.
- [x] Make the mobile layout touch-first: fullscreen video, safe-area handling,
      orientation changes, and optional controls overlay.
- [x] Add an embed/build target consistent with existing web apps before wiring
      it into the desktop binary.

## 5. Playgrounds And Receivers

- [ ] Use browser WebRTC as the primary receiver because it also supports the
      data channel.
- [ ] Keep MediaMTX as a useful bridge target for experiments with VLC, OBS,
      RTSP, HLS, WHIP/WHEP, or one-way viewing.
- [ ] Treat VLC as a one-way playback/debug target, not the interactive path.
- [ ] Study Sunshine/Moonlight for latency/control ideas, but do not target its
      protocol unless GameStream compatibility becomes a product goal.

## 6. Open Decisions

- [ ] Library choice for WebRTC: `libdatachannel` for a small embedded C++ path
      versus full libwebrtc for maximum compatibility.
- [ ] Signaling format and ownership: raw JSON over WebSocket, reuse existing IPC
      shapes, or add a small service protocol.
- [ ] NAT strategy: LAN-only first, then optional STUN/TURN (`coturn`) for remote
      mobile use.
- [ ] Security model: local-only default, bind confirmation, pairing token,
      input-control permission, and visible "streaming active" indicator.
- [ ] Encoder priority: Media Foundation first for speed of integration, NVENC
      first for latency/performance, or runtime selection.
