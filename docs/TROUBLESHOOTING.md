# Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Python 3.13 was not found` | Install Python 3.13 (64-bit). `py -0` lists installed versions. Re-run `setup.bat`. |
| `cannot reach MongoDB` | Start the service: `services.msc` → *MongoDB* → Start, or `net start MongoDB` in an elevated prompt. Check `TIM_MONGO_URI` in `backend\.env`. Prefer `127.0.0.1` over `localhost`: MongoDB listens on IPv4 by default, and `localhost` may resolve to `::1`. |
| Login says *Too many failed login attempts* | 10 failures within 15 minutes for that user/IP. Wait, or restart the backend (the throttle is in memory). Reset a forgotten password with `backend\.venv\Scripts\python.exe -m app.cli reset-password admin "NewPass!"`. |
| All API calls return 401 after changing `.env` | `TIM_SECRET_KEY` changed, which invalidates sessions. Sign in again. Stored provider API keys must also be re-entered, because they are encrypted with that key. |
| Screenshots missing; health shows *Browser unavailable* | Run `backend\.venv\Scripts\python.exe -m playwright install chromium`. Corporate proxies may block the download: set `HTTPS_PROXY` first. Screenshots can be disabled with `TIM_SCREENSHOTS_ENABLED=false`. |
| `blocked: ... resolves to non-public address` | The SSRF guard refuses private, loopback, and link-local targets. For lab targets set `TIM_ALLOW_PRIVATE_TARGETS=true` and restart. |
| crt.sh returns 502 / Wayback times out | Both services are frequently overloaded. TIM retries crt.sh and falls back to the Wayback availability API. Results are cached, so re-running later is cheap. Errors appear under **Provider runs** and on the provider's health badge. |
| A provider shows `unconfigured` | It needs an API key: **Administration → API Keys**. FOFA keys come from your account page. Censys accepts a Platform PAT, or an API ID with the secret entered in the second field. |
| Provider shows `down` | 5 consecutive failures. Use **Test** on the Providers page. The state returns to `healthy` after the next success. |
| `daily limit of N reached` | Raise or clear the provider's **Daily limit**: 0 means unlimited. |
| Credit sources never run | The default credit policy is *Only when needed*. Choose *Always* in the investigation options, or check that the provider is enabled and has a key. |
| Frontend shows *Backend unreachable* | Start `run_backend.bat`. The Vite dev server proxies `/api` to `127.0.0.1:8000`. Set `TIM_BACKEND_URL` before `npm run dev` if the API runs elsewhere. |
| Port 8000 or 5173 already in use | Find the owner with `netstat -ano \| findstr :8000` and stop it, or change `TIM_PORT` / the Vite `server.port`. |
| `npm install` is very slow inside OneDrive | OneDrive syncs `node_modules` and `.venv`. Pause syncing during setup, or move the project outside OneDrive. |
| Investigations stuck in *queued* | Only `TIM_MAX_CONCURRENT_INVESTIGATIONS` run at once. Interrupted runs are re-queued automatically when the backend restarts. |
| Demo data looks stale or duplicated | `database_setup.bat --reseed` removes only `seed: true` documents and reloads them. |
| Frontend unit tests fail with `localStorage.clear is not a function` | Node ≥ 22 ships an incomplete global `localStorage`. The test setup installs a polyfill, so make sure `src/test/setup.ts` is loaded (it is configured in `vite.config.ts`). |

## Logs

- Backend logs go to the *TIM backend* console window. Start with `run_backend.bat --log-level debug` for more detail, or set `TIM_DEBUG=true`.
- Every provider call is recorded per investigation (**Provider runs** tab) and aggregated on the Providers page.
- `/health` reports MongoDB, browser, and pipeline status. `/metrics` exposes Prometheus counters.
