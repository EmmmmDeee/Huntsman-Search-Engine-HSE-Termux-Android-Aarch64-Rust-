import { S } from '/static/js/state.js';

/* ═══════════ Page: LIVE MONITOR (#/live) — continuous re-scan ═══════════ */
export function clearLiveTimer(){ if (S.liveTimer){ clearInterval(S.liveTimer); S.liveTimer = null; } }
export function clearScanTimer(){ if (S.scanTimer){ clearTimeout(S.scanTimer); S.scanTimer = null; } }
export function clearEnginesTimer(){ if (S.enginesTimer){ clearInterval(S.enginesTimer); S.enginesTimer = null; } }

/* ═══════════ Page: SEARCH-ENGINE LIVENESS (#/engines) ═══════════ */
/* Merges the cached liveness sweep (GET /api/v1/engines/health — only ENABLED
   engines are probed) with the full engine roster + on/off state (GET
   /api/v1/settings/toggles), so disabled engines stay visible and can be
   re-enabled inline. Each row carries an Enable/Disable control wired to PUT
   /settings/toggles, closing the loop: a Blocked engine can be switched off
   right here (then skipped by both the probe and every scan). Auto-refreshes
   every 30s while open; clearEnginesTimer() (from render()) stops it. */
