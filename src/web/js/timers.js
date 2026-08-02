import { S } from '/static/js/state.js';

/* ═══════════ Page: LIVE MONITOR (#/live) — continuous re-scan ═══════════ */
export function clearLiveTimer(){ if (S.liveTimer){ clearInterval(S.liveTimer); S.liveTimer = null; } }
export function clearScanTimer(){ if (S.scanTimer){ clearTimeout(S.scanTimer); S.scanTimer = null; } }
export function clearEnginesTimer(){ if (S.enginesTimer){ clearInterval(S.enginesTimer); S.enginesTimer = null; } }

/* ═══════════ Page: SETTINGS (#/opts) — self-update + cell-DB import pollers ═══════════ */
/* Both poll a background job's phase every 2.5s and self-clear when it reaches a
   terminal phase. Navigating away MID-JOB used to leak them (the interval kept
   firing against a detached DOM, and re-entering #/opts spawned a duplicate), so
   they live in shared state and are torn down centrally by render() like every
   other page timer. */
export function clearOptsTimers(){
  if (S.optsUpdateTimer){ clearInterval(S.optsUpdateTimer); S.optsUpdateTimer = null; }
  if (S.optsCellsTimer){ clearInterval(S.optsCellsTimer); S.optsCellsTimer = null; }
}

/* ═══════════ Page: SEARCH-ENGINE LIVENESS (#/engines) ═══════════ */
/* Merges the cached liveness sweep (GET /api/v1/engines/health — only ENABLED
   engines are probed) with the full engine roster + on/off state (GET
   /api/v1/settings/toggles), so disabled engines stay visible and can be
   re-enabled inline. Each row carries an Enable/Disable control wired to PUT
   /settings/toggles, closing the loop: a Blocked engine can be switched off
   right here (then skipped by both the probe and every scan). Auto-refreshes
   every 30s while open; clearEnginesTimer() (from render()) stops it. */
