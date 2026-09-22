/* ═══════════ Slippy map for the Radar view ═══════════
 * Web-Mercator tiles from the loopback proxy (`/api/v1/tiles/{z}/{x}/{y}.png`
 * — src/api/tiles.rs says why the browser never talks to a tile server
 * itself), panned by pointer, zoomed by buttons or wheel, with markers for
 * positioned sightings. Dependency-free by policy (VENDOR_FILES is empty):
 * ~150 lines are the whole map, and nothing here phones anywhere but home. */
const TILE = 256;
export const MIN_ZOOM = 3, MAX_ZOOM = 19;

/* Tile-space coordinates (in tiles, fractional) for a lon/lat at zoom z. */
export function lonToX(lon, z){ return (lon + 180) / 360 * Math.pow(2, z); }
export function latToY(lat, z){
  const r = lat * Math.PI / 180;
  return (1 - Math.log(Math.tan(r) + 1 / Math.cos(r)) / Math.PI) / 2 * Math.pow(2, z);
}
export function xToLon(x, z){ return x / Math.pow(2, z) * 360 - 180; }
export function yToLat(y, z){
  const n = Math.PI - 2 * Math.PI * y / Math.pow(2, z);
  return 180 / Math.PI * Math.atan(0.5 * (Math.exp(n) - Math.exp(-n)));
}
export function tileUrl(z, x, y){ return `/api/v1/tiles/${z}/${x}/${y}.png`; }

/* Build a map inside `host`. Returns a small controller; the caller owns the
   host element and calls `destroy()` when the view goes away. */
export function createMap(host, opts){
  const state = { lat: (opts && opts.lat) || 0, lon: (opts && opts.lon) || 0, zoom: Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, (opts && opts.zoom) || 16)), markers: [] };
  host.classList.add('radar-map');
  host.innerHTML = `<div class="radar-map-tiles"></div><div class="radar-map-markers"></div>
    <div class="radar-map-zoom"><button type="button" class="btn btn-default btn-xs" data-zoom="1" title="Zoom in">+</button><button type="button" class="btn btn-default btn-xs" data-zoom="-1" title="Zoom out">−</button></div>
    <div class="radar-map-attr">© <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener">OpenStreetMap</a> contributors</div>`;
  const tilesEl = host.querySelector('.radar-map-tiles'), markersEl = host.querySelector('.radar-map-markers');
  const imgs = new Map(); // "z/x/y" → img, reused across renders so a pan never refetches

  function render(){
    const w = host.clientWidth || 320, h = host.clientHeight || 300, z = state.zoom, n = Math.pow(2, z);
    const cx = lonToX(state.lon, z) * TILE, cy = latToY(state.lat, z) * TILE;
    const left = cx - w / 2, top = cy - h / 2;
    const keep = new Set();
    for (let tx = Math.floor(left / TILE); tx <= Math.floor((left + w) / TILE); tx++) {
      for (let ty = Math.floor(top / TILE); ty <= Math.floor((top + h) / TILE); ty++) {
        if (ty < 0 || ty >= n) continue;
        const wx = ((tx % n) + n) % n;               // wrap the antimeridian
        const key = `${z}/${wx}/${ty}`;
        keep.add(key);
        let img = imgs.get(key);
        if (!img) {
          img = document.createElement('img');
          img.alt = ''; img.draggable = false; img.decoding = 'async';
          img.addEventListener('error', () => img.classList.add('radar-tile-missing'));
          img.src = tileUrl(z, wx, ty);
          imgs.set(key, img); tilesEl.appendChild(img);
        }
        img.style.left = `${Math.round(tx * TILE - left)}px`;
        img.style.top = `${Math.round(ty * TILE - top)}px`;
      }
    }
    for (const [key, img] of imgs) { if (!keep.has(key)) { img.remove(); imgs.delete(key); } }
    markersEl.innerHTML = '';
    for (const m of state.markers) {
      const px = lonToX(m.lon, z) * TILE - left, py = latToY(m.lat, z) * TILE - top;
      if (px < -20 || py < -20 || px > w + 20 || py > h + 20) continue;
      const el = document.createElement('div');
      el.className = m.count > 1 ? 'radar-marker radar-marker-cluster' : 'radar-marker';
      el.style.left = `${px.toFixed(1)}px`; el.style.top = `${py.toFixed(1)}px`;
      el.style.background = m.colour || 'var(--accent)';
      el.title = m.label || '';
      if (m.count > 1) el.textContent = String(m.count);
      markersEl.appendChild(el);
    }
  }

  // Pan by pointer (mouse or touch), zoom by the buttons or the wheel.
  let drag = null;
  host.addEventListener('pointerdown', ev => { if (ev.target.closest('button, a')) return; drag = { x: ev.clientX, y: ev.clientY, lat: state.lat, lon: state.lon }; host.setPointerCapture(ev.pointerId); });
  host.addEventListener('pointermove', ev => {
    if (!drag) return;
    const z = state.zoom, cx = lonToX(drag.lon, z) * TILE - (ev.clientX - drag.x), cy = latToY(drag.lat, z) * TILE - (ev.clientY - drag.y);
    state.lon = xToLon(cx / TILE, z); state.lat = Math.max(-85, Math.min(85, yToLat(cy / TILE, z)));
    render();
  });
  const endDrag = () => { drag = null; };
  host.addEventListener('pointerup', endDrag); host.addEventListener('pointercancel', endDrag);
  host.querySelectorAll('[data-zoom]').forEach(b => b.addEventListener('click', () => api.setView(state.lat, state.lon, state.zoom + Number(b.dataset.zoom))));
  host.addEventListener('wheel', ev => { ev.preventDefault(); api.setView(state.lat, state.lon, state.zoom + (ev.deltaY < 0 ? 1 : -1)); }, { passive: false });

  const api = {
    setView(lat, lon, zoom){
      state.lat = lat; state.lon = lon;
      if (zoom != null) state.zoom = Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, Math.round(zoom)));
      render();
    },
    setMarkers(markers){ state.markers = markers || []; render(); },
    getView(){ return { lat: state.lat, lon: state.lon, zoom: state.zoom }; },
    tileCount(){ return imgs.size; },
    destroy(){ imgs.clear(); host.innerHTML = ''; host.classList.remove('radar-map'); },
  };
  render();
  return api;
}
