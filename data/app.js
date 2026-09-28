'use strict';
// PresenceTrack web UI: tabs, debounced auto-save, status polling, SVG zone/object map, event log.

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const ZONES = 6, OBJECTS = 12, TARGETS = 3, EVENTS_MAX = 64, DEBOUNCE_MS = 500;
// Map geometry in mm; matches the SVG viewBox and the /api/zones + /api/objects limits.
const MAP = { xMin: -6000, xMax: 6000, yMin: 0, yMax: 6000, vbW: 12000, vbH: 6600 };
const MIN_SHAPE_MM = 100, SNAP_MM = 10;
// Docking while dragging: reach in screen px (converted to mm per map), coarse grid in mm.
const SNAP_PX = 10, SNAP_PX_COARSE = 16, GRID_SNAP_MM = 500;
// Upper bounds for the reach in mm, so that a large mm-per-px ratio (small screens) never makes an edge
// jump far; the grid cap is tighter so that fine positioning between two grid lines stays possible.
const EDGE_SNAP_TOL_MM = 200, GRID_SNAP_TOL_MM = GRID_SNAP_MM / 4;
// Rectangle given to a newly added zone (map center).
const NEW_ZONE_RECT = { x1: -1000, y1: 2000, x2: 1000, y2: 4000 };
// A newly added object gets a 400 x 400 mm cell of a 4 x 3 grid around the map center
// (same as the firmware defaults), so that several new objects do not stack.
const newObjectRect = i => {
  const x1 = -1100 + i % 4 * 600, y1 = 2400 + Math.floor(i / 4) * 600;
  return { x1, y1, x2: x1 + 400, y2: y1 + 400 };
};
const NAME_MAX = 23; // UTF-8 bytes, matches the firmware limit (char name[24])
const COORDS = ['x1', 'y1', 'x2', 'y2'];
// Raw target signal quality of the LD2450, 0..65535; matches the firmware validation of min_resolution.
const ZONE_SIGNAL_MAX = 65535;
const OBJECT_TYPES = { cabinet: 'Cabinet', sofa: 'Sofa', door: 'Door', table: 'Table', other: 'Other' };
const ROTATIONS = [0, 90, 180, 270];
// GPIOs broken out on the D1 Mini (same list as the firmware validation).
const BOARD_PINS = [[16, 'D0'], [5, 'D1'], [4, 'D2'], [0, 'D3'], [2, 'D4'], [14, 'D5'], [12, 'D6'], [13, 'D7'], [15, 'D8'], [3, 'RX'], [1, 'TX']];
const EVENT_LABELS = {
  presence_changed: 'Presence', zone_enter: 'Zone enter', zone_exit: 'Zone exit', mqtt_connected: 'MQTT',
  mqtt_disconnected: 'MQTT', config_changed: 'Config', reboot: 'System', factory_reset: 'Factory reset',
  ota_update: 'Update', network: 'Network'
};
const SVG_NS = 'http://www.w3.org/2000/svg';

let zonesConfig = [];   // zones last confirmed by the server (for the status map)
let objectsConfig = []; // objects last confirmed by the server (status map + zone list)
let eventLog = [];      // events from /api/events, oldest first
let lastEventId = 0, eventsUptimeMs = 0, eventsBusy = false;
let lastPresence = [];  // zone_presence from /api/state
let lastZoneMotion = []; // zone_motion from /api/state
let lastTargets = [];   // ld2450.targets from /api/state
let lastState = null;   // last /api/state response, rendered into the active tab only
let activeTab = 'status';
let stateBusy = false;
let systemLoaded = false;
let systemInfo = null;  // last /api/system response (upload limits for the Firmware tab)
let otaBusy = false;    // an OTA run is in progress: polling paused, controls locked
let editorMap, statusMap;

// ---------- Fetch helper ----------
async function api(method, path, obj) {
  const opt = { method, headers: {} };
  if (obj !== undefined) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(obj);
  }
  const res = await fetch(path, opt);
  let data = null;
  try { data = await res.json(); } catch (e) { /* no JSON body */ }
  if (!res.ok) throw new Error((data && data.error) || 'HTTP ' + res.status);
  return data;
}
const apiGet = path => api('GET', path);
const apiPost = (path, obj) => api('POST', path, obj);

// ---------- Input helpers ----------
function num(id, label) {
  const el = typeof id === 'string' ? $('#' + id) : id;
  const v = Number(el.value);
  if (el.value === '' || !Number.isInteger(v) || v < +el.min || v > +el.max) {
    throw new Error(`${label}: ${el.min}–${el.max}`);
  }
  return v;
}
function text(id, label, minLen) {
  const v = $('#' + id).value.trim();
  if (v.length < minLen) throw new Error(label + ' must not be empty');
  return v;
}
const setVal = (id, v) => { $('#' + id).value = v; };
const setChk = (id, v) => { $('#' + id).checked = !!v; };
const setText = (id, v) => { $('#' + id).textContent = v; };
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const snap = v => Math.round(v / SNAP_MM) * SNAP_MM;
const utf8Len = s => new TextEncoder().encode(s).length;
function h(tag, cls, content) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  if (content !== undefined) el.textContent = content;
  return el;
}

// ---------- Pins (radar + light) ----------
// GPIOs the firmware rejects for the LD2450 UART: GPIO1/3 are the USB serial console,
// GPIO16 cannot receive (no pin-change interrupt).
const PIN_UNUSABLE = { 'ld-rx-pin': [1, 3, 16], 'ld-tx-pin': [1, 3] };
function buildPinSelects() {
  $$('select.pin-select').forEach(sel => BOARD_PINS.forEach(([gpio, label]) => {
    const unusable = (PIN_UNUSABLE[sel.id] || []).includes(gpio);
    const opt = new Option(`${label} (GPIO${gpio})${unusable ? ' – not usable' : ''}`, gpio);
    opt.disabled = unusable;
    sel.add(opt);
  }));
}
// pin_warnings of a section response -> hint below the matching select (#<prefix>-<field>-warn).
function renderPinWarnings(pins, warnings) {
  pins.keys.forEach(k => {
    const el = $(`#${pins.prefix}-${k.replace('_', '-')}-warn`);
    const msgs = (warnings || []).filter(w => w.field === k).map(w => w.message);
    el.textContent = msgs.join(' ');
    el.hidden = !msgs.length;
  });
}
function restartButton(question) {
  const b = h('button', 'btn inline', 'Restart now');
  b.type = 'button';
  b.addEventListener('click', () => deviceAction('/api/reboot', question, b.parentNode));
  return b;
}
// Renders the pin warnings and the restart hint of a section response (sections with
// `pins` or a `restart` question); returns true if the restart hint is shown.
function applyRestartStatus(sec, res, saved) {
  if (!(sec.pins || sec.restart) || !res) return false;
  if (sec.pins) renderPinWarnings(sec.pins, res.pin_warnings);
  if (!res.restart_required) return false;
  const question = sec.restart || 'Reboot the device now to apply the new pins?';
  setIndicator(sec, 'warn', saved ? 'Saved – restart required' : 'Restart required', restartButton(question));
  return true;
}

// ---------- LD2450 ----------
function renderLd(c) {
  setChk('ld-enabled', c.enabled);
  setChk('ld-multi-target', c.multi_target);
  setVal('ld-max-range-mm', c.max_range_mm);
  setVal('ld-occupancy-timeout-s', c.occupancy_timeout_s);
  setVal('ld-moving-threshold-cm-s', c.moving_threshold_cm_s);
  setChk('ld-sim-enabled', c.sim_enabled);
  setVal('ld-rx-pin', c.rx_pin);
  setVal('ld-tx-pin', c.tx_pin);
}
function collectLd() {
  return {
    enabled: $('#ld-enabled').checked,
    multi_target: $('#ld-multi-target').checked,
    max_range_mm: num('ld-max-range-mm', 'Max range'),
    occupancy_timeout_s: num('ld-occupancy-timeout-s', 'Occupancy timeout'),
    moving_threshold_cm_s: num('ld-moving-threshold-cm-s', 'Moving threshold'),
    sim_enabled: $('#ld-sim-enabled').checked,
    rx_pin: +$('#ld-rx-pin').value,
    tx_pin: +$('#ld-tx-pin').value
  };
}

// ---------- Zones + objects (map shapes) ----------
// Both are index-based slots with an axis-aligned rectangle; the cards (form inputs) are the
// source of truth, the maps are redrawn from them. Objects are for orientation only (no presence).
const KINDS = {
  zone: { count: ZONES, tpl: '#zone-card-template', list: '#zone-list', label: 'Zone', section: 'zones' },
  object: { count: OBJECTS, tpl: '#object-card-template', list: '#object-list', label: 'Object', section: 'objects' }
};
function buildShapeCards(kind) {
  const k = KINDS[kind], tpl = $(k.tpl), box = $(k.list);
  for (let i = 0; i < k.count; i++) {
    const card = tpl.content.cloneNode(true);
    const el = $('.shape-card', card);
    el.dataset.kind = kind;
    el.dataset.index = i;
    el.classList.add('absent'); // hidden until loaded
    if (kind === 'zone') el.classList.add('zone-color-' + i); // --zc for swatch and selection outline
    box.appendChild(card);
  }
}
const cardsOf = kind => $$(`.shape-card[data-kind="${kind}"]`);
const shapeCard = (kind, i) => $(`.shape-card[data-kind="${kind}"][data-index="${i}"]`);
const coordInput = (card, k) => $(`.shape-coord[data-key="${k}"]`, card);
const sectionOf = kind => sections[KINDS[kind].section];
const savedShapes = kind => kind === 'zone' ? zonesConfig : objectsConfig;

// A slot is in use (present) as long as its card is not marked "absent".
const isPresent = card => !card.classList.contains('absent');
// Reads one card without validation; empty coordinates become NaN.
function readShape(card) {
  const present = isPresent(card);
  const s = { id: +card.dataset.index, name: $('.shape-name', card).value.trim(), present };
  if (card.dataset.kind === 'zone') {
    s.enabled = present && $('.zone-enabled', card).checked;
    s.min_resolution = +$('.zone-min-resolution', card).value || 0;
  } else {
    s.type = $('.object-type', card).value;
    s.rotation_deg = +$('.object-rotation', card).value;
  }
  COORDS.forEach(k => {
    const v = coordInput(card, k).value;
    s[k] = v === '' ? NaN : Number(v);
  });
  return s;
}
// Reads the current form state without validation (for the live map preview).
const readShapes = kind => cardsOf(kind).map(readShape);
const readZones = () => readShapes('zone');
const readObjects = () => readShapes('object');
function writeRect(card, r) {
  COORDS.forEach(k => { coordInput(card, k).value = r[k]; });
}
function collectShapes(kind) {
  const list = readShapes(kind), label = KINDS[kind].label;
  list.forEach((s, i) => {
    if (!s.present) return; // deleted slot: name/geometry are ignored by the firmware
    if (!s.name) throw new Error(`${label} ${i + 1}: name is missing`);
    if (utf8Len(s.name) > NAME_MAX) throw new Error(`${label} ${i + 1}: name must be at most ${NAME_MAX} bytes`);
    COORDS.forEach(k => {
      const lo = k[0] === 'x' ? MAP.xMin : MAP.yMin, hi = k[0] === 'x' ? MAP.xMax : MAP.yMax;
      if (!Number.isInteger(s[k]) || s[k] < lo || s[k] > hi) {
        throw new Error(`${s.name}: ${k.toUpperCase()} must be ${lo}–${hi} mm`);
      }
    });
    if (s.x1 >= s.x2) throw new Error(`${s.name}: X1 must be less than X2`);
    if (s.y1 >= s.y2) throw new Error(`${s.name}: Y1 must be less than Y2`);
  });
  return list; // always one entry per slot
}
const collectZones = () => collectShapes('zone');
const collectObjects = () => collectShapes('object');

// Orders and clamps a span to [lo, hi] with at least MIN_SHAPE_MM between both ends.
function normSpan(a, b, lo, hi) {
  const p = clamp(Math.round(Math.min(a, b)), lo, hi - MIN_SHAPE_MM);
  return [p, clamp(Math.round(Math.max(a, b)), p + MIN_SHAPE_MM, hi)];
}
// Returns a valid rectangle (x1 < x2, y1 < y2, inside the map), or null if a coordinate is missing.
function normRect(z) {
  if (COORDS.some(k => !Number.isFinite(z[k]))) return null;
  const x = normSpan(z.x1, z.x2, MAP.xMin, MAP.xMax), y = normSpan(z.y1, z.y2, MAP.yMin, MAP.yMax);
  return { x1: x[0], y1: y[0], x2: x[1], y2: y[1] };
}
// Span of length len around center, shifted (and if needed shortened) to stay inside [lo, hi].
function fitSpan(center, len, lo, hi) {
  len = Math.min(len, hi - lo);
  const a = clamp(Math.round(center - len / 2), lo, hi - len);
  return [a, a + len];
}
// Called on "change" of a coordinate input: typed values are ordered/clamped before saving,
// empty fields fall back to the last saved value.
function normalizeShapeCard(card) {
  const s = readShape(card), saved = savedShapes(card.dataset.kind)[s.id] || {};
  COORDS.forEach(k => { if (!Number.isFinite(s[k])) s[k] = saved[k] ?? 0; });
  writeRect(card, normRect(s));
}
// Called on "change" of the signal-quality input: a plain scalar, so just round it and keep it
// inside the range the firmware accepts, instead of saving an intermediate value that gets a 400.
function normalizeZoneSignal(card) {
  const input = $('.zone-min-resolution', card), v = Number(input.value);
  input.value = Number.isFinite(v) ? clamp(Math.round(v), 0, ZONE_SIGNAL_MAX) : 0;
}
// The rectangle is always the axis-aligned footprint: turning an object by an odd multiple
// of 90 deg swaps its width and height around the center.
function rotateObjectCard(card) {
  const rot = +$('.object-rotation', card).value, prev = +(card.dataset.rot || 0);
  card.dataset.rot = rot;
  const r = normRect(readShape(card));
  if (!r || (rot - prev) / 90 % 2 === 0) return;
  const cx = (r.x1 + r.x2) / 2, cy = (r.y1 + r.y2) / 2;
  const x = fitSpan(cx, r.y2 - r.y1, MAP.xMin, MAP.xMax), y = fitSpan(cy, r.x2 - r.x1, MAP.yMin, MAP.yMax);
  writeRect(card, { x1: x[0], y1: y[0], x2: x[1], y2: y[1] });
}

function refreshEditorUi() {
  const zones = readZones(), objects = readObjects();
  cardsOf('zone').forEach((c, i) => c.classList.toggle('off', !zones[i].enabled));
  $('#btn-zone-add').disabled = zones.every(z => z.present);
  $('#btn-object-add').disabled = objects.every(o => o.present);
  drawShapes(editorMap, zones, objects, lastPresence);
}
function setObjectFields(card, type, rot) {
  $('.object-type', card).value = OBJECT_TYPES[type] ? type : 'other';
  rot = ROTATIONS.includes(rot) ? rot : 0;
  $('.object-rotation', card).value = rot;
  card.dataset.rot = rot;
}
function renderShapes(kind, list) {
  // A 200 response with an empty/unparsable body is returned as `list === null` by api() (see
  // api()'s comment). Throwing here (instead of adopting `null`) keeps the last-known-good
  // zonesConfig/objectsConfig intact and lets the caller's own error indicator show it.
  if (!Array.isArray(list)) throw new Error('empty response');
  if (kind === 'zone') zonesConfig = list; else objectsConfig = list;
  cardsOf(kind).forEach((c, i) => {
    const s = list[i] || {};
    c.classList.toggle('absent', !s.present);
    $('.shape-name', c).value = s.name || '';
    if (kind === 'zone') {
      $('.zone-enabled', c).checked = !!s.enabled;
      $('.zone-min-resolution', c).value = s.min_resolution ?? 0;
    } else setObjectFields(c, s.type, s.rotation_deg);
    COORDS.forEach(k => { coordInput(c, k).value = s[k] ?? ''; });
  });
  refreshEditorUi();
  drawShapes(statusMap, zonesConfig, objectsConfig, lastPresence);
}
const renderZones = list => renderShapes('zone', list);
const renderObjects = list => renderShapes('object', list);
function selectShape(kind, i) {
  const match = el => el.dataset.kind === kind && +el.dataset.index === i;
  $$('.shape-card').forEach(c => c.classList.toggle('selected', match(c)));
  [...editorMap.zones, ...editorMap.objects].forEach(ms => ms.g.classList.toggle('selected', match(ms.g)));
}
// Takes the first free slot, gives it a default name/rectangle and saves right away.
function addShape(kind) {
  const card = cardsOf(kind).find(c => !isPresent(c));
  if (!card) return;
  const i = +card.dataset.index;
  card.classList.remove('absent');
  $('.shape-name', card).value = KINDS[kind].label + ' ' + (i + 1);
  if (kind === 'zone') {
    $('.zone-enabled', card).checked = false;
    $('.zone-min-resolution', card).value = 0;
    writeRect(card, NEW_ZONE_RECT);
  } else {
    setObjectFields(card, 'other', 0);
    writeRect(card, newObjectRect(i));
  }
  refreshEditorUi();
  selectShape(kind, i);
  scheduleSave(sectionOf(kind), true);
}
// Frees the slot (present=false); for a zone the firmware also removes its HA entity.
function deleteShape(card) {
  const kind = card.dataset.kind, label = KINDS[kind].label;
  if (!confirm(`Delete ${label.toLowerCase()} "${$('.shape-name', card).value.trim() || +card.dataset.index + 1}"?`)) return;
  card.classList.add('absent');
  card.classList.remove('selected');
  if (kind === 'zone') $('.zone-enabled', card).checked = false;
  refreshEditorUi();
  scheduleSave(sectionOf(kind), true);
}

// Objects whose center lies inside the zone (inclusive bounds, like the firmware target test).
function objectsInZone(zone, objects) {
  const minX = Math.min(zone.x1, zone.x2), maxX = Math.max(zone.x1, zone.x2);
  const minY = Math.min(zone.y1, zone.y2), maxY = Math.max(zone.y1, zone.y2);
  return objects.filter(o => {
    if (!o.present) return false;
    const cx = (o.x1 + o.x2) / 2, cy = (o.y1 + o.y2) / 2;
    return cx >= minX && cx <= maxX && cy >= minY && cy <= maxY;
  });
}

// ---------- Zone map (SVG) ----------
// 1 user unit = 1 mm, sensor at (0,0) looking towards +Y (down on screen).
function svgEl(tag, attrs, parent) {
  const el = document.createElementNS(SVG_NS, tag);
  setAttrs(el, attrs);
  if (parent) parent.appendChild(el);
  return el;
}
function setAttrs(el, attrs) {
  for (const k in attrs) el.setAttribute(k, attrs[k]);
}

// One group per zone/object slot: rectangle, name label, corner handles (editor only);
// objects additionally get a facing-direction arrow and a type label.
function buildShape(layer, kind, i, editable) {
  const g = svgEl('g', { class: `map-shape map-${kind}` + (kind === 'zone' ? ' zone-color-' + i : '') }, layer);
  g.dataset.kind = kind;
  g.dataset.index = i;
  const ms = { g, rect: svgEl('rect', { class: kind + '-rect' }, g), handles: [] };
  if (kind === 'object') ms.arrow = svgEl('path', { class: 'object-arrow' }, g);
  ms.label = svgEl('text', { class: kind + '-label', dy: '1.1em' }, g);
  if (kind === 'object') ms.typeLabel = svgEl('text', { class: 'object-type-label', dy: '2.3em' }, g);
  for (let c = 0; editable && c < 4; c++) {
    const hd = svgEl('circle', { class: 'shape-handle' }, g);
    hd.dataset.corner = c; // 0=x1/y1, 1=x2/y1, 2=x2/y2, 3=x1/y2
    ms.handles.push(hd);
  }
  return ms;
}

// Builds the static layers (field, FOV, 1 m grid, sensor), one group per zone and object
// (objects above the zones, so they stay draggable inside a zone) and one marker per target.
function buildMap(svg, editable) {
  const m = { svg, zones: [], objects: [], targets: [] };
  svgEl('rect', { class: 'map-field', x: MAP.xMin, y: MAP.yMin, width: MAP.xMax - MAP.xMin, height: MAP.yMax - MAP.yMin }, svg);
  // LD2450 field of view: +-60 deg azimuth up to 6 m
  const r = MAP.yMax, fx = Math.round(r * Math.sin(Math.PI / 3)), fy = Math.round(r * Math.cos(Math.PI / 3));
  svgEl('path', { class: 'map-fov', d: `M0 0L${-fx} ${fy}A${r} ${r} 0 0 0 ${fx} ${fy}Z` }, svg);
  const grid = svgEl('g', { class: 'map-grid' }, svg);
  for (let x = MAP.xMin; x <= MAP.xMax; x += 1000) {
    svgEl('line', { x1: x, y1: MAP.yMin, x2: x, y2: MAP.yMax }, grid);
    // no labels at x=0 (sensor) and at the map edges (would be clipped)
    if (x && Math.abs(x) < MAP.xMax) svgEl('text', { x, y: 40, dy: '0.9em', 'text-anchor': 'middle' }, grid).textContent = Math.abs(x / 1000) + ' m';
  }
  for (let y = MAP.yMin; y <= MAP.yMax; y += 1000) {
    svgEl('line', { x1: MAP.xMin, y1: y, x2: MAP.xMax, y2: y }, grid);
    if (y) svgEl('text', { x: 80, y: y - 60 }, grid).textContent = y / 1000 + ' m';
  }
  const zoneLayer = svgEl('g', {}, svg), objectLayer = svgEl('g', {}, svg);
  for (let i = 0; i < ZONES; i++) m.zones.push(buildShape(zoneLayer, 'zone', i, editable));
  for (let i = 0; i < OBJECTS; i++) m.objects.push(buildShape(objectLayer, 'object', i, editable));
  const targetLayer = svgEl('g', {}, svg);
  for (let t = 0; t < TARGETS; t++) {
    m.targets.push(svgEl('circle', { class: 'map-target target-' + t, cx: 0, cy: 0, visibility: 'hidden' }, targetLayer));
  }
  if (editable) m.guides = svgEl('g', { class: 'map-guides' }, svg);
  svgEl('polygon', { class: 'map-sensor', points: '-160,-140 160,-140 0,140' }, svg);
  if (editable) bindMapDrag(m);
  return m;
}

const isCoarse = () => matchMedia('(pointer: coarse)').matches;
// mm per CSS px of a map, 0 while its tab is hidden.
function mmPerPx(svg) {
  const b = svg.getBoundingClientRect();
  return b.width && b.height ? Math.max(MAP.vbW / b.width, MAP.vbH / b.height) : 0;
}
// Keeps handles, markers and labels at a constant on-screen size (k = mm per CSS px).
function scaleMap(m) {
  const k = mmPerPx(m.svg);
  if (!k) return; // tab hidden
  const handlePx = isCoarse() ? 13 : 8;
  m.svg.style.fontSize = Math.round(11 * k) + 'px'; // px inside SVG = user units
  [...m.zones, ...m.objects].forEach(ms => ms.handles.forEach(hd => hd.setAttribute('r', Math.round(handlePx * k))));
  m.targets.forEach(c => c.setAttribute('r', Math.round(7 * k)));
}
const scaleMaps = () => [statusMap, editorMap].forEach(scaleMap);

// Common geometry of a zone/object group; returns the drawn rectangle or null.
function drawShape(ms, s) {
  const r = normRect(s);
  ms.g.classList.toggle('absent', !s.present);
  if (!r) return null; // incomplete input: keep the last drawn geometry
  setAttrs(ms.rect, { x: r.x1, y: r.y1, width: r.x2 - r.x1, height: r.y2 - r.y1 });
  setAttrs(ms.label, { x: r.x1 + 60, y: r.y1 + 30 });
  ms.label.textContent = s.name;
  const pts = [[r.x1, r.y1], [r.x2, r.y1], [r.x2, r.y2], [r.x1, r.y2]];
  ms.handles.forEach((hd, c) => setAttrs(hd, { cx: pts[c][0], cy: pts[c][1] }));
  return r;
}
function drawShapes(m, zones, objects, presence) {
  m.zones.forEach((ms, i) => {
    const z = zones[i] || {};
    ms.g.classList.toggle('off', !z.enabled);
    ms.g.classList.toggle('active', !!z.enabled && presence[i] === true);
    drawShape(ms, z);
  });
  m.objects.forEach((ms, i) => {
    const o = objects[i] || {}, r = drawShape(ms, o);
    if (!r) return;
    setAttrs(ms.typeLabel, { x: r.x1 + 60, y: r.y1 + 30 });
    ms.typeLabel.textContent = OBJECT_TYPES[o.type] || OBJECT_TYPES.other;
    // Facing direction: arrow through the center, 0 deg = towards the sensor, turning clockwise
    const cx = (r.x1 + r.x2) / 2, cy = (r.y1 + r.y2) / 2, a = Math.min(r.x2 - r.x1, r.y2 - r.y1) * 0.3;
    setAttrs(ms.arrow, {
      d: `M${cx} ${cy - a}L${cx + a * 0.7} ${cy + a * 0.6}L${cx} ${cy + a * 0.2}L${cx - a * 0.7} ${cy + a * 0.6}Z`,
      transform: `rotate(${o.rotation_deg || 0} ${cx} ${cy})`
    });
  });
}

// Markers move via CSS transform so they glide between two polls; a target that
// just (re)appeared jumps to its position without animation. Moving targets pulse.
function drawTargets(m, targets) {
  m.targets.forEach((c, t) => {
    const tg = targets[t], on = !!(tg && tg.active);
    if (on) {
      c.style.transition = c.getAttribute('visibility') === 'hidden' ? 'none' : '';
      c.style.transform = `translate(${tg.x_mm}px, ${tg.y_mm}px)`;
    }
    c.classList.toggle('moving', on && !!tg.moving);
    c.setAttribute('visibility', on ? 'visible' : 'hidden');
  });
}

// Rectangles of all present zones and objects except the dragged one (all shapes dock to each other).
function otherRects(kind, index) {
  const rects = [];
  [['zone', readZones()], ['object', readObjects()]].forEach(([k, list]) => list.forEach((s, j) => {
    const r = s.present && !(k === kind && j === index) && normRect(s);
    if (r) rects.push(r);
  }));
  return rects;
}
// Snap targets per axis as { v, rank, cap } (lower rank wins, cap = max reach in mm): edges of the other
// zones/objects, map border, sensor origin (x = 0), coarse grid. Only ranks below 3 get a guide line.
function computeSnapCandidates(rects) {
  const c = { x: [], y: [] }, add = (axis, v, rank, cap = EDGE_SNAP_TOL_MM) => c[axis].push({ v, rank, cap });
  rects.forEach(r => {
    add('x', r.x1, 0); add('x', r.x2, 0); add('y', r.y1, 0); add('y', r.y2, 0);
  });
  add('x', MAP.xMin, 1); add('x', MAP.xMax, 1); add('y', MAP.yMin, 1); add('y', MAP.yMax, 1);
  add('x', 0, 2);
  for (let x = MAP.xMin; x <= MAP.xMax; x += GRID_SNAP_MM) add('x', x, 3, GRID_SNAP_TOL_MM);
  for (let y = MAP.yMin; y <= MAP.yMax; y += GRID_SNAP_MM) add('y', y, 3, GRID_SNAP_TOL_MM);
  return c;
}
// Picks the better of two snap hits (lower rank, then smaller offset); either may be null.
const betterSnap = (a, b) => !b || (a && (a.rank - b.rank || Math.abs(a.off) - Math.abs(b.off)) <= 0) ? a : b;
// Best candidate within toleranceMm as { v, rank, off } (off = v - value), or null.
function snapToCandidates(value, candidates, toleranceMm) {
  return candidates.reduce((best, c) =>
    Math.abs(c.v - value) <= Math.min(toleranceMm, c.cap) ? betterSnap(best, { v: c.v, rank: c.rank, off: c.v - value }) : best, null);
}
// Snapped position of a dragged corner; falls back to the fine SNAP_MM rounding.
function snapValue(value, candidates, toleranceMm) {
  const hit = snapToCandidates(value, candidates, toleranceMm);
  return hit ? hit.v : snap(value);
}
// Snapped shift d of a moved span [a, b]: whichever edge is closer to a target (by rank) docks there.
function snapShift(a, b, d, candidates, toleranceMm) {
  const hit = betterSnap(snapToCandidates(a + d, candidates, toleranceMm), snapToCandidates(b + d, candidates, toleranceMm));
  return hit ? d + hit.off : snap(d);
}
// Dashed guide lines through the given docked edges (only while dragging).
function drawGuides(m, xs, ys) {
  m.guides.replaceChildren();
  xs.forEach(x => svgEl('line', { class: 'map-guide', x1: x, y1: MAP.yMin, x2: x, y2: MAP.yMax }, m.guides));
  ys.forEach(y => svgEl('line', { class: 'map-guide', x1: MAP.xMin, y1: y, x2: MAP.xMax, y2: y }, m.guides));
}
// Edge values that lie on a guide-worthy snap target (zone/object edge, map border, origin).
const guidesAt = (candidates, vals) => [...new Set(vals)].filter(v => candidates.some(c => c.rank < 3 && c.v === v));

// Pointer drag on the editor map: a corner handle resizes, the rect body moves the zone/object.
// The number inputs are the source of truth; the map is redrawn from them.
function bindMapDrag(m) {
  let drag = null;
  const toMm = e => new DOMPoint(e.clientX, e.clientY).matrixTransform(m.svg.getScreenCTM().inverse());
  m.svg.addEventListener('pointerdown', e => {
    if (drag) return; // ignore a second pointer (multi-touch) while a drag is running
    const g = e.target.closest('.map-shape');
    if (!g || e.button !== 0) return;
    const kind = g.dataset.kind, i = +g.dataset.index, card = shapeCard(kind, i), r = normRect(readShape(card));
    if (!r) return;
    e.preventDefault();
    selectShape(kind, i);
    g.parentNode.appendChild(g); // bring to front (within its layer)
    const corner = e.target.classList.contains('shape-handle') ? +e.target.dataset.corner : -1;
    const tol = mmPerPx(m.svg) * (isCoarse() ? SNAP_PX_COARSE : SNAP_PX);
    drag = { id: e.pointerId, kind, card, r, corner, start: toMm(e), moved: false, tol, cands: computeSnapCandidates(otherRects(kind, i)) };
    m.svg.setPointerCapture(e.pointerId);
  });
  m.svg.addEventListener('pointermove', e => {
    if (!drag || e.pointerId !== drag.id) return;
    const p = toMm(e), r = drag.r, c = drag.corner, cx = drag.cands.x, cy = drag.cands.y;
    let n, ex, ey; // ex/ey: edges that follow the pointer (for the guide lines)
    if (c < 0) {
      const dx = clamp(snapShift(r.x1, r.x2, p.x - drag.start.x, cx, drag.tol), MAP.xMin - r.x1, MAP.xMax - r.x2);
      const dy = clamp(snapShift(r.y1, r.y2, p.y - drag.start.y, cy, drag.tol), MAP.yMin - r.y1, MAP.yMax - r.y2);
      n = { x1: r.x1 + dx, y1: r.y1 + dy, x2: r.x2 + dx, y2: r.y2 + dy };
      ex = [n.x1, n.x2];
      ey = [n.y1, n.y2];
    } else {
      const x = snapValue(p.x, cx, drag.tol), y = snapValue(p.y, cy, drag.tol);
      n = Object.assign({}, r);
      if (c === 0 || c === 3) n.x1 = clamp(x, MAP.xMin, r.x2 - MIN_SHAPE_MM);
      else n.x2 = clamp(x, r.x1 + MIN_SHAPE_MM, MAP.xMax);
      if (c === 0 || c === 1) n.y1 = clamp(y, MAP.yMin, r.y2 - MIN_SHAPE_MM);
      else n.y2 = clamp(y, r.y1 + MIN_SHAPE_MM, MAP.yMax);
      ex = [c === 0 || c === 3 ? n.x1 : n.x2];
      ey = [c === 0 || c === 1 ? n.y1 : n.y2];
    }
    writeRect(drag.card, n);
    drag.moved = true;
    drawGuides(m, guidesAt(cx, ex), guidesAt(cy, ey));
    refreshEditorUi();
  });
  const end = e => {
    if (!drag || e.pointerId !== drag.id) return;
    const moved = drag.moved, kind = drag.kind;
    drag = null;
    drawGuides(m, [], []);
    if (moved) scheduleSave(sectionOf(kind), false);
  };
  m.svg.addEventListener('pointerup', end);
  m.svg.addEventListener('pointercancel', end);
}

// ---------- BH1750 ----------
function renderBh(c) {
  setChk('bh-enabled', c.enabled);
  setVal('bh-i2c-address', c.i2c_address);
  setVal('bh-mode', c.mode);
  setVal('bh-interval-ms', c.interval_ms);
  setChk('bh-sim-enabled', c.sim_enabled);
  setVal('bh-sda-pin', c.sda_pin);
  setVal('bh-scl-pin', c.scl_pin);
}
function collectBh() {
  return {
    enabled: $('#bh-enabled').checked,
    i2c_address: +$('#bh-i2c-address').value,
    mode: +$('#bh-mode').value,
    interval_ms: num('bh-interval-ms', 'Measurement interval'),
    sim_enabled: $('#bh-sim-enabled').checked,
    sda_pin: +$('#bh-sda-pin').value,
    scl_pin: +$('#bh-scl-pin').value
  };
}

// ---------- MQTT ----------
function renderMqtt(c) {
  setChk('mqtt-enabled', c.enabled);
  setVal('mqtt-host', c.host);
  setVal('mqtt-port', c.port);
  setVal('mqtt-user', c.user);
  setVal('mqtt-pass', c.pass);
  setVal('mqtt-topic-prefix', c.topic_prefix);
  setVal('mqtt-device-name', c.device_name);
  setVal('mqtt-keepalive', c.keepalive_s);
  setVal('mqtt-socket-timeout', c.socket_timeout_s);
}
function collectMqtt() {
  const keepalive = num('mqtt-keepalive', 'MQTT keepalive');
  const socketTimeout = num('mqtt-socket-timeout', 'MQTT connection timeout');
  if (socketTimeout >= keepalive) throw new Error('Connection timeout must be lower than the keepalive');
  return {
    enabled: $('#mqtt-enabled').checked,
    host: text('mqtt-host', 'Broker', 0),
    port: num('mqtt-port', 'Port'),
    user: $('#mqtt-user').value,
    pass: $('#mqtt-pass').value,
    topic_prefix: text('mqtt-topic-prefix', 'Topic prefix', 1),
    device_name: text('mqtt-device-name', 'Device name', 1),
    keepalive_s: keepalive,
    socket_timeout_s: socketTimeout
  };
}

// ---------- Home Assistant entities ----------
// Checkbox id -> JSON field of /api/config/ha-expose.
const HA_EXPOSE = { 'ha-presence': 'presence', 'ha-target-count': 'target_count', 'ha-illuminance': 'illuminance',
  'ha-motion': 'motion', 'ha-zone-motion': 'zone_motion' };
function renderHaExpose(c) {
  Object.entries(HA_EXPOSE).forEach(([id, key]) => setChk(id, c[key]));
}
function collectHaExpose() {
  const body = {};
  Object.entries(HA_EXPOSE).forEach(([id, key]) => { body[key] = $('#' + id).checked; });
  return body;
}

// ---------- Network ----------
// Same rules as the firmware validation (validateHostname/validateIp in web_server.cpp).
const HOSTNAME_RE = /^[A-Za-z0-9]([A-Za-z0-9-]{0,29}[A-Za-z0-9])?$/;
const IPV4_RE = /^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
function ipField(id, label, required) {
  const v = $('#' + id).value.trim();
  if (!v && !required) return '';
  if (!IPV4_RE.test(v)) throw new Error(label + ': IPv4 address like 192.168.1.50');
  return v;
}
function showStaticIpFields() {
  $('#wifi-static-fields').hidden = !$('#wifi-use-static-ip').checked;
}
function renderWifi(c) {
  setChk('wifi-no-sleep', c.no_modem_sleep);
  setVal('wifi-hostname', c.hostname);
  setChk('wifi-use-static-ip', c.use_static_ip);
  setVal('wifi-static-ip', c.static_ip);
  setVal('wifi-gateway', c.gateway);
  setVal('wifi-subnet', c.subnet);
  setVal('wifi-dns', c.dns);
  $('#wifi-fallback-warn').hidden = !c.static_ip_fallback;
  showStaticIpFields();
}
function collectWifi() {
  const hostname = $('#wifi-hostname').value.trim();
  if (!HOSTNAME_RE.test(hostname)) throw new Error("Hostname: 1–31 of A–Z, a–z, 0–9 and '-', not at the start or end");
  // With DHCP the address fields are optional and only kept for later
  const req = $('#wifi-use-static-ip').checked;
  return {
    no_modem_sleep: $('#wifi-no-sleep').checked,
    hostname,
    use_static_ip: req,
    static_ip: ipField('wifi-static-ip', 'IP address', req),
    gateway: ipField('wifi-gateway', 'Gateway', req),
    subnet: ipField('wifi-subnet', 'Subnet mask', req),
    dns: ipField('wifi-dns', 'DNS server', false)
  };
}
// Erases the stored Wi-Fi credentials; the device comes back as the setup AP, not on this network.
async function resetWifiSetup() {
  if (!confirm('Forget the Wi-Fi network and restart?\n\nThe device will not reconnect to this network. ' +
    'Connect to the Wi-Fi "PresenceTrack-Setup" afterwards to set it up again.')) return;
  const msg = $('#wifi-msg');
  try {
    await apiPost('/api/wifi/reset');
    msg.textContent = 'Device is restarting. Connect to the Wi-Fi "PresenceTrack-Setup" to choose a network.';
    $$('.actions button').forEach(b => { b.disabled = true; });
  } catch (e) {
    msg.textContent = 'Error: ' + e.message;
  }
}

// ---------- Sections + auto-save ----------
// tab = data-tab the section is loaded for; the form root is `root` or #tab-<key>.
// kind: map shape kind (zones/objects share the Zones tab, each with its own list as root).
// mqtt/haExpose/wifi share the MQTT tab, each with its own card as root.
const sections = {
  ld2450: { tab: 'ld2450', path: '/api/config/ld2450', ind: 'ld-save-indicator', render: renderLd, collect: collectLd,
    pins: { prefix: 'ld', keys: ['rx_pin', 'tx_pin'] } },
  zones: { tab: 'zones', root: '#zone-list', kind: 'zone', path: '/api/zones', ind: 'zones-save-indicator', render: renderZones, collect: collectZones },
  objects: { tab: 'zones', root: '#object-list', kind: 'object', path: '/api/objects', ind: 'objects-save-indicator', render: renderObjects, collect: collectObjects },
  light: { tab: 'light', path: '/api/config/bh1750', ind: 'bh-save-indicator', render: renderBh, collect: collectBh,
    pins: { prefix: 'bh', keys: ['sda_pin', 'scl_pin'] } },
  mqtt: { tab: 'mqtt', root: '#mqtt-card', path: '/api/config/mqtt', ind: 'mqtt-save-indicator', render: renderMqtt, collect: collectMqtt },
  haExpose: { tab: 'mqtt', root: '#ha-expose-card', path: '/api/config/ha-expose', ind: 'ha-expose-save-indicator',
    render: renderHaExpose, collect: collectHaExpose },
  wifi: { tab: 'mqtt', root: '#network-card', path: '/api/config/wifi', ind: 'wifi-save-indicator', render: renderWifi, collect: collectWifi,
    restart: 'Reboot the device now to apply the new network settings? It may come back under a new IP address.' }
};

// action: optional element (e.g. a button) appended after the message.
function setIndicator(sec, cls, msg, action) {
  const el = $('#' + sec.ind);
  clearTimeout(sec.fade);
  el.textContent = msg;
  if (action) el.append(action);
  el.className = 'save-indicator show ' + cls;
  if (cls === 'ok') sec.fade = setTimeout(() => el.classList.remove('show'), 1500);
}

function scheduleSave(sec, immediate) {
  clearTimeout(sec.timer);
  setIndicator(sec, 'saving', 'Saving…');
  sec.timer = setTimeout(() => save(sec), immediate ? 0 : DEBOUNCE_MS);
}

async function save(sec) {
  sec.timer = null;
  if (sec.busy) { sec.again = true; return; } // resend after the running POST
  let body;
  try { body = sec.collect(); } catch (e) { setIndicator(sec, 'err', 'Error: ' + e.message); return; }
  sec.busy = true;
  try {
    const res = await apiPost(sec.path, body);
    if (sec.kind) {
      // See renderShapes(): a 200 with an empty/unparsable body comes back as `res === null`.
      if (!Array.isArray(res)) throw new Error('empty response');
      if (sec.kind === 'zone') zonesConfig = res; else objectsConfig = res;
      drawShapes(statusMap, zonesConfig, objectsConfig, lastPresence);
    }
    if (!sec.again && !sec.timer && !applyRestartStatus(sec, res, true)) setIndicator(sec, 'ok', 'Saved ✓');
  } catch (e) {
    setIndicator(sec, 'err', 'Error: ' + e.message);
  }
  sec.busy = false;
  if (sec.again) { sec.again = false; save(sec); }
}

async function loadSection(key) {
  const sec = sections[key];
  if (!sec || sec.timer || sec.busy) return; // do not overwrite unsaved input
  try {
    const data = await apiGet(sec.path);
    if (!sec.timer && !sec.busy) {
      sec.render(data);
      applyRestartStatus(sec, data, false);
    }
  } catch (e) {
    setIndicator(sec, 'err', 'Error: ' + e.message);
  }
}

// Text/number: input -> debounce; checkbox/select: change -> save immediately.
// Shape coordinates are additionally normalized on change (blur/enter/spinner).
const isDiscrete = t => t.type === 'checkbox' || t.tagName === 'SELECT';
function bindSection(key) {
  const sec = sections[key], root = $(sec.root || '#tab-' + key);
  root.addEventListener('input', e => {
    if (isDiscrete(e.target)) return;
    if (sec.kind) refreshEditorUi();
    scheduleSave(sec, false);
  });
  root.addEventListener('change', e => {
    const t = e.target, coord = t.classList.contains('shape-coord');
    const signal = t.classList.contains('zone-min-resolution');
    if (!isDiscrete(t) && !coord && !signal) return;
    if (coord) normalizeShapeCard(t.closest('.shape-card'));
    if (signal) normalizeZoneSignal(t.closest('.shape-card'));
    if (t.classList.contains('object-rotation')) rotateObjectCard(t.closest('.shape-card'));
    if (sec.kind) refreshEditorUi();
    scheduleSave(sec, true);
  });
}

// ---------- Status + system ----------
function fmtUptime(s) {
  const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return (d ? d + ' d ' : '') + h + ' h ' + m + ' min';
}
function fmtBytes(b) {
  if (!Number.isFinite(b)) return '–';
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KiB';
  return (b / 1048576).toFixed(2) + ' MiB';
}
function fmtAge(ms) {
  if (!Number.isFinite(ms)) return '–';
  const s = Math.round(ms / 1000);
  return s < 1 ? 'just now' : s < 120 ? s + ' s ago' : fmtUptime(s) + ' ago';
}
const orDash = v => (v === undefined || v === null || v === '') ? '–' : v;
function setFlag(id, on, yes, no) {
  const el = $('#' + id);
  el.textContent = on ? yes : no;
  el.classList.toggle('on', !!on);
}
function setChip(id, label, cls) {
  const el = typeof id === 'string' ? $('#' + id) : id;
  el.textContent = label;
  el.className = 'chip' + (cls ? ' ' + cls : '');
}
function setMqtt(connected) {
  setFlag('stat-mqtt-status', connected, 'Connected', 'Disconnected');
  setChip('sys-mqtt-status', connected ? 'Connected' : 'Disconnected', connected ? 'on' : '');
  const chip = $('#mqtt-conn-indicator');
  chip.textContent = connected ? 'MQTT connected' : 'MQTT disconnected';
  chip.classList.toggle('on', !!connected);
}
// Data source of a sensor: simulation, none (simulation off, no driver yet) or real hardware.
const sensorSource = x => x.sim_mode ? 'sim' : x.sim_enabled === false ? 'none' : 'hw';
const SIM_TEXT = { sim: 'Active', none: 'Inactive (no sensor data)', hw: 'Off' };
const SOURCE_CHIP = { sim: ['Simulated', 'warn'], none: ['Inactive (no sensor data)', ''], hw: ['Hardware', 'on'] };
const setSimChip = (id, x) => setChip(id, ...SOURCE_CHIP[sensorSource(x)]);

// Status tab: one row per enabled zone with its presence + motion chips and the objects placed in it.
function renderZoneStatusList() {
  const items = [];
  zonesConfig.forEach((z, i) => {
    if (!z.present || !z.enabled) return;
    const on = lastPresence[i] === true, moving = lastZoneMotion[i] === true;
    const chip = h('span'), motionChip = h('span'), chips = h('span', 'zone-status-chips');
    setChip(chip, on ? 'Present' : 'Absent', on ? 'on' : '');
    setChip(motionChip, moving ? 'Moving' : 'Still', moving ? 'warn' : '');
    motionChip.hidden = !on; // "Still" only makes sense while the zone is occupied
    chips.append(chip, motionChip);
    const name = h('span', 'zone-status-name');
    name.append(h('i', 'zone-color-swatch'), z.name);
    const row = h('div', 'row zone-color-' + i);
    row.append(name, chips);
    const names = objectsInZone(z, objectsConfig).map(o => o.name);
    items.push(row, h('div', 'muted zone-status-objects', names.length ? names.join(', ') : '–'));
  });
  $('#stat-zone-list').replaceChildren(...(items.length ? items : [h('p', 'muted', 'No enabled zones.')]));
}

// ---------- Event log ----------
function renderEvents() {
  const items = eventLog.slice().reverse().map(ev => {
    const li = h('li', 'ev-' + ev.type);
    li.append(h('span', 'event-time', fmtAge(eventsUptimeMs - ev.uptime_ms)),
      h('span', 'event-type', EVENT_LABELS[ev.type] || ev.type), h('span', 'event-msg', ev.message));
    return li;
  });
  $('#event-list').replaceChildren(...(items.length ? items : [h('li', 'muted', 'No events yet.')]));
}
// Incremental poll (?since=<last id>) while the Status tab is open. After a reboot the
// device starts again at id 1 (last_id below the known id, or the uptime went backwards).
async function loadEvents() {
  if (eventsBusy || otaBusy || activeTab !== 'status') return;
  eventsBusy = true;
  try {
    let r = await apiGet('/api/events?since=' + lastEventId);
    if (r.last_id < lastEventId || r.uptime_ms < eventsUptimeMs) {
      eventLog = [];
      lastEventId = 0;
      r = await apiGet('/api/events?since=0');
    }
    eventsUptimeMs = r.uptime_ms;
    (r.events || []).forEach(ev => {
      if (ev.id <= lastEventId) return;
      eventLog.push(ev);
      lastEventId = ev.id;
    });
    if (eventLog.length > EVENTS_MAX) eventLog.splice(0, eventLog.length - EVENTS_MAX);
    renderEvents();
  } catch (e) { /* keep the last list; the presence card shows "Offline" */ }
  eventsBusy = false;
}

// Renders a /api/state response into the active tab only (status, zone map or system).
function renderState(s) {
  if (!s) return;
  const l = s.ld2450 || {}, b = s.bh1750 || {}, w = s.wifi || {}, sys = s.system || {};
  const lux = b.valid ? b.illuminance_lx.toFixed(1) + ' lx' : '–';
  if (activeTab === 'status') {
    setFlag('stat-presence', l.presence, 'Present', 'Absent');
    setText('stat-target-count', orDash(l.target_count));
    for (let t = 0; t < TARGETS; t++) {
      const tg = lastTargets[t];
      setText('stat-target-' + t, tg && tg.active
        ? `X ${tg.x_mm} · Y ${tg.y_mm} mm · ${tg.speed_cm_s} cm/s · Res ${tg.resolution} · ${tg.moving ? 'Moving' : 'Still'}` : '–');
    }
    setText('stat-illuminance', lux);
    setText('stat-sim-ld2450', SIM_TEXT[sensorSource(l)]);
    setText('stat-sim-bh1750', SIM_TEXT[sensorSource(b)]);
    drawShapes(statusMap, zonesConfig, objectsConfig, lastPresence);
    drawTargets(statusMap, lastTargets);
    renderZoneStatusList();
  } else if (activeTab === 'zones') {
    drawShapes(editorMap, readZones(), readObjects(), lastPresence);
    drawTargets(editorMap, lastTargets);
  } else if (activeTab === 'system') {
    setText('sys-uptime', fmtUptime(s.uptime_s));
    setText('sys-free-heap', fmtBytes(sys.free_heap));
    setText('sys-heap-frag', Number.isFinite(sys.heap_fragmentation) ? sys.heap_fragmentation + ' %' : '–');
    setText('sys-wifi-ssid', orDash(w.ssid));
    setText('sys-wifi-rssi', Number.isFinite(w.rssi) ? w.rssi + ' dBm' : '–');
    setText('sys-wifi-ip', orDash(w.ip));
    setText('sys-wifi-mac', orDash(w.mac));
    setText('sys-mqtt-host', orDash(sys.mqtt_host));
    setSimChip('sys-ld-mode', l);
    setText('sys-ld-targets', orDash(l.target_count));
    setText('sys-ld-age', fmtAge(l.last_update_ms));
    setSimChip('sys-bh-mode', b);
    setText('sys-bh-lux', lux);
    setText('sys-bh-age', fmtAge(b.last_update_ms));
  }
}

async function loadState() {
  // Paused during an OTA run: every extra request costs heap the upload needs,
  // and a failed poll while the device reboots would flash "Offline" everywhere.
  if (stateBusy || otaBusy) return;
  stateBusy = true;
  try {
    const s = await apiGet('/api/state');
    const l = s.ld2450 || {};
    lastState = s;
    lastTargets = l.targets || [];
    lastPresence = l.zone_presence || [];
    lastZoneMotion = l.zone_motion || [];
    setMqtt(s.mqtt_connected); // header chip is visible in every tab
    renderState(s);
  } catch (e) {
    lastState = null; // keep "Offline" instead of re-rendering stale values on a tab switch
    setText('stat-presence', 'Offline');
    $('#stat-presence').classList.remove('on');
  }
  stateBusy = false;
}

// Static device info: loaded the first time the System tab is opened (and retried
// after a failure). Not part of the page load - the ESP has little heap left for
// parallel requests, so the load only asks for what the Status tab shows.
async function loadSystem() {
  try {
    const s = await apiGet('/api/system');
    setText('sys-chip-id', orDash(s.chip_id));
    setText('sys-min-free-heap', fmtBytes(s.min_free_heap));
    setText('sys-flash-size', fmtBytes(s.flash_size_bytes));
    setText('sys-sketch-size', fmtBytes(s.sketch_size_bytes));
    setText('sys-free-sketch', fmtBytes(s.free_sketch_space_bytes));
    setText('sys-core-version', orDash(s.core_version));
    setText('sys-sdk-version', orDash(s.sdk_version));
    setText('sys-reset-reason', orDash(s.reset_reason));
    setText('fw-version', orDash(s.fw_version));
    setText('gh-current', orDash(s.fw_version));
    setText('fw-sketch-size', fmtBytes(s.sketch_size_bytes));
    setText('fw-free-sketch', fmtBytes(s.free_sketch_space_bytes));
    setText('fw-max-firmware', fmtBytes(s.ota_max_firmware_bytes));
    setText('fw-fs-size', fmtBytes(s.fs_size_bytes));
    systemInfo = s;
    systemLoaded = true;
    refreshOtaHints();
  } catch (e) { /* keep placeholders */ }
}

// ---------- Tabs ----------
function openTab(name) {
  $$('.tabs button').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  $$('.tab-panel').forEach(p => p.classList.toggle('active', p.id === 'tab-' + name));
  activeTab = name;
  if (name === 'status' || name === 'system') loadState();
  Object.keys(sections).forEach(k => { if (sections[k].tab === name) loadSection(k); });
  if (name === 'status') loadEvents();
  if (name === 'system' && !systemLoaded) loadSystem();
  if (name === 'firmware' && !otaBusy) loadSystem(); // always fresh: sketch size/limits change with an update
  if (name === 'firmware') ghResume();
  scaleMaps(); // maps in hidden tabs have no size until shown
  renderState(lastState); // show the last known values until the next poll arrives
}

// ---------- Reboot / factory reset ----------
// msg: element for the progress/error text (default: the Device card on the Status tab).
async function deviceAction(path, question, msg = $('#device-msg')) {
  if (!confirm(question)) return;
  try {
    await apiPost(path);
    msg.textContent = 'Rebooting…';
    $$('.actions button').forEach(b => { b.disabled = true; });
    setTimeout(() => location.reload(), 5000);
  } catch (e) {
    msg.textContent = 'Error: ' + e.message;
  }
}

// ---------- Backup / restore ----------
// Download uses a plain <a href download> (no JS needed); restore reads the chosen
// file client-side and POSTs its parsed content straight to /api/config/restore.
const backupSec = { ind: 'backup-indicator' };
const RESTORE_TEXT = {
  question: 'Restore this backup? It replaces all current settings (zones, objects, sensors, MQTT, pins) and cannot be undone.',
  busy: 'Restoring…', done: 'Restored ✓ – reloading…', err: 'Error: '
};
// sec: indicator of the calling card - the System tab and the Firmware tab share this.
async function restoreBackupFile(file, sec = backupSec) {
  if (!file || otaBusy) return; // never race the automatic restore of an OTA run
  if (!confirm(RESTORE_TEXT.question)) return;
  setIndicator(sec, 'saving', RESTORE_TEXT.busy);
  try {
    const cfg = JSON.parse(await file.text());
    await apiPost('/api/config/restore', cfg);
    setIndicator(sec, 'ok', RESTORE_TEXT.done);
    setTimeout(() => location.reload(), 1500);
  } catch (e) {
    setIndicator(sec, 'err', RESTORE_TEXT.err + e.message);
  }
}

// ---------- Firmware / OTA update ----------
// Order of one run (startOta), each step only after the previous one succeeded:
//   1. Backup   GET /api/config/backup -> downloaded as a file AND kept in memory.
//               Mandatory for every run, also firmware-only: no backup, no upload.
//   2. Firmware POST /api/firmware   (?reboot=0 if an image follows)
//   3. Image    POST /api/filesystem (replaces the web UI and wipes /config.json)
//   4. Reboot   poll /api/system until the device answers again (like flash.sh)
//   5. Restore  only after an image: POST the in-memory backup (the same bytes as
//               the downloaded file) to /api/config/restore, then reload the page.
// The manual "restore backup" dialog is the fallback for a failed step 5 and is
// locked (otaBusy) while a run is active, so the two can never overwrite each other.
const OTA_REBOOT_GRACE_MS = 5000;   // device restarts ~300 ms after the response; skip the old instance
const OTA_POLL_INTERVAL_MS = 2000;  // same cadence as flash.sh
const OTA_POLL_TIMEOUT_MS = 90000;  // eboot copy + boot + Wi-Fi join; flash.sh allows 60 s
const OTA_PROBE_TIMEOUT_MS = 3000;
const OTA_UPLOAD_TIMEOUT_MS = 180000;
const otaSec = { ind: 'ota-indicator' };
const otaRestoreSec = { ind: 'ota-restore-indicator' };
const OTA_STEPS = { backup: 'Download config backup', firmware: 'Upload firmware',
  filesystem: 'Upload filesystem image', reboot: 'Wait for restart', restore: 'Restore settings' };
const sleep = ms => new Promise(r => setTimeout(r, ms));

// Both files are called *.bin, so they are easy to mix up: tell them apart by their
// first bytes (0xE9/gzip = ESP8266 image, "littlefs" at offset 8 = LittleFS superblock).
async function sniffOtaFile(file) {
  const b = new Uint8Array(await file.slice(0, 16).arrayBuffer());
  if (b.length >= 16 && new TextDecoder().decode(b.subarray(8, 16)) === 'littlefs') return 'filesystem';
  if (b[0] === 0xE9 || b[0] === 0x1F) return 'firmware';
  return null;
}

// -> { ok, text } for the hint below the file input. The device re-checks everything;
// this only saves a doomed upload (and, for the image, it runs before any flash write).
async function checkOtaFile(kind, file) {
  const type = await sniffOtaFile(file);
  const size = fmtBytes(file.size);
  if (kind === 'firmware') {
    if (type !== 'firmware') return { ok: false, text: `${file.name}: not an ESP8266 firmware${type === 'filesystem' ? ' (this is a filesystem image)' : ''}.` };
    const max = systemInfo && systemInfo.ota_max_firmware_bytes;
    if (!max) return { ok: true, text: `${file.name}: ${size} (free space on the device not known yet).` };
    return file.size <= max
      ? { ok: true, text: `${file.name}: ${size} - fits (max. ${fmtBytes(max)}).` }
      : { ok: false, text: `${file.name}: ${size} - too large, the OTA space holds only ${fmtBytes(max)}.` };
  }
  if (type !== 'filesystem') return { ok: false, text: `${file.name}: not a LittleFS image${type === 'firmware' ? ' (this is a firmware file)' : ''}.` };
  const fsSize = systemInfo && systemInfo.fs_size_bytes;
  if (!fsSize) return { ok: true, text: `${file.name}: ${size} (partition size not known yet).` };
  return file.size === fsSize
    ? { ok: true, text: `${file.name}: ${size} - fits the filesystem partition exactly.` }
    : { ok: false, text: `${file.name}: ${size} - does not fit, the partition is ${fmtBytes(fsSize)} (different flash layout?).` };
}

async function refreshOtaHint(kind) {
  const file = $(`#ota-${kind === 'firmware' ? 'fw' : 'fs'}-file`).files[0];
  const hint = $(`#ota-${kind === 'firmware' ? 'fw' : 'fs'}-hint`);
  const r = file ? await checkOtaFile(kind, file) : { ok: true, text: '' };
  hint.textContent = r.text;
  hint.classList.toggle('warn', !r.ok);
  return r;
}
const refreshOtaHints = () => { refreshOtaHint('firmware'); refreshOtaHint('filesystem'); };

function renderOtaSteps(keys) {
  $('#ota-steps').replaceChildren(...keys.map(k => { const li = h('li', '', OTA_STEPS[k]); li.dataset.step = k; return li; }));
}
function setOtaStep(key, state, note) {
  const li = $(`#ota-steps li[data-step="${key}"]`);
  if (!li) return;
  li.className = state; // active | done | err | skip
  li.textContent = OTA_STEPS[key] + (note ? ' - ' + note : '');
}
function setOtaProgress(fraction) {
  const bar = $('#ota-progress');
  bar.hidden = fraction === null;
  if (fraction !== null) bar.value = fraction;
}
// Also locks Reboot/Factory Reset on the Status tab: the SPA stays usable during a
// run, and a reboot mid-upload would leave a half-written filesystem behind
// (the device refuses both with 409 as well, this just avoids the dead click).
function lockOta(locked) {
  otaBusy = locked;
  ['#btn-ota-start', '#ota-fw-file', '#ota-fs-file', '#btn-ota-restore', '#btn-backup-restore',
    '#btn-reboot', '#btn-factory-reset', '#btn-gh-check', '#gh-target']
    .forEach(s => { $(s).disabled = locked; });
  $('#btn-gh-install').disabled = locked || !ghAvailable; // only with a checked, newer release
}

const pad2 = n => String(n).padStart(2, '0');
function backupTimestamp(d = new Date()) {
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}_${pad2(d.getHours())}-${pad2(d.getMinutes())}-${pad2(d.getSeconds())}`;
}

// Step 1. fetch + blob + object URL + <a download>: window.location would replace the
// SPA (and abort the run). Returns the parsed backup for the automatic restore (step 5).
// Throws unless the device really delivered a JSON object - a backup that did not
// come about is no backup, so the caller must not start the upload then.
async function downloadConfigBackup() {
  let res;
  try {
    res = await fetch('/api/config/backup', { cache: 'no-store' });
  } catch (e) {
    throw new Error('device not reachable');
  }
  if (res.status !== 200) throw new Error('device answered with HTTP ' + res.status);
  const blob = await res.blob();
  let cfg;
  try { cfg = JSON.parse(await blob.text()); } catch (e) { cfg = null; }
  if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) throw new Error('response is not a valid config backup');
  const url = URL.createObjectURL(blob);
  const a = h('a');
  a.href = url;
  // Same name scheme as the System tab's "Download backup" (same route), plus a timestamp
  a.download = `presencetrack-backup-${backupTimestamp()}.json`;
  document.body.append(a);
  a.click();
  a.remove();
  // Revoked after the click, with a short delay: some browsers start reading the blob
  // asynchronously and cancel the download if the URL is already gone.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  return cfg;
}

// Steps 2/3: multipart upload via XHR (fetch has no upload progress). ?size= lets the
// device check the exact size before the first flash write.
function otaUpload(path, file, reboot, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest(), form = new FormData();
    form.append('file', file, file.name);
    xhr.open('POST', `${path}?size=${file.size}${reboot ? '' : '&reboot=0'}`);
    xhr.timeout = OTA_UPLOAD_TIMEOUT_MS;
    xhr.upload.onprogress = e => { if (e.lengthComputable) onProgress(e.loaded / e.total); };
    xhr.onload = () => {
      let data = null;
      try { data = JSON.parse(xhr.responseText); } catch (e) { /* no JSON body */ }
      if (xhr.status === 200) { resolve(data); return; }
      const err = new Error((data && data.error) || 'HTTP ' + xhr.status);
      err.fsDamaged = !!(data && data.filesystem_damaged);
      reject(err);
    };
    xhr.onerror = () => reject(new Error('connection to the device lost'));
    xhr.ontimeout = () => reject(new Error('upload timed out'));
    xhr.send(form);
  });
}

// Step 4: same idea as flash.sh - poll /api/system until the rebooted device answers.
async function waitForDevice() {
  await sleep(OTA_REBOOT_GRACE_MS);
  const deadline = Date.now() + OTA_POLL_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), OTA_PROBE_TIMEOUT_MS);
    try {
      const res = await fetch('/api/system', { cache: 'no-store', signal: ctl.signal });
      if (res.ok) return await res.json();
    } catch (e) { /* still rebooting */ } finally { clearTimeout(timer); }
    await sleep(OTA_POLL_INTERVAL_MS);
  }
  throw new Error(`device not reachable after ${OTA_POLL_TIMEOUT_MS / 1000} s`);
}

async function startOta() {
  const fw = $('#ota-fw-file').files[0], fs = $('#ota-fs-file').files[0];
  const msg = $('#ota-msg');
  msg.classList.remove('warn');
  if (!fw && !fs) { msg.textContent = 'Please choose a firmware and/or filesystem image file.'; return; }
  const checks = [fw && await refreshOtaHint('firmware'), fs && await refreshOtaHint('filesystem')].filter(Boolean);
  if (checks.some(c => !c.ok)) {
    msg.textContent = 'Update not started: ' + checks.filter(c => !c.ok).map(c => c.text).join(' ');
    msg.classList.add('warn');
    return;
  }
  const what = [fw && 'the firmware', fs && 'the filesystem image'].filter(Boolean).join(' + ');
  if (!confirm('A config backup will be downloaded before the update. Continue?\n\n' +
    `The browser saves the file presencetrack-backup-<date_time>.json to its download folder ` +
    `(or asks for a location, depending on the browser settings).\n\n` +
    `Then ${what} will be uploaded; the device restarts and is unreachable for about a minute.` +
    (fs ? '\nThe image erases the saved settings - they are restored automatically from the backup after the restart.' : ''))) return;

  lockOta(true);
  const steps = ['backup', fw && 'firmware', fs && 'filesystem', 'reboot', 'restore'].filter(Boolean);
  renderOtaSteps(steps);
  msg.textContent = '';
  let step = 'backup';
  try {
    setOtaStep(step, 'active', 'creating backup…');
    setIndicator(otaSec, 'saving', 'Updating…');
    const backup = await downloadConfigBackup();
    setOtaStep(step, 'done', 'download started');

    for (const [key, file, path, reboot] of [['firmware', fw, '/api/firmware', !fs], ['filesystem', fs, '/api/filesystem', true]]) {
      if (!file) continue;
      step = key;
      setOtaStep(step, 'active');
      setOtaProgress(0);
      await otaUpload(path, file, reboot, f => {
        setOtaProgress(f);
        setOtaStep(key, 'active', f < 1 ? Math.round(f * 100) + ' %' : 'verifying…');
      });
      setOtaProgress(null);
      setOtaStep(step, 'done', fmtBytes(file.size));
    }

    step = 'reboot';
    setOtaStep(step, 'active', 'device is restarting…');
    const info = await waitForDevice();
    setOtaStep(step, 'done', 'Version ' + orDash(info.fw_version));

    step = 'restore';
    if (fs) {
      setOtaStep(step, 'active');
      await apiPost('/api/config/restore', backup);
      setOtaStep(step, 'done');
    } else {
      setOtaStep(step, 'skip', 'not needed, a firmware update keeps the settings');
    }
    setIndicator(otaSec, 'ok', 'Done ✓');
    // Reload: after an image the device serves the new index.html/app.js/style.css,
    // and a new firmware may come with an API this page does not know yet.
    msg.textContent = 'Update complete - reloading…';
    setTimeout(() => { otaBusy = false; location.reload(); }, 3000); // no beforeunload prompt
  } catch (e) {
    setOtaProgress(null);
    setOtaStep(step, 'err', e.message);
    setIndicator(otaSec, 'err', 'Failed');
    msg.classList.add('warn');
    msg.textContent = {
      backup: 'Backup failed - the update was NOT started. Is the device reachable?',
      firmware: 'Firmware update failed. The running firmware is unchanged, the device keeps working normally.',
      filesystem: e.fsDamaged
        ? 'Filesystem update failed, the web files are damaged. Do NOT restart the device - upload the image again right away.' +
          (fw ? ' The new firmware is already staged and becomes active with the next restart.' : '')
        : 'Filesystem update rejected, nothing was changed on the device.' + (fw ? ' The new firmware is staged and becomes active with the next restart.' : ''),
      reboot: 'The device does not respond after the restart (Wi-Fi? setup portal "PresenceTrack-Setup"?).' +
        (fs ? ' Then restore the settings from the downloaded file via "Restore from file…".' : ''),
      restore: 'Automatic restore failed. Restore the downloaded backup file via "Restore from file…".'
    }[step];
    lockOta(false);
  }
}

// ---------- Firmware / update from GitHub ----------
// The device does all the work itself (firmware_update.cpp: manifest, download, SHA-256,
// flash, reboot); this page only starts a run, polls /api/update/status and waits for the
// reboot. No backup/restore round trip as in startOta(): the device writes its in-RAM config
// into the fresh LittleFS image before it reboots.
// /api/update/check answers right away (202, state "checking"); the result arrives in
// /api/update/status as `check` ("available"/"none"/"failed"/"aborted") once the device has
// fetched manifest.json (three TLS handshakes on the ESP, typically a few seconds, a failing
// hop gives up after at most 25 s). /install still answers only once the manifest is there -
// no fetch timeout. While a run (check or install) is active the device accepts only 1 HTTP
// connection besides the waiting install request (FW_UPDATE_HTTP_CONNECTIONS), none while it
// sets up a TLS connection or sends a request (the poll then waits for the TCP retransmit,
// ~1-3 s), and needs its heap for TLS: the regular polling pauses (otaBusy), only the status
// is polled.
const GH_POLL_MS = 1000;
const GH_POLL_MISSES_MAX = 10; // consecutive failed polls outside of the reboot
const ghSec = { ind: 'gh-indicator' };
const GH_STATE_TEXT = { checking: 'Fetching manifest…', downloading: 'Connecting to GitHub…',
  flashing: 'Writing…', rebooting: 'Restarting…' };
let ghAvailable = null; // {version, firmware_size, filesystem_size} of the last check with a newer release
let ghMode = null;      // 'check' | 'install' while this page follows a run

function ghLock(mode) {
  ghMode = mode;
  lockOta(!!mode);
  $('#btn-gh-abort').hidden = !mode;
}

function ghShowProgress(s) {
  const bar = $('#gh-progress');
  bar.hidden = !(s.bytes_total > 0);
  if (s.bytes_total > 0) bar.value = s.bytes_done / s.bytes_total;
  $('#gh-msg').textContent = (GH_STATE_TEXT[s.state] || s.state) + (s.bytes_total > 0
    ? ` ${fmtBytes(s.bytes_done)} of ${fmtBytes(s.bytes_total)} (${Math.round(s.bytes_done * 100 / s.bytes_total)} %)` : '');
}

function ghFail(text) {
  const msg = $('#gh-msg');
  $('#gh-progress').hidden = true;
  msg.textContent = text;
  msg.classList.add('warn');
  setIndicator(ghSec, 'err', 'Failed');
  ghLock(null);
}

// One status poll; null if the device did not answer (lossy Wi-Fi: the caller retries).
async function ghPollStatus() {
  try {
    const res = await fetch('/api/update/status', { cache: 'no-store' });
    return await res.json();
  } catch (e) {
    return null;
  }
}

// Shows the outcome of a finished check (status fields, see firmware_update.h).
function ghShowCheck(s) {
  const msg = $('#gh-msg');
  if (s.current_version) setText('gh-current', s.current_version);
  if (s.check === 'available') {
    ghAvailable = { version: s.available_version, firmware_size: s.firmware_size, filesystem_size: s.filesystem_size };
    setText('gh-available',
      `${s.available_version} (firmware ${fmtBytes(s.firmware_size)}, web UI ${fmtBytes(s.filesystem_size)})`);
    msg.textContent = '';
    setIndicator(ghSec, 'ok', 'Checked ✓');
  } else if (s.check === 'none') {
    ghAvailable = null;
    setText('gh-available', 'no newer release');
    msg.textContent = 'The installed version is up to date.';
    setIndicator(ghSec, 'ok', 'Checked ✓');
  } else {
    ghAvailable = null;
    msg.textContent = s.check === 'aborted' ? 'Check cancelled.' : 'Check failed: ' + (s.error || 'unknown error');
    msg.classList.add('warn');
    setIndicator(ghSec, s.check === 'aborted' ? 'warn' : 'err', s.check === 'aborted' ? 'Cancelled' : 'Error');
  }
}

// Polls a running check until the device has its result, then shows it.
async function ghWaitCheck(s) {
  let misses = 0;
  while (s.state === 'checking' && s.check === 'running') {
    await sleep(GH_POLL_MS);
    const next = await ghPollStatus();
    if (!next) {
      if (++misses >= GH_POLL_MISSES_MAX) throw new Error('the device no longer responds');
      continue;
    }
    misses = 0;
    s = next;
  }
  ghShowCheck(s);
}

async function ghCheck() {
  const msg = $('#gh-msg');
  msg.classList.remove('warn');
  ghLock('check');
  setIndicator(ghSec, 'saving', 'Checking…');
  msg.textContent = 'The device is asking GitHub for the latest release…';
  try {
    const r = await apiGet('/api/update/check');
    if ('available' in r) {
      // Firmware up to 0.3.0 answered the check synchronously
      ghShowCheck({ check: r.available ? 'available' : 'none', current_version: r.current_version,
        available_version: r.version, firmware_size: r.firmware_size, filesystem_size: r.filesystem_size });
    } else {
      await ghWaitCheck(r); // 202: the device fetches the manifest now
    }
  } catch (e) {
    ghAvailable = null;
    msg.textContent = 'Check failed: ' + e.message;
    msg.classList.add('warn');
    setIndicator(ghSec, 'err', 'Error');
  }
  ghLock(null);
}

async function ghInstall() {
  if (!ghAvailable || otaBusy) return;
  const target = $('#gh-target').value, version = ghAvailable.version;
  if (!confirm(`Install version ${version} from GitHub (${target === 'both' ? 'firmware + web UI' : 'firmware only'})?\n\n` +
    'The device downloads the update itself, verifies it and then restarts; it is only partly reachable ' +
    'for about a minute. Settings are preserved. Keep this page open.')) return;
  const msg = $('#gh-msg');
  msg.classList.remove('warn');
  ghLock('install');
  setIndicator(ghSec, 'saving', 'Updating…');
  msg.textContent = 'Fetching the manifest again…';
  try {
    // version: the device refuses (409) if the release changed since the check
    await apiPost('/api/update/install', { version, target });
  } catch (e) {
    ghFail('Update not started: ' + e.message);
    return;
  }
  ghFollow(target, version);
}

// Polls the run until the device reboots (or fails), then waits for it like startOta().
async function ghFollow(target, version) {
  const msg = $('#gh-msg');
  let last = null, misses = 0;
  for (;;) {
    await sleep(GH_POLL_MS);
    const s = await ghPollStatus();
    if (!s) {
      // The restart follows 300 ms after "rebooting", so the device may vanish before
      // a poll ever sees that state: a vanished device with everything written is the reboot.
      if (last && (last.state === 'rebooting' || (last.bytes_total > 0 && last.bytes_done >= last.bytes_total))) break;
      if (++misses >= GH_POLL_MISSES_MAX) { ghFail('The device no longer responds.'); return; }
      continue;
    }
    misses = 0;
    last = s;
    ghShowProgress(s);
    if (s.state === 'rebooting') break;
    if (s.state === 'error') {
      ghFail(/^aborted/.test(s.error) ? 'Update cancelled.' + s.error.replace(/^aborted/, '') : 'Update failed: ' + s.error);
      return;
    }
    if (s.state === 'idle') { ghFail('Update ended without installing anything.'); return; }
  }
  $('#gh-progress').hidden = true;
  msg.textContent = 'Update written - device is restarting…';
  try {
    const info = await waitForDevice();
    await loadSystem();
    if (info.fw_version !== version) {
      ghFail(`The device is running again, but reports version ${orDash(info.fw_version)} instead of ${version}.`);
      return;
    }
    ghAvailable = null;
    setText('gh-available', 'installed');
    setIndicator(ghSec, 'ok', 'Done ✓');
    if (target === 'both') {
      // New index.html/app.js/style.css on the device: this page is outdated now
      msg.textContent = `Version ${version} installed - reloading…`;
      setTimeout(() => { otaBusy = false; location.reload(); }, 3000); // no beforeunload prompt
      return;
    }
    msg.textContent = `Version ${version} installed.`;
    ghLock(null);
  } catch (e) {
    ghFail(e.message);
  }
}

// Cancels the run this page follows; the loop of ghWaitCheck()/ghFollow() then sees the end.
async function ghAbort() {
  if (ghMode !== 'check' && !confirm('Cancel the update? A firmware that is already staged stays staged; a half-written ' +
    'filesystem must be installed again afterwards (do not restart the device until then).')) return;
  try {
    await apiPost('/api/update/install', { abort: true });
    $('#gh-msg').textContent = 'Cancelling…';
  } catch (e) {
    $('#gh-msg').textContent = 'Cancel failed: ' + e.message;
  }
}

// Opening the tab picks up a run that is already going (reload, second browser tab),
// shows the result of the last check and the error of the last failed update.
async function ghResume() {
  if (otaBusy) return;
  try {
    const s = await apiGet('/api/update/status');
    // "checking" without a target is a plain check
    if (s.state === 'downloading' || s.state === 'flashing' || (s.state === 'checking' && s.target)) {
      ghLock('install');
      setIndicator(ghSec, 'saving', 'Updating…');
      ghShowProgress(s);
      ghFollow(s.target, s.version);
    } else if (s.state === 'checking') {
      ghLock('check');
      setIndicator(ghSec, 'saving', 'Checking…');
      $('#gh-msg').textContent = 'The device is asking GitHub for the latest release…';
      try {
        await ghWaitCheck(s);
      } catch (e) {
        $('#gh-msg').textContent = 'Check failed: ' + e.message;
        $('#gh-msg').classList.add('warn');
      }
      ghLock(null);
    } else if (s.state === 'error') {
      $('#gh-msg').textContent = 'Last update failed: ' + s.error;
      $('#gh-msg').classList.add('warn');
    } else if (s.check && s.check !== 'running') {
      ghShowCheck(s);
      $('#btn-gh-install').disabled = !ghAvailable;
    }
  } catch (e) { /* older firmware without /api/update: nothing to show */ }
}

// ---------- Init ----------
buildShapeCards('zone');
buildShapeCards('object');
buildPinSelects();
editorMap = buildMap($('#zone-map'), true);
statusMap = buildMap($('#status-map'), false);
Object.keys(sections).forEach(bindSection);
$$('.tabs button').forEach(b => b.addEventListener('click', () => openTab(b.dataset.tab)));
$('#tab-zones').addEventListener('focusin', e => {
  const card = e.target.closest('.shape-card');
  if (card) selectShape(card.dataset.kind, +card.dataset.index);
});
$('#tab-zones').addEventListener('click', e => {
  const del = e.target.closest('.shape-delete');
  if (del) deleteShape(del.closest('.shape-card'));
});
$('#btn-zone-add').addEventListener('click', () => addShape('zone'));
$('#btn-object-add').addEventListener('click', () => addShape('object'));
$('#btn-reboot').addEventListener('click', () =>
  deviceAction('/api/reboot', 'Reboot the device now?'));
$('#btn-factory-reset').addEventListener('click', () =>
  deviceAction('/api/factory-reset', 'Reset all settings to factory defaults and reboot?'));
$('#btn-wifi-reset').addEventListener('click', resetWifiSetup);
// Show/hide before bindSection() saves the change
$('#wifi-use-static-ip').addEventListener('change', showStaticIpFields);
$('#btn-backup-restore').addEventListener('click', () => $('#backup-file-input').click());
$('#backup-file-input').addEventListener('change', e => {
  restoreBackupFile(e.target.files[0]);
  e.target.value = ''; // allow picking the same file again
});
$('#btn-ota-restore').addEventListener('click', () => $('#ota-restore-input').click());
$('#ota-restore-input').addEventListener('change', e => {
  restoreBackupFile(e.target.files[0], otaRestoreSec);
  e.target.value = '';
});
$('#ota-fw-file').addEventListener('change', () => refreshOtaHint('firmware'));
$('#ota-fs-file').addEventListener('change', () => refreshOtaHint('filesystem'));
$('#btn-ota-start').addEventListener('click', startOta);
$('#btn-gh-check').addEventListener('click', ghCheck);
$('#btn-gh-install').addEventListener('click', ghInstall);
$('#btn-gh-abort').addEventListener('click', ghAbort);
// Leaving mid-run would drop the upload and the automatic config restore.
// A running check can be left safely (it ends on its own), an update run cannot
window.addEventListener('beforeunload', e => { if (otaBusy && ghMode !== 'check') e.preventDefault(); });
window.addEventListener('resize', scaleMaps);
scaleMaps();
// Zone + object config is also needed for the status map and zone list.
// One after another instead of in parallel: the device accepts only 4 connections at
// once (web_server.cpp, MAX_HTTP_CONNECTIONS), each additional one waits ~1 s for the
// TCP retransmit - and every parallel response costs heap.
(async () => {
  await loadSection('zones');
  await loadSection('objects');
  await loadState();
  await loadEvents();
})();
setInterval(loadState, 2000);
setInterval(loadEvents, 2000);
