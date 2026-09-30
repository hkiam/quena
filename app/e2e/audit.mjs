// Shared layout audit (runs in the page via WebDriver execute).
// Runs in the page: for each container, how much of its box its children leave empty.
export const AUDIT = `
const gaps = [];
const vw = innerWidth, vh = innerHeight;
const r = (e) => e.getBoundingClientRect();
const name = (e) => e.tagName.toLowerCase() + (e.className && typeof e.className === 'string' ? '.' + e.className.trim().split(/\\s+/).join('.') : '');
const app = document.querySelector('.app');
if (app) { const a = r(app); if (Math.abs(a.height - vh) > 2 || Math.abs(a.width - vw) > 2) gaps.push({ el: '.app vs window', w: vw - a.width, h: vh - a.height }); }
// Containers that are meant to be filled completely by their (last) child.
const fill = ['.main', '.left', '.grid', '.grid-scroller', '.rpane', '.rp-content', '.inspectors', '.insp-split', '.insp-pane', '.insp-content', '.headers-view', '.textpane', '.tp-body', '.codeview', '.stats', '.timeline', '.filters', '.logpanel', '.composer', '.autoresponder'];
for (const sel of fill) for (const e of document.querySelectorAll(sel)) {
  if (!e.offsetParent && sel !== '.main') continue; // hidden
  const box = r(e);
  if (box.width < 5 || box.height < 5) continue;
  const kids = [...e.children].filter((k) => k.offsetParent || getComputedStyle(k).position === 'fixed');
  if (!kids.length) continue;
  let bottom = 0, right = 0;
  for (const k of kids) { const b = r(k); bottom = Math.max(bottom, b.bottom); right = Math.max(right, b.right); }
  // Padding and borders are intended space; measure against the content box.
  const cs = getComputedStyle(e);
  const px = (v) => parseFloat(v) || 0;
  const gh = Math.round(box.bottom - px(cs.paddingBottom) - px(cs.borderBottomWidth) - bottom);
  const gw = Math.round(box.right - px(cs.paddingRight) - px(cs.borderRightWidth) - right);
  // Scrollable containers may be short of content on purpose; only report real layout gaps.
  const scrolls = /(auto|scroll)/.test(cs.overflowY);
  if ((gh > 3 && !scrolls) || gw > 3) gaps.push({ el: name(e), w: gw, h: gh, box: [Math.round(box.width), Math.round(box.height)] });
}
// The canvas must cover the visible list area.
const sc = document.querySelector('.grid-scroller'), cv = document.querySelector('.grid-canvas');
if (sc && cv) { const a = r(sc), b = r(cv); if (a.height - b.height > 2 || a.width - b.width > 2) gaps.push({ el: 'grid-canvas vs scroller', w: Math.round(a.width - b.width), h: Math.round(a.height - b.height) }); }
return gaps;
`;


// Plugins dialog: no column squeezed to single characters (regression), every plugin says
// what it applies to.
const PLUGIN_TABLE = `
  const rows = [...document.querySelectorAll('.plugins-table tbody tr')];
  return rows.map((r) => {
    const cell = (c) => r.querySelector(c);
    const h = (c) => cell(c).getBoundingClientRect().height;
    return {
      name: cell('.pl-name b').textContent,
      nameWidth: Math.round(cell('.pl-name').getBoundingClientRect().width),
      // One line of text plus padding is ~26 px; a squeezed column wraps character by character.
      versionHeight: Math.round(h('.pl-version').valueOf() && cell('.pl-version').scrollHeight),
      versionFits: cell('.pl-version').scrollWidth <= cell('.pl-version').clientWidth + 1,
      statusFits: cell('.pl-status').scrollWidth <= cell('.pl-status').clientWidth + 1,
      oneLine: [...r.querySelectorAll('.pl-version, .pl-status')].every((c) => {
        const range = document.createRange();
        range.selectNodeContents(c);
        return range.getClientRects().length <= 1;
      }),
      applies: cell('.pl-applies').textContent.trim().length,
      // Plugins that failed to load (e.g. the deliberately broken test plugins) have no info.
      error: !!r.querySelector('.pl-name .err'),
    };
  });`;
export async function checkPluginsDialog(d, assert) {
  await d.exec(`window.__quena.menu("tools.plugins")`);
  try {
    await checkPluginsTable(d, assert);
  } finally {
    // Never leave the dialog open for the following tests.
    await d.keys(["Escape"]);
  }
}
async function checkPluginsTable(d, assert) {
  await d.waitFor(".plugins-table tbody tr", { timeout: 10000 });
  for (const [width, height] of [[1000, 700], [1600, 1000]]) {
    await d.cmd("POST", d.s("/window/rect"), { width, height });
    await new Promise((r) => setTimeout(r, 400));
    const rows = await d.exec(PLUGIN_TABLE);
    assert.ok(rows.length >= 4, `plugins: ${JSON.stringify(rows)}`);
    for (const r of rows.filter((x) => !x.error)) {
      assert.ok(r.nameWidth >= 120, `name column squeezed at ${width}px: ${JSON.stringify(r)}`);
      assert.ok(r.oneLine && r.versionFits && r.statusFits, `version/status wrap at ${width}px: ${JSON.stringify(r)}`);
      assert.ok(r.applies > 0, `"Applies to" empty: ${JSON.stringify(r)}`);
    }
  }
}
