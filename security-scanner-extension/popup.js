// Popup controller: executes content script in active tab and renders results.
const scanBtn = document.getElementById('scanBtn');
const toggleBtn = document.getElementById('toggleBtn');
const statusEl = document.getElementById('status');
const outputEl = document.getElementById('output');
let showRaw = false;
let lastResults = null;

toggleBtn.addEventListener('click', () => {
  showRaw = !showRaw;
  toggleBtn.textContent = showRaw ? 'Show Readable' : 'Show Raw JSON';
  renderResults(lastResults);
});

scanBtn.addEventListener('click', async () => {
  statusEl.textContent = 'Scanning active tab...';
  outputEl.textContent = '';
  try {
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    if (!tab || !tab.url) {
      statusEl.textContent = 'No active tab URL found.';
      return;
    }
    // execute script in the page context to gather information
    const results = await chrome.scripting.executeScript({
      target: {tabId: tab.id},
      func: () => {
        // This function runs inside the page and returns an object with findings.
        const out = { url: location.href, origin: location.origin, timestamp: Date.now() };
        try {
          // HTTPS check
          out.https = location.protocol === 'https:' ? 'HTTPS (secure)' : 'HTTP (not secure)';
        } catch (e) {
          out.https = 'Unknown';
        }
        // Mixed content detection: check common resource tags
        try {
          out.mixedContent = [];
          if (location.protocol === 'https:') {
            const els = Array.from(document.querySelectorAll('img, script, iframe, link'));
            els.forEach(el => {
              const src = el.src || el.href;
              if (src && src.startsWith('http://')) {
                out.mixedContent.push(src);
              }
            });
            // performance entries may show resources loaded
            try {
              const perf = performance.getEntriesByType('resource') || [];
              perf.forEach(p => {
                if (p.name && p.name.startsWith('http://')) {
                  if (!out.mixedContent.includes(p.name)) out.mixedContent.push(p.name);
                }
              });
            } catch(e){}
          } else {
            out.mixedContent = [];
          }
        } catch (e) {
          out.mixedContent = ['error:' + String(e)];
        }

        // Cookies (lite): JS-readable cookies only
        try {
          const raw = document.cookie || '';
          out.cookies = raw.split(';').map(s => s.trim()).filter(s => s.length>0);
        } catch(e) {
          out.cookies = [];
        }

        // Directory listing detection: check DOM for common markers
        try {
          const bodyText = document.body ? document.body.innerText || '' : '';
          const signs = ['Index of /', 'Parent Directory', 'Directory listing'];
          out.dirListing = signs.some(s => bodyText.includes(s));
        } catch(e) {
          out.dirListing = false;
        }

        // Security headers + robots.txt via fetch to same-origin resources
        async function fetchHeadersAndRobots() {
          const results = {};
          try {
            // fetch base origin to read headers (same-origin)
            const r = await fetch(location.origin, { method: 'GET', credentials: 'include' });
            const hdr = {};
            for (const pair of r.headers.entries()) { hdr[pair[0]] = pair[1]; }
            results.headers = hdr;
          } catch(e) {
            results.headers = { error: 'Could not fetch headers: ' + String(e) };
          }
          try {
            const robotsUrl = location.origin.replace(/\/$/, '') + '/robots.txt';
            const rr = await fetch(robotsUrl, { method: 'GET', credentials: 'include' });
            if (rr.ok) {
              const text = await rr.text();
              results.robots = text;
            } else {
              results.robots = null;
            }
          } catch(e) {
            results.robots = null;
          }
          return results;
        }

        // Return a promise that resolves to full results after fetches
        return fetchHeadersAndRobots().then(res => {
          out.headers = res.headers;
          out.robots = res.robots;
          return out;
        }).catch(e => {
          out.headers = { error: String(e) };
          out.robots = null;
          return out;
        });
      }
    });
    // executeScript returns array of results; grab first
    const res = results && results[0] && results[0].result ? results[0].result : null;
    lastResults = res;
    statusEl.textContent = 'Scan complete.';
    renderResults(res);
  } catch (err) {
    statusEl.textContent = 'Scan failed: ' + String(err);
    outputEl.textContent = String(err);
  }
});

function renderResults(res) {
  if (!res) {
    outputEl.textContent = 'No results yet.';
    return;
  }
  if (showRaw) {
    outputEl.textContent = JSON.stringify(res, null, 2);
    return;
  }
  // human-readable text
  let lines = [];
  lines.push('URL: ' + (res.url || ''));
  lines.push('HTTPS: ' + (res.https || ''));
  lines.push('');
  // headers shorthand: show missing common headers
  const hdr = res.headers || {};
  const important = ['strict-transport-security','content-security-policy','x-frame-options','x-content-type-options','referrer-policy','permissions-policy'];
  const missing = important.filter(h => !(h in hdr));
  lines.push('Security Headers - missing: ' + (missing.length ? missing.join(', ') : 'none'));
  lines.push('');
  lines.push('Robots.txt: ' + (res.robots ? 'Found' : 'Not found'));
  lines.push('');
  lines.push('Directory listing detected: ' + (res.dirListing ? 'Yes' : 'No'));
  lines.push('');
  lines.push('Cookies (JS-readable): ' + ((res.cookies && res.cookies.length) ? res.cookies.join('; ') : 'None / HttpOnly-only cookies may be hidden'));
  lines.push('');
  lines.push('Mixed content resources found:');
  if (res.mixedContent && res.mixedContent.length) {
    res.mixedContent.forEach(m => lines.push(' - ' + m));
  } else {
    lines.push(' None');
  }
  outputEl.textContent = lines.join('\n');
}
