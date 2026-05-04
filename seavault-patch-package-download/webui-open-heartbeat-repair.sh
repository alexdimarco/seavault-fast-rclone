#!/usr/bin/env bash
set -euo pipefail
file="internal/webui/server.go"
if [ ! -f "$file" ]; then
  echo "error: run this from the SeaVault repository root; missing $file" >&2
  exit 1
fi
python3 - <<'PY'
from pathlib import Path
import re

p = Path('internal/webui/server.go')
s = p.read_text()
orig = s

def find_function(text, names):
    for name in names:
        m = re.search(r'(?:async\s+)?function\s+' + re.escape(name) + r'\s*\([^)]*\)\s*\{', text)
        if not m:
            continue
        i = m.start()
        brace = text.find('{', m.end()-1)
        depth = 0
        in_str = None
        esc = False
        in_line = False
        in_block = False
        for j in range(brace, len(text)):
            c = text[j]
            nxt = text[j+1] if j+1 < len(text) else ''
            if in_line:
                if c == '\n':
                    in_line = False
                continue
            if in_block:
                if c == '*' and nxt == '/':
                    in_block = False
                    j += 1
                continue
            if in_str:
                if esc:
                    esc = False
                elif c == '\\':
                    esc = True
                elif c == in_str:
                    in_str = None
                continue
            if c == '/' and nxt == '/':
                in_line = True
                continue
            if c == '/' and nxt == '*':
                in_block = True
                continue
            if c in ('"', "'", '`'):
                in_str = c
                continue
            if c == '{':
                depth += 1
            elif c == '}':
                depth -= 1
                if depth == 0:
                    return i, j+1, name
    return None

def replace_function(text, names, replacement):
    found = find_function(text, names)
    if not found:
        return text, False
    a, b, _ = found
    return text[:a] + replacement.rstrip() + text[b:], True

render_func = r'''function renderTopVaultStrip(s){
  const box = $('availableVaults');
  if(!box) return;
  const vaults = Array.isArray(s && s.profiles) ? s.profiles : [];
  if(!vaults.length){
    box.innerHTML = '<span class="hint">No saved vaults. Use Create a vault to add one.</span><button class="secondary" onclick="refreshStatusFast()">Refresh vaults</button><button class="secondary" onclick="scrollToCreateVault()">Create a vault</button>';
    return;
  }
  box.innerHTML = vaults.map(v => {
    const status = v.open ? 'open' : (v.status || 'ready');
    const key = v.keychain ? 'keychain' : 'password';
    const cls = v.open ? 'open' : '';
    return '<div class="quick-vault-card '+cls+'" title="'+esc(v.vaultPath || '')+'">'
      + '<span class="status-dot" aria-hidden="true"></span>'
      + '<span class="vault-name">'+esc(v.name || v.vaultPath || 'vault')+'</span>'
      + '<span class="pill">'+esc(status)+'</span>'
      + '<span class="pill">'+esc(key)+'</span>'
      + '<button type="button" class="operation" data-name="'+esc(v.name || '')+'" data-path="'+esc(v.vaultPath || '')+'" data-keychain="'+(v.keychain?'1':'0')+'" onclick="quickOpenVault(this)">Open</button>'
      + '</div>';
  }).join('') + '<button class="secondary" onclick="refreshStatusFast()">Refresh vaults</button><button class="secondary" onclick="scrollToCreateVault()">Create a vault</button>';
}'''

# Replace whichever top vault renderer exists.
s, did_render = replace_function(s, ['renderTopVaultStrip'], render_func)
if not did_render:
    found = find_function(s, ['renderAvailableVaults'])
    if found:
        _, b, _ = found
        s = s[:b] + '\n' + render_func + s[b:]
    else:
        raise SystemExit('error: could not find renderTopVaultStrip or renderAvailableVaults in internal/webui/server.go')

quick_func = r'''async function quickOpenVault(btn){
  const name = btn.dataset.name || '';
  const path = btn.dataset.path || '';
  const hasKeychain = btn.dataset.keychain === '1';
  if(!path && !name){ showError('Could not open vault', 'Saved vault path is missing.'); return; }
  btn.disabled = true;
  const oldText = btn.textContent;
  btn.textContent = 'Opening...';
  try {
    if(hasKeychain){
      await openSavedVaultDirect(name, path, '', false, true);
      return;
    }
    showVaultPasswordModal(name, path);
  } catch(e) {
    showVaultPasswordModal(name, path);
    showError('Saved keychain password unavailable', e.message || e);
  } finally {
    btn.disabled = false;
    btn.textContent = oldText || 'Open';
  }
}'''

# Replace either the old click-whole-pill function or previous quickOpenVault.
s, did_quick = replace_function(s, ['quickOpenVault', 'openTopVaultButton'], quick_func)
if not did_quick:
    marker = 'function showVaultPasswordModal'
    if marker in s:
        s = s.replace(marker, quick_func + '\n' + marker, 1)
    else:
        raise SystemExit('error: could not find a place to insert quickOpenVault')

# Remove a duplicate openTopVaultButton if one remains, and replace it with a harmless shim.
found = find_function(s, ['openTopVaultButton'])
if found:
    a, b, _ = found
    s = s[:a] + "function openTopVaultButton(btn){ return quickOpenVault(btn); }" + s[b:]
elif 'function openTopVaultButton' not in s:
    insert_after = find_function(s, ['quickOpenVault'])
    if insert_after:
        _, b, _ = insert_after
        s = s[:b] + "\nfunction openTopVaultButton(btn){ return quickOpenVault(btn); }" + s[b:]

# Ensure modal state exists before modal helpers.
if 'let pendingVaultOpen = null;' not in s:
    marker = 'function showVaultPasswordModal'
    if marker in s:
        s = s.replace(marker, 'let pendingVaultOpen = null;\n' + marker, 1)

# Ensure scroll helper exists.
if 'function scrollToCreateVault' not in s:
    marker = 'function selectVaultCard'
    helper = "function scrollToCreateVault(){ const el=$('vault-panel'); if(el) el.scrollIntoView({behavior:'smooth', block:'start'}); }\n"
    if marker in s:
        s = s.replace(marker, helper + marker, 1)
    else:
        s += '\n' + helper


# Replace refreshStatus functions to avoid stale blocking/background-refresh and broken newline quoting.
refresh_func = r'''async function refreshStatus(){
  try {
    const s = await api('/api/status');
    if(s.browserToken) updateSessionToken(s.browserToken);
    lastStatus = s;
    renderVaultSelector(s); renderAvailableVaults(s); renderTopVaultStrip(s); renderKeychainStatus(s); renderDependencies(s); renderWebDAVStatus(s); renderWebDAVQuick(s); renderAppConfig(s);
    showHuman('Status refreshed', s);
    Promise.allSettled([refreshFiles(), refreshDavFiles(), loadProfiles()]).then(results => {
      const failed = results.filter(r => r.status === 'rejected');
      if(failed.length) appendLog('Background refresh warning', failed.map(f => f.reason && f.reason.message ? f.reason.message : String(f.reason)).join('\\n'));
    });
  } catch(e){ showError('Could not refresh status', e.message); }
}'''
s, _ = replace_function(s, ['refreshStatus'], refresh_func)

refresh_fast_func = r'''async function refreshStatusFast(){
  try {
    const s = await api('/api/status');
    if(s.browserToken) updateSessionToken(s.browserToken);
    lastStatus = s;
    renderVaultSelector(s); renderAvailableVaults(s); renderTopVaultStrip(s); renderKeychainStatus(s); renderDependencies(s); renderWebDAVStatus(s); renderWebDAVQuick(s); renderAppConfig(s);
    showHuman('Saved vaults refreshed', s, 'success');
  } catch(e){ showError('Could not refresh saved vaults', e.message); }
}'''
s, did_rsf = replace_function(s, ['refreshStatusFast'], refresh_fast_func)
if not did_rsf:
    found = find_function(s, ['refreshStatus'])
    if found:
        _, b, _ = found
        s = s[:b] + '\n' + refresh_fast_func + s[b:]

open_direct_func = r'''async function openSavedVaultDirect(name, path, password, saveKeychain, useKeychain){
  const targetPath = path || name;
  if(!targetPath){ throw new Error('Saved vault path is missing.'); }
  const req = {vaultPath: targetPath, password: password || '', savePassword: !!saveKeychain, useKeychain: !!useKeychain};
  const res = await api('/api/open',{method:'POST',headers:jsonHeaders,body:JSON.stringify(req)});
  $('vaultPath').value = targetPath;
  $('profile').value = name || '';
  $('password').value = '';
  $('savePassword').checked = false;
  const status = await api('/api/status');
  status.lastAction = res;
  lastStatus = status;
  renderVaultSelector(status); renderAvailableVaults(status); renderTopVaultStrip(status); renderKeychainStatus(status); renderDependencies(status); renderWebDAVStatus(status); renderWebDAVQuick(status); renderAppConfig(status);
  showHuman('Vault opened', status, 'success');
  await refreshFiles(); await refreshDavFiles(); await loadProfiles();
  return status;
}'''
s, did_od = replace_function(s, ['openSavedVaultDirect'], open_direct_func)
if not did_od:
    found = find_function(s, ['openSavedVault'])
    if found:
        _, b, _ = found
        s = s[:b] + '\n' + open_direct_func + s[b:]
    else:
        marker = 'function initPayload'
        if marker in s:
            s = s.replace(marker, open_direct_func + '\n' + marker, 1)

open_saved_func = r'''async function openSavedVault(name, path, useKeychain){
  await openSavedVaultDirect(name, path, '', false, !!useKeychain);
}'''
s, _ = replace_function(s, ['openSavedVault'], open_saved_func)

open_pw_func = r'''async function openSavedVaultFromPassword(name, path, passwordId, saveKeychain){
  const pw = passwordId && $(passwordId) ? $(passwordId).value : '';
  if(!pw && saveKeychain){ showVaultPasswordModal(name, path); $('vaultPasswordModalSave').checked = true; return; }
  if(!pw){
    try { await openSavedVaultDirect(name, path, '', false, true); return; }
    catch(e) { showVaultPasswordModal(name, path); showError('Saved keychain password unavailable', e.message || e); return; }
  }
  try { await openSavedVaultDirect(name, path, pw, !!saveKeychain, false); }
  catch(e){ showError('Could not open vault', e.message || e); }
}'''
s, _ = replace_function(s, ['openSavedVaultFromPassword'], open_pw_func)

heartbeat_func = r'''function startBrowserHeartbeat(){
  const beat = () => {
    fetch('/api/browser-heartbeat', {method:'POST', keepalive:true, cache:'no-store'}).catch(err => {
      try { appendLog('Browser heartbeat failed', err && err.message ? err.message : String(err), 'warning'); } catch (_) {}
    });
  };
  beat();
  window.setInterval(beat, 10000);
}'''

s, did_hb = replace_function(s, ['startBrowserHeartbeat'], heartbeat_func)
if not did_hb:
    marker = 'async function saveCurrentVaultProfile'
    if marker in s:
        s = s.replace(marker, heartbeat_func + '\n' + marker, 1)
    else:
        # Last safe fallback: put it before DOMContentLoaded block.
        s = s.replace("document.addEventListener('DOMContentLoaded'", heartbeat_func + "\ndocument.addEventListener('DOMContentLoaded'", 1)

# Ensure heartbeat starts once. If not present as a standalone call, add it before the startup refresh.
if not re.search(r'(^|[;\n])\s*startBrowserHeartbeat\s*\(\s*\)\s*;', s):
    startup = "appendLog('SeaVault GUI started','Ready.'); refreshStatus();"
    if startup in s:
        s = s.replace(startup, "startBrowserHeartbeat();\n" + startup, 1)
    else:
        s = s.replace("reportBrowserSupport();", "reportBrowserSupport();\nstartBrowserHeartbeat();", 1)

# Keep renderTopVaultStrip wired into status refresh/open/create paths.
for call in [
    'renderVaultSelector(s); renderAvailableVaults(s);',
    'renderVaultSelector(status); renderAvailableVaults(status);'
]:
    if call in s and call + ' renderTopVaultStrip' not in s:
        s = s.replace(call, call + ' renderTopVaultStrip(' + ('s' if '(s)' in call else 'status') + ');', 1)

# If refreshStatusFast is missing, add it after refreshStatus.
if 'function refreshStatusFast' not in s and 'async function refreshStatusFast' not in s:
    refresh_fast = r'''
async function refreshStatusFast(){
  try {
    const s = await api('/api/status');
    if(s.browserToken) updateSessionToken(s.browserToken);
    lastStatus = s;
    renderVaultSelector(s); renderAvailableVaults(s); renderTopVaultStrip(s); renderKeychainStatus(s); renderDependencies(s); renderWebDAVStatus(s); renderWebDAVQuick(s); renderAppConfig(s);
    showHuman('Saved vaults refreshed', s, 'success');
  } catch(e){ showError('Could not refresh saved vaults', e.message); }
}
'''
    found = find_function(s, ['refreshStatus'])
    if found:
        _, b, _ = found
        s = s[:b] + '\n' + refresh_fast.strip() + s[b:]

if s == orig:
    print('No changes needed; server.go already contains the repair changes.')
else:
    backup = p.with_suffix(p.suffix + '.bak-webui-open-heartbeat')
    backup.write_text(orig)
    p.write_text(s)
    print('Updated internal/webui/server.go')
    print('Backup written to', backup)
PY

gofmt -w internal/webui/server.go cmd/seavault/main.go 2>/dev/null || true
rm -f internal/webui/server.go.rej

echo "Repair complete. Run: go test ./internal/webui ./cmd/seavault -run '^$' -count=1 -timeout=60s"
