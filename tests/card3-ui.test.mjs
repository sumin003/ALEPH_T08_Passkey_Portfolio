import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
class Element {
    constructor() { this.hidden = false; this.disabled = false; this.textContent = ''; this.children = []; this.events = {}; }
    addEventListener(type, fn) { this.events[type] = fn; }
    replaceChildren(...nodes) { this.children = nodes; }
    append(...nodes) { this.children.push(...nodes); }
}
const tick = () => new Promise(resolve => setImmediate(resolve));
function ui(fetch) {
    const nodes = Object.fromEntries(['passkey-login','passkey-logout','private-state','private-status','private-content'].map(id => [id, new Element()]));
    const docEvents = {}, windowEvents = {};
    const registration = new Element();
    const document = { visibilityState: 'visible', getElementById: id => nodes[id], querySelector: () => registration, createElement: () => new Element(), addEventListener: (event, fn) => { docEvents[event] = fn; } };
    const window = { dispatchEvent() {}, addEventListener: (event, fn) => { windowEvents[event] = fn; } };
    runInNewContext(readFileSync(new URL('../private-access.js', import.meta.url), 'utf8'), {
        window, document, fetch, AbortSignal, CustomEvent: class { constructor(type, detail) { this.type = type; this.detail = detail; } },
        setTimeout: () => 1, clearTimeout() {}, Date
    });
    return { nodes, document, docEvents, windowEvents, registration };
}
const dataResponse = () => Response.json({ items: [{ title: '<img src=x onerror=alert(1)>', content: 'private' }], expiresAt: new Date(Date.now() + 3600000).toISOString() });

test('private rendering uses text nodes and logout clears data before waiting for the server', async () => {
    const f = ui(async url => url.startsWith('/api/auth') ? Response.json({ loggedOut: true }) : dataResponse());
    await tick();
    assert.equal(f.nodes['private-content'].hidden, false);
    assert.equal(f.registration.hidden, false);
    assert.equal(f.nodes['private-content'].children[0].children[0].textContent, '<img src=x onerror=alert(1)>');
    const pending = f.nodes['passkey-logout'].events.click();
    assert.equal(f.nodes['private-content'].hidden, true);
    assert.equal(f.registration.hidden, true);
    assert.equal(f.nodes['private-content'].children.length, 0);
    await pending;
    assert.equal(f.nodes['private-state'].textContent, '비공개 · 잠김');
});
test('a stale private response cannot reopen the page after logout', async () => {
    let resolvePrivate;
    const f = ui(url => url.startsWith('/api/auth') ? Promise.resolve(Response.json({ loggedOut: true })) : new Promise(resolve => { resolvePrivate = resolve; }));
    await f.nodes['passkey-logout'].events.click();
    resolvePrivate(dataResponse()); await tick();
    assert.equal(f.nodes['private-content'].children.length, 0);
    assert.equal(f.nodes['private-content'].hidden, true);
    assert.equal(f.registration.hidden, true);
});
test('pagehide clears private content before browser back/forward caching', async () => {
    const f = ui(async () => dataResponse()); await tick();
    assert.equal(f.nodes['private-content'].hidden, false);
    assert.equal(f.registration.hidden, false);
    f.windowEvents.pagehide();
    assert.equal(f.nodes['private-content'].children.length, 0);
    assert.equal(f.nodes['private-content'].hidden, true);
    assert.equal(f.registration.hidden, true);
});

test('registration remains hidden for anonymous and expired sessions', async () => {
    const f = ui(async () => new Response(null, {status:401}));
    await tick();
    assert.equal(f.registration.hidden, true);
    assert.match(readFileSync(new URL('../index.html', import.meta.url),'utf8'), /class="passkey-registration"[^>]* hidden/);
});
