// Quena rules — a JavaScript script that runs on every session.
// Enable it under Capture → Rules Script… (Ctrl/Cmd+R). Reloads on save.
// See the type hints (Quena.d.ts) for the full API.

// Called once when the script loads.
function onBoot() {
    console.log('Quena rules loaded');

    // Add a command to the session right-click menu (Scripts submenu):
    // Quena.registerMenu('Tag as reviewed', function (sessions) {
    //     return sessions.map(function (s) { return { id: s.id, comment: 'reviewed', color: 'green' }; });
    // });

    // Define a Custom column; fill it per session in onBeforeResponse via s.custom(),
    // or compute it here with a function:
    // Quena.registerColumn('Server', function (s) { return s.responseHeaders.get('Server') || ''; });
}

// Called before each request is forwarded. Mutate the session in place.
function onBeforeRequest(s) {
    // Example: tag slow-loading hosts, force HTTPS, block an ad host.
    // s.requestHeaders.set('X-Quena', '1');
    // if (s.host === 'ads.example.com') s.abort();
    // if (s.url.indexOf('http://') === 0) s.redirect('https://' + s.url.slice(7));
}

// Called before each response is returned to the client.
function onBeforeResponse(s) {
    // Example: strip a header, flag errors in red.
    // s.responseHeaders.remove('Set-Cookie');
    // if (s.status >= 500) s.color('red');
}

// Called after a session finishes (summary only, no bodies).
function onSessionComplete(session) {
    // console.log(session.method, session.url, session.status);
}
