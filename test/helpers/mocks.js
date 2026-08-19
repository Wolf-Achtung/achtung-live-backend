// Mock-Server und Start-Hilfe für die Tests.
//
// server.js exportiert nichts und startet beim Laden sofort den Listener.
// Die Tests fahren den Dienst deshalb als eigenen Prozess hoch und sprechen
// ihn über HTTP an - so, wie es im Betrieb auch passiert.

const http = require('http');
const path = require('path');
const { spawn } = require('child_process');

// Nimmt jede Anfrage entgegen und antwortet mit dem, was der Test vorgibt.
// `handler` bekommt (body, req) und liefert { status, json } zurück.
function startMock(handler) {
  return new Promise(resolve => {
    const calls = [];
    const server = http.createServer((req, res) => {
      let raw = '';
      req.on('data', c => { raw += c; });
      req.on('end', () => {
        calls.push({ url: req.url, body: raw });
        let out;
        try {
          out = handler(raw, req) || {};
        } catch (err) {
          out = { status: 500, json: { error: err.message } };
        }
        res.writeHead(out.status || 200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(out.json ?? {}));
      });
    });
    server.listen(0, '127.0.0.1', () => {
      resolve({
        port: server.address().port,
        calls,
        close: () => new Promise(r => server.close(r))
      });
    });
  });
}

// Baut eine OpenAI-Chat-Antwort. `finish_reason` steuert den Abschneide-Fall.
function chatCompletion(content, finish_reason = 'stop') {
  return {
    id: 'chatcmpl-test',
    object: 'chat.completion',
    model: 'gpt-4.1-mini',
    choices: [{ index: 0, message: { role: 'assistant', content }, finish_reason }],
    usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 }
  };
}

// Startet server.js mit den übergebenen ENV-Werten und wartet, bis der Port
// antwortet. Gibt eine `stop`-Funktion und die Basis-URL zurück.
async function startServer(env = {}) {
  const port = 3100 + Number(process.hrtime.bigint() % 700n);
  const child = spawn(process.execPath, [path.join(__dirname, '..', '..', 'server.js')], {
    env: {
      ...process.env,
      PORT: String(port),
      OPENAI_API_KEY: 'sk-test',
      ...env
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  let log = '';
  child.stdout.on('data', d => { log += d; });
  child.stderr.on('data', d => { log += d; });

  const base = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 20000;
  for (;;) {
    if (Date.now() > deadline) {
      child.kill('SIGKILL');
      throw new Error(`Server startete nicht auf Port ${port}. Log:\n${log}`);
    }
    try {
      const r = await fetch(`${base}/api/v2/ping`, { signal: AbortSignal.timeout(500) });
      if (r.ok) break;
    } catch {
      await new Promise(r => setTimeout(r, 100));
    }
  }

  return {
    base,
    getLog: () => log,
    stop: () => new Promise(resolve => {
      child.once('exit', resolve);
      child.kill('SIGKILL');
    })
  };
}

async function postJSON(base, route, body) {
  const res = await fetch(base + route, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(30000)
  });
  return { status: res.status, body: await res.json() };
}

module.exports = { startMock, chatCompletion, startServer, postJSON };
