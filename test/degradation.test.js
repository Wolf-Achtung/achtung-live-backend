// Prüft, dass ein Ausfall der Analyse-Stufen als Ausfall sichtbar wird und
// nicht als unauffälliges Ergebnis.
//
// Jeder Test provoziert den Fehlerfall aktiv: ein Mock-Provider antwortet mit
// 500, mit abgeschnittenem JSON oder mit einem HTTP-Fehler von LanguageTool.

const test = require('node:test');
const assert = require('node:assert');
const { startMock, chatCompletion, startServer, postJSON } = require('./helpers/mocks');

// Text mit Befunden, die nur die semantische Stufe erkennt: Kind, Gesundheit,
// Ort. Die Regex-Muster greifen hier bewusst nicht.
const SENSIBLER_TEXT =
  'Meine Tochter Lena ist seit gestern wegen ihrer Depression in der Klinik in Bonn.';

// Ein LanguageTool-Mock, der immer erreichbar ist und nichts findet. Damit
// beeinflusst der echte Dienst die Tests nicht.
const LT_LEER = { matches: [] };

test('semantische Stufe faellt aus: /api/v2/analyze kennzeichnet den Ausfall', async () => {
  const tot = await startMock(() => ({ status: 500, json: { error: { message: 'boom' } } }));
  const srv = await startServer({ OPENAI_BASE_URL: `http://127.0.0.1:${tot.port}/v1` });

  try {
    const { status, body } = await postJSON(srv.base, '/api/v2/analyze', { text: SENSIBLER_TEXT });

    assert.strictEqual(status, 200, 'Statuscode bleibt unveraendert');
    assert.strictEqual(
      body.meta.semanticAnalysisFailed, true,
      'Ohne dieses Kennzeichen ist der Ausfall von "nichts gefunden" nicht zu unterscheiden'
    );
  } finally {
    await srv.stop();
    await tot.close();
  }
});

test('semantische Stufe laeuft: /api/v2/analyze meldet keinen Ausfall', async () => {
  const ok = await startMock(() => ({
    status: 200,
    json: chatCompletion(JSON.stringify({ findings: [], rewriteSuggestion: null }))
  }));
  const srv = await startServer({ OPENAI_BASE_URL: `http://127.0.0.1:${ok.port}/v1` });

  try {
    const { body } = await postJSON(srv.base, '/api/v2/analyze', { text: SENSIBLER_TEXT });

    assert.strictEqual(
      body.meta.semanticAnalysisFailed, false,
      'Ein leeres, aber gueltiges Ergebnis darf nicht als Ausfall gelten'
    );
  } finally {
    await srv.stop();
    await ok.close();
  }
});

test('unlesbare Antwort zaehlt ebenfalls als Ausfall der semantischen Stufe', async () => {
  // Antwort kommt an, ist aber kein JSON - dasselbe Ergebnis wie ein Absturz.
  const prosa = await startMock(() => ({
    status: 200,
    json: chatCompletion('Ich kann diesen Text leider nicht analysieren.')
  }));
  const srv = await startServer({ OPENAI_BASE_URL: `http://127.0.0.1:${prosa.port}/v1` });

  try {
    const { body } = await postJSON(srv.base, '/api/v2/analyze', { text: SENSIBLER_TEXT });
    assert.strictEqual(body.meta.semanticAnalysisFailed, true);
  } finally {
    await srv.stop();
    await prosa.close();
  }
});

test('semantische Stufe faellt aus: /api/v2/analyze/predictive kennzeichnet den Ausfall', async () => {
  const tot = await startMock(() => ({ status: 500, json: { error: { message: 'boom' } } }));
  const srv = await startServer({ OPENAI_BASE_URL: `http://127.0.0.1:${tot.port}/v1` });

  try {
    const { status, body } = await postJSON(srv.base, '/api/v2/analyze/predictive', {
      text: SENSIBLER_TEXT
    });

    assert.strictEqual(status, 200);
    assert.strictEqual(
      body.meta.semanticAnalysisFailed, true,
      'Die Prognosewerte beruhen sonst unbemerkt allein auf den Regex-Mustern'
    );
  } finally {
    await srv.stop();
    await tot.close();
  }
});

test('semantische Stufe faellt aus: /api/v2/analyze/batch zaehlt die betroffenen Texte', async () => {
  const tot = await startMock(() => ({ status: 500, json: { error: { message: 'boom' } } }));
  const srv = await startServer({ OPENAI_BASE_URL: `http://127.0.0.1:${tot.port}/v1` });

  try {
    const { status, body } = await postJSON(srv.base, '/api/v2/analyze/batch', {
      texts: [SENSIBLER_TEXT, 'Zweiter Text ohne Besonderheiten.']
    });

    assert.strictEqual(status, 200);
    assert.strictEqual(
      body.semanticAnalysisFailures, 2,
      '"failed: 0" allein verschweigt, dass fuer jeden Text die semantische Stufe ausfiel'
    );
    assert.strictEqual(body.results[0].semanticAnalysisFailed, true, 'Kennzeichen je Text');
  } finally {
    await srv.stop();
    await tot.close();
  }
});

test('abgeschnittene Antwort: /api/v2/rewrite kennzeichnet das unvollstaendige Ergebnis', async () => {
  // finish_reason 'length' mit halbem JSON - genau das, was am Token-Limit
  // ankommt. Ohne Kennzeichen reicht der Dienst das Bruchstueck als fertigen
  // Text durch.
  const abgeschnitten = await startMock(() => ({
    status: 200,
    json: chatCompletion('{"rewritten": "Meine Tochter ist in einer Kli', 'length')
  }));
  const srv = await startServer({ OPENAI_BASE_URL: `http://127.0.0.1:${abgeschnitten.port}/v1` });

  try {
    const { status, body } = await postJSON(srv.base, '/api/v2/rewrite', {
      text: SENSIBLER_TEXT, mode: 'anonymize'
    });

    assert.strictEqual(status, 200, 'Statuscode bleibt unveraendert');
    assert.strictEqual(
      body.truncated, true,
      'Der Aufrufer muss erkennen koennen, dass der umgeschriebene Text unvollstaendig ist'
    );
  } finally {
    await srv.stop();
    await abgeschnitten.close();
  }
});

test('vollstaendige Antwort: /api/v2/rewrite setzt kein truncated-Kennzeichen', async () => {
  const ok = await startMock(() => ({
    status: 200,
    json: chatCompletion(JSON.stringify({ rewritten: 'Ein Familienmitglied ist im Krankenhaus.', changes: [] }))
  }));
  const srv = await startServer({ OPENAI_BASE_URL: `http://127.0.0.1:${ok.port}/v1` });

  try {
    const { body } = await postJSON(srv.base, '/api/v2/rewrite', {
      text: SENSIBLER_TEXT, mode: 'anonymize'
    });

    assert.ok(!('truncated' in body), 'Ein vollstaendiges Ergebnis darf nicht als abgeschnitten gelten');
    assert.strictEqual(body.rewritten, 'Ein Familienmitglied ist im Krankenhaus.');
  } finally {
    await srv.stop();
    await ok.close();
  }
});

test('LanguageTool nicht erreichbar: /api/v2/text-correct L0 meldet die ungeprueften Texte', async () => {
  // L0 hat keine zweite Quelle. Faellt LanguageTool aus, wurde nichts geprueft.
  const ltTot = await startMock(() => ({ status: 429, json: { message: 'too many requests' } }));
  const srv = await startServer({
    LANGUAGETOOL_API_URL: `http://127.0.0.1:${ltTot.port}/v2/check`
  });

  try {
    const { status, body } = await postJSON(srv.base, '/api/v2/text-correct', {
      text: 'Das ist ein Text mit fehlan und schlechtem Grammatik.', level: 'L0'
    });

    assert.strictEqual(status, 200, 'Statuscode bleibt unveraendert');
    assert.strictEqual(
      body.meta.languageToolAvailable, false,
      'Ohne dieses Kennzeichen liest sich der Ausfall als fehlerfreier Text'
    );
    assert.match(
      body.executiveSummary, /NICHT geprüft/,
      'Die Zusammenfassung darf nicht "0 Befund(en)" behaupten, wenn nichts geprueft wurde'
    );
  } finally {
    await srv.stop();
    await ltTot.close();
  }
});

test('LanguageTool erreichbar: /api/v2/text-correct L0 meldet ein echtes Ergebnis', async () => {
  const ltOk = await startMock(() => ({ status: 200, json: LT_LEER }));
  const srv = await startServer({
    LANGUAGETOOL_API_URL: `http://127.0.0.1:${ltOk.port}/v2/check`
  });

  try {
    const { body } = await postJSON(srv.base, '/api/v2/text-correct', {
      text: 'Ein fehlerfreier Satz.', level: 'L0'
    });

    assert.strictEqual(body.meta.languageToolAvailable, true);
    assert.match(
      body.executiveSummary, /0 Befund\(en\)/,
      'Ein gepruefter Text ohne Befunde bleibt ein normales Ergebnis'
    );
  } finally {
    await srv.stop();
    await ltOk.close();
  }
});

test('LANGUAGETOOL_API_URL steuert den Endpunkt', async () => {
  const ltOk = await startMock(() => ({ status: 200, json: LT_LEER }));
  const srv = await startServer({
    LANGUAGETOOL_API_URL: `http://127.0.0.1:${ltOk.port}/v2/check`
  });

  try {
    await postJSON(srv.base, '/api/v2/text-correct', { text: 'Ein Satz.', level: 'L0' });
    assert.strictEqual(ltOk.calls.length, 1, 'Der Dienst muss den konfigurierten Endpunkt aufrufen');
  } finally {
    await srv.stop();
    await ltOk.close();
  }
});
