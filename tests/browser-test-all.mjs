// Full interactive test of every lab — buttons, forms, payloads, user interactions
export default async function run(page, ui) {
  const results = {};

  // Helper: test a lab page
  async function testLab(name, url, testFn) {
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 8000 });
      await page.waitForTimeout(500);
      const r = await testFn();
      results[name] = { status: 'OK', ...r };
    } catch (e) {
      results[name] = { status: 'ERROR', error: e.message };
    }
  }

  // ─── 1. DASHBOARD ───
  await testLab('dashboard', 'http://127.0.0.1:8080', async () => {
    const snap = await ui.snapshot({ full: true });
    const title = await page.title();
    const labCards = await page.evaluate(() => document.querySelectorAll('.lab-card, [class*=card]').length);
    return { title, labCards, hasContent: snap.length > 100 };
  });

  // ─── 2. SQL INJECTION — VULNERABLE ───
  await testLab('sqli-vuln', 'http://127.0.0.1:5021', async () => {
    const snap = await ui.snapshot();
    const tests = {};

    // Test normal login
    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'alice', password: 'lab_alice_pass' }) });
      return { status: r.status, data: await r.json() };
    });
    tests.normalLogin = { status: r1.status, authenticated: r1.data.status === 'authenticated' };

    // Test tautology bypass
    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: "' OR '1'='1" }) });
      return { status: r.status, data: await r.json() };
    });
    tests.tautologyBypass = { status: r2.status, bypassed: r2.data.status === 'authenticated', role: r2.data.role };

    // Test comment bypass
    const r3 = await page.evaluate(async () => {
      const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: "admin'--", password: 'anything' }) });
      return { status: r.status, data: await r.json() };
    });
    tests.commentBypass = { status: r3.status, bypassed: r3.data.status === 'authenticated' };

    // Test UNION injection
    const r4 = await page.evaluate(async () => {
      const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: "' UNION SELECT 1,'injected','data','admin'--", password: 'x' }) });
      return { status: r.status, data: await r.json() };
    });
    tests.unionInjection = { status: r4.status, injectedUser: r4.data.username };

    // Test UI buttons
    const btnSnap = await ui.snapshot();
    const buttons = (btnSnap.match(/@e\d+ button/g) || []).length;

    return { tests, buttonCount: buttons, snapshot: btnSnap.substring(0, 300) };
  });

  // ─── 3. SQL INJECTION — SECURE ───
  await testLab('sqli-secure', 'http://127.0.0.1:5022', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'alice', password: 'lab_alice_pass' }) });
      return { status: r.status, data: await r.json() };
    });
    tests.normalLogin = { status: r1.status, authenticated: r1.data.status === 'authenticated' };

    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: "' OR '1'='1" }) });
      return { status: r.status, data: await r.json() };
    });
    tests.tautologyBlocked = { status: r2.status, blocked: r2.data.status === 'failed' };

    const r3 = await page.evaluate(async () => {
      const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: "admin'--", password: 'anything' }) });
      return { status: r.status, data: await r.json() };
    });
    tests.commentBlocked = { status: r3.status, blocked: r3.data.status === 'failed' };

    return { tests };
  });

  // ─── 4. COMMAND INJECTION — VULNERABLE ───
  await testLab('cmd-vuln', 'http://127.0.0.1:5003', async () => {
    const tests = {};

    // Normal ping
    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/ping', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: '127.0.0.1' }) });
      return { status: r.status, data: await r.json() };
    });
    tests.normalPing = { status: r1.status, hasOutput: r1.data.output?.length > 0 };

    // Command injection
    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/ping', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: '127.0.0.1; echo INJECTION_TEST_OK' }) });
      return { status: r.status, data: await r.json() };
    });
    tests.injection = { status: r2.status, injected: r2.data.output?.includes('INJECTION_TEST_OK') || r2.data.command?.includes('INJECTION_TEST_OK') };

    const snap = await ui.snapshot();
    const buttons = (snap.match(/@e\d+ button/g) || []).length;

    return { tests, buttonCount: buttons };
  });

  // ─── 5. COMMAND INJECTION — SECURE ───
  await testLab('cmd-secure', 'http://127.0.0.1:5004', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/ping', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: '127.0.0.1' }) });
      return { status: r.status, data: await r.json() };
    });
    tests.normalPing = { status: r1.status, blocked: r1.data.blocked };

    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/ping', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: '127.0.0.1; echo INJECTED' }) });
      return { status: r.status, data: await r.json() };
    });
    tests.injectionBlocked = { status: r2.status, blocked: r2.data.blocked };

    const r3 = await page.evaluate(async () => {
      const r = await fetch('/api/ping', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target: '8.8.8.8' }) });
      return { status: r.status, data: await r.json() };
    });
    tests.externalBlocked = { status: r3.status, blocked: r3.data.blocked };

    return { tests };
  });

  // ─── 6. XSS — VULNERABLE ───
  await testLab('xss-vuln', 'http://127.0.0.1:5001', async () => {
    const tests = {};

    // Clear first
    await page.evaluate(() => fetch('/clear'));

    // Post normal comment
    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/comment', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'TestUser', comment: 'Hello World' }) });
      return { status: r.status, data: await r.json() };
    });
    tests.normalComment = { status: r1.status, ok: r1.data.status === 'ok' };

    // Post XSS payload
    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/comment', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'Hacker', comment: '<script>alert("xss")</script>' }) });
      return { status: r.status, data: await r.json() };
    });
    tests.xssStored = { status: r2.status, stored: r2.data.status === 'ok' };

    // Check it's stored raw
    const r3 = await page.evaluate(async () => {
      const r = await fetch('/api/last');
      return await r.json();
    });
    tests.xssRaw = { storedRaw: r3.comment === '<script>alert("xss")</script>' };

    // Check all comments
    const r4 = await page.evaluate(async () => {
      const r = await fetch('/api/comments');
      return await r.json();
    });
    tests.totalComments = r4.length;

    await page.evaluate(() => fetch('/clear'));
    return { tests };
  });

  // ─── 7. XSS — SECURE ───
  await testLab('xss-secure', 'http://127.0.0.1:5002', async () => {
    const tests = {};

    await page.evaluate(() => fetch('/clear'));

    // Valid comment
    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/comment', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'TestUser', comment: 'Hello World' }) });
      return { status: r.status, data: await r.json() };
    });
    tests.normalComment = { status: r1.status, ok: r1.data.status === 'ok' };

    // XSS payload in name — rejected
    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/comment', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: '<script>alert(1)</script>', comment: 'test' }) });
      return { status: r.status, data: await r.json() };
    });
    tests.xssNameBlocked = { status: r2.status, blocked: r2.status === 400 };

    // CSP header check
    const r3 = await page.evaluate(async () => {
      const r = await fetch('/');
      return { csp: r.headers.get('Content-Security-Policy'), xfo: r.headers.get('X-Frame-Options'), xcto: r.headers.get('X-Content-Type-Options') };
    });
    tests.securityHeaders = r3;

    await page.evaluate(() => fetch('/clear'));
    return { tests };
  });

  // ─── 8. SSTI — VULNERABLE ───
  await testLab('ssti-vuln', 'http://127.0.0.1:5005', async () => {
    const tests = {};

    // Normal name
    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/greet?name=Alice');
      return await r.json();
    });
    tests.normalGreet = { output: r1.output };

    // Math injection {{7*7}}
    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/greet?name=' + encodeURIComponent('{{7*7}}'));
      return await r.json();
    });
    tests.mathInjection = { output: r2.output, evaluated: r2.output?.includes('49') };

    // Config leak attempt
    const r3 = await page.evaluate(async () => {
      const r = await fetch('/api/greet?name=' + encodeURIComponent('{{config}}'));
      return await r.json();
    });
    tests.configLeak = { hasOutput: r3.output?.length > 20, leaked: r3.output?.includes('secret') || r3.output?.includes('SECRET') };

    return { tests };
  });

  // ─── 9. SSTI — SECURE ───
  await testLab('ssti-secure', 'http://127.0.0.1:5006', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/greet?name=Alice');
      return await r.json();
    });
    tests.normalGreet = { output: r1.output };

    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/greet?name=' + encodeURIComponent('{{7*7}}'));
      return { status: r.status, data: await r.json() };
    });
    tests.mathBlocked = { status: r2.status, blocked: r2.data.blocked };

    return { tests };
  });

  // ─── 10. NoSQL — VULNERABLE ───
  await testLab('nosql-vuln', 'http://127.0.0.1:5007', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'alice', password: 'lab_alice_pass' }) });
      return { status: r.status, data: await r.json() };
    });
    tests.normalLogin = { status: r1.status, authenticated: r1.data.status === 'authenticated' };

    // $ne bypass
    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: { '$ne': null } }) });
      return { status: r.status, data: await r.json() };
    });
    tests.neBypass = { status: r2.status, bypassed: r2.data.status === 'authenticated', role: r2.data.role };

    // $gt bypass
    const r3 = await page.evaluate(async () => {
      const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: { '$gt': '' } }) });
      return { status: r.status, data: await r.json() };
    });
    tests.gtBypass = { status: r3.status, bypassed: r3.data.status === 'authenticated' };

    return { tests };
  });

  // ─── 11. NoSQL — SECURE ───
  await testLab('nosql-secure', 'http://127.0.0.1:5008', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'alice', password: 'lab_alice_pass' }) });
      return { status: r.status, data: await r.json() };
    });
    tests.normalLogin = { status: r1.status, authenticated: r1.data.status === 'authenticated' };

    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: { '$ne': null } }) });
      return { status: r.status, data: await r.json() };
    });
    tests.neBlocked = { status: r2.status, blocked: r2.data.blocked || r2.status === 400 };

    return { tests };
  });

  // ─── 12. LDAP — VULNERABLE ───
  await testLab('ldap-vuln', 'http://127.0.0.1:5009', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/search?username=ivan');
      return await r.json();
    });
    tests.normalSearch = { count: r1.count, users: r1.users };

    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/search?username=*');
      return await r.json();
    });
    tests.wildcardDump = { count: r2.count, allUsers: r2.users };

    return { tests };
  });

  // ─── 13. LDAP — SECURE ───
  await testLab('ldap-secure', 'http://127.0.0.1:5010', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/search?username=ivan');
      return await r.json();
    });
    tests.normalSearch = { count: r1.count, users: r1.users, blocked: r1.blocked };

    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/search?username=*');
      return { status: r.status, data: await r.json() };
    });
    tests.wildcardBlocked = { status: r2.status, blocked: r2.data.blocked };

    return { tests };
  });

  // ─── 14. XPath — VULNERABLE ───
  await testLab('xpath-vuln', 'http://127.0.0.1:5011', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/lookup?username=alice');
      return await r.json();
    });
    tests.normalLookup = { count: r1.count, users: r1.users };

    const r2 = await page.evaluate(async () => {
      const r = await fetch("/api/lookup?username=" + encodeURIComponent("' or '1'='1"));
      return await r.json();
    });
    tests.orInjection = { count: r2.count, allUsers: r2.users };

    return { tests };
  });

  // ─── 15. XPath — SECURE ───
  await testLab('xpath-secure', 'http://127.0.0.1:5012', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/lookup?username=alice');
      return await r.json();
    });
    tests.normalLookup = { count: r1.count, blocked: r1.blocked };

    const r2 = await page.evaluate(async () => {
      const r = await fetch("/api/lookup?username=" + encodeURIComponent("' or '1'='1"));
      return { status: r.status, data: await r.json() };
    });
    tests.injectionBlocked = { status: r2.status, blocked: r2.data.blocked };

    return { tests };
  });

  // ─── 16. HEADER — VULNERABLE ───
  await testLab('header-vuln', 'http://127.0.0.1:5017', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/set-lang?lang=fr');
      return { status: r.status, xLang: r.headers.get('X-Language'), data: await r.json() };
    });
    tests.normalLang = { status: r1.status, xLang: r1.xLang };

    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/set-lang?lang=' + encodeURIComponent('en\r\nX-Injected: true'));
      return { status: r.status, data: await r.json() };
    });
    tests.crlfInjection = { status: r2.status, injectedHeaders: r2.data.injected_headers };

    return { tests };
  });

  // ─── 17. HEADER — SECURE ───
  await testLab('header-secure', 'http://127.0.0.1:5018', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/set-lang?lang=fr');
      return { status: r.status, data: await r.json() };
    });
    tests.normalLang = { status: r1.status, blocked: r1.data.blocked };

    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/set-lang?lang=' + encodeURIComponent('en\r\nX-Injected: true'));
      return { status: r.status, data: await r.json() };
    });
    tests.crlfBlocked = { status: r2.status, blocked: r2.data.blocked };

    const r3 = await page.evaluate(async () => {
      const r = await fetch('/api/set-lang?lang=xx');
      return { status: r.status, data: await r.json() };
    });
    tests.invalidLangBlocked = { status: r3.status, blocked: r3.data.blocked };

    return { tests };
  });

  // ─── 18. LOG — VULNERABLE ───
  await testLab('log-vuln', 'http://127.0.0.1:5015', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'alice' }) });
      const r = await fetch('/api/logs');
      return await r.json();
    });
    tests.normalLog = { logCount: r1.logs?.length, lastLog: r1.logs?.[r1.logs.length - 1] };

    // Inject fake log entry
    const r2 = await page.evaluate(async () => {
      await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin\n[INFO] Login SUCCESS for: admin - BYPASS' }) });
      const r = await fetch('/api/logs');
      return await r.json();
    });
    tests.logInjection = { logCount: r2.logs?.length, hasFakeEntry: r2.logs?.some(l => typeof l === 'string' && l.includes('BYPASS')) };

    return { tests };
  });

  // ─── 19. LOG — SECURE ───
  await testLab('log-secure', 'http://127.0.0.1:5016', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'alice' }) });
      return { status: r.status, data: await r.json() };
    });
    tests.normalLogin = { status: r1.status, blocked: r1.data.blocked };

    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin\n[INFO] BYPASS' }) });
      return { status: r.status, data: await r.json() };
    });
    tests.injectionBlocked = { status: r2.status, blocked: r2.data.blocked };

    return { tests };
  });

  // ─── 20. CSV — VULNERABLE ───
  await testLab('csv-vuln', 'http://127.0.0.1:5013', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/export', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ entries: [{ name: '=SUM(1+1)', email: 'test@test.com', company: 'ACME' }] }) });
      return { status: r.status, csv: await r.text() };
    });
    tests.formulaRaw = { status: r1.status, hasRawFormula: r1.csv?.includes('=SUM(1+1)') && !r1.csv?.includes('\t=SUM') };

    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/export', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ entries: [{ name: 'Normal', email: 'ok@ok.com', company: 'OK' }] }) });
      return { status: r.status, csv: await r.text() };
    });
    tests.normalEntry = { status: r2.status, csv: r2.csv };

    return { tests };
  });

  // ─── 21. CSV — SECURE ───
  await testLab('csv-secure', 'http://127.0.0.1:5014', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/export', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ entries: [{ name: '=SUM(1+1)', email: 'test@test.com', company: 'ACME' }] }) });
      return { status: r.status, csv: await r.text() };
    });
    tests.formulaSanitized = { status: r1.status, hasTabPrefix: r1.csv?.includes('\t=SUM') };

    return { tests };
  });

  // ─── 22. EXPRESSION — VULNERABLE ───
  await testLab('expr-vuln', 'http://127.0.0.1:5019', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/calculate?expression=' + encodeURIComponent('2+2'));
      return await r.json();
    });
    tests.normalMath = { result: r1.result };

    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/calculate?expression=' + encodeURIComponent('"x"*3'));
      return await r.json();
    });
    tests.stringOp = { result: r2.result, type: r2.type };

    // Dangerous: __import__ 
    const r3 = await page.evaluate(async () => {
      const r = await fetch('/api/calculate?expression=' + encodeURIComponent('len("test")'));
      return await r.json();
    });
    tests.builtinAccess = { result: r3.result };

    return { tests };
  });

  // ─── 23. EXPRESSION — SECURE ───
  await testLab('expr-secure', 'http://127.0.0.1:5020', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/calculate?expression=' + encodeURIComponent('2+2'));
      return await r.json();
    });
    tests.normalMath = { result: r1.result, blocked: r1.blocked };

    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/calculate?expression=' + encodeURIComponent('(10+5)*2'));
      return await r.json();
    });
    tests.complexMath = { result: r2.result };

    const r3 = await page.evaluate(async () => {
      const r = await fetch('/api/calculate?expression=' + encodeURIComponent('"x"*3'));
      return { status: r.status, data: await r.json() };
    });
    tests.stringBlocked = { status: r3.status, blocked: r3.data.blocked };

    const r4 = await page.evaluate(async () => {
      const r = await fetch('/api/calculate?expression=' + encodeURIComponent('1/0'));
      return { status: r.status, data: await r.json() };
    });
    tests.divZero = { status: r4.status, blocked: r4.data.blocked, error: r4.data.error };

    return { tests };
  });

  // ─── UI INTERACTION TESTS (clicking actual buttons) ───

  // Test SQL Injection UI buttons
  await testLab('sqli-vuln-ui', 'http://127.0.0.1:5021', async () => {
    const snap = await ui.snapshot();
    const interactions = {};

    // Find and count all interactive elements
    const inputRefs = snap.match(/@e\d+ textbox/g) || [];
    const buttonRefs = snap.match(/@e\d+ button[^\n]*/g) || [];
    interactions.inputs = inputRefs.length;
    interactions.buttons = buttonRefs;

    // Try clicking tabs if present
    const tabMatch = snap.match(/@(e\d+) button "(?:Démo|Demo|Code|Théorie|Fix)"/);
    if (tabMatch) {
      await ui.click(`@${tabMatch[1]}`);
      await page.waitForTimeout(300);
      const afterTab = await ui.snapshot({ full: true });
      interactions.tabClick = 'OK';
    }

    // Find login button
    const loginMatch = snap.match(/@(e\d+) button "(?:Connexion|Login|Se connecter)"/i);
    if (loginMatch) {
      // Fill inputs first
      const uInput = snap.match(/@(e\d+) textbox/);
      if (uInput) {
        await ui.fill(`@${uInput[1]}`, 'alice');
        interactions.filledUsername = true;
      }
      interactions.loginButtonFound = true;
    }

    return interactions;
  });

  // Test Command Injection UI 
  await testLab('cmd-vuln-ui', 'http://127.0.0.1:5003', async () => {
    const snap = await ui.snapshot();
    const interactions = {};

    const inputRefs = snap.match(/@e\d+ textbox/g) || [];
    const buttonRefs = snap.match(/@e\d+ button[^\n]*/g) || [];
    interactions.inputs = inputRefs.length;
    interactions.buttons = buttonRefs;

    // Try to find the ping button
    const pingMatch = snap.match(/@(e\d+) button "(?:Ping|Exécuter|Execute)"/i);
    if (pingMatch) {
      interactions.pingButtonFound = true;
    }

    return interactions;
  });

  // ─── SSRF — VULNERABLE ───
  await testLab('ssrf-vuln', 'http://127.0.0.1:5023', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/internal/metadata');
      return { status: r.status, data: await r.json() };
    });
    tests.internalMetadata = { status: r1.status, internal: r1.data.internal };

    const r2 = await page.evaluate(async () => {
      const r = await fetch('/internal/flag');
      return { status: r.status, data: await r.json() };
    });
    tests.internalFlag = { status: r2.status, hasFlag: r2.data.flag?.startsWith('FLAG{') };

    const r3 = await page.evaluate(async () => {
      const r = await fetch('/api/fetch');
      return { status: r.status, data: await r.json() };
    });
    tests.emptyUrl = { status: r3.status };

    return { tests };
  });

  // ─── SSRF — SECURE ───
  await testLab('ssrf-secure', 'http://127.0.0.1:5024', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/fetch?url=' + encodeURIComponent('http://localhost:5000/internal/flag'));
      return { status: r.status, data: await r.json() };
    });
    tests.ssrfBlocked = { status: r1.status, blocked: r1.data.blocked };

    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/fetch?url=' + encodeURIComponent('file:///etc/passwd'));
      return { status: r.status, data: await r.json() };
    });
    tests.fileSchemeBlocked = { status: r2.status, blocked: r2.data.blocked };

    return { tests };
  });

  // ─── IDOR — VULNERABLE ───
  await testLab('idor-vuln', 'http://127.0.0.1:5025', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/user/1');
      return { status: r.status, data: await r.json() };
    });
    tests.ownProfile = { status: r1.status, username: r1.data.username };

    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/user/3');
      return { status: r.status, data: await r.json() };
    });
    tests.adminProfile = { status: r2.status, role: r2.data.role, hasFlag: r2.data.notes?.includes('FLAG{') };

    const r3 = await page.evaluate(async () => {
      const r = await fetch('/api/users');
      return { status: r.status, data: await r.json() };
    });
    tests.userList = { status: r3.status, count: r3.data.users?.length };

    return { tests };
  });

  // ─── IDOR — SECURE ───
  await testLab('idor-secure', 'http://127.0.0.1:5026', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/user/1');
      return { status: r.status, data: await r.json() };
    });
    tests.ownProfile = { status: r1.status, username: r1.data.username };

    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/user/3');
      return { status: r.status, data: await r.json() };
    });
    tests.adminBlocked = { status: r2.status, blocked: r2.data.blocked };

    return { tests };
  });

  // ─── PATH TRAVERSAL — VULNERABLE ───
  await testLab('pathtraversal-vuln', 'http://127.0.0.1:5027', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/read?file=report-q1.txt');
      return { status: r.status, data: await r.json() };
    });
    tests.normalRead = { status: r1.status, hasContent: r1.data.content?.length > 0 };

    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/read?file=' + encodeURIComponent('../../../../tmp/flag.txt'));
      return { status: r.status, data: await r.json() };
    });
    tests.traversalFlag = { status: r2.status, hasFlag: r2.data.content?.includes('FLAG{') };

    const r3 = await page.evaluate(async () => {
      const r = await fetch('/api/files');
      return { status: r.status, data: await r.json() };
    });
    tests.fileList = { status: r3.status, files: r3.data.files };

    return { tests };
  });

  // ─── PATH TRAVERSAL — SECURE ───
  await testLab('pathtraversal-secure', 'http://127.0.0.1:5028', async () => {
    const tests = {};

    const r1 = await page.evaluate(async () => {
      const r = await fetch('/api/read?file=report-q1.txt');
      return { status: r.status, data: await r.json() };
    });
    tests.normalRead = { status: r1.status, blocked: r1.data.blocked };

    const r2 = await page.evaluate(async () => {
      const r = await fetch('/api/read?file=' + encodeURIComponent('../../../../tmp/flag.txt'));
      return { status: r.status, data: await r.json() };
    });
    tests.traversalBlocked = { status: r2.status, notOk: r2.status !== 200 || !r2.data.content?.includes('FLAG{') };

    return { tests };
  });

  return results;
}
