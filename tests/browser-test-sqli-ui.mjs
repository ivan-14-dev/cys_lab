// Test UI buttons interactively for SQL Injection lab
export default async function run(page, ui) {
  const results = {};

  // Initial state
  let snap = await ui.snapshot();
  results.initialButtons = snap;

  // 1. Click "EN" (language toggle)
  await ui.click('@e1');
  await page.waitForTimeout(300);
  snap = await ui.snapshot({ full: true });
  results.afterLangToggle = snap.substring(0, 500);

  // Re-snapshot to get new refs
  snap = await ui.snapshot();

  // 2. Click "Normal" — should fill alice/lab_alice_pass
  const normalBtn = snap.match(/@(e\d+) button "Normal"/);
  if (normalBtn) {
    await ui.click(`@${normalBtn[1]}`);
    await page.waitForTimeout(200);
    // Check inputs filled
    const uVal = await page.evaluate(() => document.querySelector('#sqli-u')?.value);
    const pVal = await page.evaluate(() => document.querySelector('#sqli-p')?.value);
    results.normalButton = { username: uVal, password: pVal };
  }

  // 3. Click "Se connecter" (login)
  snap = await ui.snapshot();
  const loginBtn = snap.match(/@(e\d+) button "Se connecter"/);
  if (loginBtn) {
    await ui.click(`@${loginBtn[1]}`);
    await page.waitForTimeout(500);
    const resultText = await page.evaluate(() => document.querySelector('#sqli-result')?.innerText || '');
    results.normalLogin = resultText.substring(0, 300);
  }

  // 4. Click first "Injecter" (tautology)
  snap = await ui.snapshot();
  const injectBtns = [...snap.matchAll(/@(e\d+) button "Injecter"/g)];
  if (injectBtns.length > 0) {
    await ui.click(`@${injectBtns[0][1]}`);
    await page.waitForTimeout(200);
    const uVal = await page.evaluate(() => document.querySelector('#sqli-u')?.value);
    const pVal = await page.evaluate(() => document.querySelector('#sqli-p')?.value);
    results.inject1_filled = { username: uVal, password: pVal };

    // Now click login
    snap = await ui.snapshot();
    const loginBtn2 = snap.match(/@(e\d+) button "Se connecter"/);
    if (loginBtn2) {
      await ui.click(`@${loginBtn2[1]}`);
      await page.waitForTimeout(500);
      const resultText = await page.evaluate(() => document.querySelector('#sqli-result')?.innerText || '');
      results.inject1_result = resultText.substring(0, 300);
    }
  }

  // 5. Click second "Injecter" (comment bypass)
  snap = await ui.snapshot();
  const injectBtns2 = [...snap.matchAll(/@(e\d+) button "Injecter"/g)];
  if (injectBtns2.length > 1) {
    await ui.click(`@${injectBtns2[1][1]}`);
    await page.waitForTimeout(200);
    const uVal = await page.evaluate(() => document.querySelector('#sqli-u')?.value);
    const pVal = await page.evaluate(() => document.querySelector('#sqli-p')?.value);
    results.inject2_filled = { username: uVal, password: pVal };

    snap = await ui.snapshot();
    const loginBtn3 = snap.match(/@(e\d+) button "Se connecter"/);
    if (loginBtn3) {
      await ui.click(`@${loginBtn3[1]}`);
      await page.waitForTimeout(500);
      const resultText = await page.evaluate(() => document.querySelector('#sqli-result')?.innerText || '');
      results.inject2_result = resultText.substring(0, 300);
    }
  }

  // 6. Click tabs: Théorie, Code, Correction
  snap = await ui.snapshot();
  const theorieBtn = snap.match(/@(e\d+) button "Th[eé]orie"/);
  if (theorieBtn) {
    await ui.click(`@${theorieBtn[1]}`);
    await page.waitForTimeout(300);
    const visible = await page.evaluate(() => {
      const tabs = document.querySelectorAll('[id^="tab-"]');
      const result = {};
      tabs.forEach(t => result[t.id] = t.style.display !== 'none' && !t.hidden);
      return result;
    });
    results.theorieTab = visible;
  }

  const codeBtn = snap.match(/@(e\d+) button "Code"/);
  if (codeBtn) {
    await ui.click(`@${codeBtn[1]}`);
    await page.waitForTimeout(300);
    results.codeTabClicked = true;
  }

  const fixBtn = snap.match(/@(e\d+) button "Correction"/);
  if (fixBtn) {
    await ui.click(`@${fixBtn[1]}`);
    await page.waitForTimeout(300);
    results.fixTabClicked = true;
  }

  // 7. Test button
  snap = await ui.snapshot();
  const testBtn = snap.match(/@(e\d+) button "Test"/);
  if (testBtn) {
    results.testButtonFound = true;
  }

  return results;
}
