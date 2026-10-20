const { chromium } = require('/home/shashwat/.cache/ms-playwright-go/1.57.0/package');
const path = require('path');
const fs = require('fs');

const ARTIFACT_DIR = '/home/shashwat/.gemini/antigravity-ide/brain/b15ea338-7f7e-430f-b3a0-30e7291e1a31';
const BASE_URL = 'http://127.0.0.1:8088';

async function runBrowserAudit() {
  console.log('--- STARTING COMPREHENSIVE BROWSER AUDIT ---');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 }
  });

  const consoleLogs = [];
  const networkErrors = [];

  const page = await context.newPage();
  page.on('console', msg => {
    consoleLogs.push({ type: msg.type(), text: msg.text() });
    if (msg.type() === 'error') {
      console.error('Console Error:', msg.text());
    }
  });

  page.on('requestfailed', req => {
    networkErrors.push({ url: req.url(), failure: req.failure() });
    console.error('Network Request Failed:', req.url(), req.failure());
  });

  // 1. Initial Page Load (Overview - Light Theme by default)
  console.log('1. Testing Overview (Light Theme)...');
  await page.goto(`${BASE_URL}`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(ARTIFACT_DIR, '01_overview_light.png'), fullPage: true });

  // 2. Toggle Theme to Dark
  console.log('2. Testing Theme Toggle to Dark...');
  const themeBtn = await page.$('button[aria-label*="theme" i], button:has-text("Dark"), button:has-text("Light"), header button:has(svg)');
  if (themeBtn) {
    await themeBtn.click();
    await page.waitForTimeout(500);
    await page.screenshot({ path: path.join(ARTIFACT_DIR, '02_overview_dark.png'), fullPage: true });
  } else {
    console.warn('Theme button not found by selector');
  }

  // 3. Navigation to Runs View
  console.log('3. Testing Runs View...');
  await page.click('a[href="#runs"], button:has-text("Runs")');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(ARTIFACT_DIR, '03_runs_view.png'), fullPage: true });

  // 4. Navigation to Audit Log View
  console.log('4. Testing Audit Log View...');
  await page.click('a[href="#audit"], button:has-text("Audit")');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(ARTIFACT_DIR, '04_audit_view.png'), fullPage: true });

  // 5. Navigation to Break-it / Isolation Probes View
  console.log('5. Testing Isolation Probes (Break-it) View...');
  await page.click('a[href="#breakit"], button:has-text("Probes"), button:has-text("Active probes")');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(ARTIFACT_DIR, '05_breakit_view.png'), fullPage: true });

  // 6. Navigation to Timing View
  console.log('6. Testing Timing View...');
  await page.click('a[href="#timing"], button:has-text("Timing")');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(ARTIFACT_DIR, '06_timing_view.png'), fullPage: true });

  // 7. Navigation to Threat Model View
  console.log('7. Testing Threat Model View...');
  await page.click('a[href="#threat"], button:has-text("Threat model")');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(ARTIFACT_DIR, '07_threat_model_view.png'), fullPage: true });

  // 8. Navigation to Confidentiality / Data Handling View
  console.log('8. Testing Data Handling View...');
  await page.click('a[href="#data-handling"], button:has-text("Data handling")');
  await page.waitForTimeout(1000);
  await page.screenshot({ path: path.join(ARTIFACT_DIR, '08_data_handling_view.png'), fullPage: true });

  // 9. Operator Access Modal
  console.log('9. Testing Operator Access Modal...');
  const opBtn = await page.$('button:has-text("Operator"), button:has-text("Login")');
  if (opBtn) {
    await opBtn.click();
    await page.waitForTimeout(500);
    await page.screenshot({ path: path.join(ARTIFACT_DIR, '09_operator_modal.png') });
    // Dismiss modal
    const cancelBtn = await page.$('button:has-text("Cancel"), button[aria-label="Close"]');
    if (cancelBtn) await cancelBtn.click();
    await page.waitForTimeout(500);
  }

  // 10. Responsive Viewport: Tablet (1024x768)
  console.log('10. Testing Tablet Viewport (1024x768)...');
  await page.setViewportSize({ width: 1024, height: 768 });
  await page.goto(`${BASE_URL}/#overview`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(ARTIFACT_DIR, '10_tablet_1024.png') });

  // 11. Responsive Viewport: Mobile (390x844)
  console.log('11. Testing Mobile Viewport (390x844)...');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${BASE_URL}/#overview`, { waitUntil: 'networkidle' });
  await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(ARTIFACT_DIR, '11_mobile_390.png') });

  // Check overflow
  const isOverflowing = await page.evaluate(() => {
    return document.documentElement.scrollWidth > window.innerWidth;
  });
  console.log('Mobile horizontal overflow detected:', isOverflowing);

  await browser.close();

  console.log('--- BROWSER AUDIT SUMMARY ---');
  console.log('Total Console Messages:', consoleLogs.length);
  console.log('Total Console Errors:', consoleLogs.filter(c => c.type === 'error').length);
  console.log('Total Network Errors:', networkErrors.length);
  console.log('Audit Completed Successfully!');
}

runBrowserAudit().catch(err => {
  console.error('Audit script failed:', err);
  process.exit(1);
});
