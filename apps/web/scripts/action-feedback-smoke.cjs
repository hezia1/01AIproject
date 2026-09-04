const { chromium } = require('playwright-core');
const assert = require('node:assert/strict');
const fs = require('node:fs');

(async () => {
  // Guard against new native controls accidentally bypassing the shared behavior.
  for (const file of fs.readdirSync('src', { recursive: true }).filter(file => file.endsWith('.tsx') && file !== 'action-feedback.tsx')) {
    assert(!/<(?:button|form)(?:\s|>)/.test(fs.readFileSync(`src/${file}`, 'utf8')), `${file}: unwrapped interactive control`);
  }
  const browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome', headless: true });
  try {
    const page = await browser.newPage();
    let release, calls = 0;
    await page.route('**/api/feedback-fixture/**', async route => {
      const mode = route.request().url().split('/').pop();
      if (mode === 'slow') { calls++; await new Promise(resolve => { release = resolve; }); }
      await route.fulfill({ status: mode === 'error' ? 403 : 200, contentType: 'application/json', body: JSON.stringify(mode === 'error' ? { detail: '测试权限拒绝' } : { status: 'queued', completed: false }) });
    });
    await page.goto(process.env.ADMIN_UI_BASE_URL || 'http://localhost:5173', { waitUntil: 'networkidle' });
    await page.evaluate(async () => {
      const React = await import('/node_modules/.vite/deps/react.js');
      const ReactDOM = await import('/node_modules/.vite/deps/react-dom_client.js');
      const { FeedbackButton, FeedbackForm } = await import('/src/action-feedback.tsx');
      const { request, feedbackFetch } = await import('/src/api.ts');
      const host = document.createElement('section'); host.id = 'feedback-fixture'; document.body.appendChild(host);
      const h = (React.default ?? React).createElement;
      (ReactDOM.default ?? ReactDOM).createRoot(host).render(h('div', {},
        h(FeedbackButton, { onClick: () => request('/feedback-fixture/slow') }, '慢操作'),
        h(FeedbackButton, { onClick: () => request('/feedback-fixture/error').catch(() => { window.localErrorHandled = true; }) }, '失败操作'),
        h(FeedbackButton, { onClick: () => { window.navigationChanged = true; } }, '导航操作'),
        h(FeedbackButton, { onClick: () => { throw new Error('同步失败测试'); } }, '同步异常'),
        h(FeedbackButton, { onClick: () => feedbackFetch('/api/feedback-fixture/error').then(async response => { window.downloadFailureBody = await response.json(); }) }, '导出失败'),
        h(FeedbackForm, { onSubmit: event => { event.preventDefault(); return request('/feedback-fixture/slow'); } },
          h('input', { required: true, 'aria-label': '反馈测试必填字段' }), h(FeedbackButton, { type: 'submit' }, '提交测试'))));
      window.backgroundFeedbackProbe = () => request('/feedback-fixture/error').catch(() => {});
    });
    const fixture = page.locator('#feedback-fixture'), toast = page.locator('.action-feedback-toast');
    const slow = fixture.getByRole('button', { name: '慢操作', exact: true });
    await slow.waitFor();
    await slow.evaluate(button => { button.click(); button.click(); });
    await page.waitForFunction(() => document.querySelector('#feedback-fixture button')?.getAttribute('aria-busy') === 'true');
    assert(await slow.isDisabled());
    assert((await toast.innerText()).includes('处理中'));
    await page.waitForTimeout(100);
    assert.equal(calls, 1, 'double clicks must not submit twice');
    release();
    await page.waitForFunction(() => document.querySelector('.action-feedback-toast')?.textContent.includes('操作已结束'));
    assert(!(await toast.innerText()).includes('成功'), 'queued response must not be reported as business success');
    assert(!(await slow.isDisabled()));
    await fixture.getByRole('button', { name: '失败操作' }).click();
    await page.waitForFunction(() => document.querySelector('.action-feedback-toast')?.textContent.includes('测试权限拒绝'));
    assert.equal(await page.evaluate(() => window.localErrorHandled), true);
    await page.setViewportSize({ width: 390, height: 844 });
    assert(await toast.evaluate(el => el.getBoundingClientRect().right <= innerWidth));
    await toast.getByRole('button', { name: '关闭操作提示' }).click();
    await fixture.getByRole('button', { name: '导出失败' }).click();
    await page.waitForFunction(() => document.querySelector('.action-feedback-toast')?.textContent.includes('测试权限拒绝'));
    assert.equal(await page.evaluate(() => window.downloadFailureBody.detail), '测试权限拒绝', 'original response body remains available');
    await toast.getByRole('button', { name: '关闭操作提示' }).click();
    await fixture.getByRole('button', { name: '导航操作' }).click();
    assert.equal(await page.evaluate(() => window.navigationChanged), true);
    assert.equal(await fixture.getByRole('button', { name: '导航操作' }).getAttribute('data-feedback-pressed'), 'true');
    await page.evaluate(() => window.backgroundFeedbackProbe());
    assert(await toast.evaluate(el => el.classList.contains('empty')), 'background failures must not trigger action toasts');
    await fixture.getByRole('button', { name: '同步异常' }).click();
    assert((await toast.innerText()).includes('同步失败测试'));
    await toast.getByRole('button', { name: '关闭操作提示' }).click();
    await fixture.getByRole('button', { name: '提交测试' }).click();
    assert.equal(calls, 1, 'HTML required validation remains in effect');
    await fixture.getByLabel('反馈测试必填字段').fill('ready');
    await fixture.getByLabel('反馈测试必填字段').press('Enter');
    await page.waitForFunction(() => document.querySelector('#feedback-fixture form')?.getAttribute('aria-busy') === 'true');
    assert(await fixture.getByRole('button', { name: '提交测试' }).isDisabled());
    await page.waitForTimeout(100); assert.equal(calls, 2); release();
    await page.waitForFunction(() => document.querySelector('#feedback-fixture form')?.getAttribute('aria-busy') !== 'true');
    console.log('Shared control coverage, pending/neutral completion/failure, double-click guard, keyboard form submission, validation, background isolation and mobile feedback passed.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
