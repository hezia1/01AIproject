const { chromium } = require('playwright-core');
const assert = require('node:assert/strict');

(async () => {
  const browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || 'chrome', headless: true });
  try {
    const page = await browser.newPage();
    await page.goto(process.env.ADMIN_UI_BASE_URL || 'http://localhost:5173', { waitUntil: 'networkidle' });
    await page.evaluate(async () => {
      const React = await import('/node_modules/.vite/deps/react.js');
      const ReactDOM = await import('/node_modules/.vite/deps/react-dom_client.js');
      const { createRoot } = ReactDOM.default ?? ReactDOM;
      const { PagedTable, PagedItems } = await import('/src/pagination.tsx');
      const host = document.createElement('section'); host.id = 'pagination-fixture'; document.body.appendChild(host);
      const root = createRoot(host), h = (React.default ?? React).createElement;
      window.paginationRender = count => root.render(h('div', {},
        h('section', { id: 'table-fixture' }, h(PagedTable, {}, h('thead', {}, h('tr', {}, h('th', {}, '编号'))), h('tbody', {}, Array.from({ length: count }, (_, i) => h('tr', { key: i }, h('td', {}, h('button', { onClick: () => { window.paginationClicked = i; } }, `row-${i}`))))))),
        h('section', { id: 'cards-fixture' }, h(PagedItems, {}, Array.from({ length: count }, (_, i) => h('article', { key: i }, `card-${i}`))))));
      window.paginationRender(23);
    });
    const table = page.locator('#table-fixture');
    await table.getByRole('button', { name: 'row-0', exact: true }).waitFor();
    assert.equal(await table.locator('tbody tr').count(), 10);
    await table.getByRole('button', { name: '下一页' }).click();
    assert.equal(await table.locator('tbody tr').count(), 10);
    await table.getByRole('button', { name: '下一页' }).click();
    assert.equal(await table.locator('tbody tr').count(), 3);
    await table.getByRole('button', { name: 'row-22', exact: true }).click();
    assert.equal(await page.evaluate(() => window.paginationClicked), 22);
    const cards = page.locator('#cards-fixture');
    assert.equal(await cards.locator('article').count(), 10);
    assert.equal(await cards.locator('article').first().innerText(), 'card-0', 'lists page independently');
    await cards.getByRole('button', { name: '下一页' }).click();
    assert.equal(await cards.locator('article').first().innerText(), 'card-10');
    await page.evaluate(() => window.paginationRender(1));
    await table.getByRole('button', { name: 'row-0', exact: true }).waitFor();
    assert.equal(await table.locator('tbody tr').count(), 1, 'shrinking/filtering clamps the page');
    assert.equal(await cards.locator('article').count(), 1);
    console.log('Pagination 10/10/3, independent lists, last-page row actions and filtered-page clamping passed.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
