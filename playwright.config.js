const { defineConfig } = require('@playwright/test');
module.exports = defineConfig({
  testDir: './dashboard',
  testMatch: 'visualizer.e2e.js',
  timeout: 30000,
  use: { baseURL: 'http://127.0.0.1:8100', headless: true },
  webServer: {
    command: 'cargo run --quiet -- serve --bind 127.0.0.1:8100',
    url: 'http://127.0.0.1:8100',
    reuseExistingServer: false,
    timeout: 120000
  }
});
