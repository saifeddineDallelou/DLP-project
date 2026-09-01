const app = require('./app');
const { startBaselineRefresh } = require('./lib/baseline-refresh');

const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  console.log(`DLP API listening on port ${PORT}`);

  // Started here rather than in app.js so importing the app -- which every
  // test file does -- never starts a background timer.
  startBaselineRefresh();
});
