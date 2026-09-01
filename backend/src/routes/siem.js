const express = require('express');
const { authenticate, requireRole } = require('../middleware/auth');
const { config, toEvent, forward } = require('../lib/siem');

const router = express.Router();

// GET /api/siem/status
// Whether forwarding is on, and where to. Secrets are never echoed: the
// webhook URL and auth header are reported as present/absent, not returned.
// An admin needs to know the integration is configured; nobody needs the
// bearer token read back to them over an API.
router.get('/status', authenticate, requireRole('ADMIN', 'ANALYST'), (_req, res) => {
  const cfg = config();
  res.json({
    mode: cfg.mode,
    enabled: cfg.enabled,
    webhook: cfg.mode === 'webhook'
      ? { urlConfigured: Boolean(cfg.webhookUrl), authConfigured: Boolean(cfg.webhookAuth) }
      : null,
    syslog: cfg.mode === 'syslog'
      ? { host: cfg.syslogHost, port: cfg.syslogPort, protocol: cfg.syslogProtocol }
      : null,
    timeoutMs: cfg.timeoutMs,
  });
});

// POST /api/siem/test
// Send one synthetic event through the real path. Forwarding is
// fire-and-forget everywhere else -- deliberately, so a dead SIEM cannot
// block an agent reporting an incident -- which means a misconfiguration is
// otherwise silent until someone goes looking for events that never arrived.
// This is the one place delivery is awaited and the result reported.
router.post('/test', authenticate, requireRole('ADMIN'), async (req, res, next) => {
  try {
    const cfg = config();
    if (!cfg.enabled) {
      return res.status(400).json({
        error: 'SIEM forwarding is off. Set SIEM_MODE to "webhook" or "syslog".',
        mode: cfg.mode,
      });
    }

    const sample = toEvent('INCIDENT', {
      id: '00000000-0000-0000-0000-000000000000',
      createdAt: new Date(),
      severity: 'LOW',
      agentId: null,
      channel: 'CLIPBOARD',
      riskScore: 0,
      evidence: 'connectivity test from the DLP platform — not a real incident',
    }, {
      hostname: cfg.hostname,
      policyName: 'SIEM connectivity test',
      raw: { test: true, requestedBy: req.user?.email ?? null },
    });

    const delivered = await forward([sample]);

    res.status(delivered ? 200 : 502).json({
      delivered,
      mode: cfg.mode,
      message: delivered
        ? 'Test event accepted by the configured SIEM.'
        : 'Delivery failed. Check the server log for the reason, and verify the host, port and credentials.',
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
