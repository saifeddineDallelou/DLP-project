const http = require('http');
const dgram = require('dgram');
const request = require('supertest');
const app = require('../src/app');
const {
  config, toEvent, toSyslog, forward, SYSLOG_FACILITY, SYSLOG_SEVERITY,
} = require('../src/lib/siem');
const {
  prisma, resetDb, createUser, authHeader, createAgent, createPolicy,
} = require('./helpers');

afterEach(resetDb);
afterAll(() => prisma.$disconnect());

const silent = { log() {}, error() {} };

function envFor(overrides) {
  return { SIEM_MODE: 'off', ...overrides };
}

describe('config', () => {
  test('is off unless explicitly enabled', () => {
    expect(config({}).enabled).toBe(false);
    expect(config({ SIEM_MODE: 'off' }).enabled).toBe(false);
  });

  test('recognises both sinks', () => {
    expect(config({ SIEM_MODE: 'webhook' }).enabled).toBe(true);
    expect(config({ SIEM_MODE: 'syslog' }).enabled).toBe(true);
  });

  test('is case-insensitive about the mode', () => {
    expect(config({ SIEM_MODE: 'WEBHOOK' }).mode).toBe('webhook');
  });
});

describe('toEvent', () => {
  test('normalises an incident', () => {
    const e = toEvent('INCIDENT', {
      id: 'i1',
      createdAt: new Date('2026-01-01T10:00:00Z'),
      severity: 'CRITICAL',
      agentId: 'a1',
      channel: 'CLIPBOARD',
      riskScore: 0.9,
      evidence: Buffer.from('card.txt'),
    }, { hostname: 'WS-01', policyName: 'PCI', complianceRule: 'PCI-DSS' });

    expect(e).toMatchObject({
      source: 'dlp-platform',
      kind: 'INCIDENT',
      id: 'i1',
      severity: 'CRITICAL',
      hostname: 'WS-01',
      complianceRule: 'PCI-DSS',
      channel: 'CLIPBOARD',
    });
    expect(e.timestamp).toBe('2026-01-01T10:00:00.000Z');
  });

  test('decodes a Bytes evidence column to text', () => {
    // Prisma returns Bytes as a Buffer; passed through untouched it would
    // serialise as {"type":"Buffer","data":[...]} and be useless in a SIEM.
    const e = toEvent('INCIDENT', { id: 'i1', evidence: Buffer.from('report.pdf') });
    expect(e.detail).toBe('report.pdf');
  });

  test('truncates an oversized detail rather than shipping it whole', () => {
    const e = toEvent('INCIDENT', { id: 'i1', evidence: 'x'.repeat(5000) });
    expect(e.detail.length).toBeLessThan(600);
  });

  test('gives all three sources one shape, so one correlation rule works', () => {
    const keys = (e) => Object.keys(e).sort();
    const incident = toEvent('INCIDENT', { id: 'i' });
    const attempt = toEvent('AI_LEAK_ATTEMPT', { id: 'a' });
    const behavior = toEvent('BEHAVIOR_EVENT', { id: 'b' });
    expect(keys(attempt)).toEqual(keys(incident));
    expect(keys(behavior)).toEqual(keys(incident));
  });

  test('reads the channel from whichever field the source uses', () => {
    expect(toEvent('INCIDENT', { id: 'i', channel: 'FILE' }).channel).toBe('FILE');
    expect(toEvent('AI_LEAK_ATTEMPT', { id: 'a', platform: 'OPENAI_CHATGPT' }).channel).toBe('OPENAI_CHATGPT');
    expect(toEvent('BEHAVIOR_EVENT', { id: 'b', eventType: 'USB_INSERT' }).channel).toBe('USB_INSERT');
  });
});

describe('toSyslog', () => {
  const cfg = config({ SIEM_MODE: 'syslog', SIEM_HOSTNAME: 'dlp-1' });

  test('encodes RFC 5424 priority from our severity', () => {
    const line = toSyslog(toEvent('INCIDENT', { id: 'i', severity: 'CRITICAL' }), cfg);
    const pri = SYSLOG_FACILITY * 8 + SYSLOG_SEVERITY.CRITICAL;
    expect(line.startsWith(`<${pri}>1 `)).toBe(true);
  });

  test('maps each severity to a distinct level', () => {
    const pris = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => {
      const line = toSyslog(toEvent('INCIDENT', { id: 'i', severity: sev }), cfg);
      return line.slice(1, line.indexOf('>'));
    });
    expect(new Set(pris).size).toBe(4);
  });

  test('falls back to notice for an event with no severity', () => {
    const line = toSyslog(toEvent('BEHAVIOR_EVENT', { id: 'b' }), cfg);
    expect(line.startsWith(`<${SYSLOG_FACILITY * 8 + 5}>1 `)).toBe(true);
  });

  test('carries the event as parseable JSON in the message', () => {
    const line = toSyslog(toEvent('INCIDENT', { id: 'i1', severity: 'LOW' }), cfg);
    const json = line.slice(line.indexOf('{'));
    expect(JSON.parse(json).id).toBe('i1');
  });
});

describe('forward — webhook', () => {
  let server;
  let received;
  let respondWith;

  beforeEach((done) => {
    received = [];
    respondWith = 200;
    server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        received.push({ headers: req.headers, body: JSON.parse(body || '{}') });
        res.writeHead(respondWith);
        res.end();
      });
    });
    server.listen(0, '127.0.0.1', done);
  });

  afterEach((done) => { server.close(done); });

  const url = () => `http://127.0.0.1:${server.address().port}/ingest`;

  test('posts the events and reports success', async () => {
    const ok = await forward([toEvent('INCIDENT', { id: 'i1', severity: 'HIGH' })], {
      env: envFor({ SIEM_MODE: 'webhook', SIEM_WEBHOOK_URL: url() }),
      logger: silent,
    });
    expect(ok).toBe(true);
    expect(received).toHaveLength(1);
    expect(received[0].body.events[0].id).toBe('i1');
  });

  test('sends the configured authorization header', async () => {
    await forward([toEvent('INCIDENT', { id: 'i1' })], {
      env: envFor({ SIEM_MODE: 'webhook', SIEM_WEBHOOK_URL: url(), SIEM_WEBHOOK_AUTH: 'Bearer abc' }),
      logger: silent,
    });
    expect(received[0].headers.authorization).toBe('Bearer abc');
  });

  test('reports failure on a non-2xx response without throwing', async () => {
    respondWith = 503;
    const ok = await forward([toEvent('INCIDENT', { id: 'i1' })], {
      env: envFor({ SIEM_MODE: 'webhook', SIEM_WEBHOOK_URL: url() }),
      logger: silent,
    });
    expect(ok).toBe(false);
  });

  test('reports failure on an unreachable host without throwing', async () => {
    const ok = await forward([toEvent('INCIDENT', { id: 'i1' })], {
      // Port 1 is reserved and refuses immediately.
      env: envFor({ SIEM_MODE: 'webhook', SIEM_WEBHOOK_URL: 'http://127.0.0.1:1/x' }),
      logger: silent,
    });
    expect(ok).toBe(false);
  });

  test('refuses to send when the URL is missing', async () => {
    const ok = await forward([toEvent('INCIDENT', { id: 'i1' })], {
      env: envFor({ SIEM_MODE: 'webhook' }),
      logger: silent,
    });
    expect(ok).toBe(false);
  });
});

describe('forward — syslog over UDP', () => {
  let sock;
  let messages;

  beforeEach((done) => {
    messages = [];
    sock = dgram.createSocket('udp4');
    sock.on('message', (m) => messages.push(m.toString('utf8')));
    sock.bind(0, '127.0.0.1', done);
  });

  afterEach((done) => { sock.close(done); });

  test('delivers a well-formed line', async () => {
    const ok = await forward([toEvent('INCIDENT', { id: 'i1', severity: 'HIGH' })], {
      env: envFor({
        SIEM_MODE: 'syslog',
        SIEM_SYSLOG_HOST: '127.0.0.1',
        SIEM_SYSLOG_PORT: String(sock.address().port),
        SIEM_SYSLOG_PROTOCOL: 'udp',
      }),
      logger: silent,
    });
    expect(ok).toBe(true);

    await new Promise((r) => setTimeout(r, 120));
    expect(messages).toHaveLength(1);
    expect(messages[0]).toMatch(/^<\d+>1 /);
    expect(JSON.parse(messages[0].slice(messages[0].indexOf('{'))).id).toBe('i1');
  });

  test('refuses to send when the host is missing', async () => {
    const ok = await forward([toEvent('INCIDENT', { id: 'i1' })], {
      env: envFor({ SIEM_MODE: 'syslog' }),
      logger: silent,
    });
    expect(ok).toBe(false);
  });
});

describe('forward — disabled and edge cases', () => {
  test('does nothing when forwarding is off', async () => {
    const ok = await forward([toEvent('INCIDENT', { id: 'i1' })], { env: envFor({}), logger: silent });
    expect(ok).toBe(false);
  });

  test('does nothing with an empty batch', async () => {
    const ok = await forward([], {
      env: envFor({ SIEM_MODE: 'webhook', SIEM_WEBHOOK_URL: 'http://127.0.0.1:1/x' }),
      logger: silent,
    });
    expect(ok).toBe(false);
  });

  test('accepts a single event as well as an array', async () => {
    const ok = await forward(toEvent('INCIDENT', { id: 'i1' }), { env: envFor({}), logger: silent });
    expect(ok).toBe(false); // off, but must not throw on a non-array
  });
});

describe('forwarding never breaks the request that produced the event', () => {
  // The property that matters most: a dead SIEM must not turn a monitoring
  // outage into a detection outage. Every emitter forwards fire-and-forget.
  const deadSiem = { SIEM_MODE: 'webhook', SIEM_WEBHOOK_URL: 'http://127.0.0.1:1/dead' };

  let saved;
  beforeEach(() => {
    saved = { ...process.env };
    Object.assign(process.env, deadSiem);
  });
  afterEach(() => {
    process.env.SIEM_MODE = saved.SIEM_MODE ?? 'off';
    delete process.env.SIEM_WEBHOOK_URL;
    if (saved.SIEM_WEBHOOK_URL) process.env.SIEM_WEBHOOK_URL = saved.SIEM_WEBHOOK_URL;
  });

  test('an incident is still recorded when the SIEM is unreachable', async () => {
    const agent = await createAgent();
    const policy = await createPolicy();
    const res = await request(app)
      .post('/api/incidents')
      .set('x-agent-token', agent.token)
      .send({ agentId: agent.id, policyId: policy.id, channel: 'CLIPBOARD', severity: 'HIGH' });

    expect(res.status).toBe(201);
    expect(await prisma.incident.count()).toBe(1);
  });

  test('an AI leak attempt is still recorded when the SIEM is unreachable', async () => {
    const agent = await createAgent();
    const res = await request(app)
      .post('/api/ai-policy/attempt')
      .set('x-agent-token', agent.token)
      .send({ agentId: agent.id, platform: 'OPENAI_CHATGPT', method: 'CLIPBOARD', riskScore: 0.9 });

    expect(res.status).toBe(201);
    expect(await prisma.aiLeakAttempt.count()).toBe(1);
  });

  test('a behaviour event is still recorded when the SIEM is unreachable', async () => {
    const agent = await createAgent();
    const res = await request(app)
      .post('/api/ueba/events')
      .set('x-agent-token', agent.token)
      .send({ agentId: agent.id, userId: 'WS\\jdoe', eventType: 'USB_INSERT', metadata: {} });

    expect(res.status).toBe(201);
    expect(await prisma.behaviorEvent.count()).toBe(1);
  });
});

describe('GET /api/siem/status', () => {
  test('requires ADMIN or ANALYST', async () => {
    const { user } = await createUser({ role: 'VIEWER' });
    const res = await request(app).get('/api/siem/status').set('Authorization', authHeader(user));
    expect(res.status).toBe(403);
  });

  test('reports the mode without echoing secrets', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    process.env.SIEM_MODE = 'webhook';
    process.env.SIEM_WEBHOOK_URL = 'https://siem.example/ingest';
    process.env.SIEM_WEBHOOK_AUTH = 'Bearer supersecret';

    const res = await request(app).get('/api/siem/status').set('Authorization', authHeader(user));

    expect(res.status).toBe(200);
    expect(res.body.mode).toBe('webhook');
    expect(res.body.webhook).toEqual({ urlConfigured: true, authConfigured: true });
    // The credential must never come back out over the API.
    expect(JSON.stringify(res.body)).not.toContain('supersecret');
    expect(JSON.stringify(res.body)).not.toContain('siem.example');

    process.env.SIEM_MODE = 'off';
    delete process.env.SIEM_WEBHOOK_URL;
    delete process.env.SIEM_WEBHOOK_AUTH;
  });
});

describe('POST /api/siem/test', () => {
  test('requires ADMIN', async () => {
    const { user } = await createUser({ role: 'ANALYST' });
    const res = await request(app).post('/api/siem/test').set('Authorization', authHeader(user));
    expect(res.status).toBe(403);
  });

  test('explains that forwarding is off rather than silently succeeding', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    process.env.SIEM_MODE = 'off';
    const res = await request(app).post('/api/siem/test').set('Authorization', authHeader(user));
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/SIEM_MODE/);
  });

  test('reports a delivery failure instead of claiming success', async () => {
    const { user } = await createUser({ role: 'ADMIN' });
    process.env.SIEM_MODE = 'webhook';
    process.env.SIEM_WEBHOOK_URL = 'http://127.0.0.1:1/dead';

    const res = await request(app).post('/api/siem/test').set('Authorization', authHeader(user));

    expect(res.status).toBe(502);
    expect(res.body.delivered).toBe(false);

    process.env.SIEM_MODE = 'off';
    delete process.env.SIEM_WEBHOOK_URL;
  });
});
