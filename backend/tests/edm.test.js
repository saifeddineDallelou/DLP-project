const request = require('supertest');
const app = require('../src/app');
const { prisma, resetDb, createUser, authHeader } = require('./helpers');

// The classifier owns EDM; this router only adds authentication and an audit
// trail in front of it. So `fetch` is stubbed rather than a real classifier
// being run: what is under test is the proxy's own behaviour -- who may call
// it, what reaches the upstream, what is recorded, and what happens when the
// classifier is down.
let fetchCalls;
const realFetch = global.fetch;

function stubFetch(handler) {
  fetchCalls = [];
  global.fetch = async (url, init = {}) => {
    fetchCalls.push({ url: String(url), init });
    return handler(String(url), init);
  };
}

const ok = (body, status = 200) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => body,
  text: async () => JSON.stringify(body),
});

afterEach(async () => {
  global.fetch = realFetch;
  await resetDb();
});
afterAll(() => prisma.$disconnect());

const SET = {
  name: 'customers', rule: 'GDPR',
  columns: { name: 3, city: 2, ref: 3 },
  totalValues: 8, minFields: 2, rowCount: 3,
};

const ROWS = [{ name: 'Sarah Okafor', city: 'Manchester', ref: 'CR-4472819' }];

describe('GET /api/edm', () => {
  test('requires authentication', async () => {
    stubFetch(() => ok([SET]));
    const res = await request(app).get('/api/edm');
    expect(res.status).toBe(401);
    expect(fetchCalls).toHaveLength(0);
  });

  test('a viewer may list sets', async () => {
    stubFetch(() => ok([SET]));
    const { user } = await createUser({ role: 'VIEWER' });
    const res = await request(app).get('/api/edm').set('Authorization', authHeader(user));
    expect(res.status).toBe(200);
    expect(res.body[0].name).toBe('customers');
    expect(res.body[0].minFields).toBe(2);
  });

  test('reports 503 rather than 500 when the classifier is down', async () => {
    stubFetch(() => { throw new Error('ECONNREFUSED'); });
    const { user } = await createUser();
    const res = await request(app).get('/api/edm').set('Authorization', authHeader(user));
    expect(res.status).toBe(503);
  });
});

describe('POST /api/edm', () => {
  test('a VIEWER may not index records', async () => {
    stubFetch(() => ok(SET, 201));
    const { user } = await createUser({ role: 'VIEWER' });
    const res = await request(app).post('/api/edm')
      .set('Authorization', authHeader(user))
      .send({ name: 'customers', rows: ROWS });
    expect(res.status).toBe(403);
    // The rows must never reach the classifier on a rejected request.
    expect(fetchCalls).toHaveLength(0);
  });

  test('rejects an empty rows array before calling the classifier', async () => {
    stubFetch(() => ok(SET, 201));
    const { user } = await createUser({ role: 'ANALYST' });
    const res = await request(app).post('/api/edm')
      .set('Authorization', authHeader(user))
      .send({ name: 'customers', rows: [] });
    expect(res.status).toBe(400);
    expect(fetchCalls).toHaveLength(0);
  });

  test('forwards name, rule and min_fields to the classifier', async () => {
    stubFetch(() => ok(SET, 201));
    const { user } = await createUser({ role: 'ANALYST' });
    await request(app).post('/api/edm')
      .set('Authorization', authHeader(user))
      .send({ name: '  customers  ', rows: ROWS, rule: 'GDPR', min_fields: 2 });

    const sent = JSON.parse(fetchCalls[0].init.body);
    expect(sent.name).toBe('customers');       // trimmed
    expect(sent.rule).toBe('GDPR');
    expect(sent.min_fields).toBe(2);
    expect(sent.rows).toEqual(ROWS);
  });

  test('min_fields defaults to 1 -- per-value matching, the old behaviour', async () => {
    stubFetch(() => ok(SET, 201));
    const { user } = await createUser({ role: 'ANALYST' });
    await request(app).post('/api/edm')
      .set('Authorization', authHeader(user))
      .send({ name: 'customers', rows: ROWS });
    expect(JSON.parse(fetchCalls[0].init.body).min_fields).toBe(1);
  });

  test('audits the upload without recording any row content', async () => {
    stubFetch(() => ok(SET, 201));
    const { user } = await createUser({ role: 'ADMIN' });
    await request(app).post('/api/edm')
      .set('Authorization', authHeader(user))
      .send({ name: 'customers', rows: ROWS, rule: 'GDPR', min_fields: 2 });

    const [log] = await prisma.auditLog.findMany({ where: { action: 'CREATE_EDM_SET' } });
    expect(log.resourceId).toBe('customers');
    expect(log.metadata).toEqual({ rowsSubmitted: 1, columns: 3, minFields: 2, rule: 'GDPR' });
    // The whole point of hashing is not creating a second copy of the data.
    // An audit trail that recorded it would put one straight back.
    const blob = JSON.stringify(log);
    for (const secret of ['Sarah', 'Okafor', 'Manchester', 'CR-4472819']) {
      expect(blob).not.toContain(secret);
    }
  });

  test('surfaces the rejection message the classifier gave', async () => {
    stubFetch(() => ok({ detail: 'min_fields is 5 but the rows have only 2 indexable column(s)' }, 422));
    const { user } = await createUser({ role: 'ANALYST' });
    const res = await request(app).post('/api/edm')
      .set('Authorization', authHeader(user))
      .send({ name: 'bad', rows: ROWS, min_fields: 5 });
    expect(res.status).toBe(422);
    expect(res.body.error).toMatch(/min_fields is 5/);
  });

  test('does not write an audit row when the upload failed', async () => {
    stubFetch(() => ok({ detail: 'No indexable values.' }, 422));
    const { user } = await createUser({ role: 'ANALYST' });
    await request(app).post('/api/edm')
      .set('Authorization', authHeader(user))
      .send({ name: 'bad', rows: ROWS });
    expect(await prisma.auditLog.count({ where: { action: 'CREATE_EDM_SET' } })).toBe(0);
  });
});

describe('DELETE /api/edm/:name', () => {
  test('an ANALYST may not delete a set', async () => {
    stubFetch(() => ok(null, 204));
    const { user } = await createUser({ role: 'ANALYST' });
    const res = await request(app).delete('/api/edm/customers')
      .set('Authorization', authHeader(user));
    expect(res.status).toBe(403);
    expect(fetchCalls).toHaveLength(0);
  });

  test('an ADMIN may, and it is audited', async () => {
    stubFetch(() => ok(null, 204));
    const { user } = await createUser({ role: 'ADMIN' });
    const res = await request(app).delete('/api/edm/customers')
      .set('Authorization', authHeader(user));
    expect(res.status).toBe(204);

    const [log] = await prisma.auditLog.findMany({ where: { action: 'DELETE_EDM_SET' } });
    expect(log.resourceId).toBe('customers');
  });

  test('a name with a slash cannot escape the upstream path', async () => {
    stubFetch(() => ok(null, 204));
    const { user } = await createUser({ role: 'ADMIN' });
    await request(app).delete('/api/edm/' + encodeURIComponent('../agents'))
      .set('Authorization', authHeader(user));
    expect(fetchCalls[0].url).toContain('%2F');
    expect(fetchCalls[0].url).not.toContain('/edm/../');
  });

  test('passes through a 404 for a set that does not exist', async () => {
    stubFetch(() => ok({ detail: 'not found' }, 404));
    const { user } = await createUser({ role: 'ADMIN' });
    const res = await request(app).delete('/api/edm/nope')
      .set('Authorization', authHeader(user));
    expect(res.status).toBe(404);
    expect(await prisma.auditLog.count({ where: { action: 'DELETE_EDM_SET' } })).toBe(0);
  });
});
