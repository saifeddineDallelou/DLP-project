const request = require('supertest');
const jwt = require('jsonwebtoken');
const app = require('../src/app');
const { prisma, resetDb, createUser } = require('./helpers');

afterEach(resetDb);
afterAll(() => prisma.$disconnect());

describe('POST /api/auth/login', () => {
  test('rejects missing email/password', async () => {
    const res = await request(app).post('/api/auth/login').send({});
    expect(res.status).toBe(400);
  });

  test('rejects unknown email', async () => {
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: 'nope@test.local', password: 'whatever' });
    expect(res.status).toBe(401);
  });

  test('rejects wrong password', async () => {
    const { user } = await createUser({ password: 'CorrectHorse1!' });
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: user.email, password: 'wrong' });
    expect(res.status).toBe(401);
  });

  test('logs in with correct credentials and writes an audit log', async () => {
    const { user, password } = await createUser({ role: 'ADMIN' });
    const res = await request(app)
      .post('/api/auth/login')
      .send({ email: user.email, password });

    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeDefined();
    expect(res.body.refreshToken).toBeDefined();
    expect(res.body.user).toEqual({ id: user.id, email: user.email, role: 'ADMIN' });

    const payload = jwt.verify(res.body.accessToken, process.env.JWT_SECRET);
    expect(payload.sub).toBe(user.id);
    expect(payload.role).toBe('ADMIN');

    const logs = await prisma.auditLog.findMany({ where: { userId: user.id, action: 'LOGIN' } });
    expect(logs).toHaveLength(1);
  });
});

describe('POST /api/auth/refresh', () => {
  test('rejects missing refreshToken', async () => {
    const res = await request(app).post('/api/auth/refresh').send({});
    expect(res.status).toBe(400);
  });

  test('rejects an invalid refresh token', async () => {
    const res = await request(app).post('/api/auth/refresh').send({ refreshToken: 'garbage' });
    expect(res.status).toBe(401);
  });

  test('rejects a refresh token for a deleted user', async () => {
    const { user } = await createUser();
    const refreshToken = jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    await prisma.user.delete({ where: { id: user.id } });

    const res = await request(app).post('/api/auth/refresh').send({ refreshToken });
    expect(res.status).toBe(401);
  });

  test('issues new tokens for a valid refresh token', async () => {
    const { user, password } = await createUser();
    const login = await request(app).post('/api/auth/login').send({ email: user.email, password });

    const res = await request(app)
      .post('/api/auth/refresh')
      .send({ refreshToken: login.body.refreshToken });

    expect(res.status).toBe(200);
    expect(res.body.accessToken).toBeDefined();
    expect(res.body.refreshToken).toBeDefined();
  });
});
