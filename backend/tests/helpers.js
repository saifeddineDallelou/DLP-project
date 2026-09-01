const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { randomUUID } = require('crypto');
const prisma = require('../src/lib/prisma');

// Delete in FK-safe order (children before parents).
async function resetDb() {
  await prisma.auditLog.deleteMany();
  await prisma.incident.deleteMany();
  await prisma.behaviorEvent.deleteMany();
  await prisma.aiLeakAttempt.deleteMany();
  await prisma.userBehaviorBaseline.deleteMany();
  await prisma.appRule.deleteMany();
  await prisma.agent.deleteMany();
  await prisma.policy.deleteMany();
  await prisma.user.deleteMany();
}

async function createUser({ role = 'ANALYST', email, password = 'Passw0rd!' } = {}) {
  const passwordHash = await bcrypt.hash(password, 4); // low cost factor — tests only
  const user = await prisma.user.create({
    data: { email: email || `${randomUUID()}@test.local`, passwordHash, role },
  });
  return { user, password };
}

function signAccessToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '15m' },
  );
}

function authHeader(user) {
  return `Bearer ${signAccessToken(user)}`;
}

async function createAgent(overrides = {}) {
  return prisma.agent.create({
    data: {
      hostname: overrides.hostname || `host-${randomUUID()}`,
      os: overrides.os || 'Windows 11',
      version: overrides.version || '1.0.0',
      token: overrides.token || randomUUID(),
      ...overrides,
    },
  });
}

async function createPolicy(overrides = {}) {
  return prisma.policy.create({
    data: {
      name: overrides.name || 'Test Policy',
      description: overrides.description ?? null,
      conditions: overrides.conditions || { patterns: ['SSN'], threshold: 1 },
      action: overrides.action || 'ALERT',
      severity: overrides.severity || 'MEDIUM',
      // Was silently dropped: a test asking for a disabled policy got an
      // enabled one, so any assertion about disabled behaviour passed for
      // the wrong reason.
      enabled: overrides.enabled ?? true,
    },
  });
}

module.exports = {
  prisma,
  resetDb,
  createUser,
  signAccessToken,
  authHeader,
  createAgent,
  createPolicy,
};
