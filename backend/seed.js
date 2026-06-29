require('dotenv/config');
const bcrypt = require('bcrypt');
const prisma = require('./src/lib/prisma');

async function seed() {
  console.log('Seeding...');

  // ── Admin user ──────────────────────────────────────────────────────────────
  const passwordHash = await bcrypt.hash('Admin123!', 12);
  const admin = await prisma.user.upsert({
    where:  { email: 'admin@dlp.local' },
    update: {},
    create: { email: 'admin@dlp.local', passwordHash, role: 'ADMIN' },
  });
  console.log(`  admin user   : ${admin.email}  (${admin.id})`);

  // ── Sample policy ───────────────────────────────────────────────────────────
  const policy = await prisma.policy.upsert({
    where:  { id: 'seed-policy-pii-001' },
    update: {},
    create: {
      id:          'seed-policy-pii-001',
      name:        'PII Detection',
      description: 'Blocks transmission of personally identifiable information',
      conditions:  { patterns: ['SSN', 'CREDIT_CARD', 'EMAIL'], threshold: 1 },
      action:      'BLOCK',
      severity:    'HIGH',
    },
  });
  console.log(`  policy       : "${policy.name}"  (${policy.id})`);

  // ── Seed agent ──────────────────────────────────────────────────────────────
  const agent = await prisma.agent.upsert({
    where:  { hostname: 'seed-workstation-01' },
    update: {},
    create: {
      id:       'seed-agent-001',
      hostname: 'seed-workstation-01',
      os:       'Windows 11',
      version:  '1.0.0',
      token:    'seed-agent-token-do-not-use-in-prod',
    },
  });
  console.log(`  seed agent   : ${agent.hostname}  (${agent.id})`);

  // ── Behavior baseline for admin ─────────────────────────────────────────────
  const baseline = await prisma.userBehaviorBaseline.upsert({
    where:  { userId: admin.id },
    update: {},
    create: {
      userId:               admin.id,
      avgDailyFiles:        120,
      avgDailyVolumeMB:     45.5,
      avgWorkingHourStart:  8,
      avgWorkingHourEnd:    18,
      avgUsbFrequency:      0.2,
      riskScore:            0.1,
      lastUpdated:          new Date(),
    },
  });
  console.log(`  baseline     : riskScore=${baseline.riskScore}  user=${admin.email}`);

  // ── Behavior events ─────────────────────────────────────────────────────────
  const event1 = await prisma.behaviorEvent.upsert({
    where:  { id: 'seed-event-001' },
    update: {},
    create: {
      id:        'seed-event-001',
      agentId:   agent.id,
      userId:    'admin',
      eventType: 'AFTER_HOURS_ACCESS',
      metadata:  { hour: 23, filesAccessed: 15, note: 'Late-night bulk file access' },
      timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 h ago
    },
  });
  console.log(`  event 1      : ${event1.eventType}  (${event1.id})`);

  const event2 = await prisma.behaviorEvent.upsert({
    where:  { id: 'seed-event-002' },
    update: {},
    create: {
      id:        'seed-event-002',
      agentId:   agent.id,
      userId:    'admin',
      eventType: 'USB_INSERT',
      metadata:  { deviceId: 'USB\\VID_0781&PID_5567', volumeLabel: 'SanDisk', sizeMB: 32768 },
      timestamp: new Date(Date.now() - 30 * 60 * 1000), // 30 min ago
    },
  });
  console.log(`  event 2      : ${event2.eventType}  (${event2.id})`);

  // ── AI leak attempt ─────────────────────────────────────────────────────────
  const attempt = await prisma.aiLeakAttempt.upsert({
    where:  { id: 'seed-ai-attempt-001' },
    update: {},
    create: {
      id:            'seed-ai-attempt-001',
      agentId:       agent.id,
      platform:      'CHATGPT',
      method:        'CLIPBOARD',
      contentSample: 'SSN: 123-45-6789, Card: 4111111111111111',
      riskScore:     0.92,
      blocked:       true,
      timestamp:     new Date(Date.now() - 15 * 60 * 1000), // 15 min ago
    },
  });
  console.log(`  AI attempt   : ${attempt.platform}/${attempt.method}  blocked=${attempt.blocked}  (${attempt.id})`);

  console.log('\nSeed complete.');
}

seed()
  .catch((err) => { console.error(err); process.exit(1); })
  .finally(() => prisma.$disconnect());
