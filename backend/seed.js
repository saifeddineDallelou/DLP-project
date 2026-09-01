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

  // ── Restricted app rules (migrated from the agent's old hardcoded watchlist) ─
  const APP_RULES = [
    ['7zg', '7-Zip GUI'], ['7z', '7-Zip archiver'], ['winrar', 'WinRAR archiver'],
    ['winzip', 'WinZip archiver'], ['peazip', 'PeaZip archiver'], ['bandizip', 'Bandizip archiver'],
    ['teamviewer', 'TeamViewer remote access'], ['anydesk', 'AnyDesk remote access'],
    ['chromeremotedesktop', 'Chrome Remote Desktop'], ['radmin', 'Radmin remote access'],
    ['ammyy', 'Ammyy Admin'], ['logmein', 'LogMeIn remote access'], ['uvnc', 'UltraVNC'],
    ['tigervnc', 'TigerVNC'], ['realvnc', 'RealVNC'], ['vncviewer', 'VNC Viewer'],
    ['filezilla', 'FileZilla FTP'], ['winscp', 'WinSCP SFTP'], ['smartftp', 'SmartFTP'],
    ['coreftp', 'CoreFTP'], ['ftp', 'FTP client'], ['megasync', 'MEGA cloud sync'],
    ['ngrok', 'ngrok tunnel'], ['frpc', 'frp client tunnel'], ['putty', 'PuTTY SSH'],
    ['kitty', 'KiTTY SSH'], ['plink', 'Plink SSH'], ['usbdeview', 'USB enumerator'],
    ['diskpart', 'DiskPart disk utility'], ['obs64', 'OBS Studio recording'],
    ['obs32', 'OBS Studio recording (32-bit)'], ['obs', 'OBS Studio'],
    ['camtasia', 'Camtasia recording'], ['bandicam', 'Bandicam recording'],
    ['fraps', 'FRAPS capture'], ['wireshark', 'Wireshark packet capture'],
    ['rawcap', 'RawCap capture'], ['utorrent', 'uTorrent'], ['qbittorrent', 'qBittorrent'],
    ['bittorrent', 'BitTorrent'], ['transmission', 'Transmission torrent'],
  ];
  for (const [keyword, label] of APP_RULES) {
    await prisma.appRule.upsert({ where: { keyword }, update: {}, create: { keyword, label } });
  }
  console.log(`  app rules    : ${APP_RULES.length} restricted-app rules seeded`);

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
  // Keyed by the OS username 'admin', matching what the seeded BehaviorEvents
  // below report -- NOT by admin.id. UserBehaviorBaseline.userId identifies the
  // monitored person as the agent names them, which is a different identity
  // space from a dashboard User row (see the note on the model). Keying this by
  // the User UUID produced a baseline that matched no events and rendered as a
  // card labelled with a raw UUID.
  const baseline = await prisma.userBehaviorBaseline.upsert({
    where:  { userId: 'admin' },
    update: {},
    create: {
      userId:               'admin',
      department:           'Engineering',
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

  // ── Monitored people ────────────────────────────────────────────────────────
  // These are OS usernames as the agent reports them, NOT dashboard User rows --
  // BehaviorEvent.userId is a free string for exactly this reason (a SOC analyst
  // with a login and the employees they monitor are different populations).
  //
  // They are seeded as EVENTS rather than as ready-made baselines, for two
  // reasons: the UEBA page builds its cards from users who have events, so a
  // bare baseline never appears on screen; and letting the refresh job derive
  // the baselines is the honest demonstration -- the numbers on the page are
  // then computed from behaviour, not typed into a seed file.
  //
  // Peer-relative scoring needs at least two OTHER members of a department for
  // a median worth comparing against, hence three per group.
  const people = [
    { user: 'j.rivera', dept: 'Engineering', filesPerDay: 130, mbPerDay: 55,   hour: 10 },
    { user: 's.okafor', dept: 'Engineering', filesPerDay: 95,  mbPerDay: 38,   hour: 11 },
    { user: 'a.hassan', dept: 'Engineering', filesPerDay: 150, mbPerDay: 70,   hour: 9  },
    { user: 'l.chen',   dept: 'Finance',     filesPerDay: 22,  mbPerDay: 8,    hour: 9  },
    { user: 'd.moreau', dept: 'Finance',     filesPerDay: 18,  mbPerDay: 11,   hour: 10 },
    // Finance, but moving two orders of magnitude more than the rest of Finance.
    // This is the card a demo should open on: unremarkable in isolation, obvious
    // the moment it is placed next to its peer group.
    { user: 'k.novak',  dept: 'Finance',     filesPerDay: 240, mbPerDay: 3200, hour: 2  },
  ];

  let eventCount = 0;
  for (const p of people) {
    // Ten working days of history, so the median has something to sit in the
    // middle of and the 10th/90th-percentile hours are meaningful.
    for (let d = 0; d < 10; d++) {
      const jitter = 0.85 + ((d * 7) % 10) / 30;   // deterministic, not random
      await prisma.behaviorEvent.upsert({
        where:  { id: `seed-ev-${p.user}-${d}` },
        update: {},
        create: {
          id:        `seed-ev-${p.user}-${d}`,
          agentId:   agent.id,
          userId:    p.user,
          eventType: p.hour >= 19 || p.hour <= 6 ? 'AFTER_HOURS_ACCESS' : 'FILE_ACCESS',
          metadata:  {
            count:  Math.round(p.filesPerDay * jitter),
            sizeMB: Math.round(p.mbPerDay * jitter),
            hour:   p.hour,
          },
          timestamp: new Date(Date.now() - d * 24 * 60 * 60 * 1000),
        },
      });
      eventCount++;
    }

    // Department is admin-declared -- the agent reports a username and has no
    // idea what team anyone is on -- so it is seeded here. The numbers are not:
    // the refresh job derives those from the events above.
    await prisma.userBehaviorBaseline.upsert({
      where:  { userId: p.user },
      update: { department: p.dept },
      create: {
        userId:              p.user,
        department:          p.dept,
        avgDailyFiles:       0,
        avgDailyVolumeMB:    0,
        avgWorkingHourStart: 9,
        avgWorkingHourEnd:   18,
        avgUsbFrequency:     0,
        riskScore:           0,
        // Backdated so the refresh job treats it as stale and computes the real
        // numbers on the next pass, which is at API boot.
        lastUpdated:         new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
      },
    });
  }
  console.log(`  people       : ${people.length} monitored users, ${eventCount} events, Engineering / Finance`);

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
      platform:      'OPENAI_CHATGPT',
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
