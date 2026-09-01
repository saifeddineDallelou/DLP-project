const net = require('net');

/**
 * SIEM forwarding.
 *
 * Without this the platform is a silo: incidents, AI leak attempts and
 * behaviour events live only in its own Postgres and its own dashboard, so a
 * SOC already running Splunk, Sentinel or Elastic has to go and look at a
 * second console to see DLP at all. Everything a SIEM needs is already
 * recorded -- this is a formatter and a sink, not new data.
 *
 * Two sinks, because real deployments differ:
 *   webhook  HTTP POST of a JSON envelope. What Splunk HEC, Sentinel's
 *            Logs Ingestion API and most SaaS SIEMs accept.
 *   syslog   RFC 5424 over UDP or TCP. What an on-prem collector expects,
 *            and the only option in environments where the endpoint fleet
 *            cannot reach an HTTPS endpoint directly.
 *
 * DELIVERY IS BEST-EFFORT AND NEVER BLOCKS. A forward failure must not fail
 * the request that produced the event: an unreachable SIEM would otherwise
 * stop agents recording incidents at all, turning a monitoring outage into a
 * detection outage. Failures are logged and dropped.
 */

const DEFAULT_TIMEOUT_MS = 5000;

// RFC 5424 severity, derived from our own Severity enum. A SIEM's own
// dashboards and alert rules key off this, so the mapping has to be
// deliberate rather than everything arriving as "notice".
const SYSLOG_SEVERITY = {
  CRITICAL: 2,   // crit
  HIGH: 3,       // err
  MEDIUM: 4,     // warning
  LOW: 5,        // notice
};
const SYSLOG_FACILITY = 13;   // log audit
const DEFAULT_SEVERITY = 5;

function config(env = process.env) {
  const mode = (env.SIEM_MODE || 'off').toLowerCase();
  return {
    mode,
    enabled: mode === 'webhook' || mode === 'syslog',
    webhookUrl: env.SIEM_WEBHOOK_URL || '',
    webhookAuth: env.SIEM_WEBHOOK_AUTH || '',
    syslogHost: env.SIEM_SYSLOG_HOST || '',
    syslogPort: Number(env.SIEM_SYSLOG_PORT) || 514,
    syslogProtocol: (env.SIEM_SYSLOG_PROTOCOL || 'udp').toLowerCase(),
    timeoutMs: Number(env.SIEM_TIMEOUT_MS) || DEFAULT_TIMEOUT_MS,
    hostname: env.SIEM_HOSTNAME || 'dlp-platform',
  };
}

/**
 * Normalise a database row into one event shape.
 *
 * A single shape across all three sources is the point: a SOC analyst writes
 * one correlation rule, not three. `raw` carries the source-specific fields
 * so nothing is lost by normalising.
 */
const MAX_DETAIL = 512;

function asText(value) {
  if (value == null) return null;
  const s = Buffer.isBuffer(value) ? value.toString('utf8') : String(value);
  return s.length > MAX_DETAIL ? `${s.slice(0, MAX_DETAIL)}…` : s;
}

function toEvent(kind, row, extra = {}) {
  const base = {
    source: 'dlp-platform',
    kind,                                   // INCIDENT | AI_LEAK_ATTEMPT | BEHAVIOR_EVENT
    id: row.id,
    timestamp: (row.createdAt || row.timestamp || new Date()).toISOString(),
    severity: row.severity || extra.severity || null,
    agentId: row.agentId ?? null,
    hostname: extra.hostname ?? null,
    userId: row.userId ?? extra.userId ?? null,
    policyId: row.policyId ?? null,
    policyName: extra.policyName ?? null,
    complianceRule: extra.complianceRule ?? null,
    riskScore: row.riskScore ?? null,
    action: extra.action ?? null,
    blocked: typeof row.blocked === 'boolean' ? row.blocked : extra.blocked ?? null,
    channel: row.channel ?? row.platform ?? row.eventType ?? null,
    // Already masked by the time it reaches here -- the classifier masks
    // detections and agent/src/evidence.py builds reports from those, never
    // from raw content. Forwarding must not become the place a secret leaks.
    // Incident.evidence is a Bytes column, so it arrives as a Buffer and
    // would serialise as {"type":"Buffer","data":[...]} if passed through.
    detail: asText(row.evidence ?? row.contentSample),
    raw: extra.raw ?? null,
  };
  return base;
}

/** RFC 5424 line. Structured data is skipped in favour of a JSON MSG, which
 *  every modern SIEM parses and which survives field additions. */
function toSyslog(event, cfg) {
  const sev = SYSLOG_SEVERITY[event.severity] ?? DEFAULT_SEVERITY;
  const pri = SYSLOG_FACILITY * 8 + sev;
  const ts = event.timestamp;
  const app = 'dlp';
  const msgId = event.kind;
  return `<${pri}>1 ${ts} ${cfg.hostname} ${app} - ${msgId} - ${JSON.stringify(event)}`;
}

async function sendWebhook(events, cfg, logger) {
  if (!cfg.webhookUrl) {
    logger.error('[siem] SIEM_MODE=webhook but SIEM_WEBHOOK_URL is unset -- dropping');
    return false;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), cfg.timeoutMs);
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (cfg.webhookAuth) headers.Authorization = cfg.webhookAuth;

    const res = await fetch(cfg.webhookUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({ events }),
      signal: controller.signal,
    });
    if (!res.ok) {
      logger.error(`[siem] webhook responded ${res.status}`);
      return false;
    }
    return true;
  } catch (err) {
    logger.error(`[siem] webhook failed: ${err.message}`);
    return false;
  } finally {
    clearTimeout(timer);
  }
}

async function sendSyslog(events, cfg, logger) {
  if (!cfg.syslogHost) {
    logger.error('[siem] SIEM_MODE=syslog but SIEM_SYSLOG_HOST is unset -- dropping');
    return false;
  }
  const lines = events.map((e) => toSyslog(e, cfg));

  if (cfg.syslogProtocol === 'tcp') {
    return new Promise((resolve) => {
      const socket = net.createConnection({ host: cfg.syslogHost, port: cfg.syslogPort });
      let settled = false;
      const done = (ok, why) => {
        if (settled) return;
        settled = true;
        if (!ok) logger.error(`[siem] syslog/tcp failed: ${why}`);
        socket.destroy();
        resolve(ok);
      };
      socket.setTimeout(cfg.timeoutMs);
      socket.on('timeout', () => done(false, 'timeout'));
      socket.on('error', (err) => done(false, err.message));
      socket.on('connect', () => {
        // Octet-counted framing (RFC 6587) -- length-prefixed, so a
        // collector never mis-splits a message containing a newline.
        socket.write(lines.map((l) => `${Buffer.byteLength(l)} ${l}`).join(''), () => done(true));
      });
    });
  }

  // UDP. Fire-and-forget by design: syslog over UDP has no delivery
  // guarantee, and waiting for one would be pretending otherwise.
  const dgram = require('dgram');
  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    let pending = lines.length;
    let ok = true;
    const finish = () => {
      socket.close();
      resolve(ok);
    };
    for (const line of lines) {
      const buf = Buffer.from(line, 'utf8');
      socket.send(buf, 0, buf.length, cfg.syslogPort, cfg.syslogHost, (err) => {
        if (err) {
          ok = false;
          logger.error(`[siem] syslog/udp failed: ${err.message}`);
        }
        if (--pending === 0) finish();
      });
    }
    if (lines.length === 0) finish();
  });
}

/**
 * Forward one or more events. Resolves to true when delivered, false on any
 * failure -- callers ignore the result. Never throws.
 */
async function forward(events, { env = process.env, logger = console } = {}) {
  const list = (Array.isArray(events) ? events : [events]).filter(Boolean);
  if (list.length === 0) return false;

  const cfg = config(env);
  if (!cfg.enabled) return false;

  try {
    return cfg.mode === 'webhook'
      ? await sendWebhook(list, cfg, logger)
      : await sendSyslog(list, cfg, logger);
  } catch (err) {
    logger.error(`[siem] forward failed: ${err.message}`);
    return false;
  }
}

/**
 * Fire-and-forget wrapper for use inside a request handler.
 *
 * Deliberately not awaited by callers: a slow or unreachable SIEM must never
 * delay an agent reporting an incident, and must never fail that request. An
 * unhandled rejection here would crash the process, so it is swallowed.
 */
function forwardAsync(events, opts = {}) {
  forward(events, opts).catch(() => {});
}

module.exports = {
  config,
  toEvent,
  toSyslog,
  forward,
  forwardAsync,
  SYSLOG_SEVERITY,
  SYSLOG_FACILITY,
};
