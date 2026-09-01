require('dotenv/config');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');

const authRoutes      = require('./routes/auth');
const policiesRoutes  = require('./routes/policies');
const agentsRoutes    = require('./routes/agents');
const incidentsRoutes = require('./routes/incidents');
const classifyRoutes  = require('./routes/classify');
const uebaRoutes      = require('./routes/ueba');
const aiPolicyRoutes  = require('./routes/ai-policy');
const appRulesRoutes  = require('./routes/app-rules');
const reportsRoutes   = require('./routes/reports');
const auditRoutes     = require('./routes/audit');
const siemRoutes      = require('./routes/siem');

const app = express();

app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN || 'http://localhost:5173', credentials: true }));
if (process.env.NODE_ENV !== 'test') app.use(morgan('dev'));
app.use(express.json());

app.get('/api/health', (_req, res) => res.json({ status: 'ok', ts: Date.now() }));

app.use('/api/auth',      authRoutes);
app.use('/api/policies',  policiesRoutes);
app.use('/api/agents',    agentsRoutes);
app.use('/api/incidents', incidentsRoutes);
app.use('/api/classify',  classifyRoutes);
app.use('/api/ueba',      uebaRoutes);
app.use('/api/ai-policy', aiPolicyRoutes);
app.use('/api/app-rules', appRulesRoutes);
app.use('/api/reports',   reportsRoutes);
app.use('/api/audit',     auditRoutes);
app.use('/api/siem',      siemRoutes);

// 404
app.use((_req, res) => res.status(404).json({ error: 'Not found' }));

// Global error handler
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
});

module.exports = app;
