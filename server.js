/**
 * Midnight Circus — backend exemplo com storage remoto + validação da senha da equipe.
 *
 * Como usar:
 *   npm init -y
 *   npm install express cors
 *
 *   # recomendado em produção:
 *   TEAM_PASSWORD='CIRCUS170326' SITE_ORIGIN='https://seu-site.com' node midnight-circus-server-auth-example.js
 *
 *   # para teste local, o backend usa CIRCUS170326 se TEAM_PASSWORD não estiver definido.
 *   node midnight-circus-server-auth-example.js
 *
 * Depois, no HTML, troque:
 *   SERVER_STORAGE_CONFIG.baseUrl = 'https://SEU-SERVIDOR.com/api'
 * por:
 *   SERVER_STORAGE_CONFIG.baseUrl = 'https://seu-dominio-ou-api.com/api'
 *
 * Observações importantes:
 * - A senha da equipe é validada aqui no servidor, não no HTML.
 * - Não publique a senha em repositório público. Em produção, use variável de ambiente TEAM_PASSWORD.
 * - Este exemplo salva JSON em disco. Para uso real, prefira banco de dados e autenticação robusta.
 */

const express = require('express');
const cors = require('cors');
const fs = require('fs/promises');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 10000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const TEAM_PASSWORD = process.env.TEAM_PASSWORD || 'CIRCUS170326';
const DEFAULT_SITE_ID = process.env.SITE_ID || 'midnight-circus';

app.use(express.json({ limit: '25mb' }));
app.use(cors({
  origin: process.env.SITE_ORIGIN || true,
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization']
}));

function safeName(value) {
  const cleaned = String(value || '').replace(/[^a-zA-Z0-9_-]/g, '');
  if (!cleaned) throw new Error('Nome inválido');
  return cleaned;
}

function normalizeUsername(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9._-]/g, '')
    .slice(0, 24);
}

async function collectionPath(siteId, collection) {
  const safeSite = safeName(siteId || DEFAULT_SITE_ID);
  const safeCollection = safeName(collection);
  const dir = path.join(DATA_DIR, safeSite);
  await fs.mkdir(dir, { recursive: true });
  return path.join(dir, `${safeCollection}.json`);
}

async function readCollection(siteId, collection, defaultData) {
  const file = await collectionPath(siteId, collection);
  const raw = await fs.readFile(file, 'utf8').catch(() => null);
  if (!raw) return { data: defaultData, updatedAt: null };
  const parsed = JSON.parse(raw);
  if (parsed && Object.prototype.hasOwnProperty.call(parsed, 'data')) return parsed;
  return { data: parsed, updatedAt: null };
}

async function writeCollection(siteId, collection, data) {
  const file = await collectionPath(siteId, collection);
  const payload = { data, updatedAt: new Date().toISOString() };
  await fs.writeFile(file, JSON.stringify(payload, null, 2), 'utf8');
  return payload;
}

async function readAccounts() {
  const payload = await readCollection(DEFAULT_SITE_ID, 'accounts', {});
  return payload.data || {};
}

async function writeAccounts(accounts) {
  return writeCollection(DEFAULT_SITE_ID, 'accounts', accounts || {});
}

async function readSessions() {
  const payload = await readCollection(DEFAULT_SITE_ID, 'sessions', {});
  return payload.data || {};
}

async function writeSessions(sessions) {
  return writeCollection(DEFAULT_SITE_ID, 'sessions', sessions || {});
}

async function createSession(username) {
  const sessions = await readSessions();
  const token = crypto.randomBytes(32).toString('hex');
  sessions[token] = {
    username,
    createdAt: new Date().toISOString()
  };
  await writeSessions(sessions);
  return token;
}

async function getSessionFromRequest(req) {
  const authHeader = req.get('Authorization') || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  if (!token) return null;
  const sessions = await readSessions();
  const session = sessions[token];
  return session ? { token, ...session } : null;
}

function publicAccount(account) {
  if (!account) return null;
  return {
    username: account.username,
    displayName: account.displayName || account.username,
    createdAt: account.createdAt
  };
}

function requireTeamPassword(teamPassword) {
  if (!teamPassword || teamPassword !== TEAM_PASSWORD) {
    const err = new Error('Senha da equipe incorreta.');
    err.status = 403;
    throw err;
  }
}

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'midnight-circus-storage-auth' });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const username = normalizeUsername(req.body?.username);
    const displayName = String(req.body?.displayName || username).trim().slice(0, 32);
    const teamPassword = String(req.body?.teamPassword || '');

    requireTeamPassword(teamPassword);

    if (!username || username.length < 3) {
      return res.status(400).json({ error: 'Usuário precisa ter pelo menos 3 caracteres válidos.' });
    }

    const accounts = await readAccounts();
    if (accounts[username]) {
      return res.status(409).json({ error: 'Esse usuário já existe. Escolha outro.' });
    }

    const account = {
      username,
      displayName: displayName || username,
      createdAt: new Date().toISOString()
    };

    accounts[username] = account;
    await writeAccounts(accounts);

    const token = await createSession(username);
    res.json({ ok: true, account: publicAccount(account), token });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message || 'Erro ao criar conta.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const username = normalizeUsername(req.body?.username);
    const teamPassword = String(req.body?.teamPassword || '');

    requireTeamPassword(teamPassword);

    const accounts = await readAccounts();
    const account = accounts[username];
    if (!account) {
      return res.status(401).json({ error: 'Usuário ou senha da equipe incorretos.' });
    }

    const token = await createSession(username);
    res.json({ ok: true, account: publicAccount(account), token });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message || 'Erro ao entrar.' });
  }
});

app.post('/api/auth/logout', async (req, res) => {
  try {
    const token = String(req.body?.token || '').trim();
    if (token) {
      const sessions = await readSessions();
      delete sessions[token];
      await writeSessions(sessions);
    }
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Erro ao sair.' });
  }
});

app.get('/api/storage/:siteId/:collection', async (req, res) => {
  try {
    const collection = req.params.collection;
    const defaultData = collection === 'accounts' || collection === 'sessions' ? {} : [];

    if (collection === 'sessions') {
      return res.status(403).json({ error: 'Coleção protegida.' });
    }

    const payload = await readCollection(req.params.siteId, collection, defaultData);

    // Nunca exponha dados sensíveis. Atualmente accounts só contém dados públicos.
    if (collection === 'accounts') {
      const publicAccounts = {};
      for (const [username, account] of Object.entries(payload.data || {})) {
        publicAccounts[username] = publicAccount(account);
      }
      return res.json({ data: publicAccounts, updatedAt: payload.updatedAt });
    }

    res.json(payload);
  } catch (err) {
    res.status(400).json({ error: err.message || 'Erro ao carregar coleção.' });
  }
});

app.put('/api/storage/:siteId/:collection', async (req, res) => {
  try {
    const collection = req.params.collection;

    // accounts/sessions são controlados pelos endpoints /auth.
    if (collection === 'accounts' || collection === 'sessions') {
      return res.status(403).json({ error: 'Coleção protegida. Use /api/auth.' });
    }

    const session = await getSessionFromRequest(req);
    if (!session) {
      return res.status(401).json({ error: 'Login necessário para salvar dados no servidor.' });
    }

    const payload = await writeCollection(req.params.siteId, collection, req.body?.data);
    res.json({ ok: true, updatedAt: payload.updatedAt, user: session.username });
  } catch (err) {
    res.status(400).json({ error: err.message || 'Erro ao salvar coleção.' });
  }
});

app.listen(PORT, () => {
  console.log(`Midnight Circus API rodando em http://localhost:${PORT}/api`);
  if (!process.env.TEAM_PASSWORD) {
    console.warn('Aviso: TEAM_PASSWORD não definido. Usando senha padrão de teste: CIRCUS170326');
  }
});
