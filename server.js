/**
 * Midnight Circus — backend Render + Supabase
 *
 * Variáveis de ambiente obrigatórias no Render:
 *   SUPABASE_URL=https://xxxx.supabase.co
 *   SUPABASE_SERVICE_ROLE_KEY=sua_service_role_key
 *   TEAM_PASSWORD=CIRCUS170326
 *   SITE_ORIGIN=https://midnightcirc.us
 *
 * O front-end pode usar baseUrl sem /api:
 *   https://midnight-circus-api.onrender.com
 *
 * Este servidor também aceita rotas com /api para compatibilidade:
 *   /api/auth/login, /api/storage/...
 */

const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 10000;
const TEAM_PASSWORD = process.env.TEAM_PASSWORD || 'CIRCUS170326';
const DEFAULT_SITE_ID = process.env.SITE_ID || 'midnight-circus';
const SITE_ORIGIN = process.env.SITE_ORIGIN || true;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.warn('[Midnight Circus] SUPABASE_URL ou SUPABASE_SERVICE_ROLE_KEY não configurado. Configure no Render.');
}

const supabase = SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
      auth: { persistSession: false, autoRefreshToken: false }
    })
  : null;

app.use(express.json({ limit: '35mb' }));
app.use(cors({
  origin: SITE_ORIGIN,
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'],
  methods: ['GET', 'POST', 'PUT', 'OPTIONS']
}));

function normalizeUsername(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9._-]/g, '')
    .slice(0, 24);
}

function publicAccount(account) {
  if (!account) return null;
  return {
    username: account.username,
    displayName: account.display_name || account.displayName || account.username,
    createdAt: account.created_at || account.createdAt || null
  };
}

function requireSupabase() {
  if (!supabase) {
    const err = new Error('Supabase não configurado no servidor. Configure SUPABASE_URL e SUPABASE_SERVICE_ROLE_KEY no Render.');
    err.status = 500;
    throw err;
  }
}

function requireTeamPassword(teamPassword) {
  if (!teamPassword || teamPassword !== TEAM_PASSWORD) {
    const err = new Error('Senha da equipe incorreta.');
    err.status = 403;
    throw err;
  }
}

async function getSessionFromRequest(req) {
  requireSupabase();
  const authHeader = req.get('Authorization') || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  if (!token) return null;

  const { data, error } = await supabase
    .from('mc_sessions')
    .select('token, username, created_at')
    .eq('token', token)
    .maybeSingle();

  if (error) throw error;
  return data || null;
}

async function createSession(username) {
  requireSupabase();
  const token = crypto.randomBytes(32).toString('hex');
  const { error } = await supabase
    .from('mc_sessions')
    .insert({ token, username });
  if (error) throw error;
  return token;
}

async function handleHealth(_req, res) {
  res.json({
    ok: true,
    service: 'midnight-circus-supabase-api',
    storage: supabase ? 'supabase' : 'not-configured'
  });
}

async function handleRegister(req, res) {
  try {
    requireSupabase();
    const username = normalizeUsername(req.body?.username);
    const displayName = String(req.body?.displayName || username).trim().slice(0, 32);
    const teamPassword = String(req.body?.teamPassword || '');

    requireTeamPassword(teamPassword);

    if (!username || username.length < 3) {
      return res.status(400).json({ error: 'Usuário precisa ter pelo menos 3 caracteres válidos.' });
    }

    const { data: existing, error: existingError } = await supabase
      .from('mc_accounts')
      .select('username')
      .eq('username', username)
      .maybeSingle();

    if (existingError) throw existingError;
    if (existing) return res.status(409).json({ error: 'Esse usuário já existe. Escolha outro.' });

    const accountRow = {
      username,
      display_name: displayName || username
    };

    const { data: account, error: insertError } = await supabase
      .from('mc_accounts')
      .insert(accountRow)
      .select('username, display_name, created_at')
      .single();

    if (insertError) throw insertError;

    const token = await createSession(username);
    res.json({ ok: true, account: publicAccount(account), token });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message || 'Erro ao criar conta.' });
  }
}

async function handleLogin(req, res) {
  try {
    requireSupabase();
    const username = normalizeUsername(req.body?.username);
    const teamPassword = String(req.body?.teamPassword || '');

    requireTeamPassword(teamPassword);

    const { data: account, error } = await supabase
      .from('mc_accounts')
      .select('username, display_name, created_at')
      .eq('username', username)
      .maybeSingle();

    if (error) throw error;
    if (!account) return res.status(401).json({ error: 'Usuário ou senha da equipe incorretos.' });

    const token = await createSession(username);
    res.json({ ok: true, account: publicAccount(account), token });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message || 'Erro ao entrar.' });
  }
}

async function handleLogout(req, res) {
  try {
    requireSupabase();
    const token = String(req.body?.token || '').trim();
    if (token) {
      const { error } = await supabase
        .from('mc_sessions')
        .delete()
        .eq('token', token);
      if (error) throw error;
    }
    res.json({ ok: true });
  } catch (err) {
    res.status(err.status || 500).json({ error: err.message || 'Erro ao sair.' });
  }
}

function defaultCollectionData(collection) {
  return collection === 'accounts' || collection === 'sessions' ? {} : [];
}

async function handleGetStorage(req, res) {
  try {
    requireSupabase();
    const siteId = String(req.params.siteId || DEFAULT_SITE_ID);
    const collection = String(req.params.collection || '');

    if (collection === 'sessions') {
      return res.status(403).json({ error: 'Coleção protegida.' });
    }

    // Compatibilidade: se o front pedir accounts, devolve uma versão pública.
    if (collection === 'accounts') {
      const { data, error } = await supabase
        .from('mc_accounts')
        .select('username, display_name, created_at')
        .order('created_at', { ascending: true });
      if (error) throw error;
      const publicAccounts = {};
      for (const account of data || []) {
        publicAccounts[account.username] = publicAccount(account);
      }
      return res.json({ data: publicAccounts, updatedAt: null });
    }

    const { data, error } = await supabase
      .from('mc_storage')
      .select('data, updated_at')
      .eq('site_id', siteId)
      .eq('collection', collection)
      .maybeSingle();

    if (error) throw error;

    res.json({
      data: data?.data ?? defaultCollectionData(collection),
      updatedAt: data?.updated_at || null
    });
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message || 'Erro ao carregar coleção.' });
  }
}

async function handlePutStorage(req, res) {
  try {
    requireSupabase();
    const siteId = String(req.params.siteId || DEFAULT_SITE_ID);
    const collection = String(req.params.collection || '');

    if (collection === 'accounts' || collection === 'sessions') {
      return res.status(403).json({ error: 'Coleção protegida. Use /auth.' });
    }

    const session = await getSessionFromRequest(req);
    if (!session) return res.status(401).json({ error: 'Login necessário para salvar dados no servidor.' });

    const dataToSave = req.body?.data ?? defaultCollectionData(collection);
    const updatedAt = new Date().toISOString();

    const { data, error } = await supabase
      .from('mc_storage')
      .upsert({
        site_id: siteId,
        collection,
        data: dataToSave,
        updated_at: updatedAt
      }, { onConflict: 'site_id,collection' })
      .select('updated_at')
      .single();

    if (error) throw error;

    res.json({ ok: true, updatedAt: data?.updated_at || updatedAt, user: session.username });
  } catch (err) {
    res.status(err.status || 400).json({ error: err.message || 'Erro ao salvar coleção.' });
  }
}

// Rotas sem /api, compatíveis com seu HTML atual.
app.get('/health', handleHealth);
app.post('/auth/register', handleRegister);
app.post('/auth/login', handleLogin);
app.post('/auth/logout', handleLogout);
app.get('/storage/:siteId/:collection', handleGetStorage);
app.put('/storage/:siteId/:collection', handlePutStorage);

// Rotas com /api, para compatibilidade com versões antigas do HTML.
app.get('/api/health', handleHealth);
app.post('/api/auth/register', handleRegister);
app.post('/api/auth/login', handleLogin);
app.post('/api/auth/logout', handleLogout);
app.get('/api/storage/:siteId/:collection', handleGetStorage);
app.put('/api/storage/:siteId/:collection', handlePutStorage);

app.use((_req, res) => {
  res.status(404).json({ error: 'Rota não encontrada.' });
});

app.listen(PORT, () => {
  console.log(`Midnight Circus API rodando na porta ${PORT}`);
  console.log(`Health check: http://localhost:${PORT}/health ou /api/health`);
  if (!process.env.TEAM_PASSWORD) {
    console.warn('Aviso: TEAM_PASSWORD não definido. Usando senha padrão: CIRCUS170326');
  }
});
