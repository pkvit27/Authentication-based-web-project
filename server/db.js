// Database persistence layer using Node.js built-in SQLite
const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const fs = require('node:fs');

const dbPath = path.join(__dirname, 'zerotrust.db');
const db = new DatabaseSync(dbPath);

// Initialize database schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'Security Analyst',
    face_enrolled INTEGER DEFAULT 0,
    face_vector TEXT,
    face_landmarks TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    trust_score REAL DEFAULT 85.0,
    p_anomaly REAL DEFAULT 0.05,
    mu_tt REAL DEFAULT 80.0,
    mu_mfa REAL DEFAULT 65.0,
    last_verified_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    username TEXT,
    action TEXT NOT NULL,
    decision TEXT NOT NULL,
    trust_score REAL,
    mu_tt REAL,
    mu_mfa REAL,
    factors TEXT,
    timestamp TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS telemetry_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    data_json TEXT NOT NULL,
    timestamp TEXT NOT NULL
  );
`);

// Safe Schema Migrations for Voice Biometrics
try { db.exec(`ALTER TABLE users ADD COLUMN voice_enrolled INTEGER DEFAULT 0`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN voice_vector TEXT`); } catch (e) {}
try { db.exec(`ALTER TABLE users ADD COLUMN voice_passphrase TEXT DEFAULT 'Zero-Trust Secure Access 2026'`); } catch (e) {}

console.log('[DB] SQLite database initialized successfully at', dbPath);

module.exports = {
  db,
  
  // User Helpers
  getUserByUsername: (username) => {
    const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
    return stmt.get(username);
  },

  getUserById: (id) => {
    const stmt = db.prepare('SELECT * FROM users WHERE id = ?');
    return stmt.get(id);
  },

  createUser: ({ id, username, password_hash, salt, full_name, role, face_enrolled, face_vector, face_landmarks, voice_enrolled = 0, voice_vector = null, voice_passphrase = 'Zero-Trust Secure Access 2026', created_at }) => {
    const stmt = db.prepare(`
      INSERT INTO users (id, username, password_hash, salt, full_name, role, face_enrolled, face_vector, face_landmarks, voice_enrolled, voice_vector, voice_passphrase, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    return stmt.run(id, username, password_hash, salt, full_name, role, face_enrolled || 0, face_vector, face_landmarks, voice_enrolled || 0, voice_vector, voice_passphrase, created_at);
  },

  updateUserFace: (id, face_vector, face_landmarks) => {
    const stmt = db.prepare(`
      UPDATE users SET face_enrolled = 1, face_vector = ?, face_landmarks = ? WHERE id = ?
    `);
    return stmt.run(face_vector, face_landmarks, id);
  },

  updateUserVoice: (id, voice_vector, passphrase = 'Zero-Trust Secure Access 2026') => {
    const stmt = db.prepare(`
      UPDATE users SET voice_enrolled = 1, voice_vector = ?, voice_passphrase = ? WHERE id = ?
    `);
    return stmt.run(voice_vector, passphrase, id);
  },

  getAllUsers: () => {
    const stmt = db.prepare('SELECT id, username, full_name, role, face_enrolled, voice_enrolled, created_at FROM users ORDER BY created_at DESC');
    return stmt.all();
  },

  // Session Helpers
  createSession: ({ id, user_id, token, status, trust_score, p_anomaly, mu_tt, mu_mfa, last_verified_at, created_at }) => {
    const stmt = db.prepare(`
      INSERT INTO sessions (id, user_id, token, status, trust_score, p_anomaly, mu_tt, mu_mfa, last_verified_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    return stmt.run(id, user_id, token, status, trust_score, p_anomaly, mu_tt, mu_mfa, last_verified_at, created_at);
  },

  getSessionByToken: (token) => {
    const stmt = db.prepare('SELECT * FROM sessions WHERE token = ?');
    return stmt.get(token);
  },

  updateSessionStatus: (id, status, trust_score, p_anomaly, mu_tt, mu_mfa) => {
    const stmt = db.prepare(`
      UPDATE sessions
      SET status = ?, trust_score = ?, p_anomaly = ?, mu_tt = ?, mu_mfa = ?, last_verified_at = datetime('now')
      WHERE id = ?
    `);
    return stmt.run(status, trust_score, p_anomaly, mu_tt, mu_mfa, id);
  },

  deleteSession: (token) => {
    const stmt = db.prepare('DELETE FROM sessions WHERE token = ?');
    return stmt.run(token);
  },

  // Audit Logs
  logAudit: ({ session_id, username, action, decision, trust_score, mu_tt, mu_mfa, factors, timestamp }) => {
    const stmt = db.prepare(`
      INSERT INTO audit_logs (session_id, username, action, decision, trust_score, mu_tt, mu_mfa, factors, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    return stmt.run(session_id, username, action, decision, trust_score, mu_tt, mu_mfa, JSON.stringify(factors), timestamp);
  },

  getRecentLogs: (limit = 50) => {
    const stmt = db.prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?');
    return stmt.all(limit);
  }
};
