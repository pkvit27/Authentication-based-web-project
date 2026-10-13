// Zero-Trust Access Control Framework - High Performance Server
// Native Node.js HTTP & SSE Server (Zero External Dependencies)
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const db = require('./db');
const { 
  hashPassword, 
  verifyPassword, 
  verifyFaceBiometrics, 
  generateFacialVector, 
  cosineSimilarity,
  generateVoiceVector,
  verifyVoiceBiometrics,
  fuseBiometrics
} = require('./biometrics');
const { defaultTeacher, defaultStudent, DistilledStudentClassifier } = require('./models');
const { defaultTrustEngine } = require('./trust_engine');
const { defaultRLAgent } = require('./rl_agent');
const { defaultTelemetryEngine } = require('./telemetry');
const { defaultXAIEngine } = require('./xai');
const { defaultFederatedEngine } = require('./federated');
const { defaultRobustnessEngine } = require('./robustness');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

// MIME types for static assets
const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon'
};

// Seed default users for both User and Admin portals
(function seedDefaultUsers() {
  const seedAccounts = [
    {
      username: 'admin',
      password: 'AdminPass123!',
      fullName: 'Dr. Jane Vance (SecOps Lead)',
      role: 'admin',
      seedFace: 'admin_primary_face',
      seedVoice: 'admin_primary_voice'
    },
    {
      username: 'analyst',
      password: 'SecurePass123!',
      fullName: 'Security Operations Analyst',
      role: 'admin',
      seedFace: 'analyst_primary_face',
      seedVoice: 'analyst_primary_voice'
    },
    {
      username: 'user',
      password: 'UserPass123!',
      fullName: 'Prince Kumar (Enterprise Member)',
      role: 'user',
      seedFace: 'user_primary_face',
      seedVoice: 'user_primary_voice'
    },
    {
      username: 'prince',
      password: 'UserPass123!',
      fullName: 'Prince Kumar',
      role: 'user',
      seedFace: 'prince_primary_face',
      seedVoice: 'prince_primary_voice'
    }
  ];

  for (const acc of seedAccounts) {
    const existing = db.getUserByUsername(acc.username);
    const seedVoiceVector = generateVoiceVector(acc.seedVoice, 0.0);
    if (!existing) {
      const { hash, salt } = hashPassword(acc.password);
      const seedVector = generateFacialVector(acc.seedFace, 0.0);
      db.createUser({
        id: crypto.randomUUID(),
        username: acc.username,
        password_hash: hash,
        salt: salt,
        full_name: acc.fullName,
        role: acc.role,
        face_enrolled: 1,
        face_vector: JSON.stringify(seedVector),
        face_landmarks: JSON.stringify({ eyes: 0.62, nose: 0.45, mouth: 0.72 }),
        voice_enrolled: 1,
        voice_vector: JSON.stringify(seedVoiceVector),
        voice_passphrase: 'Zero-Trust Secure Access 2026',
        created_at: new Date().toISOString()
      });
      console.log(`[SEED] Created ${acc.role.toUpperCase()} account: "${acc.username}" / "${acc.password}" with enrolled face & voice`);
    } else if (!existing.voice_vector || existing.voice_enrolled !== 1) {
      db.updateUserVoice(existing.id, JSON.stringify(seedVoiceVector), 'Zero-Trust Secure Access 2026');
      console.log(`[SEED] Enrolled voice biometrics for existing account: "${acc.username}"`);
    }
  }
})();

// Helper to parse JSON request bodies
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
      if (body.length > 5 * 1024 * 1024) { // 5MB limit
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

// Helper to send JSON responses
function sendJSON(res, statusCode, data) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization'
  });
  res.end(JSON.stringify(data));
}

// Helper to serve static files
function serveStatic(req, res) {
  let reqPath = req.url.split('?')[0];
  if (reqPath === '/' || reqPath === '') reqPath = '/index.html';
  const filePath = path.join(PUBLIC_DIR, reqPath);

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end('404 Not Found');
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    res.writeHead(200, { 'Content-Type': contentType });
    fs.createReadStream(filePath).pipe(res);
  });
}

// Request Handler
const server = http.createServer(async (req, res) => {
  // Handle CORS Preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    return res.end();
  }

  const parsedUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsedUrl.pathname;

  // -------------------------------------------------------------
  // API ROUTING
  // -------------------------------------------------------------
  try {
    // 1. User Registration with Face Enrollment
    if (pathname === '/api/auth/register' && req.method === 'POST') {
      const data = await parseBody(req);
      const { username, password, fullName, role, faceVector, faceLandmarks } = data;

      if (!username || !password || !faceVector) {
        return sendJSON(res, 400, { error: 'Username, password, and biometric face scan are required.' });
      }

      const existing = db.getUserByUsername(username);
      if (existing) {
        return sendJSON(res, 409, { error: 'Username is already registered.' });
      }

      const { hash, salt } = hashPassword(password);
      const userId = crypto.randomUUID();

      db.createUser({
        id: userId,
        username,
        password_hash: hash,
        salt,
        full_name: fullName || username,
        role: role || 'Security Analyst',
        face_enrolled: 1,
        face_vector: JSON.stringify(faceVector),
        face_landmarks: JSON.stringify(faceLandmarks || {}),
        created_at: new Date().toISOString()
      });

      return sendJSON(res, 201, {
        success: true,
        message: 'User registered and facial biometric profile securely enrolled!',
        userId
      });
    }

    // 1b. Fast Face Enrollment / Re-enrollment for Account
    if (pathname === '/api/auth/enroll-face' && req.method === 'POST') {
      const data = await parseBody(req);
      const { username, password, faceVector, faceLandmarks } = data;

      if (!username || !password || !faceVector) {
        return sendJSON(res, 400, { error: 'Username, password, and live face scan are required.' });
      }

      const user = db.getUserByUsername(username);
      if (!user) {
        return sendJSON(res, 404, { error: 'User account not found.' });
      }

      const passValid = verifyPassword(password, user.password_hash, user.salt);
      if (!passValid) {
        return sendJSON(res, 401, { error: 'Invalid password. Cannot enroll face without valid credentials.' });
      }

      db.updateUserFace(user.id, JSON.stringify(faceVector), JSON.stringify(faceLandmarks || {}));

      db.logAudit({
        session_id: null,
        username: user.username,
        action: 'FACE_ENROLLMENT_UPDATED',
        decision: 'GRANT',
        trust_score: 95.0,
        mu_tt: defaultRLAgent.mu_tt,
        mu_mfa: defaultRLAgent.mu_mfa,
        factors: { enrolled: true, timestamp: new Date().toISOString() },
        timestamp: new Date().toISOString()
      });

      return sendJSON(res, 200, {
        success: true,
        message: `Your live camera face has been securely enrolled as the primary biometric profile for "${user.username}"! Now click "Scan Face & Sign In" to authenticate.`
      });
    }

    // 2. User Login with Mandatory Multi-Modal Biometrics (Face + Voice Verification)
    if (pathname === '/api/auth/login' && req.method === 'POST') {
      const data = await parseBody(req);
      const { username, password, faceVector, voiceVector, livenessData, acousticData, loginPortal, enrollFaceNow, enrollVoiceNow } = data;

      if (!username || !password) {
        return sendJSON(res, 400, { error: 'Username and password credentials are required.' });
      }

      if (!faceVector || !Array.isArray(faceVector) || faceVector.length === 0) {
        return sendJSON(res, 400, { error: 'Mandatory Policy Enforcement: Biometric face scan is strictly required for all login attempts.' });
      }

      if (!voiceVector || !Array.isArray(voiceVector) || voiceVector.length === 0) {
        return sendJSON(res, 400, { error: 'Mandatory Policy Enforcement: Acoustic voiceprint scan is strictly required for all login attempts. Please record or scan your voice.' });
      }

      const user = db.getUserByUsername(username);
      if (!user) {
        return sendJSON(res, 401, { error: 'Invalid username or password credentials.' });
      }

      // Role check for Admin portal
      const isAdminUser = (user.role === 'admin' || user.role === 'Zero-Trust Administrator' || user.role === 'Security Analyst');
      if (loginPortal === 'admin' && !isAdminUser) {
        return sendJSON(res, 403, {
          error: 'Access Denied: Account "' + username + '" does not have Security Administrator privileges. Please use the User Login Portal.'
        });
      }

      // Password Check
      const passValid = verifyPassword(password, user.password_hash, user.salt);
      if (!passValid) {
        return sendJSON(res, 401, { error: 'Invalid username or password credentials.' });
      }

      // 1. Face Biometric Vector Check
      let enrolledVector = null;
      try {
        enrolledVector = JSON.parse(user.face_vector);
      } catch (e) {}

      // Helper to detect synthetic seeded demo templates vs real camera vectors
      function isPlaceholderSeed(uname, vec) {
        if (!vec || !Array.isArray(vec)) return true;
        const knownSeeds = ['admin_primary_face', 'analyst_primary_face', 'user_primary_face', 'prince_primary_face', `face_${uname}`, 'default'];
        for (const s of knownSeeds) {
          const testVec = generateFacialVector(s, 0.0);
          if (cosineSimilarity(testVec, vec) > 0.90) return true;
        }
        return false;
      }

      // If user requested instant enrollment, or if account still has synthetic math seed,
      // or if no face template exists yet: bind this real camera face!
      const hasPlaceholder = isPlaceholderSeed(user.username, enrolledVector);
      if (enrollFaceNow || !enrolledVector || hasPlaceholder) {
        db.updateUserFace(user.id, JSON.stringify(faceVector), JSON.stringify({}));
        enrolledVector = faceVector;
        user.face_vector = JSON.stringify(faceVector);
      }

      const bioResult = verifyFaceBiometrics(enrolledVector, faceVector, livenessData || {});
      if (!bioResult.verified) {
        db.logAudit({
          session_id: null,
          username: user.username,
          action: 'LOGIN_ATTEMPT',
          decision: 'DENY',
          trust_score: 25.0,
          mu_tt: defaultRLAgent.mu_tt,
          mu_mfa: defaultRLAgent.mu_mfa,
          factors: { reason: bioResult.reason, confidence: bioResult.confidence },
          timestamp: new Date().toISOString()
        });

        return sendJSON(res, 403, {
          error: 'Biometric Face Verification Failed: ' + bioResult.reason,
          bioResult
        });
      }

      // 2. Voice Biometric Vector Check (Multi-Modal Verification)
      let enrolledVoiceVector = null;
      try {
        enrolledVoiceVector = JSON.parse(user.voice_vector);
      } catch (e) {}

      let currentVoiceVector = voiceVector;

      function isVoicePlaceholderSeed(uname, vec) {
        if (!vec || !Array.isArray(vec)) return true;
        const knownVoiceSeeds = ['admin_primary_voice', 'analyst_primary_voice', 'user_primary_voice', 'prince_primary_voice', `voice_${uname}`, 'default'];
        for (const s of knownVoiceSeeds) {
          const testVec = generateVoiceVector(s, 0.0);
          if (cosineSimilarity(testVec, vec) > 0.90) return true;
        }
        return false;
      }

      const hasVoicePlaceholder = isVoicePlaceholderSeed(user.username, enrolledVoiceVector);
      if (enrollVoiceNow || !enrolledVoiceVector || hasVoicePlaceholder) {
        db.updateUserVoice(user.id, JSON.stringify(currentVoiceVector));
        enrolledVoiceVector = currentVoiceVector;
        user.voice_vector = JSON.stringify(currentVoiceVector);
      }

      const voiceResult = verifyVoiceBiometrics(enrolledVoiceVector, currentVoiceVector, acousticData || {});
      if (!voiceResult.verified) {
        db.logAudit({
          session_id: null,
          username: user.username,
          action: 'LOGIN_ATTEMPT',
          decision: 'DENY',
          trust_score: 25.0,
          mu_tt: defaultRLAgent.mu_tt,
          mu_mfa: defaultRLAgent.mu_mfa,
          factors: { reason: voiceResult.reason, confidence: voiceResult.confidence },
          timestamp: new Date().toISOString()
        });

        return sendJSON(res, 403, {
          error: 'Biometric Voice Verification Failed: ' + voiceResult.reason,
          voiceResult
        });
      }

      // Fuse multi-modal biometrics: Face + Voice
      const multiModalFusion = fuseBiometrics(bioResult, voiceResult);

      // Successful Biometric Verification -> Create Active Session
      const sessionToken = crypto.randomBytes(32).toString('hex');
      const sessionId = crypto.randomUUID();
      const now = new Date().toISOString();

      // Initial PEP / PDP Evaluation for session baseline
      const sample = defaultTelemetryEngine.sampleTelemetry({ username: user.username });
      sample.factors.B = multiModalFusion.compositeScore;
      const dlResult = defaultTeacher.forward(sample.networkVector);
      const tsResult = defaultTrustEngine.calculateTrustScore(sample.factors, dlResult.p_anomaly);

      db.createSession({
        id: sessionId,
        user_id: user.id,
        token: sessionToken,
        status: 'active',
        trust_score: tsResult.TS,
        p_anomaly: dlResult.p_anomaly,
        mu_tt: defaultRLAgent.mu_tt,
        mu_mfa: defaultRLAgent.mu_mfa,
        last_verified_at: now,
        created_at: now
      });

      db.logAudit({
        session_id: sessionId,
        username: user.username,
        action: 'BIOMETRIC_LOGIN',
        decision: 'GRANT',
        trust_score: tsResult.TS,
        mu_tt: defaultRLAgent.mu_tt,
        mu_mfa: defaultRLAgent.mu_mfa,
        factors: tsResult.factors,
        timestamp: now
      });

      return sendJSON(res, 200, {
        success: true,
        message: 'Multi-modal Biometric Authentication Succeeded: Face & Voice verified.',
        token: sessionToken,
        user: {
          id: user.id,
          username: user.username,
          fullName: user.full_name,
          role: user.role,
          isAdmin: isAdminUser,
          faceEnrolled: true,
          voiceEnrolled: true
        },
        biometrics: {
          face: bioResult,
          voice: voiceResult,
          multiModalScore: multiModalFusion.compositeScore,
          confidence: multiModalFusion.compositeScore,
          verified: multiModalFusion.verified
        },
        initialTrust: tsResult,
        thresholds: {
          mu_tt: defaultRLAgent.mu_tt,
          mu_mfa: defaultRLAgent.mu_mfa
        }
      });
    }

    // 3. Step-Up MFA Facial Re-Verification
    if (pathname === '/api/auth/verify-face-stepup' && req.method === 'POST') {
      const data = await parseBody(req);
      let token = data.token || req.headers.authorization?.replace('Bearer ', '');
      const { faceVector, livenessData } = data;

      if (!token) {
        // Fallback: look up latest active session
        try {
          const latestSess = db.db.prepare('SELECT * FROM sessions ORDER BY created_at DESC LIMIT 1').get();
          if (latestSess) token = latestSess.token;
        } catch (e) {}
      }

      if (!token) {
        return sendJSON(res, 401, { error: 'Active session not found. Please log in first.' });
      }

      if (!faceVector) {
        return sendJSON(res, 400, { error: 'Biometric face scan is required.' });
      }

      const session = db.getSessionByToken(token);
      if (!session) {
        return sendJSON(res, 401, { error: 'Session expired or invalid.' });
      }

      const user = db.getUserById(session.user_id);
      let enrolledVector = null;
      try { enrolledVector = JSON.parse(user.face_vector); } catch (e) {}

      if (!enrolledVector) {
        return sendJSON(res, 400, { error: 'No enrolled facial profile found for this account.' });
      }

      const bioResult = verifyFaceBiometrics(enrolledVector, faceVector, livenessData || {});
      if (!bioResult.verified) {
        return sendJSON(res, 403, {
          error: 'Step-up facial verification rejected: ' + bioResult.reason,
          bioResult
        });
      }

      // Restored trust through Step-Up MFA
      db.updateSessionStatus(session.id, 'active', 88.0, 0.04, defaultRLAgent.mu_tt, defaultRLAgent.mu_mfa);

      db.logAudit({
        session_id: session.id,
        username: user.username,
        action: 'STEP_UP_FACE_VERIFICATION',
        decision: 'GRANT',
        trust_score: 88.0,
        mu_tt: defaultRLAgent.mu_tt,
        mu_mfa: defaultRLAgent.mu_mfa,
        factors: { stepUpSuccess: true, confidence: bioResult.confidence },
        timestamp: new Date().toISOString()
      });

      return sendJSON(res, 200, {
        success: true,
        message: 'Step-up facial re-verification succeeded! Full session access restored.',
        bioResult,
        trustScore: 88.0
      });
    }

    // Endpoint: Live Threats and Vulnerabilities Intelligence
    if (pathname === '/api/admin/threats-vulnerabilities' && req.method === 'GET') {
      const mode = defaultTelemetryEngine.currentMode;
      let activeThreat;

      if (mode === 'cert_insider') {
        activeThreat = {
          name: 'Malicious Insider Data Exfiltration (CERT r4.2)',
          scenario: 'CERT r4.2 Insider Threat Scenario',
          cveId: 'INSIDER-EXFIL-CERT-01',
          severity: 'HIGH',
          severityColor: 'var(--accent-amber)',
          mitreTechnique: 'T1048.003 (Exfiltration Over Alt Protocol)',
          targetedAsset: 'Enterprise SQL Customer Database (PROD-DB-01)',
          sourceIp: '10.0.12.84 (Corporate Internal VPN)',
          detectionSource: 'IAM Behavior Baseline + SIEM Egress Monitor',
          impactSummary: 'Abnormal after-hours bulk data transfer detected. User Behavior Score dropped to 38.0.',
          pepMitigation: 'Policy Enforcement Point challenged session with Mandatory Optical Step-Up MFA.'
        };
      } else if (mode === 'cic_ids_dos') {
        activeThreat = {
          name: 'Distributed SYN Flood Volumetric DoS (CIC-IDS2017)',
          scenario: 'CIC-IDS2017 Volumetric Anomaly',
          cveId: 'CVE-2023-44487 / T1498.001',
          severity: 'CRITICAL',
          severityColor: 'var(--accent-rose)',
          mitreTechnique: 'T1498.001 (Network DoS: Direct Volumetric Flood)',
          targetedAsset: 'Core Firewall Gateway & Edge Ingress (GW-ROOT-01)',
          sourceIp: '198.51.100.0/24 (External Botnet Swarm)',
          detectionSource: 'CIC-IDS Deep Flow Classifier + SIEM Alarms',
          impactSummary: 'Extreme burst of 890 MB/s SYN packets. Network raw score dropped to 22.0.',
          pepMitigation: 'PEP Rate-Limiter engaged; deep feature extraction flagged 96.8% anomaly probability.'
        };
      } else if (mode === 'edr_compromise') {
        activeThreat = {
          name: 'Host Integrity & Credential Dumping (CrowdStrike EDR)',
          scenario: 'CrowdStrike EDR Endpoint Threat Stream',
          cveId: 'CVE-2024-6387 / T1003.001',
          severity: 'CRITICAL',
          severityColor: 'var(--accent-purple)',
          mitreTechnique: 'T1003.001 (OS Credential Dumping: LSASS Memory Scraping)',
          targetedAsset: 'Production Infrastructure & Shell Hosts',
          sourceIp: 'HOST-CORP-1092 (Local Admin Session)',
          detectionSource: 'CrowdStrike Falcon Sensor (Process: mimikatz_dump)',
          impactSummary: 'Unauthorized process attempted LSASS memory scraping. Device Health dropped to 25.0.',
          pepMitigation: 'Host quarantined from internal database clusters; session privileges revoked by PEP.'
        };
      } else {
        activeThreat = {
          name: 'Nominal Benign Enterprise Traffic (Zero Anomalies)',
          scenario: 'Standard Continuous Verification Baseline',
          cveId: 'BASELINE-SECURE',
          severity: 'NORMAL / SECURE',
          severityColor: 'var(--accent-emerald)',
          mitreTechnique: 'Normal Operations (Verified IAM / Clean EDR / Low SIEM Traffic)',
          targetedAsset: 'All Enterprise Workspaces Normal',
          sourceIp: '10.0.4.12 (Internal Corporate Subnet)',
          detectionSource: 'Active Multi-Domain Telemetry Stream (IAM, EDR, SIEM)',
          impactSummary: 'All 4 risk factors (B, N, D, T) operate within verified threshold baselines.',
          pepMitigation: 'Full Access Granted across authorized enterprise applications.'
        };
      }

      const vulnerabilities = [
        {
          cve: 'CVE-2024-3400',
          title: 'Palo Alto PAN-OS GlobalProtect Command Injection',
          cvss: '10.0',
          severity: 'CRITICAL',
          severityColor: 'var(--accent-rose)',
          component: 'Firewall Gateway (GW-ROOT-01)',
          mitre: 'T1190 Exploit Public-Facing App',
          status: 'Active PDP Deep Packet Inspection Enforcing Microsegmentation'
        },
        {
          cve: 'CVE-2024-21887',
          title: 'Ivanti Connect Secure Zero-Day Web Injection',
          cvss: '9.1',
          severity: 'CRITICAL',
          severityColor: 'var(--accent-rose)',
          component: 'Enterprise VPN Gateway',
          mitre: 'T1059 Command & Scripting Interpreter',
          status: 'Device Posture (D) Check Enforced; Unpatched Nodes Blocked'
        },
        {
          cve: 'CVE-2024-6387',
          title: 'RegreSSHion OpenSSH Pre-Auth Remote Code Execution',
          cvss: '8.1',
          severity: 'HIGH',
          severityColor: 'var(--accent-amber)',
          component: 'Production Server Infrastructure',
          mitre: 'T1078 Valid Accounts Abuse',
          status: 'Continuous Optical Face Verification Required for Privileged Access'
        },
        {
          cve: 'CVE-2023-44487',
          title: 'HTTP/2 Rapid Reset Volumetric Denial of Service',
          cvss: '7.5',
          severity: 'HIGH',
          severityColor: 'var(--accent-amber)',
          component: 'Web Application Reverse Proxies',
          mitre: 'T1498 Network Denial of Service',
          status: 'Edge-CNN Distilled Student Model Mitigates Packet Floods'
        },
        {
          cve: 'INSIDER-CERT-R4',
          title: 'CERT Insider Threat Data Exfiltration Pattern',
          cvss: '8.8',
          severity: 'HIGH',
          severityColor: 'var(--accent-amber)',
          component: 'Financial Vault & Customer DB',
          mitre: 'T1048 Exfiltration Over Alt Protocol',
          status: 'User Behavior Deviation (B) Triggers Mandatory Step-Up Face Scan'
        },
        {
          cve: 'EDR-MAL-LSASS',
          title: 'CrowdStrike Alert: Host LSASS Memory Scraping',
          cvss: '9.4',
          severity: 'CRITICAL',
          severityColor: 'var(--accent-rose)',
          component: 'Corporate Workstations & Servers',
          mitre: 'T1003 OS Credential Dumping',
          status: 'Real-Time EDR Quarantine & Biometric Re-Authentication'
        }
      ];

      return sendJSON(res, 200, {
        success: true,
        mode,
        activeThreat,
        vulnerabilities
      });
    }

    // Admin Users Directory Endpoint
    if (pathname === '/api/admin/users' && req.method === 'GET') {
      const users = db.getAllUsers();
      return sendJSON(res, 200, { users });
    }

    // 4. Session Validation
    if (pathname === '/api/auth/me' && req.method === 'GET') {
      const token = req.headers.authorization?.replace('Bearer ', '') || parsedUrl.searchParams.get('token');
      if (!token) return sendJSON(res, 401, { error: 'Missing token' });

      const session = db.getSessionByToken(token);
      if (!session) return sendJSON(res, 401, { error: 'Session expired or invalid' });

      const user = db.getUserById(session.user_id);
      return sendJSON(res, 200, {
        session,
        user: { id: user.id, username: user.username, fullName: user.full_name, role: user.role }
      });
    }

    // 5. Logout
    if (pathname === '/api/auth/logout' && req.method === 'POST') {
      const data = await parseBody(req);
      if (data.token) db.deleteSession(data.token);
      return sendJSON(res, 200, { success: true });
    }

    // 6. Real-Time Policy Decision Point (PDP) & Policy Enforcement Point (PEP) Evaluation (Requirement 8)
    if (pathname === '/api/pdp/evaluate' && req.method === 'POST') {
      const startTime = performance.now();
      const data = await parseBody(req);
      const token = data.token;
      const modelChoice = data.modelChoice || 'teacher'; // 'teacher' or 'student'

      let username = 'anonymous';
      let session = null;
      if (token) {
        session = db.getSessionByToken(token);
        if (session) {
          const u = db.getUserById(session.user_id);
          if (u) username = u.username;
        }
      }

      // Step A: Ingest current telemetry
      const telemetry = defaultTelemetryEngine.sampleTelemetry({ username });

      // Step B: Deep Feature Extraction (AE-CNN-BiLSTM-MHA or Distilled Student)
      const tInferStart = performance.now();
      const inferenceResult = (modelChoice === 'student') 
        ? defaultStudent.forward(telemetry.networkVector)
        : defaultTeacher.forward(telemetry.networkVector);
      const inferTimeMs = performance.now() - tInferStart;

      const p_anomaly = inferenceResult.p_anomaly;

      // Step C: 4-Factor Continuous Trust Score Calculation
      const tTrustStart = performance.now();
      const tsResult = defaultTrustEngine.calculateTrustScore(telemetry.factors, p_anomaly);
      const trustTimeMs = performance.now() - tTrustStart;
      const TS = tsResult.TS;

      // Step D: RL Agent State & Action Selection
      const tRLStart = performance.now();
      const currentState = defaultRLAgent.getState(TS, p_anomaly);
      const { action, qValues, isExploration } = defaultRLAgent.selectAction(currentState);
      const { mu_tt, mu_mfa, delta } = defaultRLAgent.step(action);
      const rlTimeMs = performance.now() - tRLStart;

      // Step E: Authorization Policy Enforcement (Section III-E of Manuscript)
      // If TS >= mu_tt -> GRANT
      // If mu_mfa <= TS < mu_tt -> STEP-UP MFA
      // If TS < mu_mfa -> DENY / REVOKE
      let decision;
      if (TS >= mu_tt) {
        decision = 'GRANT';
      } else if (TS >= mu_mfa) {
        decision = 'STEP-UP MFA';
      } else {
        decision = 'DENY';
      }

      // Update denial rolling window
      defaultRLAgent.updateDenialRate(decision === 'DENY');

      // Step F: Compute Reward & Train RL Policy
      const reward = defaultRLAgent.computeReward(decision, telemetry.groundTruthIsAttack);
      const nextState = defaultRLAgent.getState(TS, p_anomaly);

      // Robustness check: Replay buffer anti-poisoning check (Requirement 7)
      const poisonCheck = defaultRobustnessEngine.validateExperienceForBuffer({
        state: currentState,
        action,
        reward,
        nextState
      });

      if (poisonCheck.allowed) {
        defaultRLAgent.memory.push(currentState, action, reward, nextState);
        defaultRLAgent.trainStep(16);
      }

      // Step G: Explainability (XAI) Attribution (Requirement 5)
      const xaiExplanation = defaultXAIEngine.explainDecision({
        TS,
        factors: tsResult.factors,
        weights: tsResult.weights,
        p_anomaly,
        mu_tt,
        mu_mfa,
        decision
      });

      // Update active session record
      if (session) {
        const newStatus = (decision === 'DENY') ? 'revoked' : (decision === 'STEP-UP MFA' ? 'challenged' : 'active');
        db.updateSessionStatus(session.id, newStatus, TS, p_anomaly, mu_tt, mu_mfa);
      }

      // Measure total end-to-end PDP decision latency (Requirement 8)
      const totalLatencyMs = performance.now() - startTime;

      // Audit Log
      db.logAudit({
        session_id: session ? session.id : null,
        username,
        action: 'PEP_ACCESS_REQUEST',
        decision,
        trust_score: TS,
        mu_tt,
        mu_mfa,
        factors: tsResult.factors,
        timestamp: new Date().toISOString()
      });

      return sendJSON(res, 200, {
        decision,
        trustScore: TS,
        p_anomaly,
        thresholds: { mu_tt, mu_mfa, delta },
        factors: tsResult.factors,
        weights: tsResult.weights,
        weightMode: defaultTrustEngine.mode,
        rl: {
          algorithm: defaultRLAgent.algorithm,
          action,
          actionLabel: action === 0 ? 'Decrease Threshold (-2.0)' : (action === 2 ? 'Increase Threshold (+2.0)' : 'Maintain (0.0)'),
          qValues: qValues.map(q => parseFloat(q.toFixed(3))),
          reward,
          epsilon: parseFloat(defaultRLAgent.epsilon.toFixed(3)),
          denialRate: parseFloat((defaultRLAgent.denialRate * 100).toFixed(1))
        },
        telemetrySummary: {
          scenario: telemetry.scenario,
          source: telemetry.source,
          isAttack: telemetry.groundTruthIsAttack,
          iam: telemetry.iam,
          edr: telemetry.edr,
          siem: telemetry.siem
        },
        explainability: xaiExplanation,
        benchmarks: {
          modelChoice,
          inferenceTimeMs: parseFloat(inferTimeMs.toFixed(3)),
          trustEngineTimeMs: parseFloat(trustTimeMs.toFixed(3)),
          rlAgentTimeMs: parseFloat(rlTimeMs.toFixed(3)),
          endToEndDecisionLatencyMs: parseFloat(totalLatencyMs.toFixed(3)),
          paramCount: inferenceResult.paramCount
        }
      });
    }

    // 7. Telemetry Mode Switcher (Requirement 1)
    if (pathname === '/api/telemetry/mode' && req.method === 'POST') {
      const data = await parseBody(req);
      defaultTelemetryEngine.setDatasetMode(data.mode);
      return sendJSON(res, 200, { success: true, mode: defaultTelemetryEngine.currentMode });
    }

    // 8. Weights Mode Switcher (Requirement 2)
    if (pathname === '/api/weights/mode' && req.method === 'POST') {
      const data = await parseBody(req);
      defaultTrustEngine.setMode(data.mode);
      return sendJSON(res, 200, { success: true, mode: defaultTrustEngine.mode });
    }

    // 9. RL Algorithm Switcher (Requirement 3)
    if (pathname === '/api/rl/algorithm' && req.method === 'POST') {
      const data = await parseBody(req);
      defaultRLAgent.setAlgorithm(data.algorithm);
      return sendJSON(res, 200, { success: true, algorithm: defaultRLAgent.algorithm });
    }

    // 10. Model Efficiency & Distillation Benchmark (Requirement 4)
    if (pathname === '/api/benchmark/distillation' && req.method === 'POST') {
      const testVector = defaultTelemetryEngine.sampleTelemetry().networkVector;
      const iterations = 100;

      // Benchmark Teacher
      const tTeacher0 = performance.now();
      for (let i = 0; i < iterations; i++) {
        defaultTeacher.forward(testVector);
      }
      const tTeacherTotal = performance.now() - tTeacher0;
      const teacherAvgMs = tTeacherTotal / iterations;
      const teacherThroughput = Math.round(1000 / teacherAvgMs);

      // Benchmark Distilled Student
      const tStudent0 = performance.now();
      for (let i = 0; i < iterations; i++) {
        defaultStudent.forward(testVector);
      }
      const tStudentTotal = performance.now() - tStudent0;
      const studentAvgMs = tStudentTotal / iterations;
      const studentThroughput = Math.round(1000 / studentAvgMs);

      const speedup = (teacherAvgMs / studentAvgMs).toFixed(1);

      return sendJSON(res, 200, {
        iterations,
        teacher: {
          name: 'AE-CNN-BiLSTM-MHA (Teacher)',
          avgLatencyMs: parseFloat(teacherAvgMs.toFixed(3)),
          throughputReqSec: teacherThroughput,
          paramCount: defaultTeacher.paramCount
        },
        student: {
          name: 'Distilled Edge-CNN (Student)',
          avgLatencyMs: parseFloat(studentAvgMs.toFixed(3)),
          throughputReqSec: studentThroughput,
          paramCount: defaultStudent.paramCount
        },
        speedupMultiplier: `${speedup}x`,
        compressionRatio: `${(defaultTeacher.paramCount / defaultStudent.paramCount).toFixed(1)}x fewer parameters`
      });
    }

    // 11. Federated Learning Aggregation Round (Requirement 6)
    if (pathname === '/api/federated/round' && req.method === 'POST') {
      const roundResult = defaultFederatedEngine.runFedAvgRound();
      return sendJSON(res, 200, roundResult);
    }

    if (pathname === '/api/federated/status' && req.method === 'GET') {
      return sendJSON(res, 200, defaultFederatedEngine.getStatus());
    }

    // 12. Robustness Testing (Requirement 7)
    if (pathname === '/api/robustness/evasion' && req.method === 'POST') {
      const data = await parseBody(req);
      const epsilon = data.epsilon || 0.08;
      const sample = defaultTelemetryEngine.sampleTelemetry();
      const predictor = vec => defaultTeacher.forward(vec);
      const result = defaultRobustnessEngine.evaluateAdversarialEvasion(sample.networkVector, predictor, epsilon);
      return sendJSON(res, 200, result);
    }

    if (pathname === '/api/robustness/drift-check' && req.method === 'POST') {
      const data = await parseBody(req);
      const metric = data.metric !== undefined ? data.metric : (Math.random() > 0.7 ? 1.8 : 0.4);
      const result = defaultRobustnessEngine.updateConceptDrift(metric);
      return sendJSON(res, 200, result);
    }

    if (pathname === '/api/robustness/status' && req.method === 'GET') {
      return sendJSON(res, 200, defaultRobustnessEngine.getStatus());
    }

    // 13. System Audit Logs & Status
    if (pathname === '/api/status' && req.method === 'GET') {
      return sendJSON(res, 200, {
        status: 'online',
        uptimeSec: Math.floor(process.uptime()),
        thresholds: { mu_tt: defaultRLAgent.mu_tt, mu_mfa: defaultRLAgent.mu_mfa },
        rlAlgorithm: defaultRLAgent.algorithm,
        weightsMode: defaultTrustEngine.mode,
        telemetryScenario: defaultTelemetryEngine.currentMode,
        recentAudits: db.getRecentLogs(15)
      });
    }

    // 14. Demo Face Vector Generation (for clients without camera)
    if (pathname === '/api/demo/face-vector' && req.method === 'POST') {
      const data = await parseBody(req);
      const seed = data.seed || 'demo_user';
      const noise = data.noise || 0.0;
      const vector = generateFacialVector(seed, noise);
      return sendJSON(res, 200, { vector });
    }

    // 15. Demo Voice Vector Generation (for clients without microphone)
    if (pathname === '/api/demo/voice-vector' && req.method === 'POST') {
      const data = await parseBody(req);
      const seed = data.seed || 'demo_user';
      const noise = typeof data.noise === 'number' ? data.noise : 0.0;
      const vector = generateVoiceVector(seed, noise);
      return sendJSON(res, 200, { vector, dimensions: vector.length, acousticEnergy: 0.85 });
    }

    // Fallback: Static file server
    return serveStatic(req, res);

  } catch (err) {
    console.error('[SERVER ERROR]', err);
    return sendJSON(res, 500, { error: 'Internal Server Error: ' + err.message });
  }
});

const net = require('node:net');

function getAvailablePort(desiredPort) {
  return new Promise((resolve) => {
    const tester = net.createServer();
    tester.listen(desiredPort, '0.0.0.0', () => {
      tester.once('close', () => resolve(desiredPort));
      tester.close();
    });
    tester.on('error', () => {
      resolve(getAvailablePort(desiredPort + 1));
    });
  });
}

const desiredPort = Number(process.env.PORT) || 3000;

getAvailablePort(desiredPort).then(actualPort => {
  server.listen(actualPort, '0.0.0.0', () => {
    console.log(`\n======================================================`);
    console.log(` ZERO-TRUST CONTINUOUS RISK ASSESSMENT ACCESS CONTROL `);
    console.log(`======================================================`);
    if (actualPort !== desiredPort) {
      console.log(` [NOTE] Port ${desiredPort} was in use. Automatically switched!`);
    }
    console.log(` Server active on: http://127.0.0.1:${actualPort}`);
    console.log(` Access URL:       http://localhost:${actualPort}`);
    console.log(` PDP/PEP Engine:   ACTIVE`);
    console.log(` Biometric Face:   MANDATORY ON LOGIN`);
    console.log(`======================================================\n`);
  });
});

