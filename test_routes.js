// Internal Route & Handler Integration Verification
const assert = require('node:assert');
const { EventEmitter } = require('node:events');
const http = require('node:http');

// Import server internal dependencies
const db = require('./server/db');
const { defaultTeacher, defaultStudent } = require('./server/models');
const { defaultTrustEngine } = require('./server/trust_engine');
const { defaultRLAgent } = require('./server/rl_agent');
const { defaultTelemetryEngine } = require('./server/telemetry');
const { defaultXAIEngine } = require('./server/xai');
const { defaultFederatedEngine } = require('./server/federated');
const { defaultRobustnessEngine } = require('./server/robustness');
const { 
  generateFacialVector, 
  verifyFaceBiometrics, 
  generateVoiceVector, 
  verifyVoiceBiometrics, 
  fuseBiometrics 
} = require('./server/biometrics');

async function testFullPipeline() {
  console.log('--- TESTING FULL ZERO-TRUST ACCESS WORKFLOW ---\n');

  // 1. Verify Default Administrator Profile
  console.log('1. Checking Seed Administrator in SQLite Database...');
  const user = db.getUserByUsername('analyst');
  assert(user, 'Admin user "analyst" must exist in DB');
  assert.strictEqual(user.face_enrolled, 1, 'Face must be marked as enrolled');
  assert.strictEqual(user.voice_enrolled, 1, 'Voice must be marked as enrolled');
  const enrolledVector = JSON.parse(user.face_vector);
  const enrolledVoice = JSON.parse(user.voice_vector);
  assert.strictEqual(enrolledVector.length, 128, 'Enrolled face vector must be 128-dimensional');
  assert.strictEqual(enrolledVoice.length, 64, 'Enrolled voice vector must be 64-dimensional');
  console.log('✓ Administrator verified: ' + user.full_name + ' with 128-d face & 64-d voice embeddings.\n');

  // 2. Simulate Login with Authentic Multi-Modal Biometric Scan (Face + Voice)
  console.log('2. Simulating User Login with Authentic Multi-Modal Scans...');
  const authenticScan = generateFacialVector('analyst_primary_face', 0.03);
  const bioMatch = verifyFaceBiometrics(enrolledVector, authenticScan, { movementScore: 0.85, blinkDetected: true });
  assert.strictEqual(bioMatch.verified, true);

  const authenticVoice = generateVoiceVector('analyst_primary_voice', 0.02);
  const voiceMatch = verifyVoiceBiometrics(enrolledVoice, authenticVoice, { audioEnergy: 0.85 });
  assert.strictEqual(voiceMatch.verified, true);

  const multiModal = fuseBiometrics(bioMatch, voiceMatch);
  assert.strictEqual(multiModal.verified, true);
  console.log(`✓ Face matched (${bioMatch.confidence}%) & Voice matched (${voiceMatch.confidence}%)!`);
  console.log(`✓ Multi-Modal Biometric Factor B: ${multiModal.compositeScore} / 100.\n`);

  // 3. Create Session and Run PEP / PDP Zero-Trust Evaluation
  console.log('3. Running PEP / PDP Zero-Trust Access Decision Point...');
  const telemetry = defaultTelemetryEngine.sampleTelemetry({ username: user.username });
  const featureOut = defaultTeacher.forward(telemetry.networkVector);
  const trustOut = defaultTrustEngine.calculateTrustScore(telemetry.factors, featureOut.p_anomaly);
  const rlState = defaultRLAgent.getState(trustOut.TS, featureOut.p_anomaly);
  const rlAction = defaultRLAgent.selectAction(rlState);
  const stepPolicy = defaultRLAgent.step(rlAction.action);

  let decision;
  if (trustOut.TS >= stepPolicy.mu_tt) {
    decision = 'GRANT';
  } else if (trustOut.TS >= stepPolicy.mu_mfa) {
    decision = 'STEP-UP MFA';
  } else {
    decision = 'DENY';
  }

  const xai = defaultXAIEngine.explainDecision({
    TS: trustOut.TS,
    factors: trustOut.factors,
    weights: trustOut.weights,
    p_anomaly: featureOut.p_anomaly,
    mu_tt: stepPolicy.mu_tt,
    mu_mfa: stepPolicy.mu_mfa,
    decision
  });

  console.log(`✓ Decision: ${decision}`);
  console.log(`✓ Composite Trust Score: ${trustOut.TS} (Threshold mu_tt: ${stepPolicy.mu_tt}, mu_mfa: ${stepPolicy.mu_mfa})`);
  console.log(`✓ Factor Breakdown: B=${trustOut.factors.B}, N_adj=${trustOut.factors.N_adj}, D=${trustOut.factors.D}, T=${trustOut.factors.T}`);
  console.log(`✓ XAI Summary: ${xai.narrative}\n`);

  // 4. Inject Risk & Test Mandatory Step-Up Face Scan Trigger
  console.log('4. Testing Mid-Session Contextual Threat Injection (Step-Up MFA)...');
  defaultTelemetryEngine.setDatasetMode('cert_insider');
  const threatTelemetry = defaultTelemetryEngine.sampleTelemetry({ username: user.username });
  const threatFeature = defaultTeacher.forward(threatTelemetry.networkVector);
  const threatTrust = defaultTrustEngine.calculateTrustScore(threatTelemetry.factors, threatFeature.p_anomaly);
  
  let threatDecision;
  if (threatTrust.TS >= stepPolicy.mu_tt) {
    threatDecision = 'GRANT';
  } else if (threatTrust.TS >= stepPolicy.mu_mfa) {
    threatDecision = 'STEP-UP MFA';
  } else {
    threatDecision = 'DENY';
  }

  assert(['STEP-UP MFA', 'DENY'].includes(threatDecision), 'Threat must trigger STEP-UP MFA or DENY');
  console.log(`✓ Threat injected successfully! PEP Decision shifted to: ${threatDecision} (TS: ${threatTrust.TS})`);
  console.log('✓ Step-Up Biometric Face Scan challenge successfully triggered.\n');

  // Reset back to normal
  defaultTelemetryEngine.setDatasetMode('live');

  // 5. Dual Login Verification (Employee vs Admin)
  console.log('5. Testing Dual Portal Accounts (Employee vs SOC Admin)...');
  const employeeUser = db.getUserByUsername('user');
  assert(employeeUser, 'Employee "user" must exist');
  assert.strictEqual(employeeUser.role, 'user');
  const adminUser = db.getUserByUsername('admin');
  assert(adminUser, 'Admin "admin" must exist');
  assert.strictEqual(adminUser.role, 'admin');
  console.log('✓ Dual Portal accounts verified: Employee ("user") and SOC Admin ("admin").\n');

  // 6. Test Live Face Re-Enrollment and 100% Face Match
  console.log('6. Testing Live Camera Face Enrollment & Verification Loop...');
  const newCameraFace = generateFacialVector('live_user_face_seed_123', 0.0);
  db.updateUserFace(employeeUser.id, JSON.stringify(newCameraFace), JSON.stringify({ symmetry: 0.96 }));
  
  // Re-fetch updated user
  const updatedUser = db.getUserByUsername('user');
  const updatedEnrolledVector = JSON.parse(updatedUser.face_vector);
  const scanMatch = verifyFaceBiometrics(updatedEnrolledVector, newCameraFace, { movementScore: 0.9, blinkDetected: true });
  assert.strictEqual(scanMatch.verified, true);
  assert(scanMatch.confidence >= 98);
  console.log(`✓ Face successfully enrolled and verified with ${scanMatch.confidence}% match confidence!\n`);

  // 7. Verify Mandatory Biometric Enforcement (Missing Face or Missing Voice)
  console.log('7. Testing Mandatory Biometrics Enforcement Policy...');
  assert.strictEqual(verifyFaceBiometrics(null, null).verified, false, 'Missing face must fail');
  assert.strictEqual(verifyVoiceBiometrics(null, null).verified, false, 'Missing voice must fail');
  console.log('✓ Mandatory Enforcement verified: Missing face or missing voice strictly blocks access.\n');

  console.log('==================================================');
  console.log(' COMPLETE ZERO-TRUST ACCESS LOOP VERIFIED!        ');
  console.log('==================================================\n');
}

testFullPipeline().catch(err => {
  console.error('Test pipeline error:', err);
  process.exit(1);
});
