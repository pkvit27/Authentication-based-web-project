// Comprehensive Verification Script for Zero-Trust Access Control Framework
const assert = require('node:assert');
const { 
  hashPassword, 
  verifyPassword, 
  verifyFaceBiometrics, 
  generateFacialVector,
  generateVoiceVector,
  verifyVoiceBiometrics,
  fuseBiometrics
} = require('./server/biometrics');
const { defaultTeacher, defaultStudent } = require('./server/models');
const { defaultTrustEngine } = require('./server/trust_engine');
const { defaultRLAgent } = require('./server/rl_agent');
const { defaultTelemetryEngine } = require('./server/telemetry');
const { defaultXAIEngine } = require('./server/xai');
const { defaultFederatedEngine } = require('./server/federated');
const { defaultRobustnessEngine } = require('./server/robustness');

async function runTests() {
  console.log('--- STARTING ZERO-TRUST VERIFICATION SUITE ---\n');

  // Test 1: Password Hashing and verification
  console.log('[TEST 1] Password Hashing & Salt Verification...');
  const { hash, salt } = hashPassword('MySecretPass123!');
  assert(verifyPassword('MySecretPass123!', hash, salt), 'Password should verify successfully');
  assert(!verifyPassword('WrongPass!', hash, salt), 'Wrong password must be rejected');
  console.log('✓ Password Cryptography passed.\n');

  // Test 2: Biometric Facial Vector Matching & Rejection
  console.log('[TEST 2] Biometric Facial Vector Matching & Anti-Spoofing...');
  const enrolledFace = generateFacialVector('person_alice_face', 0.0);
  const sameFaceScan = generateFacialVector('person_alice_face', 0.05); // slight natural variance
  const differentFaceScan = generateFacialVector('person_bob_face', 0.0);

  const matchResult = verifyFaceBiometrics(enrolledFace, sameFaceScan, { movementScore: 0.85, blinkDetected: true });
  assert(matchResult.verified, 'Authentic face scan must verify: ' + JSON.stringify(matchResult));
  assert(matchResult.confidence >= 80, 'Match confidence should be >= 80%');

  const imposterResult = verifyFaceBiometrics(enrolledFace, differentFaceScan, { movementScore: 0.85 });
  assert(!imposterResult.verified, 'Imposter face must be rejected');
  assert(imposterResult.confidence < 78, 'Imposter confidence should be low');

  const spoofResult = verifyFaceBiometrics(enrolledFace, sameFaceScan, { movementScore: 0.1 }); // static photo spoof
  assert(!spoofResult.verified, 'Spoofed face without movement must be rejected');
  console.log('✓ Biometric Face Verification & Anti-Spoofing passed.\n');

  // Test 2B: Biometric Voiceprint Verification & Multi-Modal Fusion
  console.log('[TEST 2B] Biometric Voiceprint Verification & Multi-Modal Fusion...');
  const enrolledVoice = generateVoiceVector('admin_primary_voice', 0.0);
  const sameVoiceSample = generateVoiceVector('admin_primary_voice', 0.03);
  const imposterVoiceSample = generateVoiceVector('imposter_voice_sample', 0.0);

  const voiceMatch = verifyVoiceBiometrics(enrolledVoice, sameVoiceSample, { audioEnergy: 0.82 });
  assert(voiceMatch.verified, 'Authentic voice sample must verify');
  assert(voiceMatch.confidence >= 85, 'Voice confidence should be >= 85%');

  const voiceImposter = verifyVoiceBiometrics(enrolledVoice, imposterVoiceSample, { audioEnergy: 0.82 });
  assert(!voiceImposter.verified, 'Imposter voice must be rejected');

  const voiceSilentSpoof = verifyVoiceBiometrics(enrolledVoice, sameVoiceSample, { audioEnergy: 0.02 });
  assert(!voiceSilentSpoof.verified, 'Silent audio spoof must fail acoustic liveness');

  const multiModal = fuseBiometrics(matchResult, voiceMatch);
  assert(multiModal.verified, 'Multi-modal fusion must pass when both face & voice match');
  assert(multiModal.compositeScore >= 85, 'Composite Factor B should be high: ' + multiModal.compositeScore);
  console.log(`✓ Voice Match: ${voiceMatch.confidence}% | Composite Factor B: ${multiModal.compositeScore}`);
  console.log('✓ Voiceprint Verification & Multi-Modal Biometrics passed.\n');

  // Test 3: Deep Feature Extraction (AE-CNN-BiLSTM-MHA & Student)
  console.log('[TEST 3] Deep Feature Extraction & Model Distillation...');
  const testFlow = defaultTelemetryEngine.sampleTelemetry().networkVector;
  const teacherOut = defaultTeacher.forward(testFlow);
  const studentOut = defaultStudent.forward(testFlow);

  assert(teacherOut.p_anomaly >= 0 && teacherOut.p_anomaly <= 1, 'P_anomaly must be in [0, 1]');
  assert(studentOut.p_anomaly >= 0 && studentOut.p_anomaly <= 1, 'Student P_anomaly must be in [0, 1]');
  assert(studentOut.latencyMs <= teacherOut.latencyMs * 1.5, 'Student model should be low latency');
  console.log(`✓ Teacher Latency: ${teacherOut.latencyMs}ms | Student Latency: ${studentOut.latencyMs}ms`);
  console.log('✓ Deep Feature Extraction & Distillation models passed.\n');

  // Test 4: 4-Factor Trust Engine & Learned Weights
  console.log('[TEST 4] 4-Factor Continuous Trust Engine (B, N, D, T)...');
  defaultTrustEngine.setMode('learned');
  const normalTrust = defaultTrustEngine.calculateTrustScore({ B: 90, N_raw: 92, D: 88, T: 95 }, 0.04);
  assert(normalTrust.TS > 80, 'Normal benign trust score should be high: ' + normalTrust.TS);

  const compromisedTrust = defaultTrustEngine.calculateTrustScore({ B: 40, N_raw: 30, D: 25, T: 40 }, 0.75);
  assert(compromisedTrust.TS < 55, 'Compromised trust score should be severely degraded: ' + compromisedTrust.TS);
  console.log(`✓ Normal TS: ${normalTrust.TS} | Compromised TS: ${compromisedTrust.TS}`);
  console.log('✓ Trust Score calculation & dynamic attention passed.\n');

  // Test 5: RL Policy Controller (DQN / Dueling / DDQN)
  console.log('[TEST 5] DRL Policy Controller & Threshold Adaptation...');
  const state = defaultRLAgent.getState(normalTrust.TS, 0.04);
  const actionObj = defaultRLAgent.selectAction(state);
  const stepObj = defaultRLAgent.step(actionObj.action);
  assert(stepObj.mu_tt >= 50 && stepObj.mu_tt <= 95, 'mu_tt must be within [50, 95]');
  assert(stepObj.mu_mfa === stepObj.mu_tt - 15, 'mu_mfa must equal mu_tt - 15');
  console.log(`✓ RL Action: ${actionObj.action} | Adapted mu_tt: ${stepObj.mu_tt} | mu_mfa: ${stepObj.mu_mfa}`);
  console.log('✓ Reinforcement Learning Agent passed.\n');

  // Test 6: Explainable AI (SHAP & Attention Attribution)
  console.log('[TEST 6] Explainable AI (XAI) Attribution...');
  const xai = defaultXAIEngine.explainDecision({
    TS: compromisedTrust.TS,
    factors: compromisedTrust.factors,
    weights: compromisedTrust.weights,
    p_anomaly: 0.75,
    mu_tt: 80.0,
    mu_mfa: 65.0,
    decision: 'DENY'
  });
  assert(xai.contributions.length === 4, 'Must have 4 factor contributions');
  assert(xai.narrative.includes('DENIED'), 'Narrative should reflect DENY decision');
  console.log('✓ XAI Narrative: ' + xai.narrative);
  console.log('✓ Explainability Engine passed.\n');

  // Test 7: Multi-Tenant Federated Learning (FedAvg)
  console.log('[TEST 7] Federated Learning Aggregation...');
  const fedRound = defaultFederatedEngine.runFedAvgRound();
  assert(fedRound.round >= 1, 'FedAvg round must increment');
  assert(fedRound.globalWeights.length === 4, 'Global weights must be 4 dimensions');
  console.log(`✓ FedAvg Round ${fedRound.round} completed across 3 cloud tenants. Global Loss: ${fedRound.globalLoss}`);
  console.log('✓ Federated Learning passed.\n');

  // Test 8: Robustness & Anti-Poisoning
  console.log('[TEST 8] Robustness: Adversarial Evasion & Anti-Poisoning Filter...');
  const evasionReport = defaultRobustnessEngine.evaluateAdversarialEvasion(testFlow, vec => defaultTeacher.forward(vec), 0.1);
  assert(evasionReport !== null, 'Adversarial report should be generated');

  const poisonedExp = {
    state: [0.3, 0.8, 0.8, 0.05], // high anomaly
    action: 0, // lowering threshold
    reward: 10.0, // fake high positive reward
    nextState: [0.3, 0.8, 0.78, 0.05]
  };
  const poisonCheck = defaultRobustnessEngine.validateExperienceForBuffer(poisonedExp);
  assert(!poisonCheck.allowed, 'Poisoned experience must be intercepted by anti-poisoning filter');
  console.log('✓ Anti-Poisoning filter successfully blocked malicious experience.');
  console.log('✓ Robustness Engine passed.\n');

  console.log('==================================================');
  console.log(' ALL 8 ZERO-TRUST AND BIOMETRIC TESTS PASSED!     ');
  console.log('==================================================\n');
}

runTests().catch(err => {
  console.error('Test failed:', err);
  process.exit(1);
});
