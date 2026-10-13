// Automated End-to-End HTTP Integration Test Suite
const assert = require('node:assert');

async function runHttpTests() {
  const port = process.env.PORT || 3004;
  const baseUrl = process.env.TEST_URL || `http://127.0.0.1:${port}`;
  console.log(`--- STARTING HTTP INTEGRATION TEST SUITE (Target: ${baseUrl}) ---\n`);

  // Helper fetch wrapper
  async function post(path, body) {
    const res = await fetch(`${baseUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json().catch(() => ({}));
    return { status: res.status, data };
  }

  async function get(path) {
    const res = await fetch(`${baseUrl}${path}`);
    const data = await res.json().catch(() => ({}));
    return { status: res.status, data };
  }

  // Test A: Health check / Status
  console.log('[HTTP 1] Testing GET /api/status...');
  const statusRes = await get('/api/status');
  assert.strictEqual(statusRes.status, 200);
  assert.strictEqual(statusRes.data.status, 'online');
  console.log('✓ Server status endpoint verified.\n');

  // Test B: Login without face scan must be rejected
  console.log('[HTTP 2] Testing Mandatory Face Scan Enforcement on Login...');
  const noFaceLogin = await post('/api/auth/login', {
    username: 'analyst',
    password: 'SecurePass123!'
  });
  assert.strictEqual(noFaceLogin.status, 400);
  assert(noFaceLogin.data.error.includes('Biometric face scan is mandatory'));
  console.log('✓ Login without face scan rejected as expected.\n');

  // Test C: Login with Imposter Face Scan must fail
  console.log('[HTTP 3] Testing Imposter Face Scan Rejection...');
  // Get an imposter face vector
  const imposterBioRes = await post('/api/demo/face-vector', { seed: 'imposter_stranger', noise: 0.0 });
  const imposterLogin = await post('/api/auth/login', {
    username: 'analyst',
    password: 'SecurePass123!',
    faceVector: imposterBioRes.data.vector
  });
  assert.strictEqual(imposterLogin.status, 403);
  assert(imposterLogin.data.error.includes('Biometric Face Verification Failed'));
  console.log('✓ Imposter biometric attempt blocked by PEP.\n');

  // Test D: Authentic Login with Matching Face Scan
  console.log('[HTTP 4] Testing Authentic Login with Enrolled Face Scan...');
  const matchBioRes = await post('/api/demo/face-vector', { seed: 'analyst_primary_face', noise: 0.02 });
  const authLogin = await post('/api/auth/login', {
    username: 'analyst',
    password: 'SecurePass123!',
    faceVector: matchBioRes.data.vector,
    livenessData: { movementScore: 0.88, blinkDetected: true }
  });
  assert.strictEqual(authLogin.status, 200);
  assert(authLogin.data.token, 'Should receive session token');
  assert.strictEqual(authLogin.data.biometrics.verified, true);
  console.log(`✓ Login Succeeded! Token: ${authLogin.data.token.slice(0, 12)}... Match Confidence: ${authLogin.data.biometrics.confidence}%\n`);

  const userToken = authLogin.data.token;

  // Test E: PDP Real-Time Evaluation
  console.log('[HTTP 5] Testing PDP Access Evaluation Pipeline (Requirement 8)...');
  const pdpRes = await post('/api/pdp/evaluate', { token: userToken, modelChoice: 'teacher' });
  assert.strictEqual(pdpRes.status, 200);
  assert(['GRANT', 'STEP-UP MFA', 'DENY'].includes(pdpRes.data.decision));
  assert(pdpRes.data.trustScore > 0);
  assert(pdpRes.data.benchmarks.endToEndDecisionLatencyMs > 0);
  console.log(`✓ PDP Decision: ${pdpRes.data.decision} | Trust Score: ${pdpRes.data.trustScore} | Latency: ${pdpRes.data.benchmarks.endToEndDecisionLatencyMs}ms\n`);

  // Test F: Future Work Req 4: Model Distillation Benchmark
  console.log('[HTTP 6] Testing Model Distillation Benchmark (Requirement 4)...');
  const distillRes = await post('/api/benchmark/distillation', {});
  assert.strictEqual(distillRes.status, 200);
  assert(distillRes.data.student.throughputReqSec > distillRes.data.teacher.throughputReqSec);
  console.log(`✓ Teacher: ${distillRes.data.teacher.avgLatencyMs}ms vs Student: ${distillRes.data.student.avgLatencyMs}ms (${distillRes.data.speedupMultiplier})\n`);

  // Test G: Future Work Req 6: Federated Learning Round
  console.log('[HTTP 7] Testing Multi-Tenant Federated Learning (Requirement 6)...');
  const fedRes = await post('/api/federated/round', {});
  assert.strictEqual(fedRes.status, 200);
  assert.strictEqual(fedRes.data.round, 1);
  console.log(`✓ FedAvg completed across 3 tenants. Global Loss: ${fedRes.data.globalLoss}\n`);

  // Test H: Dual Portal Role Restriction (Employee cannot access Admin portal)
  console.log('[HTTP 8] Testing Dual Portal Role Restriction...');
  const userFaceRes = await post('/api/demo/face-vector', { seed: 'user_primary_face', noise: 0.0 });
  const employeeInAdminPortal = await post('/api/auth/login', {
    username: 'user',
    password: 'UserPass123!',
    faceVector: userFaceRes.data.vector,
    loginPortal: 'admin'
  });
  assert.strictEqual(employeeInAdminPortal.status, 403);
  assert(employeeInAdminPortal.data.error.includes('does not have Security Administrator privileges'));
  console.log('✓ Employee blocked from Admin Portal with 403 Forbidden as expected.\n');

  // Test I: Fast Live Face Enrollment & Verification
  console.log('[HTTP 9] Testing Live Face Enrollment Endpoint (/api/auth/enroll-face)...');
  const liveCamFace = await post('/api/demo/face-vector', { seed: 'live_webcam_face_test', noise: 0.01 });
  const enrollRes = await post('/api/auth/enroll-face', {
    username: 'prince',
    password: 'UserPass123!',
    faceVector: liveCamFace.data.vector,
    faceLandmarks: { nose: 0.5, eyes: 0.6 }
  });
  assert.strictEqual(enrollRes.status, 200);
  assert.strictEqual(enrollRes.data.success, true);
  console.log('✓ Live camera facial template enrolled successfully.\n');

  // Test J: Verify Login with Newly Enrolled Live Face
  console.log('[HTTP 10] Testing Login Verification with Newly Enrolled Live Face...');
  const enrolledLogin = await post('/api/auth/login', {
    username: 'prince',
    password: 'UserPass123!',
    faceVector: liveCamFace.data.vector,
    loginPortal: 'user',
    livenessData: { movementScore: 0.92, blinkDetected: true }
  });
  assert.strictEqual(enrolledLogin.status, 200);
  assert.strictEqual(enrolledLogin.data.biometrics.verified, true);
  assert(enrolledLogin.data.biometrics.confidence >= 95);
  console.log(`✓ Verified newly enrolled live face with ${enrolledLogin.data.biometrics.confidence}% confidence!\n`);

  console.log('==================================================');
  console.log(' ALL HTTP INTEGRATION TESTS PASSED SUCCESSFULLY!  ');
  console.log('==================================================\n');
}

runHttpTests().catch(err => {
  console.error('HTTP test failed:', err);
  process.exit(1);
});
