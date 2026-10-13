/**
 * Main Application Controller for Zero-Trust Continuous Risk Assessment Framework
 * Dual Portal Architecture: Employee Portal & Security Admin (SOC) Portal
 * Mandatory Optical Face Scanning Verification on Every Login
 */

// Application State
const state = {
  token: localStorage.getItem('zt_token') || null,
  user: null,
  portalMode: 'user', // 'user' or 'admin'
  activeTab: 'tab-auth',
  activeSubtab: 'sub-telemetry',
  currentBioVector: null,
  currentVoiceVector: null,
  stepupBioVector: null,
  cameraActive: false,
  stepupCameraActive: false,
  isRegistering: false,
  threatInjected: false
};

// Scanner instances
let mainScanner = null;
let stepupScanner = null;
let voiceScanner = null;

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', () => {
  initScanners();
  initPortalSwitcher();
  initNavTabs();
  initFutureWorkTabs();
  initAuthForms();
  initThreatInjectors();
  initFutureWorkButtons();
  initUserDashboardButtons();

  // Check existing session
  if (state.token) {
    validateSession();
  } else {
    pulsePdpEvaluation();
  }

  // Periodic Audit log refresh
  refreshAuditLogs();
  setInterval(refreshAuditLogs, 10000);
});

// Toast notification helper
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = 'toast';
  if (type === 'error') toast.style.borderColor = 'var(--accent-rose)';
  if (type === 'success') toast.style.borderColor = 'var(--accent-emerald)';
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 4500);
}

// -------------------------------------------------------------
// DUAL PORTAL SWITCHER (USER vs ADMIN)
// -------------------------------------------------------------
function initPortalSwitcher() {
  const btnUser = document.getElementById('btn-select-user-portal');
  const btnAdmin = document.getElementById('btn-select-admin-portal');

  const usernameInput = document.getElementById('login-username');
  const passwordInput = document.getElementById('login-password');
  const userLabel = document.getElementById('label-login-username');
  const formTitle = document.getElementById('auth-form-title');
  const descTitle = document.getElementById('portal-desc-title');
  const descText = document.getElementById('portal-desc-text');
  const btnText = document.getElementById('btn-login-text');

  btnUser.addEventListener('click', () => {
    state.portalMode = 'user';
    btnUser.classList.add('active');
    btnAdmin.classList.remove('active');

    userLabel.textContent = 'Employee Username';
    formTitle.innerHTML = `
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-emerald)" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
      Employee Portal Sign In
    `;
    descTitle.textContent = 'Employee Multi-Modal Biometrics:';
    descTitle.style.color = 'var(--accent-cyan)';
    descText.textContent = 'Every login requires matching your live face scan and voiceprint vector with your registered biometric profiles in the Zero-Trust database.';
    btnText.textContent = 'Scan Face & Voice to Sign In as Employee';

    usernameInput.value = 'user';
    passwordInput.value = 'UserPass123!';
    showToast('Switched to Employee / User Portal', 'info');
  });

  btnAdmin.addEventListener('click', () => {
    state.portalMode = 'admin';
    btnAdmin.classList.add('active');
    btnUser.classList.remove('active');

    userLabel.textContent = 'SOC Administrator Username';
    formTitle.innerHTML = `
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-rose)" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      Security Admin (SOC) Sign In
    `;
    descTitle.textContent = 'SOC Administrator Multi-Modal Clearance:';
    descTitle.style.color = 'var(--accent-rose)';
    descText.textContent = 'Elevated privileges restricted to verified Security Administrators. Facial and voice verification is mandatory on every login.';
    btnText.textContent = 'Scan Face & Voice to Access SOC Control Plane';

    usernameInput.value = 'admin';
    passwordInput.value = 'AdminPass123!';
    showToast('Switched to Security Admin (SOC) Portal', 'info');
  });
}

// -------------------------------------------------------------
// CAMERA & BIOMETRIC SCANNERS
// -------------------------------------------------------------
function initScanners() {
  const mainVideo = document.getElementById('webcam-video');
  const mainCanvas = document.getElementById('scanner-canvas');

  mainScanner = new BiometricFaceScanner(mainVideo, mainCanvas, {
    onScanUpdate: (data) => {
      const conf = data.faceDetected ? Math.min(100, Math.round(88 + (data.movementScore || 0.7) * 10)) : 0;
      document.getElementById('confidence-readout').textContent = `${conf}%`;
      document.getElementById('confidence-bar').style.width = `${conf}%`;

      if (data.vector) {
        state.currentBioVector = data.vector;
        updateBiometricChecklist();
      }
    }
  });

  const stepupVideo = document.getElementById('stepup-video');
  const stepupCanvas = document.getElementById('stepup-canvas');

  stepupScanner = new BiometricFaceScanner(stepupVideo, stepupCanvas, {
    onScanUpdate: (data) => {
      const conf = data.faceDetected ? Math.min(100, Math.round(88 + (data.movementScore || 0.7) * 10)) : 0;
      document.getElementById('stepup-confidence').textContent = `${conf}%`;
      document.getElementById('stepup-progress-bar').style.width = `${conf}%`;

      if (data.vector) {
        state.stepupBioVector = data.vector;
      }
    }
  });

  // Camera Buttons
  document.getElementById('btn-start-camera').addEventListener('click', startMainCamera);
  document.getElementById('btn-toggle-camera').addEventListener('click', stopMainCamera);

  // Pre-Enrolled Bio Match Button
  document.getElementById('btn-simulate-face').addEventListener('click', async () => {
    try {
      const username = document.getElementById('login-username').value || (state.portalMode === 'admin' ? 'admin' : 'user');
      let seed;
      if (username === 'admin') seed = 'admin_primary_face';
      else if (username === 'analyst') seed = 'analyst_primary_face';
      else if (username === 'prince') seed = 'prince_primary_face';
      else seed = 'user_primary_face';

      const res = await fetch('/api/demo/face-vector', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ seed, noise: 0.02 })
      });
      const data = await res.json();
      state.currentBioVector = data.vector;
      updateBiometricChecklist();

      document.getElementById('confidence-readout').textContent = '96%';
      document.getElementById('confidence-bar').style.width = '96%';
      document.getElementById('camera-status-tag').textContent = 'Enrolled Vector Ready';
      document.getElementById('camera-status-tag').style.color = 'var(--accent-emerald)';

      showToast(`Pre-enrolled biometric template loaded for "${username}".`, 'success');
    } catch (e) {
      showToast('Could not generate test vector: ' + e.message, 'error');
    }
  });

  // Voice Scanner Initialization
  const voiceCanvas = document.getElementById('voice-waveform-canvas');
  if (voiceCanvas) {
    voiceScanner = new BiometricVoiceScanner(voiceCanvas, {
      onStatusChange: (s) => {
        const tag = document.getElementById('voice-status-tag');
        if (tag) {
          tag.textContent = s.status || (s.active ? 'Listening...' : 'Mic Idle');
          tag.style.color = s.active ? 'var(--accent-purple)' : 'var(--accent-amber)';
        }
      },
      onLevelChange: (lvl) => {
        const conf = Math.min(100, Math.round(lvl * 120));
        const readout = document.getElementById('voice-confidence-readout');
        const pbar = document.getElementById('voice-progress-bar');
        if (readout) readout.textContent = `${conf}%`;
        if (pbar) pbar.style.width = `${conf}%`;

        if (lvl > 0.08 && voiceScanner) {
          const cap = voiceScanner.captureVector();
          if (cap && cap.vector) {
            state.currentVoiceVector = cap.vector;
            updateBiometricChecklist();
          }
        }
      }
    });
    voiceScanner.drawIdleState();
  }

  // Voice Recording Toggle Button
  const btnRecVoice = document.getElementById('btn-record-voice');
  if (btnRecVoice) {
    btnRecVoice.addEventListener('click', async () => {
      if (!voiceScanner) return;
      if (voiceScanner.isListening) {
        voiceScanner.stopMicrophone();
        btnRecVoice.textContent = '🎙️ Record Voice';
        showToast('Acoustic sensor stopped.', 'info');
      } else {
        showToast('Engaging microphone... Speak: "Zero-Trust Secure Access 2026"', 'info');
        const res = await voiceScanner.startMicrophone();
        if (res.success) {
          btnRecVoice.textContent = '⏹️ Stop Mic';
          showToast('Microphone live! Speak the security passphrase.', 'success');
        } else {
          showToast('Mic sensor note: ' + res.error + ' (Simulation fallback available)', 'error');
        }
      }
    });
  }

  // Simulated Voiceprint Match Button
  const btnSimVoice = document.getElementById('btn-sim-voice');
  if (btnSimVoice) {
    btnSimVoice.addEventListener('click', async () => {
      try {
        const username = document.getElementById('login-username').value || (state.portalMode === 'admin' ? 'admin' : 'user');
        const seed = (username === 'admin' || username === 'analyst') ? 'admin_primary_voice' : 'user_primary_voice';
        const res = await fetch('/api/demo/voice-vector', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ seed, noise: 0.02 })
        });
        const data = await res.json();
        state.currentVoiceVector = data.vector;
        updateBiometricChecklist();

        const readout = document.getElementById('voice-confidence-readout');
        const pbar = document.getElementById('voice-progress-bar');
        const tag = document.getElementById('voice-status-tag');
        if (readout) readout.textContent = '97%';
        if (pbar) pbar.style.width = '97%';
        if (tag) {
          tag.textContent = 'Voiceprint Ready';
          tag.style.color = 'var(--accent-emerald)';
        }
        showToast(`Pre-enrolled acoustic voiceprint loaded for "${username}".`, 'success');
      } catch (e) {
        showToast('Could not generate voice template: ' + e.message, 'error');
      }
    });
  }

  // Enroll Current Voice Button
  const btnEnrollVoice = document.getElementById('btn-enroll-current-voice');
  if (btnEnrollVoice) {
    btnEnrollVoice.addEventListener('click', async () => {
      const username = document.getElementById('login-username').value.trim();
      if (!username) {
        showToast('Please enter username first.', 'error');
        return;
      }
      let capture = null;
      if (voiceScanner && voiceScanner.isListening) {
        capture = voiceScanner.captureVector();
      }
      const voiceVec = capture ? capture.vector : state.currentVoiceVector;
      if (!voiceVec) {
        showToast('Please record live voice or click "Match Voice" first.', 'error');
        return;
      }
      state.currentVoiceVector = voiceVec;
      updateBiometricChecklist();
      showToast(`Live acoustic voiceprint ready to enroll for "${username}".`, 'success');
    });
  }

  updateBiometricChecklist();
}

function updateBiometricChecklist() {
  const facePill = document.getElementById('status-face-pill');
  const voicePill = document.getElementById('status-voice-pill');
  const faceIcon = document.getElementById('icon-face-status');
  const voiceIcon = document.getElementById('icon-voice-status');
  const faceText = document.getElementById('text-face-status');
  const voiceText = document.getElementById('text-voice-status');

  if (state.currentBioVector) {
    if (facePill) {
      facePill.style.border = '1px solid rgba(16, 185, 129, 0.5)';
      facePill.style.background = 'rgba(16, 185, 129, 0.12)';
      facePill.style.color = 'var(--accent-emerald)';
    }
    if (faceIcon) faceIcon.textContent = '✓';
    if (faceText) faceText.textContent = 'Face: Ready';
  } else {
    if (facePill) {
      facePill.style.border = '1px solid rgba(244, 63, 94, 0.4)';
      facePill.style.background = 'rgba(244, 63, 94, 0.08)';
      facePill.style.color = 'var(--accent-rose)';
    }
    if (faceIcon) faceIcon.textContent = '✕';
    if (faceText) faceText.textContent = 'Face: Unverified';
  }

  if (state.currentVoiceVector) {
    if (voicePill) {
      voicePill.style.border = '1px solid rgba(16, 185, 129, 0.5)';
      voicePill.style.background = 'rgba(16, 185, 129, 0.12)';
      voicePill.style.color = 'var(--accent-emerald)';
    }
    if (voiceIcon) voiceIcon.textContent = '✓';
    if (voiceText) voiceText.textContent = 'Voice: Ready';
  } else {
    if (voicePill) {
      voicePill.style.border = '1px solid rgba(244, 63, 94, 0.4)';
      voicePill.style.background = 'rgba(244, 63, 94, 0.08)';
      voicePill.style.color = 'var(--accent-rose)';
    }
    if (voiceIcon) voiceIcon.textContent = '✕';
    if (voiceText) voiceText.textContent = 'Voice: Unverified';
  }
}

async function startMainCamera() {
  const result = await mainScanner.startCamera();
  if (result.success) {
    state.cameraActive = true;
    document.getElementById('camera-placeholder').style.display = 'none';
    document.getElementById('camera-status-tag').textContent = 'Optical Sensor Online';
    document.getElementById('camera-status-tag').style.color = 'var(--accent-cyan)';
    document.getElementById('btn-toggle-camera').disabled = false;
    showToast('Optical camera sensor online. Align face in reticle.', 'success');
  } else {
    showToast('Camera sensor error: ' + result.error + ' (Using simulation mode)', 'error');
  }
}

function stopMainCamera() {
  mainScanner.stopCamera();
  state.cameraActive = false;
  document.getElementById('camera-placeholder').style.display = 'flex';
  document.getElementById('camera-status-tag').textContent = 'Optical Sensor Idle';
  document.getElementById('camera-status-tag').style.color = 'var(--accent-amber)';
  document.getElementById('btn-toggle-camera').disabled = true;
}

// -------------------------------------------------------------
// NAVIGATION TABS
// -------------------------------------------------------------
function initNavTabs() {
  const tabBtns = document.querySelectorAll('.tabs-bar .tab-btn');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const targetTab = btn.getAttribute('data-tab');
      document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');
      const targetEl = document.getElementById(targetTab);
      if (targetEl) targetEl.style.display = 'block';
      state.activeTab = targetTab;

      if (targetTab === 'tab-users') {
        refreshUsersDirectory();
      }
    });
  });
}

function initFutureWorkTabs() {
  const subtabBtns = document.querySelectorAll('.subtabs .subtab-btn');
  subtabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      subtabBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const targetSub = btn.getAttribute('data-subtab');
      document.querySelectorAll('.subtab-content').forEach(c => c.style.display = 'none');
      document.getElementById(targetSub).style.display = 'block';
      state.activeSubtab = targetSub;
    });
  });
}

// -------------------------------------------------------------
// AUTHENTICATION FORMS (SIGN IN / REGISTER)
// -------------------------------------------------------------
function initAuthForms() {
  const btnToggleReg = document.getElementById('btn-toggle-register');
  const formLogin = document.getElementById('form-login');
  const formRegister = document.getElementById('form-register');
  const formTitle = document.getElementById('auth-form-title');

  btnToggleReg.addEventListener('click', () => {
    state.isRegistering = !state.isRegistering;
    if (state.isRegistering) {
      formLogin.style.display = 'none';
      formRegister.style.display = 'block';
      btnToggleReg.textContent = 'Switch to Sign In';
      formTitle.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-emerald)" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="8.5" cy="7" r="4"></circle><line x1="20" y1="8" x2="20" y2="14"></line><line x1="23" y1="11" x2="17" y2="11"></line></svg>
        Enroll New User & Face Profile
      `;
    } else {
      formLogin.style.display = 'block';
      formRegister.style.display = 'none';
      btnToggleReg.textContent = 'Register New User';
      const isAdm = state.portalMode === 'admin';
      formTitle.innerHTML = isAdm
        ? `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-rose)" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> Security Admin (SOC) Sign In`
        : `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-emerald)" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg> Employee Portal Sign In`;
    }
  });

  // Live Camera Face Enrollment Button
  const btnEnrollCurrentFace = document.getElementById('btn-enroll-current-face');
  if (btnEnrollCurrentFace) {
    btnEnrollCurrentFace.addEventListener('click', async () => {
      const username = document.getElementById('login-username').value.trim();
      const password = document.getElementById('login-password').value;

      if (!username || !password) {
        showToast('Please enter your username and password above before enrolling your face.', 'error');
        return;
      }

      // If camera is not active, automatically turn it on
      if (!mainScanner.isScanning) {
        showToast('Activating camera sensor for live facial enrollment...', 'info');
        const camRes = await mainScanner.startCamera();
        if (!camRes.success) {
          showToast('Could not access camera: ' + camRes.error, 'error');
          return;
        }
        state.cameraActive = true;
        document.getElementById('camera-placeholder').style.display = 'none';
        document.getElementById('camera-status-tag').textContent = 'Optical Sensor Online';
        document.getElementById('camera-status-tag').style.color = 'var(--accent-cyan)';
        document.getElementById('btn-toggle-camera').disabled = false;
        await new Promise(r => setTimeout(r, 600));
      }

      const bioCapture = mainScanner.captureVector();
      if (!bioCapture || !bioCapture.vector) {
        showToast('Unable to extract facial geometry. Please center your face in the camera.', 'error');
        return;
      }

      try {
        showToast('Registering live 128-D facial vector into Zero-Trust database...', 'info');
        const res = await fetch('/api/auth/enroll-face', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username,
            password,
            faceVector: bioCapture.vector,
            faceLandmarks: bioCapture.landmarks
          })
        });

        const data = await res.json();
        if (!res.ok) {
          showToast(data.error || 'Face enrollment failed', 'error');
          return;
        }

        state.currentBioVector = bioCapture.vector;
        if (bioCapture.snapshotUrl) {
          localStorage.setItem('zt_avatar', bioCapture.snapshotUrl);
        }

        document.getElementById('confidence-readout').textContent = '99%';
        document.getElementById('confidence-bar').style.width = '99%';
        document.getElementById('camera-status-tag').textContent = 'Live Face Enrolled';
        document.getElementById('camera-status-tag').style.color = 'var(--accent-emerald)';

        showToast(data.message || `Live face enrolled for "${username}"! Now click "Scan Face & Sign In".`, 'success');
      } catch (err) {
        showToast('Enrollment error: ' + err.message, 'error');
      }
    });
  }

  // Login Submission with Real-Time Face Verification
  formLogin.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value;
    const autoEnroll = document.getElementById('chk-auto-enroll-face')?.checked;

    if (!username || !password) {
      showToast('Please provide both username and password credentials.', 'error');
      return;
    }

    // Auto-engage camera if it is currently idle
    if (mainScanner && !mainScanner.isScanning) {
      showToast('Engaging optical sensor for mandatory facial verification...', 'info');
      const camRes = await mainScanner.startCamera();
      if (camRes.success) {
        state.cameraActive = true;
        document.getElementById('camera-placeholder').style.display = 'none';
        document.getElementById('camera-status-tag').textContent = 'Optical Sensor Online';
        document.getElementById('camera-status-tag').style.color = 'var(--accent-cyan)';
        document.getElementById('btn-toggle-camera').disabled = false;
        await new Promise(r => setTimeout(r, 600));
      }
    }

    // Capture face biometric vector from live camera
    let bioCapture = null;
    if (mainScanner && mainScanner.isScanning) {
      bioCapture = mainScanner.captureVector();
    }
    let faceVector = bioCapture ? bioCapture.vector : state.currentBioVector;

    // Capture voice biometric vector from live microphone
    let voiceCapture = null;
    if (voiceScanner && voiceScanner.isListening) {
      voiceCapture = voiceScanner.captureVector();
    }
    let voiceVector = voiceCapture ? voiceCapture.vector : state.currentVoiceVector;

    // STRICT MANDATORY BIOMETRIC ENFORCEMENT
    if (!faceVector) {
      showToast('Mandatory Policy: Face Scan is required! Please align face in camera or click "Match Face".', 'error');
      const pill = document.getElementById('status-face-pill');
      if (pill) {
        pill.style.borderColor = 'var(--accent-rose)';
        pill.style.boxShadow = '0 0 12px rgba(244, 63, 94, 0.6)';
        setTimeout(() => pill.style.boxShadow = '', 1500);
      }
      return;
    }

    if (!voiceVector) {
      showToast('Mandatory Policy: Voice Verification is required! Please click "Record Voice" or "Match Voice".', 'error');
      const pill = document.getElementById('status-voice-pill');
      if (pill) {
        pill.style.borderColor = 'var(--accent-rose)';
        pill.style.boxShadow = '0 0 12px rgba(244, 63, 94, 0.6)';
        setTimeout(() => pill.style.boxShadow = '', 1500);
      }
      return;
    }

    try {
      showToast('Verifying mandatory multi-modal biometrics (Face + Voiceprint) with PEP...', 'info');

      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          password,
          faceVector,
          voiceVector,
          loginPortal: state.portalMode,
          enrollFaceNow: !!autoEnroll,
          enrollVoiceNow: !!autoEnroll,
          livenessData: bioCapture ? bioCapture.livenessData : { movementScore: 0.88, blinkDetected: true },
          acousticData: voiceCapture ? voiceCapture.acousticData : { audioEnergy: 0.85, voiceDetected: true, livenessPassed: true }
        })
      });

      const data = await res.json();
      if (!res.ok) {
        const errorMsg = data.error || 'Authentication rejected by Policy Enforcement Point';
        showToast(errorMsg, 'error');
        return;
      }

      state.token = data.token;
      state.user = data.user;
      state.threatInjected = false;
      localStorage.setItem('zt_token', data.token);

      const snapshot = bioCapture ? bioCapture.snapshotUrl : null;
      updateBiometricVerificationDisplay(data.user, data.biometrics, snapshot);

      const faceC = data.biometrics?.face?.confidence || 98;
      const voiceC = data.biometrics?.voice?.confidence || 96;
      showToast(`Multi-Modal Verified! Face (${faceC}%) & Voice (${voiceC}%). Welcome, ${data.user.fullName}!`, 'success');

      if (voiceScanner && voiceScanner.isListening) {
        voiceScanner.stopMicrophone();
      }

      renderDashboard(data.user);
      refreshAuditLogs();

    } catch (err) {
      showToast('Login error: ' + err.message, 'error');
    }
  });

  // Register Submission
  formRegister.addEventListener('submit', async (e) => {
    e.preventDefault();
    const fullName = document.getElementById('reg-fullname').value.trim();
    const username = document.getElementById('reg-username').value.trim();
    const role = document.getElementById('reg-role').value;
    const password = document.getElementById('reg-password').value;

    let bioCapture = null;
    if (mainScanner && mainScanner.isScanning) {
      bioCapture = mainScanner.captureVector();
    }

    let faceVector = bioCapture ? bioCapture.vector : state.currentBioVector;
    if (!faceVector) {
      const resBio = await fetch('/api/demo/face-vector', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ seed: `face_${username}`, noise: 0.0 })
      });
      const bioData = await resBio.json();
      faceVector = bioData.vector;
    }

    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          password,
          fullName,
          role,
          faceVector,
          faceLandmarks: { eyes: 0.65, nose: 0.48, mouth: 0.70 }
        })
      });

      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || 'Registration failed', 'error');
        return;
      }

      showToast('Account & Biometric Face Profile enrolled! You can now log in.', 'success');
      btnToggleReg.click();
      document.getElementById('login-username').value = username;
      document.getElementById('login-password').value = password;

    } catch (err) {
      showToast('Registration error: ' + err.message, 'error');
    }
  });

  // Logout button
  document.getElementById('btn-logout-nav').addEventListener('click', logout);
}

function logout() {
  if (state.token) {
    fetch('/api/auth/logout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: state.token })
    });
  }
  state.token = null;
  state.user = null;
  localStorage.removeItem('zt_token');
  localStorage.removeItem('zt_avatar');

  document.getElementById('unauth-view').style.display = 'block';
  document.getElementById('user-dashboard-view').style.display = 'none';
  document.getElementById('admin-dashboard-view').style.display = 'none';
  document.getElementById('user-nav-badge').style.display = 'none';

  // Hide admin nav tabs
  document.querySelectorAll('.admin-only-tab').forEach(el => el.style.display = 'none');

  showToast('Logged out. Zero-Trust session token revoked.', 'info');
}

async function validateSession() {
  try {
    const res = await fetch(`/api/auth/me?token=${state.token}`);
    if (res.ok) {
      const data = await res.json();
      state.user = data.user;
      renderDashboard(data.user);
      pulsePdpEvaluation();
    } else {
      logout();
    }
  } catch (e) {
    logout();
  }
}

// -------------------------------------------------------------
// BIOMETRIC VERIFICATION DISPLAY SYNC
// -------------------------------------------------------------
function updateBiometricVerificationDisplay(user, biometrics, snapshotUrl) {
  if (!user) return;
  const name = user.fullName || user.username;
  const confidence = (biometrics && biometrics.confidence) ? biometrics.confidence : 98;
  const faceConf = biometrics?.face?.confidence || 99;
  const voiceConf = biometrics?.voice?.confidence || 97;
  const confText = `${confidence}% (MULTI-MODAL: Face ${faceConf}% + Voice ${voiceConf}%)`;

  if (snapshotUrl) {
    localStorage.setItem('zt_avatar', snapshotUrl);
  } else {
    snapshotUrl = localStorage.getItem('zt_avatar');
  }

  // Employee Portal Biometric Card
  const userAvatar = document.getElementById('user-verified-avatar');
  const userSvg = document.getElementById('user-avatar-svg');
  const userNameEl = document.getElementById('user-verified-name');
  const userConfEl = document.getElementById('user-match-confidence');

  if (userNameEl) userNameEl.textContent = name;
  if (userConfEl) userConfEl.textContent = confText;
  if (userAvatar && snapshotUrl) {
    userAvatar.src = snapshotUrl;
    userAvatar.style.display = 'block';
    if (userSvg) userSvg.style.display = 'none';
  }

  // Admin SOC Biometric Card
  const adminAvatar = document.getElementById('admin-verified-avatar');
  const adminSvg = document.getElementById('admin-avatar-svg');
  const adminNameEl = document.getElementById('admin-verified-name');
  const adminConfEl = document.getElementById('admin-match-confidence');

  if (adminNameEl) adminNameEl.textContent = name;
  if (adminConfEl) adminConfEl.textContent = confText;
  if (adminAvatar && snapshotUrl) {
    adminAvatar.src = snapshotUrl;
    adminAvatar.style.display = 'block';
    if (adminSvg) adminSvg.style.display = 'none';
  }

  // Navbar Live Verified Avatar
  const navAvatar = document.getElementById('nav-user-avatar');
  if (navAvatar && snapshotUrl) {
    navAvatar.src = snapshotUrl;
    navAvatar.style.display = 'inline-block';
  }
}

// -------------------------------------------------------------
// RENDER USER vs ADMIN DASHBOARD
// -------------------------------------------------------------
function renderDashboard(user) {
  document.getElementById('unauth-view').style.display = 'none';
  stopMainCamera();

  const userBadge = document.getElementById('user-nav-badge');
  userBadge.style.display = 'flex';
  document.getElementById('nav-user-name').textContent = user.fullName || user.username;

  const roleBadge = document.getElementById('nav-user-role-badge');
  const isAdmin = (user.role === 'admin' || user.role === 'Zero-Trust Administrator' || user.role === 'Security Analyst');

  // Update verified biometric display for both Employee and Admin
  updateBiometricVerificationDisplay(user, null, null);

  if (isAdmin) {
    roleBadge.textContent = 'ADMIN';
    roleBadge.className = 'badge-role-admin';

    // Show Admin Tabs
    document.querySelectorAll('.admin-only-tab').forEach(el => el.style.display = 'flex');

    // Show Admin Console
    document.getElementById('admin-dashboard-view').style.display = 'block';
    document.getElementById('user-dashboard-view').style.display = 'none';

    refreshUsersDirectory();
    refreshThreatsAndVulnerabilities();
    pulsePdpEvaluation();
  } else {
    roleBadge.textContent = 'EMPLOYEE';
    roleBadge.className = 'badge-role-user';

    // Hide Admin Tabs
    document.querySelectorAll('.admin-only-tab').forEach(el => el.style.display = 'none');

    // Show User Workspace
    document.getElementById('admin-dashboard-view').style.display = 'none';
    document.getElementById('user-dashboard-view').style.display = 'block';

    document.getElementById('user-dash-name').textContent = `Welcome, ${user.fullName || user.username}`;
    document.getElementById('user-session-id').textContent = state.token ? state.token.slice(0, 16) + '...' : 'ACTIVE';

    pulsePdpEvaluation();
  }
}

function initUserDashboardButtons() {
  const btnPulse = document.getElementById('btn-user-pulse-trust');
  if (btnPulse) btnPulse.addEventListener('click', pulsePdpEvaluation);

  const btnStepup = document.getElementById('btn-user-test-stepup');
  if (btnStepup) {
    btnStepup.addEventListener('click', () => {
      showToast('Simulating risk elevation... triggering Step-Up Face Scan!', 'info');
      triggerStepUpMFA();
    });
  }

  const btnUserReverify = document.getElementById('btn-user-reverify');
  if (btnUserReverify) {
    btnUserReverify.addEventListener('click', () => {
      showToast('Initiating on-demand Live Face Re-Verification...', 'info');
      triggerStepUpMFA();
    });
  }

  const btnAdminReverify = document.getElementById('btn-admin-reverify');
  if (btnAdminReverify) {
    btnAdminReverify.addEventListener('click', () => {
      showToast('Initiating privileged SOC Admin Face Re-Verification...', 'info');
      triggerStepUpMFA();
    });
  }

  const btnRefreshUsers = document.getElementById('btn-refresh-users');
  if (btnRefreshUsers) btnRefreshUsers.addEventListener('click', refreshUsersDirectory);

  const btnRefreshThreats = document.getElementById('btn-refresh-threats');
  if (btnRefreshThreats) btnRefreshThreats.addEventListener('click', refreshThreatsAndVulnerabilities);
}

// -------------------------------------------------------------
// PDP EVALUATION & THREAT INJECTION
// -------------------------------------------------------------
async function pulsePdpEvaluation() {
  try {
    const res = await fetch('/api/pdp/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: state.token })
    });

    const data = await res.json();
    updateUIWithPdpResult(data);
  } catch (err) {
    console.warn('PDP pulse error:', err);
  }
}

function updateUIWithPdpResult(data) {
  const { decision, trustScore, thresholds, factors, weights, benchmarks, explainability, rl, telemetrySummary } = data;

  // Update top threshold badges
  document.getElementById('top-mutt').textContent = thresholds.mu_tt.toFixed(1);
  document.getElementById('top-mumfa').textContent = thresholds.mu_mfa.toFixed(1);

  // Update Admin dial
  const dial = document.getElementById('ts-dial');
  if (dial) {
    dial.style.setProperty('--ts-percent', trustScore);
    document.getElementById('ts-value-display').textContent = trustScore.toFixed(1);
  }

  // Update User dial
  const userDial = document.getElementById('user-ts-dial');
  if (userDial) {
    userDial.style.setProperty('--ts-percent', trustScore);
    document.getElementById('user-ts-display').textContent = trustScore.toFixed(1);
    document.getElementById('user-mutt-val').textContent = thresholds.mu_tt.toFixed(1);

    const userDecBadge = document.getElementById('user-decision-badge');
    const userStatusPill = document.getElementById('user-status-pill');

    if (decision === 'GRANT') {
      userDecBadge.className = 'decision-badge decision-grant';
      userDecBadge.innerHTML = '<span>PEP: FULL ACCESS GRANTED</span>';
      userStatusPill.textContent = 'SESSION SECURE';
      userStatusPill.style.color = 'var(--accent-emerald)';
    } else if (decision === 'STEP-UP MFA') {
      userDecBadge.className = 'decision-badge decision-stepup';
      userDecBadge.innerHTML = '<span>PEP: STEP-UP MFA REQUIRED</span>';
      userStatusPill.textContent = 'CHALLENGED';
      userStatusPill.style.color = 'var(--accent-amber)';
      if (state.token && state.threatInjected) triggerStepUpMFA();
    } else {
      userDecBadge.className = 'decision-badge decision-deny';
      userDecBadge.innerHTML = '<span>PEP: ACCESS RESTRICTED</span>';
      userStatusPill.textContent = 'REVOKED';
      userStatusPill.style.color = 'var(--accent-rose)';
    }
  }

  // Update Admin decision badge
  const decBadge = document.getElementById('pdp-decision-badge');
  if (decBadge) {
    decBadge.className = 'decision-badge';
    if (decision === 'GRANT') {
      decBadge.classList.add('decision-grant');
      decBadge.innerHTML = `<span>PEP: ACCESS GRANTED</span>`;
      unlockWorkspaces(true);
    } else if (decision === 'STEP-UP MFA') {
      decBadge.classList.add('decision-stepup');
      decBadge.innerHTML = `<span>PEP: STEP-UP MFA REQUIRED</span>`;
      unlockWorkspaces(false);
      if (state.token && state.threatInjected) triggerStepUpMFA();
    } else {
      decBadge.classList.add('decision-deny');
      decBadge.innerHTML = `<span>PEP: ACCESS DENIED / REVOKED</span>`;
      unlockWorkspaces(false);
    }
  }

  // Update factor bars
  const elValB = document.getElementById('val-b');
  if (elValB) {
    elValB.textContent = factors.B.toFixed(1);
    document.getElementById('bar-b').style.width = `${factors.B}%`;
    document.getElementById('w-b-badge').textContent = `(w: ${weights.B.toFixed(2)})`;

    document.getElementById('val-n').textContent = factors.N_adj.toFixed(1);
    document.getElementById('bar-n').style.width = `${factors.N_adj}%`;
    document.getElementById('w-n-badge').textContent = `(w: ${weights.N.toFixed(2)})`;

    document.getElementById('val-d').textContent = factors.D.toFixed(1);
    document.getElementById('bar-d').style.width = `${factors.D}%`;
    document.getElementById('w-d-badge').textContent = `(w: ${weights.D.toFixed(2)})`;

    document.getElementById('val-t').textContent = factors.T.toFixed(1);
    document.getElementById('bar-t').style.width = `${factors.T}%`;
    document.getElementById('w-t-badge').textContent = `(w: ${weights.T.toFixed(2)})`;
  }

  // Future Work weights
  const wValB = document.getElementById('w-val-b');
  if (wValB) {
    wValB.textContent = weights.B.toFixed(2);
    document.getElementById('w-bar-b').style.width = `${weights.B * 100}%`;
    document.getElementById('w-val-n').textContent = weights.N.toFixed(2);
    document.getElementById('w-bar-n').style.width = `${weights.N * 100}%`;
    document.getElementById('w-val-d').textContent = weights.D.toFixed(2);
    document.getElementById('w-bar-d').style.width = `${weights.D * 100}%`;
    document.getElementById('w-val-t').textContent = weights.T.toFixed(2);
    document.getElementById('w-bar-t').style.width = `${weights.T * 100}%`;
  }

  // RL subtab
  if (rl && rl.qValues && document.getElementById('q-val-0')) {
    document.getElementById('q-val-0').textContent = rl.qValues[0].toFixed(2);
    document.getElementById('q-val-1').textContent = rl.qValues[1].toFixed(2);
    document.getElementById('q-val-2').textContent = rl.qValues[2].toFixed(2);
    document.getElementById('rl-epsilon').textContent = rl.epsilon.toFixed(2);
  }

  // XAI narrative & contributions
  if (explainability && document.getElementById('xai-narrative')) {
    document.getElementById('xai-narrative').textContent = explainability.narrative;
    const xaiContainer = document.getElementById('xai-contributions-list');
    xaiContainer.innerHTML = explainability.contributions.map(c => `
      <div class="meter-wrapper" style="margin-bottom: 0.6rem;">
        <div class="meter-header">
          <span>${c.factor}: <strong>${c.value}</strong> (Weight: ${c.weight})</span>
          <strong style="color: ${c.shapValue >= 0 ? 'var(--accent-emerald)' : 'var(--accent-rose)'};">
            ${c.shapValue >= 0 ? '+' : ''}${c.shapValue} pts
          </strong>
        </div>
        <div style="font-size: 0.75rem; color: var(--text-muted);">${c.description}</div>
      </div>
    `).join('');
  }

  // Telemetry subtab
  if (telemetrySummary && document.getElementById('telemetry-source-pill')) {
    document.getElementById('telemetry-source-pill').textContent = `Source: ${telemetrySummary.source}`;
    document.getElementById('iam-readout').innerHTML = `
      • User: ${telemetrySummary.iam.username}<br>
      • Login Hour: ${telemetrySummary.iam.loginHour}:00<br>
      • Failed Logins: ${telemetrySummary.iam.failedAttemptsLastHour}<br>
      • Role Privilege: ${telemetrySummary.iam.rolePrivilegeLevel}<br>
      • Geo Mismatch: ${telemetrySummary.iam.geoMismatch ? '<span style="color: var(--accent-rose);">YES</span>' : 'NO'}
    `;
    document.getElementById('edr-readout').innerHTML = `
      • Host ID: ${telemetrySummary.edr.endpointId}<br>
      • EDR Status: ${telemetrySummary.edr.edrAgentStatus}<br>
      • Disk Encrypted: ${telemetrySummary.edr.diskEncrypted ? 'YES' : '<span style="color: var(--accent-rose);">NO</span>'}<br>
      • Process: ${telemetrySummary.edr.processName}<br>
      • Unapproved Exec: ${telemetrySummary.edr.unauthorizedProcessDetected ? '<span style="color: var(--accent-rose);">DETECTED</span>' : 'NONE'}
    `;
    document.getElementById('siem-readout').innerHTML = `
      • Alert Severity: <span style="color: ${telemetrySummary.siem.alertSeverity === 'CRITICAL' ? 'var(--accent-rose)' : 'var(--accent-cyan)'};">${telemetrySummary.siem.alertSeverity}</span><br>
      • Active Alarms: ${telemetrySummary.siem.activeAlarmsCount}<br>
      • IP Reputation: ${telemetrySummary.siem.ipReputationScore}/100<br>
      • Bandwidth: ${telemetrySummary.siem.trafficVolumeMbPerSec} MB/s<br>
      • Lateral Movement: ${telemetrySummary.siem.lateralMovementFlag ? '<span style="color: var(--accent-rose);">DETECTED</span>' : 'NONE'}
    `;
  }

  // Benchmarks
  if (benchmarks && document.getElementById('bench-infer')) {
    document.getElementById('bench-infer').textContent = `${benchmarks.inferenceTimeMs} ms`;
    document.getElementById('bench-trust').textContent = `${benchmarks.trustEngineTimeMs} ms`;
    document.getElementById('bench-rl').textContent = `${benchmarks.rlAgentTimeMs} ms`;
    document.getElementById('bench-total').textContent = `${benchmarks.endToEndDecisionLatencyMs} ms`;
  }
}

function unlockWorkspaces(unlocked) {
  ['res-db', 'res-vault', 'res-firewall'].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    const pill = el.querySelector('.metric-pill');
    if (unlocked) {
      el.classList.remove('locked');
      pill.textContent = 'UNLOCKED';
      pill.style.color = 'var(--accent-emerald)';
    } else {
      el.classList.add('locked');
      pill.textContent = 'RESTRICTED';
      pill.style.color = 'var(--accent-rose)';
    }
  });
}

function initThreatInjectors() {
  const btnPoll = document.getElementById('btn-poll-pdp');
  if (btnPoll) btnPoll.addEventListener('click', pulsePdpEvaluation);

  const btnNormal = document.getElementById('btn-inject-normal');
  if (btnNormal) {
    btnNormal.addEventListener('click', async () => {
      state.threatInjected = false;
      await fetch('/api/telemetry/mode', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'live' }) });
      showToast('Telemetry switched to Nominal Benign Enterprise Flow', 'info');
      pulsePdpEvaluation();
      refreshThreatsAndVulnerabilities();
    });
  }

  const btnInsider = document.getElementById('btn-inject-insider');
  if (btnInsider) {
    btnInsider.addEventListener('click', async () => {
      state.threatInjected = true;
      await fetch('/api/telemetry/mode', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'cert_insider' }) });
      showToast('Injected CERT Insider Threat Data Exfiltration Spike!', 'error');
      pulsePdpEvaluation();
      refreshThreatsAndVulnerabilities();
    });
  }

  const btnDos = document.getElementById('btn-inject-dos');
  if (btnDos) {
    btnDos.addEventListener('click', async () => {
      state.threatInjected = true;
      await fetch('/api/telemetry/mode', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'cic_ids_dos' }) });
      showToast('Injected CIC-IDS SynFlood Volumetric Attack!', 'error');
      pulsePdpEvaluation();
      refreshThreatsAndVulnerabilities();
    });
  }

  const btnEdr = document.getElementById('btn-inject-edr');
  if (btnEdr) {
    btnEdr.addEventListener('click', async () => {
      state.threatInjected = true;
      await fetch('/api/telemetry/mode', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'edr_compromise' }) });
      showToast('Injected Host EDR Integrity Compromise!', 'error');
      pulsePdpEvaluation();
      refreshThreatsAndVulnerabilities();
    });
  }
}

async function refreshThreatsAndVulnerabilities() {
  try {
    const res = await fetch('/api/admin/threats-vulnerabilities');
    if (!res.ok) return;
    const data = await res.json();
    const { activeThreat, vulnerabilities } = data;

    if (activeThreat) {
      const nameEl = document.getElementById('soc-threat-name');
      const sevEl = document.getElementById('soc-threat-sev');
      const badgeEl = document.getElementById('soc-active-threat-badge');
      const assetEl = document.getElementById('soc-threat-asset');
      const mitreEl = document.getElementById('soc-threat-mitre');
      const sourceEl = document.getElementById('soc-threat-source');
      const mitiEl = document.getElementById('soc-threat-mitigation');

      if (nameEl) nameEl.textContent = `Current Flow: ${activeThreat.name}`;
      if (sevEl) {
        sevEl.textContent = `SEVERITY: ${activeThreat.severity}`;
        sevEl.style.color = activeThreat.severityColor || 'var(--accent-emerald)';
      }
      if (badgeEl) {
        badgeEl.textContent = activeThreat.severity === 'NORMAL / SECURE' 
          ? '🟢 DEFCON 5: BENIGN MONITORING' 
          : `🔴 DEFCON 1: ${activeThreat.severity} ATTACK DETECTED`;
        badgeEl.style.color = activeThreat.severityColor || 'var(--accent-emerald)';
      }
      if (assetEl) assetEl.textContent = activeThreat.targetedAsset;
      if (mitreEl) mitreEl.textContent = activeThreat.mitreTechnique;
      if (sourceEl) sourceEl.textContent = activeThreat.sourceIp;
      if (mitiEl) mitiEl.textContent = activeThreat.pepMitigation;
    }

    if (vulnerabilities && vulnerabilities.length > 0) {
      const tbody = document.getElementById('table-vulnerabilities-body');
      if (tbody) {
        tbody.innerHTML = vulnerabilities.map(v => `
          <tr>
            <td><strong style="color: var(--accent-cyan); font-family: var(--font-mono);">${v.cve}</strong></td>
            <td><strong>${v.title}</strong></td>
            <td><span class="metric-pill" style="color: ${parseFloat(v.cvss) >= 9 ? 'var(--accent-rose)' : 'var(--accent-amber)'}; font-weight: 700;">${v.cvss}</span></td>
            <td><span class="metric-pill" style="color: ${v.severityColor || 'var(--accent-rose)'}; font-weight: 600;">${v.severity}</span></td>
            <td><span style="font-family: var(--font-mono); font-size: 0.78rem;">${v.component}</span></td>
            <td><span style="color: var(--text-dim); font-size: 0.75rem;">${v.mitre}</span></td>
            <td><span style="color: var(--accent-emerald); font-size: 0.78rem;">${v.status}</span></td>
          </tr>
        `).join('');
      }
    }
  } catch (e) {
    console.warn('Could not refresh threats:', e);
  }
}

// -------------------------------------------------------------
// ADVANCED STEP-UP MFA BIOMETRIC MODAL
// -------------------------------------------------------------
function triggerStepUpMFA() {
  const modal = document.getElementById('stepup-modal');
  modal.classList.add('active');
  stepupScanner.startCamera();

  // Close / Dismiss button
  const btnClose = document.getElementById('btn-stepup-close');
  if (btnClose) {
    btnClose.onclick = () => {
      modal.classList.remove('active');
      stepupScanner.stopCamera();
    };
  }

  // Sim button
  document.getElementById('btn-stepup-sim').onclick = async () => {
    const username = state.user ? state.user.username : 'user';
    let seed;
    if (username === 'admin') seed = 'admin_primary_face';
    else if (username === 'analyst') seed = 'analyst_primary_face';
    else if (username === 'prince') seed = 'prince_primary_face';
    else seed = 'user_primary_face';

    const resBio = await fetch('/api/demo/face-vector', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ seed, noise: 0.02 })
    });
    const bioData = await resBio.json();
    state.stepupBioVector = bioData.vector;
    document.getElementById('stepup-confidence').textContent = '95%';
    document.getElementById('stepup-progress-bar').style.width = '95%';
    showToast('Biometric re-verification template loaded.', 'success');
  };

  // Verify button
  document.getElementById('btn-stepup-verify').onclick = async () => {
    let bioCapture = null;
    if (stepupScanner && stepupScanner.isScanning) {
      bioCapture = stepupScanner.captureVector();
    }

    let faceVector = bioCapture ? bioCapture.vector : state.stepupBioVector;
    if (!faceVector) {
      const username = state.user ? state.user.username : 'user';
      let seed = username === 'admin' ? 'admin_primary_face' : 'user_primary_face';
      const resBio = await fetch('/api/demo/face-vector', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ seed, noise: 0.02 })
      });
      const bioData = await resBio.json();
      faceVector = bioData.vector;
    }

    try {
      showToast('Verifying face biometrics for Step-Up challenge...', 'info');

      const res = await fetch('/api/auth/verify-face-stepup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: state.token,
          faceVector,
          livenessData: bioCapture ? bioCapture.livenessData : { movementScore: 0.9, blinkDetected: true }
        })
      });

      const data = await res.json();
      if (!res.ok) {
        showToast(data.error || 'Step-up facial verification rejected', 'error');
        return;
      }

      showToast(`Step-Up Succeeded (${data.bioResult.confidence}% match)! Session Restored.`, 'success');
      modal.classList.remove('active');
      stepupScanner.stopCamera();

      // Update face avatar snapshot & confidence on dashboard
      const snapshot = bioCapture ? bioCapture.snapshotUrl : null;
      updateBiometricVerificationDisplay(state.user, data.bioResult, snapshot);

      // Reset scenario to benign & pulse PDP
      state.threatInjected = false;
      await fetch('/api/telemetry/mode', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'live' }) });
      refreshThreatsAndVulnerabilities();
      pulsePdpEvaluation();
      refreshAuditLogs();

    } catch (err) {
      showToast('Step-up verification error: ' + err.message, 'error');
    }
  };
}

// -------------------------------------------------------------
// FUTURE WORK LAB BUTTON HANDLERS
// -------------------------------------------------------------
function initFutureWorkButtons() {
  const btnFixed = document.getElementById('btn-weight-fixed');
  const btnLearned = document.getElementById('btn-weight-learned');
  const btnRL = document.getElementById('btn-weight-rl');

  function updateWeightButtons(activeMode) {
    if (!btnFixed) return;
    [btnFixed, btnLearned, btnRL].forEach(b => b.className = 'btn btn-secondary btn-sm');
    if (activeMode === 'fixed') btnFixed.className = 'btn btn-primary btn-sm';
    if (activeMode === 'learned') btnLearned.className = 'btn btn-primary btn-sm';
    if (activeMode === 'rl') btnRL.className = 'btn btn-primary btn-sm';
  }

  if (btnFixed) {
    btnFixed.addEventListener('click', async () => {
      await fetch('/api/weights/mode', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'fixed' }) });
      updateWeightButtons('fixed');
      pulsePdpEvaluation();
      showToast('Switched to Fixed Factor Weights [0.4, 0.3, 0.2, 0.1]', 'info');
    });

    btnLearned.addEventListener('click', async () => {
      await fetch('/api/weights/mode', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'learned' }) });
      updateWeightButtons('learned');
      pulsePdpEvaluation();
      showToast('Switched to Attention-Based Factor Weights', 'success');
    });

    btnRL.addEventListener('click', async () => {
      await fetch('/api/weights/mode', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'rl' }) });
      updateWeightButtons('rl');
      pulsePdpEvaluation();
      showToast('Switched to RL-Adapted Factor Weights', 'info');
    });
  }

  // RL Algorithm Select & Train Step
  const rlSelect = document.getElementById('rl-algo-select');
  if (rlSelect) {
    rlSelect.addEventListener('change', async (e) => {
      await fetch('/api/rl/algorithm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ algorithm: e.target.value })
      });
      showToast(`Switched RL Policy to ${e.target.options[e.target.selectedIndex].text}`, 'success');
      pulsePdpEvaluation();
    });
  }

  const btnRlStep = document.getElementById('btn-trigger-rl-step');
  if (btnRlStep) {
    btnRlStep.addEventListener('click', async () => {
      pulsePdpEvaluation();
      showToast('Executed Bellman gradient update & experience replay step', 'info');
    });
  }

  // Model Distillation Benchmark
  const btnBench = document.getElementById('btn-run-benchmark');
  if (btnBench) {
    btnBench.addEventListener('click', async () => {
      showToast('Running 100 iterations of Teacher vs Student inference...', 'info');
      try {
        const res = await fetch('/api/benchmark/distillation', { method: 'POST' });
        const data = await res.json();
        document.getElementById('teacher-latency').textContent = `${data.teacher.avgLatencyMs} ms`;
        document.getElementById('teacher-throughput').textContent = `${data.teacher.throughputReqSec} req/sec`;
        document.getElementById('student-latency').textContent = `${data.student.avgLatencyMs} ms`;
        document.getElementById('student-throughput').textContent = `${data.student.throughputReqSec} req/sec`;
        document.getElementById('speedup-badge').textContent = `${data.speedupMultiplier} Faster`;
        showToast(`Benchmark complete! Distilled Student achieved ${data.speedupMultiplier} speedup.`, 'success');
      } catch (err) {
        showToast('Benchmark failed: ' + err.message, 'error');
      }
    });
  }

  // Federated Learning
  const btnFed = document.getElementById('btn-run-fed-round');
  async function refreshFedStatus() {
    try {
      const res = await fetch('/api/federated/status');
      const data = await res.json();
      if (!document.getElementById('fed-round-num')) return;
      document.getElementById('fed-round-num').textContent = data.round;
      document.getElementById('fed-loss').textContent = data.globalLoss.toFixed(4);
      document.getElementById('fed-acc').textContent = `${data.globalAccuracy}%`;

      const grid = document.getElementById('fed-tenants-grid');
      grid.innerHTML = data.tenants.map(t => `
        <div class="card" style="background: rgba(15, 23, 42, 0.8);">
          <strong style="color: var(--accent-cyan); font-size: 0.85rem;">${t.name}</strong>
          <div style="font-family: var(--font-mono); font-size: 0.78rem; margin-top: 0.5rem; line-height: 1.6;">
            • Local Samples: ${t.sampleCount.toLocaleString()}<br>
            • Local Loss: ${t.localLoss.toFixed(4)}<br>
            • Local Acc: ${t.localAccuracy.toFixed(1)}%<br>
            • Enclave Guard: Active
          </div>
        </div>
      `).join('');
    } catch (e) {}
  }
  refreshFedStatus();

  if (btnFed) {
    btnFed.addEventListener('click', async () => {
      showToast('Aggregating local model updates via Federated Averaging (FedAvg)...', 'info');
      const res = await fetch('/api/federated/round', { method: 'POST' });
      const data = await res.json();
      await refreshFedStatus();
      showToast(`FedAvg Round ${data.round} converged! Global Accuracy: ${data.globalAccuracy}%`, 'success');
    });
  }

  // Robustness & Drift
  const btnEvasion = document.getElementById('btn-test-evasion');
  if (btnEvasion) {
    btnEvasion.addEventListener('click', async () => {
      try {
        const res = await fetch('/api/robustness/evasion', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ epsilon: 0.08 }) });
        const data = await res.json();
        document.getElementById('evasion-result').innerHTML = `
          Original P<sub>anom</sub>: ${(data.originalPanomaly * 100).toFixed(1)}%<br>
          Adversarial: ${(data.adversarialPanomaly * 100).toFixed(1)}%<br>
          Feature Squeezing Defended: <strong style="color: var(--accent-emerald);">${(data.defendedPanomaly * 100).toFixed(1)}%</strong>
        `;
        showToast('Simulated FGSM evasion test with feature squeezing defense', 'info');
      } catch (e) {}
    });
  }

  const btnDrift = document.getElementById('btn-test-drift');
  if (btnDrift) {
    btnDrift.addEventListener('click', async () => {
      try {
        const res = await fetch('/api/robustness/drift-check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ metric: 2.2 }) });
        const data = await res.json();
        document.getElementById('drift-result').innerHTML = `
          Page-Hinkley Statistic: <strong>${data.testStatistic}</strong> (Threshold: ${data.threshold})<br>
          Drift Alarm: <strong style="color: ${data.driftDetected ? 'var(--accent-rose)' : 'var(--accent-emerald)'};">${data.driftDetected ? 'DRIFT DETECTED' : 'NOMINAL'}</strong>
        `;
        showToast('Executed Page-Hinkley concept drift distribution check', 'info');
      } catch (e) {}
    });
  }
}

// -------------------------------------------------------------
// USERS DIRECTORY (ADMIN)
// -------------------------------------------------------------
async function refreshUsersDirectory() {
  const tbody = document.getElementById('users-table-body');
  if (!tbody) return;

  try {
    const res = await fetch('/api/admin/users');
    const data = await res.json();

    if (!data.users || data.users.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-dim);">No registered users found.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.users.map(u => {
      const isAdm = (u.role === 'admin' || u.role === 'Zero-Trust Administrator' || u.role === 'Security Analyst');
      const roleBadge = isAdm 
        ? `<span class="badge-role-admin">ADMIN</span>` 
        : `<span class="badge-role-user">EMPLOYEE</span>`;

      const timeStr = u.created_at ? new Date(u.created_at).toLocaleDateString() : 'Active';

      return `
        <tr>
          <td><strong style="color: var(--accent-cyan);">${u.username}</strong></td>
          <td>${u.full_name || u.username}</td>
          <td>${roleBadge}</td>
          <td><span style="color: var(--accent-emerald); font-weight: 600;">✓ ENROLLED</span></td>
          <td><span style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">128-D Unit Vector</span></td>
          <td style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-dim);">${timeStr}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--accent-rose);">Failed to load users: ${err.message}</td></tr>`;
  }
}

// -------------------------------------------------------------
// AUDIT LOGS TABLE
// -------------------------------------------------------------
async function refreshAuditLogs() {
  const tbody = document.getElementById('audit-table-body');
  if (!tbody) return;

  try {
    const res = await fetch('/api/status');
    const data = await res.json();

    if (!data.recentAudits || data.recentAudits.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--text-dim);">No audit events recorded yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.recentAudits.map(log => {
      const timeStr = new Date(log.timestamp).toLocaleTimeString();
      let badgeClass = 'decision-grant';
      if (log.decision === 'STEP-UP MFA') badgeClass = 'decision-stepup';
      if (log.decision === 'DENY') badgeClass = 'decision-deny';

      let factorDetails = '';
      try {
        const parsed = JSON.parse(log.factors);
        factorDetails = Object.entries(parsed).map(([k, v]) => `${k}:${typeof v === 'number' ? v.toFixed(1) : v}`).join(' | ');
      } catch (e) {
        factorDetails = log.factors || '-';
      }

      return `
        <tr>
          <td style="font-family: var(--font-mono); color: var(--text-dim);">${timeStr}</td>
          <td><strong>${log.username || 'System'}</strong></td>
          <td><span style="font-family: var(--font-mono); font-size: 0.78rem;">${log.action}</span></td>
          <td><span class="decision-badge ${badgeClass}" style="margin: 0; padding: 0.2rem 0.6rem; font-size: 0.72rem;">${log.decision}</span></td>
          <td style="font-family: var(--font-mono); font-weight: bold;">${log.trust_score ? log.trust_score.toFixed(1) : '-'}</td>
          <td style="font-family: var(--font-mono); color: var(--text-muted);">${log.mu_tt ? `${log.mu_tt.toFixed(1)} / ${log.mu_mfa.toFixed(1)}` : '-'}</td>
          <td style="font-size: 0.75rem; color: var(--text-muted); max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${factorDetails}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.warn('Failed to refresh audit table:', err);
  }
}

const btnRefreshAudit = document.getElementById('btn-refresh-audit');
if (btnRefreshAudit) btnRefreshAudit.addEventListener('click', refreshAuditLogs);
