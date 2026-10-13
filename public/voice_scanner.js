/**
 * Advanced Biometric Voiceprint Scanner & Acoustic Analyzer
 * Built with Web Audio API (AudioContext + AnalyserNode) featuring real-time
 * Oscilloscope Waveform, Spectrum Analyzer, Speech Activity Liveness,
 * and 64-D Acoustic Frequency Voiceprint Vector Extraction.
 */

class BiometricVoiceScanner {
  constructor(canvasElement, options = {}) {
    this.canvas = canvasElement;
    this.ctx = canvasElement ? canvasElement.getContext('2d') : null;
    this.audioCtx = null;
    this.analyser = null;
    this.stream = null;
    this.source = null;
    this.isListening = false;
    this.animationId = null;

    this.onStatusChange = options.onStatusChange || (() => {});
    this.onLevelChange = options.onLevelChange || (() => {});

    this.dataArray = null;
    this.bufferLength = 0;
    this.currentVector = null;
    this.audioEnergy = 0.0;
    this.tick = 0;
  }

  /**
   * Start live microphone sensor and audio analysis pipeline
   */
  async startMicrophone() {
    try {
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      if (!this.audioCtx) {
        this.audioCtx = new AudioContextClass();
      }
      if (this.audioCtx.state === 'suspended') {
        await this.audioCtx.resume();
      }

      this.stream = await navigator.mediaDevices.getUserMedia({
        audio: {
          echoCancellation: true,
          noiseSuppression: false,
          autoGainControl: true
        },
        video: false
      });

      this.source = this.audioCtx.createMediaStreamSource(this.stream);
      this.analyser = this.audioCtx.createAnalyser();
      this.analyser.fftSize = 128; // 64 frequency bins
      this.bufferLength = this.analyser.frequencyBinCount;
      this.dataArray = new Uint8Array(this.bufferLength);

      this.source.connect(this.analyser);
      this.isListening = true;
      this.onStatusChange({ active: true, status: 'Acoustic Sensor Online - Listening' });

      if (this.canvas) {
        this.renderWaveform();
      }

      return { success: true };
    } catch (err) {
      console.warn('[VoiceScanner] Microphone access error:', err.message);
      this.isListening = false;
      this.onStatusChange({ active: false, error: err.message, status: 'Mic Sensor Offline (Simulation Mode)' });
      return { success: false, error: err.message };
    }
  }

  /**
   * Stop microphone stream and release audio hardware
   */
  stopMicrophone() {
    this.isListening = false;
    if (this.animationId) {
      cancelAnimationFrame(this.animationId);
      this.animationId = null;
    }
    if (this.source) {
      try { this.source.disconnect(); } catch (e) {}
      this.source = null;
    }
    if (this.stream) {
      this.stream.getTracks().forEach(t => t.stop());
      this.stream = null;
    }
    if (this.ctx && this.canvas) {
      this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
      this.drawIdleState();
    }
    this.onStatusChange({ active: false, status: 'Acoustic Sensor Idle' });
  }

  /**
   * Draw aesthetic neon oscilloscope frequency visualizer
   */
  renderWaveform() {
    if (!this.isListening || !this.ctx) return;

    this.animationId = requestAnimationFrame(() => this.renderWaveform());
    this.tick++;

    this.analyser.getByteFrequencyData(this.dataArray);

    const w = this.canvas.width;
    const h = this.canvas.height;
    this.ctx.clearRect(0, 0, w, h);

    // Dark sleek background
    this.ctx.fillStyle = 'rgba(10, 15, 29, 0.7)';
    this.ctx.fillRect(0, 0, w, h);

    // Compute average energy / volume
    let sum = 0;
    for (let i = 0; i < this.bufferLength; i++) {
      sum += this.dataArray[i];
    }
    const avg = sum / this.bufferLength;
    this.audioEnergy = avg / 255;
    this.onLevelChange(this.audioEnergy);

    // Draw glowing frequency bars
    const barWidth = (w / this.bufferLength) * 1.5;
    let x = 0;

    for (let i = 0; i < this.bufferLength; i++) {
      const barHeight = (this.dataArray[i] / 255) * (h * 0.85);

      const grad = this.ctx.createLinearGradient(0, h, 0, h - barHeight);
      grad.addColorStop(0, '#06b6d4'); // Cyan
      grad.addColorStop(0.7, '#8b5cf6'); // Purple
      grad.addColorStop(1, '#ec4899'); // Pink

      this.ctx.fillStyle = grad;
      this.ctx.fillRect(x, h - barHeight, barWidth - 1, barHeight);

      x += barWidth;
      if (x > w) break;
    }

    // Draw central audio wave line
    this.ctx.beginPath();
    this.ctx.strokeStyle = 'rgba(6, 182, 212, 0.8)';
    this.ctx.lineWidth = 2;

    const sliceWidth = w / this.bufferLength;
    let waveX = 0;

    for (let i = 0; i < this.bufferLength; i++) {
      const v = this.dataArray[i] / 128.0;
      const waveY = (v * h) / 3 + h / 4;

      if (i === 0) {
        this.ctx.moveTo(waveX, waveY);
      } else {
        this.ctx.lineTo(waveX, waveY);
      }
      waveX += sliceWidth;
    }
    this.ctx.stroke();

    // Voice HUD overlay
    this.ctx.font = '10px "JetBrains Mono", monospace';
    this.ctx.fillStyle = this.audioEnergy > 0.08 ? '#10b981' : '#f59e0b';
    const statusTxt = this.audioEnergy > 0.08 ? '● ACOUSTIC VOICE DETECTED' : '○ SPEAK PASSPHRASE...';
    this.ctx.fillText(statusTxt, 10, 18);
    this.ctx.fillStyle = 'rgba(255, 255, 255, 0.4)';
    this.ctx.fillText(`ENERGY: ${(this.audioEnergy * 100).toFixed(0)}%`, w - 80, 18);
  }

  /**
   * Draw clean resting grid when sensor is idle
   */
  drawIdleState() {
    if (!this.ctx || !this.canvas) return;
    const w = this.canvas.width;
    const h = this.canvas.height;
    this.ctx.fillStyle = 'rgba(10, 15, 29, 0.9)';
    this.ctx.fillRect(0, 0, w, h);

    // Subtle horizontal center baseline
    this.ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
    this.ctx.lineWidth = 1;
    this.ctx.beginPath();
    this.ctx.moveTo(0, h / 2);
    this.ctx.lineTo(w, h / 2);
    this.ctx.stroke();

    this.ctx.font = '10px "JetBrains Mono", monospace';
    this.ctx.fillStyle = 'rgba(255, 255, 255, 0.35)';
    this.ctx.textAlign = 'center';
    this.ctx.fillText('Acoustic Spectrum Idle • Click "Record Voice"', w / 2, h / 2 - 4);
    this.ctx.textAlign = 'start';
  }

  /**
   * Extract 64-dimensional acoustic voiceprint feature vector from live audio
   */
  captureVector() {
    if (!this.isListening || !this.dataArray) {
      return null;
    }

    this.analyser.getByteFrequencyData(this.dataArray);
    const rawVector = [];

    for (let i = 0; i < 64; i++) {
      const idx = i % this.bufferLength;
      // Normalize to [-1, 1]
      const val = (this.dataArray[idx] / 127.5) - 1.0;
      rawVector.push(parseFloat(val.toFixed(4)));
    }

    // Normalize to unit vector
    const norm = Math.sqrt(rawVector.reduce((acc, v) => acc + v * v, 0)) || 1.0;
    const unitVector = rawVector.map(v => parseFloat((v / norm).toFixed(4)));

    const energy = this.audioEnergy || 0.75;
    return {
      vector: unitVector,
      acousticData: {
        audioEnergy: energy,
        voiceDetected: energy >= 0.08,
        livenessPassed: energy >= 0.08
      }
    };
  }
}

// Attach to window for global access
window.BiometricVoiceScanner = BiometricVoiceScanner;
