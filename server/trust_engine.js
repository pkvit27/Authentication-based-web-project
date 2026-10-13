// 4-Factor Continuous Trust Score Engine
// Implements Fixed Weights, Attention-Learned Weights, and RL-Adapted Weights (Requirement 2)

class TrustEngine {
  constructor(mode = 'learned') {
    // Modes: 'fixed', 'learned' (Attention-based), 'rl' (RL-Adapted)
    this.mode = mode;
    this.fixedWeights = { B: 0.40, N: 0.30, D: 0.20, T: 0.10 };
    this.rlAdaptedWeights = { B: 0.35, N: 0.35, D: 0.20, T: 0.10 };
  }

  setMode(mode) {
    if (['fixed', 'learned', 'rl'].includes(mode)) {
      this.mode = mode;
    }
  }

  /**
   * Compute factor attention weights dynamically (Requirement 2: Attention across factors)
   * High-variance or critical-risk factors receive elevated attention weights
   */
  computeAttentionWeights(B, N_adj, D, T) {
    // Invert scores to represent risk salience: high risk = high attention
    const riskScores = [
      (100 - B) / 100,
      (100 - N_adj) / 100,
      (100 - D) / 100,
      (100 - T) / 100
    ];

    // Compute scaled softmax with baseline bias
    const baseLogits = [0.4, 0.3, 0.2, 0.1];
    const temperature = 0.8;
    const logits = riskScores.map((r, i) => (baseLogits[i] * 1.5 + r * 2.0) / temperature);

    const maxLogit = Math.max(...logits);
    const exps = logits.map(l => Math.exp(l - maxLogit));
    const sumExps = exps.reduce((a, b) => a + b, 0);

    const weights = exps.map(e => e / sumExps);

    return {
      B: parseFloat(weights[0].toFixed(3)),
      N: parseFloat(weights[1].toFixed(3)),
      D: parseFloat(weights[2].toFixed(3)),
      T: parseFloat(weights[3].toFixed(3))
    };
  }

  /**
   * Calculate Trust Score
   * @param {Object} factors - { B, N_raw, D, T } each in [0, 100]
   * @param {number} p_anomaly - deep learning anomaly probability in [0, 1]
   */
  calculateTrustScore(factors, p_anomaly) {
    const B = Math.max(0, Math.min(100, factors.B !== undefined ? factors.B : 85.0));
    const N_raw = Math.max(0, Math.min(100, factors.N_raw !== undefined ? factors.N_raw : 90.0));
    const D = Math.max(0, Math.min(100, factors.D !== undefined ? factors.D : 80.0));
    const T = Math.max(0, Math.min(100, factors.T !== undefined ? factors.T : 85.0));

    // Equation 3 from Paper: Nadj = Nraw * (1.0 - Panomaly)
    const N_adj = parseFloat((N_raw * (1.0 - p_anomaly)).toFixed(2));

    let activeWeights;
    if (this.mode === 'fixed') {
      activeWeights = { ...this.fixedWeights };
    } else if (this.mode === 'learned') {
      activeWeights = this.computeAttentionWeights(B, N_adj, D, T);
    } else {
      activeWeights = { ...this.rlAdaptedWeights };
    }

    // Equation 4 from Paper: TS = wB * B + wN * Nadj + wD * D + wT * T
    const TS_raw = (activeWeights.B * B) + 
                   (activeWeights.N * N_adj) + 
                   (activeWeights.D * D) + 
                   (activeWeights.T * T);

    const TS = Math.max(0.0, Math.min(100.0, parseFloat(TS_raw.toFixed(2))));

    return {
      TS,
      factors: {
        B: parseFloat(B.toFixed(2)),
        N_raw: parseFloat(N_raw.toFixed(2)),
        N_adj: parseFloat(N_adj.toFixed(2)),
        D: parseFloat(D.toFixed(2)),
        T: parseFloat(T.toFixed(2))
      },
      p_anomaly: parseFloat(p_anomaly.toFixed(4)),
      weights: activeWeights,
      mode: this.mode
    };
  }

  updateRLWeights(newWeights) {
    if (newWeights && newWeights.B && newWeights.N && newWeights.D && newWeights.T) {
      const sum = newWeights.B + newWeights.N + newWeights.D + newWeights.T;
      this.rlAdaptedWeights = {
        B: parseFloat((newWeights.B / sum).toFixed(3)),
        N: parseFloat((newWeights.N / sum).toFixed(3)),
        D: parseFloat((newWeights.D / sum).toFixed(3)),
        T: parseFloat((newWeights.T / sum).toFixed(3))
      };
    }
  }
}

const defaultTrustEngine = new TrustEngine('learned');

module.exports = {
  TrustEngine,
  defaultTrustEngine
};
