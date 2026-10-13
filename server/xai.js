// Explainable AI (XAI) Engine (Requirement 5)
// Implements SHAP-style Shapley factor decomposition and attention attribution for PDP auditability

class XAIEngine {
  constructor() {
    // Nominal baseline expected values for benign baseline session
    this.baseline = {
      TS: 88.0,
      B: 90.0,
      N_adj: 88.0,
      D: 88.0,
      T: 90.0,
      weights: { B: 0.35, N: 0.35, D: 0.20, T: 0.10 }
    };
  }

  /**
   * Compute SHAP-style attribution values for the Policy Decision Point
   * Decomposes delta: TS - E[TS] into additive factor contributions
   */
  explainDecision({ TS, factors, weights, p_anomaly, mu_tt, mu_mfa, decision }) {
    const { B, N_adj, D, T } = factors;
    const baseTS = this.baseline.TS;

    // Marginal contributions phi_i = w_i * (factor_i - base_factor_i)
    const phi_B = parseFloat((weights.B * (B - this.baseline.B)).toFixed(2));
    const phi_N = parseFloat((weights.N * (N_adj - this.baseline.N_adj)).toFixed(2));
    const phi_D = parseFloat((weights.D * (D - this.baseline.D)).toFixed(2));
    const phi_T = parseFloat((weights.T * (T - this.baseline.T)).toFixed(2));

    // Base anomaly penalty impact
    const anomalyImpact = parseFloat((-p_anomaly * 40.0).toFixed(2));

    const contributions = [
      {
        factor: 'User Behavior (B)',
        code: 'B',
        value: B,
        baseline: this.baseline.B,
        weight: weights.B,
        shapValue: phi_B,
        impact: phi_B >= 0 ? 'positive' : 'negative',
        description: phi_B < -5 ? 'Deviation in access hours or abnormal data transfer volume' : 'Normal login timing and request patterns'
      },
      {
        factor: 'Network Context (N_adj)',
        code: 'N',
        value: N_adj,
        baseline: this.baseline.N_adj,
        weight: weights.N,
        shapValue: phi_N,
        impact: phi_N >= 0 ? 'positive' : 'negative',
        description: phi_N < -5 ? `Deep packet anomaly detected (P_anomaly: ${(p_anomaly * 100).toFixed(1)}%)` : 'Consistent protocol flows and normal packet rates'
      },
      {
        factor: 'Device Posture (D)',
        code: 'D',
        value: D,
        baseline: this.baseline.D,
        weight: weights.D,
        shapValue: phi_D,
        impact: phi_D >= 0 ? 'positive' : 'negative',
        description: phi_D < -5 ? 'Endpoint EDR agent degraded or unpatched OS version' : 'Compliant EDR agent and verified host integrity'
      },
      {
        factor: 'Threat History (T)',
        code: 'T',
        value: T,
        baseline: this.baseline.T,
        weight: weights.T,
        shapValue: phi_T,
        impact: phi_T >= 0 ? 'positive' : 'negative',
        description: phi_T < -5 ? 'Active alarms or low IP reputation in SIEM logs' : 'Clean security history with zero recent violations'
      }
    ];

    // Generate Human-Readable Analyst Audit Summary
    let narrative = '';
    const topNegative = [...contributions].sort((a, b) => a.shapValue - b.shapValue)[0];

    if (decision === 'GRANT') {
      narrative = `Session GRANTED: Composite Trust Score (${TS}) exceeds dynamic threshold mu_tt (${mu_tt}). All risk vectors remain within verified baselines.`;
    } else if (decision === 'STEP-UP MFA') {
      narrative = `Access STEP-UP CHALLENGE REQUIRED: Trust Score (${TS}) dropped below authorization threshold (${mu_tt}) into Step-up boundary [${mu_mfa}, ${mu_tt}). Primary risk driver is ${topNegative.factor} contributing ${topNegative.shapValue} pts (${topNegative.description}). Mandatory facial re-verification required to maintain access.`;
    } else {
      narrative = `Access DENIED / REVOKED: Trust Score (${TS}) breached critical boundary mu_mfa (${mu_mfa}). Severe penalties identified across ${topNegative.factor} (${topNegative.shapValue} pts). Session terminated by PEP.`;
    }

    return {
      baseTrustScore: baseTS,
      finalTrustScore: TS,
      decision,
      mu_tt,
      mu_mfa,
      p_anomaly,
      contributions,
      narrative
    };
  }
}

const defaultXAIEngine = new XAIEngine();

module.exports = {
  XAIEngine,
  defaultXAIEngine
};
