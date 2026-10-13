// Robustness & Attack Defense Center (Requirement 7)
// Simulates Adversarial Evasion (FGSM), Concept Drift Detection (Page-Hinkley), and Replay Buffer Anti-Poisoning

class RobustnessEngine {
  constructor() {
    // Concept Drift detector parameters (Page-Hinkley Test)
    this.phThreshold = 15.0;
    this.phAlpha = 0.05;
    this.phMean = 0.5;
    this.phCumulativeSum = 0;
    this.phMinSum = Infinity;
    this.driftDetected = false;
    this.driftHistory = [];

    // Adversarial Perturbation stats
    this.adversarialEvaluations = [];

    // Anti-Poisoning Replay Buffer stats
    this.poisonAttemptsBlocked = 0;
    this.poisonFilterActive = true;
  }

  /**
   * Simulate Adversarial Evasion Attack (Fast Gradient Sign Method proxy on feature vectors)
   * Evaluates if attacker can evade anomaly detection by perturbing non-sensitive flow dimensions
   */
  evaluateAdversarialEvasion(featureVector, originalPredictor, epsilon = 0.08) {
    const originalResult = originalPredictor(featureVector);

    // Perturb vector in direction minimizing anomaly output (adversary objective)
    const perturbedVector = featureVector.map((val, idx) => {
      // Perturb network bytes / duration slightly to disguise attack
      const sign = (idx % 2 === 0) ? -1 : 1;
      const perturbed = val + sign * epsilon;
      return Math.max(0, Math.min(1, parseFloat(perturbed.toFixed(4))));
    });

    const adversarialResult = originalPredictor(perturbedVector);

    // Defensive Feature Squeezing: reduce precision to nullify small perturbations
    const defendedVector = perturbedVector.map(val => Math.round(val * 10) / 10);
    const defendedResult = originalPredictor(defendedVector);

    const evasionSuccessful = (originalResult.p_anomaly > 0.60 && adversarialResult.p_anomaly < 0.40);
    const defensePreventedEvasion = (defendedResult.p_anomaly >= 0.55);

    const report = {
      epsilon,
      originalPanomaly: originalResult.p_anomaly,
      adversarialPanomaly: adversarialResult.p_anomaly,
      defendedPanomaly: defendedResult.p_anomaly,
      evasionSuccessful,
      defenseEffective: defensePreventedEvasion,
      timestamp: new Date().toISOString()
    };

    this.adversarialEvaluations.push(report);
    if (this.adversarialEvaluations.length > 20) this.adversarialEvaluations.shift();

    return report;
  }

  /**
   * Concept Drift Detection using Page-Hinkley Statistical Test
   * Monitors statistical distribution changes across incoming traffic batches
   */
  updateConceptDrift(sampleMetric) {
    // sampleMetric is error or traffic deviation
    this.phMean = 0.95 * this.phMean + 0.05 * sampleMetric;
    const diff = sampleMetric - this.phMean - this.phAlpha;
    this.phCumulativeSum = Math.max(0, this.phCumulativeSum + diff);

    if (this.phCumulativeSum < this.phMinSum) {
      this.phMinSum = this.phCumulativeSum;
    }

    const testStatistic = this.phCumulativeSum - this.phMinSum;
    this.driftDetected = (testStatistic > this.phThreshold);

    if (this.driftDetected) {
      this.driftHistory.push({
        statistic: parseFloat(testStatistic.toFixed(3)),
        timestamp: new Date().toISOString(),
        alert: 'CRITICAL CONCEPT DRIFT: Traffic distribution altered significantly from training baseline. Model adaptation recommended.'
      });
      // Reset detector after alarm
      this.phCumulativeSum = 0;
      this.phMinSum = 0;
    }

    return {
      testStatistic: parseFloat(testStatistic.toFixed(3)),
      threshold: this.phThreshold,
      driftDetected: this.driftDetected,
      alertHistoryCount: this.driftHistory.length
    };
  }

  /**
   * DQN Feedback Loop Anti-Poisoning Filter
   * Identifies spoofed or artificially high rewards crafted to coerce the DQN into lowering mu_tt
   */
  validateExperienceForBuffer(experience) {
    if (!this.poisonFilterActive) return { allowed: true };

    const { state, action, reward, nextState } = experience;

    // Poison signature: High positive reward despite elevated anomaly score and decreased threshold
    const [TS_norm, p_anomaly, mu_tt_norm, denial_rate] = state;
    const isDecreasingThreshold = (action === 0);
    const isHighAnomaly = (p_anomaly > 0.65);
    const isUnusualHighReward = (reward > 5.0 && isDecreasingThreshold && isHighAnomaly);

    if (isUnusualHighReward) {
      this.poisonAttemptsBlocked++;
      return {
        allowed: false,
        reason: 'Poisoning signature detected: Malicious positive reward submitted during high-anomaly state with threshold reduction'
      };
    }

    return { allowed: true };
  }

  getStatus() {
    return {
      poisonAttemptsBlocked: this.poisonAttemptsBlocked,
      poisonFilterActive: this.poisonFilterActive,
      driftThreshold: this.phThreshold,
      lastDriftAlert: this.driftHistory[this.driftHistory.length - 1] || null,
      recentAdversarialTests: this.adversarialEvaluations
    };
  }
}

const defaultRobustnessEngine = new RobustnessEngine();

module.exports = {
  RobustnessEngine,
  defaultRobustnessEngine
};
