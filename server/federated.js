// Multi-Tenant Federated Learning Engine (Requirement 6)
// Simulates privacy-preserving model training across isolated cloud tenants via Federated Averaging (FedAvg)

class FederatedLearningEngine {
  constructor() {
    this.tenants = [
      {
        id: 'tenant_fin',
        name: 'Enterprise Finance Cloud',
        sampleCount: 14200,
        localLoss: 0.184,
        localAccuracy: 94.2,
        weights: [0.38, 0.32, 0.18, 0.12]
      },
      {
        id: 'tenant_health',
        name: 'Healthcare Patient Vault',
        sampleCount: 9800,
        localLoss: 0.210,
        localAccuracy: 92.8,
        weights: [0.42, 0.28, 0.20, 0.10]
      },
      {
        id: 'tenant_ops',
        name: 'DevOps & Infrastructure Edge',
        sampleCount: 22400,
        localLoss: 0.155,
        localAccuracy: 96.1,
        weights: [0.34, 0.36, 0.19, 0.11]
      }
    ];

    this.round = 1;
    this.globalWeights = [0.37, 0.33, 0.19, 0.11];
    this.globalLoss = 0.176;
    this.globalAccuracy = 94.8;
    this.roundHistory = [];
  }

  /**
   * Execute one Federated Averaging (FedAvg) round
   * w_global = sum( (n_k / N) * w_k )
   */
  runFedAvgRound() {
    const totalSamples = this.tenants.reduce((sum, t) => sum + t.sampleCount, 0);

    // Compute weighted average of tenant model updates
    const newGlobalWeights = [0, 0, 0, 0];
    let newWeightedLoss = 0;
    let newWeightedAcc = 0;

    this.tenants.forEach(tenant => {
      // Simulate local SGD epoch jitter
      tenant.localLoss = Math.max(0.04, tenant.localLoss * 0.94 + (Math.random() - 0.5) * 0.01);
      tenant.localAccuracy = Math.min(99.4, tenant.localAccuracy * 1.008 + (Math.random() - 0.5) * 0.2);

      const ratio = tenant.sampleCount / totalSamples;
      for (let i = 0; i < 4; i++) {
        newGlobalWeights[i] += ratio * tenant.weights[i];
      }
      newWeightedLoss += ratio * tenant.localLoss;
      newWeightedAcc += ratio * tenant.localAccuracy;
    });

    this.globalWeights = newGlobalWeights.map(w => parseFloat(w.toFixed(4)));
    this.globalLoss = parseFloat(newWeightedLoss.toFixed(4));
    this.globalAccuracy = parseFloat(newWeightedAcc.toFixed(2));
    this.round += 1;

    // Distribute aggregated global weights back to all tenants
    this.tenants.forEach(tenant => {
      tenant.weights = [...this.globalWeights];
    });

    const roundReport = {
      round: this.round - 1,
      globalWeights: this.globalWeights,
      globalLoss: this.globalLoss,
      globalAccuracy: this.globalAccuracy,
      totalSamples,
      tenantDetails: this.tenants.map(t => ({
        name: t.name,
        samples: t.sampleCount,
        loss: parseFloat(t.localLoss.toFixed(4)),
        accuracy: parseFloat(t.localAccuracy.toFixed(2))
      })),
      timestamp: new Date().toISOString()
    };

    this.roundHistory.push(roundReport);
    if (this.roundHistory.length > 20) this.roundHistory.shift();

    return roundReport;
  }

  getStatus() {
    return {
      round: this.round,
      globalWeights: this.globalWeights,
      globalLoss: this.globalLoss,
      globalAccuracy: this.globalAccuracy,
      tenants: this.tenants,
      history: this.roundHistory
    };
  }
}

const defaultFederatedEngine = new FederatedLearningEngine();

module.exports = {
  FederatedLearningEngine,
  defaultFederatedEngine
};
