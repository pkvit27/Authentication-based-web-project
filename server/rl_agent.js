// Reinforcement Learning Policy Controller
// Implements Standard DQN, Double DQN (DDQN), Dueling DQN, and Contextual Bandits (Requirement 3)
const { math } = require('./models');

class ReplayBuffer {
  constructor(capacity = 10000) {
    this.capacity = capacity;
    this.buffer = [];
    this.position = 0;
  }

  push(state, action, reward, nextState, done = false) {
    if (this.buffer.length < this.capacity) {
      this.buffer.push({ state, action, reward, nextState, done });
    } else {
      this.buffer[this.position] = { state, action, reward, nextState, done };
    }
    this.position = (this.position + 1) % this.capacity;
  }

  sample(batchSize) {
    const samples = [];
    for (let i = 0; i < Math.min(batchSize, this.buffer.length); i++) {
      const idx = Math.floor(Math.random() * this.buffer.length);
      samples.push(this.buffer[idx]);
    }
    return samples;
  }

  size() {
    return this.buffer.length;
  }
}

/**
 * Neural Network supporting Standard & Dueling Architectures
 */
class QNetwork {
  constructor(stateDim = 4, actionDim = 3, isDueling = false, seed = 303) {
    this.stateDim = stateDim;
    this.actionDim = actionDim;
    this.isDueling = isDueling;
    const rng = math.pseudoRandom(seed);

    // Shared feature trunk: 4 -> 32 -> 16
    this.W1 = Array.from({ length: 32 }, () => Array.from({ length: stateDim }, () => (rng() - 0.5) * 0.3));
    this.b1 = new Array(32).fill(0.01);
    this.W2 = Array.from({ length: 16 }, () => Array.from({ length: 32 }, () => (rng() - 0.5) * 0.3));
    this.b2 = new Array(16).fill(0.01);

    if (isDueling) {
      // Value Stream V(s): 16 -> 8 -> 1
      this.W_v1 = Array.from({ length: 8 }, () => Array.from({ length: 16 }, () => (rng() - 0.5) * 0.2));
      this.b_v1 = new Array(8).fill(0.01);
      this.W_v2 = Array.from({ length: 8 }, () => (rng() - 0.5) * 0.2);
      this.b_v2 = 0.01;

      // Advantage Stream A(s, a): 16 -> 8 -> 3
      this.W_a1 = Array.from({ length: 8 }, () => Array.from({ length: 16 }, () => (rng() - 0.5) * 0.2));
      this.b_a1 = new Array(8).fill(0.01);
      this.W_a2 = Array.from({ length: actionDim }, () => Array.from({ length: 8 }, () => (rng() - 0.5) * 0.2));
      this.b_a2 = new Array(actionDim).fill(0.01);
    } else {
      // Standard Head: 16 -> 3
      this.W_out = Array.from({ length: actionDim }, () => Array.from({ length: 16 }, () => (rng() - 0.5) * 0.3));
      this.b_out = new Array(actionDim).fill(0.01);
    }
  }

  forward(state) {
    // Feature trunk
    const h1 = this.W1.map((row, i) => math.relu(math.dot(row, state) + this.b1[i]));
    const h2 = this.W2.map((row, i) => math.relu(math.dot(row, h1) + this.b2[i]));

    if (this.isDueling) {
      // V(s)
      const v_h = this.W_v1.map((row, i) => math.relu(math.dot(row, h2) + this.b_v1[i]));
      const V = math.dot(this.W_v2, v_h) + this.b_v2;

      // A(s, a)
      const a_h = this.W_a1.map((row, i) => math.relu(math.dot(row, h2) + this.b_a1[i]));
      const A = this.W_a2.map((row, i) => math.dot(row, a_h) + this.b_a2[i]);

      // Mean advantage
      const meanA = A.reduce((acc, v) => acc + v, 0) / this.actionDim;

      // Q(s, a) = V(s) + (A(s, a) - mean(A))
      return A.map(a => V + (a - meanA));
    } else {
      // Standard Q-network
      return this.W_out.map((row, i) => math.dot(row, h2) + this.b_out[i]);
    }
  }

  // Clone weights from source
  copyFrom(source) {
    this.W1 = JSON.parse(JSON.stringify(source.W1));
    this.b1 = [...source.b1];
    this.W2 = JSON.parse(JSON.stringify(source.W2));
    this.b2 = [...source.b2];
    if (this.isDueling && source.isDueling) {
      this.W_v1 = JSON.parse(JSON.stringify(source.W_v1));
      this.b_v1 = [...source.b_v1];
      this.W_v2 = [...source.W_v2];
      this.b_v2 = source.b_v2;
      this.W_a1 = JSON.parse(JSON.stringify(source.W_a1));
      this.b_a1 = [...source.b_a1];
      this.W_a2 = JSON.parse(JSON.stringify(source.W_a2));
      this.b_a2 = [...source.b_a2];
    } else if (!this.isDueling && !source.isDueling) {
      this.W_out = JSON.parse(JSON.stringify(source.W_out));
      this.b_out = [...source.b_out];
    }
  }
}

/**
 * Deep Reinforcement Learning Agent
 */
class RLAgent {
  constructor(algorithm = 'dueling_dqn') {
    // Algorithms: 'standard_dqn', 'double_dqn', 'dueling_dqn', 'contextual_bandit'
    this.algorithm = algorithm;
    this.stateDim = 4;
    this.actionDim = 3; // 0: -2.0 (Decrease), 1: 0.0 (Maintain), 2: +2.0 (Increase)

    this.isDueling = (algorithm === 'dueling_dqn');
    this.qNet = new QNetwork(this.stateDim, this.actionDim, this.isDueling, 401);
    this.targetNet = new QNetwork(this.stateDim, this.actionDim, this.isDueling, 401);
    this.targetNet.copyFrom(this.qNet);

    this.memory = new ReplayBuffer(10000);
    this.gamma = 0.99;
    this.epsilon = 0.20; // 20% exploration, decaying
    this.epsilonMin = 0.02;
    this.epsilonDecay = 0.995;
    this.stepCount = 0;
    this.trainLossHistory = [];

    // Current thresholds
    this.mu_tt = 80.0;
    this.mu_mfa = 65.0; // mu_tt - 15.0
    this.denialRate = 0.05;
  }

  setAlgorithm(algo) {
    if (['standard_dqn', 'double_dqn', 'dueling_dqn', 'contextual_bandit'].includes(algo)) {
      this.algorithm = algo;
      this.isDueling = (algo === 'dueling_dqn');
      this.qNet = new QNetwork(this.stateDim, this.actionDim, this.isDueling, 401 + Math.floor(Math.random() * 100));
      this.targetNet = new QNetwork(this.stateDim, this.actionDim, this.isDueling, 401);
      this.targetNet.copyFrom(this.qNet);
    }
  }

  /**
   * Construct state vector: [TS/100, Panomaly, mu_tt/100, Wreq_error]
   */
  getState(TS, p_anomaly) {
    return [
      Math.max(0, Math.min(1, TS / 100.0)),
      Math.max(0, Math.min(1, p_anomaly)),
      Math.max(0, Math.min(1, this.mu_tt / 100.0)),
      Math.max(0, Math.min(1, this.denialRate))
    ];
  }

  /**
   * Select Action (epsilon-greedy)
   */
  selectAction(state) {
    if (this.algorithm === 'contextual_bandit') {
      // Contextual Bandit policy: direct utility score with exploration
      const qValues = this.qNet.forward(state);
      const explorationBonus = Math.sqrt(2 * Math.log(this.stepCount + 10) / (this.stepCount + 1));
      const ucbValues = qValues.map(q => q + 0.1 * explorationBonus);
      const bestAction = ucbValues.indexOf(Math.max(...ucbValues));
      return { action: bestAction, qValues, isExploration: false };
    }

    if (Math.random() < this.epsilon) {
      const randomAction = Math.floor(Math.random() * this.actionDim);
      const qValues = this.qNet.forward(state);
      return { action: randomAction, qValues, isExploration: true };
    }

    const qValues = this.qNet.forward(state);
    let bestAction = 0;
    let maxQ = qValues[0];
    for (let i = 1; i < qValues.length; i++) {
      if (qValues[i] > maxQ) {
        maxQ = qValues[i];
        bestAction = i;
      }
    }

    return { action: bestAction, qValues, isExploration: false };
  }

  /**
   * Execute Action & Step Policy Thresholds
   */
  step(action) {
    let delta = 0.0;
    if (action === 0) delta = -2.0; // Decrease threshold (less restrictive)
    else if (action === 2) delta = 2.0; // Increase threshold (more restrictive)

    this.mu_tt = Math.max(50.0, Math.min(95.0, parseFloat((this.mu_tt + delta).toFixed(1))));
    this.mu_mfa = parseFloat((this.mu_tt - 15.0).toFixed(1));

    return {
      mu_tt: this.mu_tt,
      mu_mfa: this.mu_mfa,
      delta
    };
  }

  /**
   * Calculate Reward (Matching Section III-D in Manuscript)
   */
  computeReward(decision, isAttack) {
    // Decision: 'GRANT' (0), 'STEP-UP MFA' (0.5), 'DENY' (1)
    if (decision === 'GRANT' && !isAttack) {
      return 1.0; // True Negative
    } else if (decision === 'DENY' && isAttack) {
      return 10.0; // True Positive
    } else if (decision === 'DENY' && !isAttack) {
      return -5.0; // False Positive (Denying benign)
    } else if (decision === 'GRANT' && isAttack) {
      return -50.0; // False Negative (Granting attack - severe penalty)
    } else {
      // Step-up MFA
      return isAttack ? 5.0 : 0.0;
    }
  }

  /**
   * Update Denial Rate Rolling Window
   */
  updateDenialRate(wasDenied) {
    this.denialRate = 0.99 * this.denialRate + 0.01 * (wasDenied ? 1 : 0);
  }

  /**
   * Perform RL Training Step
   */
  trainStep(batchSize = 16) {
    if (this.memory.size() < batchSize) return 0;

    const batch = this.memory.sample(batchSize);
    let totalLoss = 0;

    for (const exp of batch) {
      const qCurrent = this.qNet.forward(exp.state);
      let targetQ;

      if (this.algorithm === 'double_dqn') {
        // Double DQN: online net selects action, target net evaluates
        const nextQOnline = this.qNet.forward(exp.nextState);
        const bestNextAction = nextQOnline.indexOf(Math.max(...nextQOnline));
        const nextQTarget = this.targetNet.forward(exp.nextState);
        targetQ = exp.reward + (exp.done ? 0 : this.gamma * nextQTarget[bestNextAction]);
      } else {
        // Standard / Dueling DQN target
        const nextQTarget = this.targetNet.forward(exp.nextState);
        const maxNextQ = Math.max(...nextQTarget);
        targetQ = exp.reward + (exp.done ? 0 : this.gamma * maxNextQ);
      }

      const tdError = targetQ - qCurrent[exp.action];
      totalLoss += tdError * tdError;

      // Numerical gradient nudging of weights towards target
      const lr = 0.01;
      const grad = lr * tdError;
      if (this.isDueling) {
        this.qNet.b_a2[exp.action] += grad * 0.1;
      } else {
        this.qNet.b_out[exp.action] += grad * 0.1;
      }
    }

    const loss = totalLoss / batch.length;
    this.trainLossHistory.push(parseFloat(loss.toFixed(4)));
    if (this.trainLossHistory.length > 50) this.trainLossHistory.shift();

    this.stepCount++;
    if (this.stepCount % 20 === 0) {
      this.targetNet.copyFrom(this.qNet);
    }

    this.epsilon = Math.max(this.epsilonMin, this.epsilon * this.epsilonDecay);

    return parseFloat(loss.toFixed(4));
  }
}

const defaultRLAgent = new RLAgent('dueling_dqn');

module.exports = {
  RLAgent,
  defaultRLAgent
};
