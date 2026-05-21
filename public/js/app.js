// DOM Elements
const agentSelect = document.getElementById('agentSelect');
const methodSelect = document.getElementById('methodSelect');
const toolCallGroup = document.getElementById('toolCallGroup');
const toolSelect = document.getElementById('toolSelect');
const toolParams = document.getElementById('toolParams');
const runSimBtn = document.getElementById('runSimBtn');
const resetSimBtn = document.getElementById('resetSimBtn');
const yamlContent = document.getElementById('yamlContent');
const applyPolicyBtn = document.getElementById('applyPolicyBtn');
const editorFeedback = document.getElementById('editorFeedback');
const simSteps = document.getElementById('simSteps');
const verdictBanner = document.getElementById('verdictBanner');
const verdictIcon = document.getElementById('verdictIcon');
const verdictTitle = document.getElementById('verdictTitle');
const verdictSub = document.getElementById('verdictSub');
const toolsGrid = document.getElementById('toolsGrid');

// Sandbox & Metrics Elements
const sandboxExpression = document.getElementById('sandboxExpression');
const sandboxContext = document.getElementById('sandboxContext');
const runSandboxBtn = document.getElementById('runSandboxBtn');
const sandboxResult = document.getElementById('sandboxResult');

const metricTotal = document.getElementById('metricTotal');
const metricAllowed = document.getElementById('metricAllowed');
const metricDenied = document.getElementById('metricDenied');
const metricRate = document.getElementById('metricRate');

const auditLogsBody = document.getElementById('auditLogsBody');

// Architecture Blocks
const blockAgent = document.getElementById('blockAgent');
const blockEnvoy = document.getElementById('blockEnvoy');
const blockAuth = document.getElementById('blockAuth');
const blockMCP = document.getElementById('blockMCP');
const conn1 = document.getElementById('connector1');
const conn2 = document.getElementById('connector2');
const conn3 = document.getElementById('connector3');

// Default params mapping for standard demo tools
const DEFAULT_PARAMS = {
  add: '{ "a": 12, "b": 8 }',
  subtract: '{ "a": 50, "b": 15 }',
  read_file: '{ "filepath": "etc/config.json" }',
  delete_database: '{ "confirm": true }'
};

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
  loadPolicy();
  setupEventListeners();
  updateToolsMatrix();
  refreshMetricsAndLogs();
  
  // Refresh metrics and logs periodically
  setInterval(refreshMetricsAndLogs, 3000);
});

// Event Listeners Configuration
function setupEventListeners() {
  // Method change
  methodSelect.addEventListener('change', () => {
    if (methodSelect.value === 'tools/call') {
      toolCallGroup.style.display = 'grid';
    } else {
      toolCallGroup.style.display = 'none';
    }
  });

  // Tool change: Load default JSON arguments
  toolSelect.addEventListener('change', () => {
    const selectedTool = toolSelect.value;
    if (DEFAULT_PARAMS[selectedTool]) {
      toolParams.value = DEFAULT_PARAMS[selectedTool];
    }
  });

  // Agent change: update matrix
  agentSelect.addEventListener('change', () => {
    updateToolsMatrix();
  });

  // Apply policy YAML button
  applyPolicyBtn.addEventListener('click', applyPolicy);

  // Run simulation flow
  runSimBtn.addEventListener('click', runSimulation);

  // Reset simulation
  resetSimBtn.addEventListener('click', resetSimulationUI);

  // Sandbox evaluate
  runSandboxBtn.addEventListener('click', evaluateSandbox);
}

// metrics and sandbox logic

async function refreshMetricsAndLogs() {
  try {
    const [metricsRes, logsRes] = await Promise.all([
      fetch('/api/metrics'),
      fetch('/api/audit-logs')
    ]);
    
    if (metricsRes.ok) {
      const metrics = await metricsRes.json();
      metricTotal.textContent = metrics.totalRequests;
      metricAllowed.textContent = metrics.allowedRequests;
      metricDenied.textContent = metrics.deniedRequests;
      metricRate.textContent = metrics.protectionRate + '%';
    }
    
    if (logsRes.ok) {
      const logs = await logsRes.json();
      renderAuditLogs(logs);
    }
  } catch (err) {
    console.error('Failed to fetch metrics and logs', err);
  }
}

function renderAuditLogs(logs) {
  if (!logs || logs.length === 0) return;
  
  auditLogsBody.innerHTML = '';
  logs.forEach(log => {
    const time = new Date(log.timestamp).toLocaleTimeString();
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML = `
      <div class="log-time">[${time}]</div>
      <div class="log-agent">${log.agent}</div>
      <div class="log-action">${log.method}${log.toolName ? ' : ' + log.toolName : ''}</div>
      <div class="log-verdict ${log.verdict === 'ALLOW' ? 'allow' : 'deny'}">${log.verdict}</div>
      <div class="log-reason">${log.reason} (Rule: ${log.matchedRule})</div>
    `;
    auditLogsBody.appendChild(entry);
  });
}

async function evaluateSandbox() {
  const expression = sandboxExpression.value;
  let context = {};
  
  try {
    context = JSON.parse(sandboxContext.value);
  } catch (e) {
    sandboxResult.className = 'sandbox-result error';
    sandboxResult.innerHTML = '<i class="fa-solid fa-triangle-exclamation" style="margin-right: 8px;"></i> Invalid JSON Context';
    return;
  }
  
  if (!expression) {
    sandboxResult.className = 'sandbox-result error';
    sandboxResult.innerHTML = '<i class="fa-solid fa-triangle-exclamation" style="margin-right: 8px;"></i> Expression is required';
    return;
  }

  runSandboxBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
  
  try {
    const response = await fetch('/api/sandbox', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ expression, context })
    });
    
    const data = await response.json();
    if (response.ok) {
      sandboxResult.className = `sandbox-result ${data.result ? 'success' : 'error'}`;
      sandboxResult.innerHTML = `<i class="fa-solid ${data.result ? 'fa-check' : 'fa-xmark'}" style="margin-right: 8px;"></i> ${data.result ? 'MATCH' : 'NO MATCH'}: ${data.log}`;
    } else {
      sandboxResult.className = 'sandbox-result error';
      sandboxResult.innerHTML = `<i class="fa-solid fa-triangle-exclamation" style="margin-right: 8px;"></i> Error: ${data.error}`;
    }
  } catch (err) {
    sandboxResult.className = 'sandbox-result error';
    sandboxResult.innerHTML = '<i class="fa-solid fa-triangle-exclamation" style="margin-right: 8px;"></i> Network Error';
  } finally {
    runSandboxBtn.innerHTML = '<i class="fa-solid fa-play"></i> Evaluate';
  }
}

// api calls

// Load the pre-configured policy from backend
async function loadPolicy() {
  try {
    const response = await fetch('/api/policy');
    const data = await response.json();
    if (data.yaml) {
      yamlContent.value = data.yaml;
    }
  } catch (err) {
    showEditorFeedback('Error fetching policy', false);
  }
}

// Save policy edit
async function applyPolicy() {
  const content = yamlContent.value;
  try {
    const response = await fetch('/api/policy', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ yaml: content })
    });

    const data = await response.json();
    if (response.ok) {
      showEditorFeedback('Policy YAML validated & applied successfully!', true);
      // Refresh the matrix immediately!
      updateToolsMatrix();
    } else {
      showEditorFeedback(data.error || 'Failed to save policy', false);
    }
  } catch (err) {
    showEditorFeedback('Network error saving policy', false);
  }
}

// Visual editor alert feedback
function showEditorFeedback(msg, isSuccess) {
  editorFeedback.textContent = msg;
  editorFeedback.className = `feedback-msg ${isSuccess ? 'success' : 'error'}`;
  
  setTimeout(() => {
    editorFeedback.className = 'feedback-msg';
  }, 4000);
}

// Fetch list of tools for selected agent to draw authorization matrix
async function updateToolsMatrix() {
  const agent = agentSelect.value;
  
  try {
    // We call GET /tools/list simulating current agent context
    const response = await fetch('/tools/list', {
      headers: {
        'x-mcp-agent': agent
      }
    });

    const data = await response.json();
    const allowedToolNames = (data.tools || []).map(t => t.name);

    // List of all mock tools
    const allTools = [
      { name: 'add', desc: 'Adds two numbers together' },
      { name: 'subtract', desc: 'Subtracts second number from first' },
      { name: 'read_file', desc: 'Reads the contents of a local system file securely' },
      { name: 'delete_database', desc: 'DANGER: Deletes the entire production database. Irreversible!' }
    ];

    toolsGrid.innerHTML = '';
    
    allTools.forEach(tool => {
      const isAllowed = allowedToolNames.includes(tool.name);
      const card = document.createElement('div');
      card.className = 'tool-item';
      
      card.innerHTML = `
        <div class="tool-status-header">
          <span class="tool-name-badge" style="color: ${isAllowed ? 'var(--accent-success)' : 'var(--accent-error)'}">${tool.name}()</span>
          <span class="tool-status-indicator ${isAllowed ? 'tool-status-allowed' : 'tool-status-denied'}">
            ${isAllowed ? '<i class="fa-solid fa-check"></i> Allowed' : '<i class="fa-solid fa-ban"></i> Blocked'}
          </span>
        </div>
        <p class="tool-desc">${tool.desc}</p>
      `;
      
      toolsGrid.appendChild(card);
    });

  } catch (err) {
    console.error('Error loading tools matrix:', err);
  }
}

// Main simulation orchestration
async function runSimulation() {
  resetSimulationUI();
  
  const agent = agentSelect.value;
  const method = methodSelect.value;
  const toolName = toolSelect.value;
  let args = {};

  if (method === 'tools/call') {
    try {
      args = JSON.parse(toolParams.value);
    } catch (e) {
      alert('Invalid JSON arguments syntax. Please correct it.');
      return;
    }
  }

  // Construct standard MCP request structure
  const mcpPayload = {
    method: method
  };

  if (method === 'tools/call') {
    mcpPayload.params = {
      name: toolName,
      arguments: args
    };
  }

  runSimBtn.disabled = true;
  runSimBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Processing...';

  try {
    const response = await fetch('/api/simulate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-mcp-agent': agent
      },
      body: JSON.stringify(mcpPayload)
    });

    const data = await response.json();
    
    // Trigger high-fidelity step-by-step visual animation pipeline
    await animatePipelineFlow(data.steps, data.response);
    
    // Refresh metrics and logs
    refreshMetricsAndLogs();

  } catch (err) {
    console.error('Simulation error:', err);
    alert('Failed to connect to simulation server.');
  } finally {
    runSimBtn.disabled = false;
    runSimBtn.innerHTML = '<i class="fa-solid fa-play"></i> Run Simulation Flow';
  }
}

// High-fidelity pipeline sequence delay animator
async function animatePipelineFlow(steps, responseBody) {
  const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
  
  simSteps.innerHTML = '';
  
  // Step 1: AI Request
  blockAgent.classList.add('active');
  createStepCard(
    1,
    'Client / Agent Request Sent',
    'The AI agent initiates an RPC request targeting the Gateway route.',
    steps.incomingPayload
  );
  await delay(1000);

  // Connection 1 glow
  conn1.style.background = 'linear-gradient(90deg, var(--accent-purple), var(--accent-cyan))';
  conn1.style.animation = 'pulseGlow 1.5s infinite';
  
  // Step 2: ext_proc parsing
  blockEnvoy.classList.add('active');
  createStepCard(
    2,
    'Envoy ext_proc Parsing',
    'The Envoy sidecar processes the incoming request body, parses out JSON properties, and isolates the target method & parameters.',
    steps.extractedMetadata
  );
  await delay(1200);

  // Connection 2 glow
  conn2.style.background = 'linear-gradient(90deg, var(--accent-purple), var(--accent-cyan))';
  conn2.style.animation = 'pulseGlow 1.5s infinite';

  // Step 3: Header Injection
  createStepCard(
    3,
    'Metadata Headers Injected',
    'ext_proc translates payload parameters into HTTP request metadata headers, forwarding context to the Authorino engine.',
    steps.generatedHeaders
  );
  await delay(1000);

  // Connection 3 glow
  conn3.style.background = 'linear-gradient(90deg, var(--accent-purple), var(--accent-cyan))';
  conn3.style.animation = 'pulseGlow 1.5s infinite';

  // Step 4: Policy Match & Rules evaluation
  blockAuth.classList.add('active');
  
  const isAllowed = steps.verdict === 'ALLOW';
  const stepCard4 = createStepCard(
    4,
    `AccessPolicy Rule Evaluation`,
    `Authorino evaluates injected headers against target rules. Injected agent identity matched: <strong>"${steps.matchedRuleName}"</strong>.`,
    null,
    steps.authLogs
  );
  
  if (isAllowed) {
    stepCard4.classList.add('success-step');
  } else {
    stepCard4.classList.add('error-step');
  }
  await delay(1200);

  // Step 5: Verdict Banner and final execution
  showVerdictBanner(steps.verdict, steps.statusCode, responseBody);
  
  if (isAllowed) {
    blockMCP.classList.add('success-verdict');
    createStepCard(
      5,
      'MCP Server Response (200 OK)',
      'Gateway verified authorized state! Request forwarded successfully. Tool executed, output returned to agent.',
      responseBody
    );
  } else {
    blockAuth.classList.add('error-verdict');
    createStepCard(
      5,
      'Blocked by AccessPolicy (403 Forbidden)',
      'Policy check failed! Request blocked at Gateway. Mock MCP server was not called.',
      responseBody
    );
  }
}

// UI step logging constructor
function createStepCard(num, title, desc, code = null, logs = null) {
  const card = document.createElement('div');
  card.className = 'step-card active-step';
  
  let headerHtml = `
    <div class="step-header">
      <span class="step-num">Step ${num}</span>
      <span class="step-title">${title}</span>
    </div>
    <div class="step-details">${desc}</div>
  `;

  let codeHtml = '';
  if (code) {
    codeHtml = `
      <pre class="code-block">${JSON.stringify(code, null, 2)}</pre>
    `;
  }

  let logsHtml = '';
  if (logs && logs.length > 0) {
    const lines = logs.map(line => `<div class="log-line">${line}</div>`).join('');
    logsHtml = `
      <div style="margin-top: 10px; padding: 10px; background: rgba(0,0,0,0.3); border-radius: 6px; border: 1px solid rgba(255,255,255,0.03);">
        <h4 style="font-size: 11px; text-transform: uppercase; color: var(--accent-purple); margin-bottom: 6px;">Evaluation Logs:</h4>
        ${lines}
      </div>
    `;
  }

  card.innerHTML = headerHtml + codeHtml + logsHtml;
  simSteps.appendChild(card);
  
  // Auto scroll down to capture newest step
  simSteps.scrollTop = simSteps.scrollHeight;
  
  return card;
}

// Display ALLOW or DENY visual banner at top of console
function showVerdictBanner(verdict, statusCode, responseBody) {
  verdictBanner.className = 'verdict-banner';
  
  if (verdict === 'ALLOW') {
    verdictBanner.classList.add('allow');
    verdictIcon.className = 'fa-solid fa-shield-checkmark';
    verdictTitle.textContent = `Verdict: ALLOW (${statusCode} OK)`;
    
    if (responseBody && responseBody.content) {
      verdictSub.textContent = `Success: "${responseBody.content[0].text}"`;
    } else {
      verdictSub.textContent = 'Tools listed successfully and dynamically filtered.';
    }
  } else {
    verdictBanner.classList.add('deny');
    verdictIcon.className = 'fa-solid fa-shield-xmark';
    verdictTitle.textContent = `Verdict: DENY (${statusCode} Forbidden)`;
    verdictSub.textContent = responseBody.message || 'Access denied by active policy rule.';
  }
}

// Reset UI state to empty defaults
function resetSimulationUI() {
  // Reset blocks
  blockAgent.className = 'arch-block';
  blockEnvoy.className = 'arch-block';
  blockAuth.className = 'arch-block';
  blockMCP.className = 'arch-block';
  
  // Reset connectors
  conn1.style.background = 'var(--border-color)';
  conn1.style.animation = 'none';
  conn2.style.background = 'var(--border-color)';
  conn2.style.animation = 'none';
  conn3.style.background = 'var(--border-color)';
  conn3.style.animation = 'none';

  // Reset steps
  simSteps.innerHTML = '';
  verdictBanner.className = 'verdict-banner';
  verdictBanner.style.display = 'none';
}
