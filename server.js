const express = require('express');
const cors = require('cors');
const yaml = require('js-yaml');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Path to the policy YAML file
const POLICY_FILE = path.join(__dirname, 'policies', 'default-policy.yaml');

// List of available tools on the fake MCP server
const AVAILABLE_TOOLS = [
  {
    name: 'add',
    description: 'Adds two numbers together',
    inputSchema: {
      type: 'object',
      properties: {
        a: { type: 'number', description: 'First number' },
        b: { type: 'number', description: 'Second number' }
      },
      required: ['a', 'b']
    },
    handler: (params) => {
      const { a, b } = params;
      return { result: a + b, formatted: `${a} + ${b} = ${a + b}` };
    }
  },
  {
    name: 'subtract',
    description: 'Subtracts the second number from the first',
    inputSchema: {
      type: 'object',
      properties: {
        a: { type: 'number', description: 'Minuend' },
        b: { type: 'number', description: 'Subtrahend' }
      },
      required: ['a', 'b']
    },
    handler: (params) => {
      const { a, b } = params;
      return { result: a - b, formatted: `${a} - ${b} = ${a - b}` };
    }
  },
  {
    name: 'read_file',
    description: 'Reads the contents of a local system file securely',
    inputSchema: {
      type: 'object',
      properties: {
        filepath: { type: 'string', description: 'Relative path of the file to read' }
      },
      required: ['filepath']
    },
    handler: (params) => {
      const { filepath } = params;
      return { 
        result: `[Mock file contents of '${filepath}']:\nThis is a simulation of tool-level authorization. Access permitted!`,
        formatted: `Successfully read file: ${filepath}`
      };
    }
  },
  {
    name: 'delete_database',
    description: 'DANGER: Deletes the entire production database. Irreversible!',
    inputSchema: {
      type: 'object',
      properties: {
        confirm: { type: 'boolean', description: 'Set to true to confirm deletion' }
      },
      required: ['confirm']
    },
    handler: (params) => {
      if (params.confirm) {
        return { result: 'DATABASE DELETED', formatted: 'Database wiped successfully.' };
      }
      return { result: 'Aborted', formatted: 'Database deletion aborted. Confirmation missing.' };
    }
  }
];

// Helper to read the policy
function loadPolicy() {
  try {
    const fileContents = fs.readFileSync(POLICY_FILE, 'utf8');
    return yaml.load(fileContents);
  } catch (e) {
    console.error('Error loading policy YAML:', e);
    // Return a basic fallback if file load fails
    return {
      apiVersion: 'kuadrant.io/v1alpha1',
      kind: 'MCPRouteAccessPolicy',
      metadata: { name: 'fallback-policy' },
      spec: { rules: [] }
    };
  }
}

// Helper to save the policy
function savePolicy(policyData) {
  try {
    const yamlStr = yaml.dump(policyData);
    fs.writeFileSync(POLICY_FILE, yamlStr, 'utf8');
    return true;
  } catch (e) {
    console.error('Error saving policy YAML:', e);
    return false;
  }
}

// auth engine logic

// cel expression parser
function evaluateMatch(matchStr, headers) {
  if (!matchStr) return false;
  
  // Normalize match strings and evaluate common patterns
  // E.g.: "request.headers['x-mcp-agent'] == 'student-agent'"
  const cleaned = matchStr.replace(/\s+/g, ' ');
  
  // Match bracket syntax: request.headers['x-mcp-agent'] == 'value'
  const bracketRegex = /request\.headers\['([^']+)'\]\s*==\s*'([^']+)'/;
  const bracketMatch = cleaned.match(bracketRegex);
  if (bracketMatch) {
    const headerName = bracketMatch[1].toLowerCase();
    const expectedValue = bracketMatch[2];
    const headerValue = headers[headerName] || headers[bracketMatch[1]];
    return headerValue === expectedValue;
  }

  // Match dot syntax: request.headers.x-mcp-agent == 'value'
  const dotRegex = /request\.headers\.([a-zA-Z0-9_-]+)\s*==\s*'([^']+)'/;
  const dotMatch = cleaned.match(dotRegex);
  if (dotMatch) {
    const headerName = dotMatch[1].toLowerCase();
    const expectedValue = dotMatch[2];
    const headerValue = headers[headerName] || headers[dotMatch[1]];
    return headerValue === expectedValue;
  }

  return false;
}

// track metrics
const gatewayMetrics = {
  totalRequests: 0,
  allowedRequests: 0,
  deniedRequests: 0,
  protectionRate: '100.0'
};

// keep last 100 logs
const auditLogs = [];

// Helper to record gateway simulation and direct HTTP calls
function recordGatewayRequest(agent, method, toolName, toolArgs, verdict, statusCode, matchedRule, reason) {
  gatewayMetrics.totalRequests += 1;
  if (verdict === 'ALLOW') {
    gatewayMetrics.allowedRequests += 1;
  } else {
    gatewayMetrics.deniedRequests += 1;
  }

  // Calculate protection rate: percentage of denied requests over total requests
  const total = gatewayMetrics.totalRequests;
  const denied = gatewayMetrics.deniedRequests;
  gatewayMetrics.protectionRate = total > 0 ? ((denied / total) * 100).toFixed(1) : '100.0';

  const logEntry = {
    id: `log-${Date.now()}-${Math.random().toString(36).substr(2, 5)}`,
    timestamp: new Date().toISOString(),
    agent,
    method,
    toolName,
    arguments: toolArgs || null,
    verdict,
    statusCode,
    matchedRule: matchedRule || 'None (Default Deny)',
    reason
  };

  auditLogs.unshift(logEntry);
  if (auditLogs.length > 100) {
    auditLogs.pop();
  }

  return logEntry;
}

// evaluate individual cel expressions
function evaluateCELClause(clause, context) {
  clause = clause.trim();
  const toolName = context.name || '';
  const args = context.arguments || {};

  // Helper to resolve nested property variables
  function resolveValue(path) {
    path = path.trim();
    if (path === "tool.name") return toolName;
    if (path.startsWith("tool.arguments.")) {
      const argName = path.substring("tool.arguments.".length);
      return args[argName] !== undefined ? args[argName] : undefined;
    }
    // Handle string literal
    if ((path.startsWith("'") && path.endsWith("'")) || (path.startsWith('"') && path.endsWith('"'))) {
      return path.slice(1, -1);
    }
    // Handle boolean literals
    if (path === 'true') return true;
    if (path === 'false') return false;
    // Handle numeric literals
    if (!isNaN(path) && path !== '') {
      return Number(path);
    }
    return undefined;
  }

  // Handle .startsWith('...') method
  if (clause.includes('.startsWith(')) {
    const match = clause.match(/(.+)\.startsWith\((.+)\)/);
    if (match) {
      const val = resolveValue(match[1]);
      const param = resolveValue(match[2]);
      const result = typeof val === 'string' && typeof param === 'string' && val.startsWith(param);
      return {
        matched: result,
        log: `CEL: ${match[1]}.startsWith('${param}') evaluated to ${result} (actual: '${val}')`
      };
    }
  }

  // Handle .endsWith('...') method
  if (clause.includes('.endsWith(')) {
    const match = clause.match(/(.+)\.endsWith\((.+)\)/);
    if (match) {
      const val = resolveValue(match[1]);
      const param = resolveValue(match[2]);
      const result = typeof val === 'string' && typeof param === 'string' && val.endsWith(param);
      return {
        matched: result,
        log: `CEL: ${match[1]}.endsWith('${param}') evaluated to ${result} (actual: '${val}')`
      };
    }
  }

  // Handle operators: ==, !=, <=, >=, <, >
  const operators = ['==', '!=', '<=', '>=', '<', '>'];
  for (const op of operators) {
    if (clause.includes(op)) {
      const parts = clause.split(op);
      if (parts.length === 2) {
        const leftExpr = parts[0].trim();
        const rightExpr = parts[1].trim();
        const left = resolveValue(leftExpr);
        const right = resolveValue(rightExpr);
        let result = false;

        if (left === undefined || right === undefined) {
          result = false;
        } else if (op === '==') {
          result = left == right;
        } else if (op === '!=') {
          result = left != right;
        } else {
          // Compare numbers
          const leftNum = Number(left);
          const rightNum = Number(right);
          if (!isNaN(leftNum) && !isNaN(rightNum)) {
            if (op === '<') result = leftNum < rightNum;
            else if (op === '>') result = leftNum > rightNum;
            else if (op === '<=') result = leftNum <= rightNum;
            else if (op === '>=') result = leftNum >= rightNum;
          }
        }
        return {
          matched: result,
          log: `CEL: ${leftExpr} ${op} ${rightExpr} evaluated to ${result} (resolved: '${left}' ${op} '${right}')`
        };
      }
    }
  }

  return { matched: false, log: `CEL syntax clause not fully parsed: '${clause}'` };
}

// Evaluate a full CEL rule rule supporting logical && conjunctions
function evaluateCELRule(celRule, context) {
  if (!celRule || !context) return { matched: false, log: 'Invalid rule or evaluation context' };

  // Split by logical '&&' and verify all clauses are satisfied (logical AND)
  const clauses = celRule.split('&&');
  const logs = [];
  let finalResult = true;

  for (const clause of clauses) {
    const res = evaluateCELClause(clause, context);
    logs.push(res.log);
    if (!res.matched) {
      finalResult = false;
    }
  }

  return {
    matched: finalResult,
    log: logs.join(' && ')
  };
}

// Authorize requested tool using AccessPolicy
function authorizeRequest(method, toolName, toolArgs, headers, policy) {
  const logs = [];
  logs.push(`Starting authorization logic for method: ${method}`);
  
  if (method === 'tools/list') {
    logs.push("Authorization for listing tools requested.");
  } else {
    logs.push(`Authorization for tool call requested: '${toolName}' with arguments: ${JSON.stringify(toolArgs || {})}`);
  }

  const rules = policy?.spec?.rules || [];
  if (rules.length === 0) {
    logs.push('WARNING: No rules found in AccessPolicy. Defaulting to DENY.');
    return { allowed: false, logs, matchedRule: null };
  }

  // Find matching rule based on agent identity (match clause)
  let matchedRule = null;
  for (const rule of rules) {
    logs.push(`Evaluating rule: '${rule.name}' with match clause: "${rule.match}"`);
    if (evaluateMatch(rule.match, headers)) {
      matchedRule = rule;
      logs.push(`SUCCESS: Rule '${rule.name}' matches the incoming request context!`);
      break;
    } else {
      logs.push(`Rule '${rule.name}' does not match request context.`);
    }
  }

  if (!matchedRule) {
    logs.push('DENIED: No matching rule found in AccessPolicy for current request context.');
    return { allowed: false, logs, matchedRule: null };
  }

  // For tools/list, we allow it to pass through, filtering is handled separately
  if (method === 'tools/list') {
    logs.push('ALLOWED: tools/list operation authorized. Listing will be dynamically filtered based on this rule.');
    return { allowed: true, logs, matchedRule };
  }

  // Authorizing actual tool call
  if (!toolName) {
    logs.push('DENIED: Method is tools/call but x-mcp-toolname is empty.');
    return { allowed: false, logs, matchedRule };
  }

  // Check allowedTools list
  const allowedTools = matchedRule.allowedTools || [];
  logs.push(`Allowed tools explicitly in rule: [${allowedTools.join(', ')}]`);

  if (allowedTools.includes('*')) {
    logs.push("ALLOWED: Wildcard '*' found. Access granted to all tools.");
    return { allowed: true, logs, matchedRule };
  }

  if (allowedTools.includes(toolName)) {
    logs.push(`ALLOWED: Tool '${toolName}' found in explicit allowedTools list.`);
    return { allowed: true, logs, matchedRule };
  }

  // Check CEL rules
  const celRules = matchedRule.cel || [];
  if (celRules.length > 0) {
    logs.push(`Evaluating ${celRules.length} CEL expression(s) for rule '${matchedRule.name}'...`);
    for (const celRule of celRules) {
      const context = { name: toolName, arguments: toolArgs || {} };
      const evaluation = evaluateCELRule(celRule, context);
      logs.push(`- ${evaluation.log}`);
      if (evaluation.matched) {
        logs.push(`ALLOWED: Access granted by CEL rule: "${celRule}"`);
        return { allowed: true, logs, matchedRule };
      }
    }
  }

  logs.push(`DENIED: Tool '${toolName}' not allowed by allowedTools list or CEL rules.`);
  return { allowed: false, logs, matchedRule };
}

// Filter the available tools based on the matched rule
function filterToolsForAgent(matchedRule, toolsList) {
  if (!matchedRule) return [];
  const allowedTools = matchedRule.allowedTools || [];
  
  if (allowedTools.includes('*')) {
    return toolsList.map(t => ({ name: t.name, description: t.description, inputSchema: t.inputSchema }));
  }

  // Supply dummy values for listing evaluations to bypass argument constraints
  const dummyContext = {
    name: '',
    arguments: {
      filepath: 'public/placeholder.txt', // mock path to pass startsWith('public/')
      confirm: true,
      a: 10,
      b: 10
    }
  };

  return toolsList
    .filter(tool => {
      // 1. Is it explicitly listed?
      if (allowedTools.includes(tool.name)) return true;

      // 2. Does it pass any CEL rule?
      const celRules = matchedRule.cel || [];
      for (const celRule of celRules) {
        dummyContext.name = tool.name;
        if (evaluateCELRule(celRule, dummyContext).matched) return true;
      }
      return false;
    })
    .map(t => ({ name: t.name, description: t.description, inputSchema: t.inputSchema }));
}

// ext_proc mock middleware
function extProcMiddleware(req, res, next) {
  // If calling an MCP endpoint
  if (req.path === '/tools/call' || req.path === '/api/simulate') {
    const { method, params } = req.body || {};
    
    // Simulate ext_proc header generation based on parsed JSON body
    if (method) {
      req.headers['x-mcp-method'] = method;
      if (method === 'tools/call' && params && params.name) {
        req.headers['x-mcp-toolname'] = params.name;
      }
    }
  } else if (req.path === '/tools/list') {
    // For listing, the method is tools/list
    req.headers['x-mcp-method'] = 'tools/list';
  }
  next();
}

app.use(extProcMiddleware);

// api routes

// Retrieve current AccessPolicy YAML
app.get('/api/policy', (req, res) => {
  try {
    const fileContents = fs.readFileSync(POLICY_FILE, 'utf8');
    res.json({ yaml: fileContents });
  } catch (e) {
    res.status(500).json({ error: 'Failed to read policy file' });
  }
});

// Update AccessPolicy YAML
app.post('/api/policy', (req, res) => {
  const { yaml: yamlContent } = req.body;
  if (!yamlContent) {
    return res.status(400).json({ error: 'YAML content is required' });
  }

  try {
    const parsed = yaml.load(yamlContent);
    
    // Quick validation of the CRD structure
    if (parsed.kind !== 'MCPRouteAccessPolicy') {
      return res.status(400).json({ error: 'Invalid custom resource kind. Expected MCPRouteAccessPolicy.' });
    }
    if (!parsed.spec || !parsed.spec.rules) {
      return res.status(400).json({ error: 'Invalid schema. Spec rules are required.' });
    }

    fs.writeFileSync(POLICY_FILE, yamlContent, 'utf8');
    res.json({ success: true, policy: parsed });
  } catch (e) {
    res.status(400).json({ error: `YAML Parsing Error: ${e.message}` });
  }
});

// High-fidelity pipeline simulation endpoint
app.post('/api/simulate', (req, res) => {
  const payload = req.body;
  const agent = req.headers['x-mcp-agent'] || 'student-agent';
  
  // Step 1 & 2: ext_proc-like parsing & header injection
  const method = payload.method;
  const toolName = (method === 'tools/call' && payload.params) ? payload.params.name : null;
  
  const extProcHeaders = {
    'x-mcp-agent': agent,
    'x-mcp-method': method
  };
  if (toolName) {
    extProcHeaders['x-mcp-toolname'] = toolName;
  }

  // Load latest policy
  const policy = loadPolicy();

  // Step 3 & 4: Evaluate AccessPolicy & generate decision logs
  const authResult = authorizeRequest(method, toolName, payload.params?.arguments, extProcHeaders, policy);

  let finalResponse = null;
  let filteredTools = [];

  if (authResult.allowed) {
    if (method === 'tools/list') {
      // Dynamic tools/list filtering based on the matching rule
      filteredTools = filterToolsForAgent(authResult.matchedRule, AVAILABLE_TOOLS);
      finalResponse = { tools: filteredTools };
    } else if (method === 'tools/call') {
      // Execute mock tool logic
      const targetTool = AVAILABLE_TOOLS.find(t => t.name === toolName);
      if (targetTool) {
        const params = payload.params?.arguments || {};
        const result = targetTool.handler(params);
        finalResponse = {
          content: [
            {
              type: 'text',
              text: result.formatted
            }
          ],
          data: result.result
        };
      } else {
        finalResponse = { error: `Tool '${toolName}' not found on MCP Server` };
      }
    }
  } else {
    finalResponse = {
      error: '403 Forbidden',
      message: `Access denied by policy rule: ${authResult.matchedRule?.name || 'Default Deny'}`
    };
  }

  // Record audit log
  recordGatewayRequest(agent, method, toolName, payload.params?.arguments, authResult.allowed ? 'ALLOW' : 'DENY', authResult.allowed ? 200 : 403, authResult.matchedRule?.name, authResult.allowed ? 'Policy allowed access' : `Access denied by policy rule: ${authResult.matchedRule?.name || 'Default Deny'}`);

  res.json({
    steps: {
      incomingPayload: payload,
      extractedMetadata: {
        method,
        toolName
      },
      generatedHeaders: extProcHeaders,
      matchedRuleName: authResult.matchedRule?.name || 'None (Default Deny)',
      authLogs: authResult.logs,
      verdict: authResult.allowed ? 'ALLOW' : 'DENY',
      statusCode: authResult.allowed ? 200 : 403
    },
    response: finalResponse
  });
});

// GET /api/metrics
app.get('/api/metrics', (req, res) => {
  res.json(gatewayMetrics);
});

// GET /api/audit-logs
app.get('/api/audit-logs', (req, res) => {
  res.json(auditLogs);
});

// POST /api/sandbox
app.post('/api/sandbox', (req, res) => {
  const { expression, context } = req.body;
  if (!expression) {
    return res.status(400).json({ error: 'Expression is required' });
  }
  
  const ctx = context || { name: '', arguments: {} };
  const evaluation = evaluateCELRule(expression, ctx);
  
  res.json({
    expression,
    context: ctx,
    result: evaluation.matched,
    log: evaluation.log
  });
});

// mcp endpoints

// GET /tools/list
app.get('/tools/list', (req, res) => {
  const agent = req.headers['x-mcp-agent'] || 'student-agent';
  const policy = loadPolicy();
  
  // Set headers simulated by ext_proc
  const extProcHeaders = {
    'x-mcp-agent': agent,
    'x-mcp-method': 'tools/list'
  };

  const authResult = authorizeRequest('tools/list', null, null, extProcHeaders, policy);
  
  if (!authResult.allowed) {
    recordGatewayRequest(agent, 'tools/list', null, null, 'DENY', 403, authResult.matchedRule?.name, 'Access denied');
    return res.status(403).json({ error: 'Forbidden', message: 'Access denied' });
  }

  recordGatewayRequest(agent, 'tools/list', null, null, 'ALLOW', 200, authResult.matchedRule?.name, 'Access granted');
  const filtered = filterToolsForAgent(authResult.matchedRule, AVAILABLE_TOOLS);
  res.json({ tools: filtered });
});

// POST /tools/call
app.post('/tools/call', (req, res) => {
  const agent = req.headers['x-mcp-agent'] || 'student-agent';
  const { method, params } = req.body || {};

  if (method !== 'tools/call') {
    return res.status(400).json({ error: 'Invalid Method', message: 'Expected tools/call' });
  }

  const toolName = params?.name;
  if (!toolName) {
    return res.status(400).json({ error: 'Bad Request', message: 'Missing tool name' });
  }

  const policy = loadPolicy();
  const args = params?.arguments || {};
  const extProcHeaders = {
    'x-mcp-agent': agent,
    'x-mcp-method': 'tools/call',
    'x-mcp-toolname': toolName
  };

  const authResult = authorizeRequest('tools/call', toolName, args, extProcHeaders, policy);

  if (!authResult.allowed) {
    recordGatewayRequest(agent, 'tools/call', toolName, args, 'DENY', 403, authResult.matchedRule?.name, `Access to tool '${toolName}' is forbidden`);
    return res.status(403).json({
      error: '403 Forbidden',
      message: `Access to tool '${toolName}' is forbidden for agent '${agent}'`
    });
  }

  recordGatewayRequest(agent, 'tools/call', toolName, args, 'ALLOW', 200, authResult.matchedRule?.name, 'Access granted');
  
  const targetTool = AVAILABLE_TOOLS.find(t => t.name === toolName);
  if (!targetTool) {
    return res.status(404).json({ error: 'Not Found', message: `Tool '${toolName}' not found` });
  }

  const result = targetTool.handler(args);
  
  res.json({
    content: [
      {
        type: 'text',
        text: result.formatted
      }
    ],
    data: result.result
  });
});

// Serve UI dashboard
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
  console.log(`server listening on port ${PORT}`);
});
