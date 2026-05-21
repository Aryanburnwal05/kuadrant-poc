# CNCF Kuadrant MCP Gateway AccessPolicy Proof-Of-Concept

Welcome to the Kuadrant MCP Gateway AccessPolicy Proof-Of-Concept (POC)! 

**What problem does this solve?**
Currently, when you host AI Model Context Protocol (MCP) servers behind an API Gateway, you can usually only secure it at the route level (e.g., blocking the entire `/tools/call` path). But what if you have multiple AI agents, and a "guest agent" should only have access to a `calculator` tool, while an "admin agent" needs access to `delete_database`? Route-level auth fails here. We need **granular, tool-level authorization**.

**How it works**
This POC acts as a mock API Gateway and Policy Engine. It intercepts incoming JSON requests from AI agents, extracts the exact tool they are trying to use, and evaluates it against a declarative `AccessPolicy` YAML file. It either allows the request to pass through to the MCP server or blocks it with a 403 Forbidden.

**Main Features**
1. Dynamic authorization matrix based on client identity headers.
2. Support for Common Expression Language (CEL) rules (e.g., `tool.arguments.filepath.startsWith('public/')`).
3. Real-time security metrics (Total, Allowed, Denied, Protection Rate).
4. Interactive CEL Sandbox for testing rules safely.
5. Persistent live audit logs tracking every gateway decision.

---

## Architecture Overview

Here is a simple look at how a request flows through the system:

```text
[ AI Agent ] 
     |
  (POST /tools/call)
     |
     v
[ API Gateway (ext_proc) ]
     |
  (Extracts Tool Name & Injects Headers)
     |
     v
[ Policy Engine ]
     |
  (Evaluates AccessPolicy YAML)
     |
    / \
  (Allowed?)
  /     \
YES     NO
 /       \
v         v
[ MCP Server ]    [ 403 Forbidden ]
```

1. **MCP Gateway**: Intercepts the request and parses the body to extract the tool name and arguments.
2. **AccessPolicy CRD**: A declarative YAML file that defines who can access what.
3. **Authorization Flow**: The engine matches the agent's identity against the policy rules.
4. **Tool Request Evaluation**: It checks explicit tool lists and dynamic CEL conditions.
5. **Audit Logging & Metrics**: Every decision is logged and security metrics are updated in real-time.

---

## Prerequisites

Because this is a lightweight simulation designed for easy testing, you don't need a heavy Kubernetes or Go setup. You only need:

1. **Node.js**: v16 or newer
2. **npm**: v8 or newer
3. **Git**

*(Note: There is no Docker or Kubernetes cluster required to run this standalone POC).*

---

## Clone the Repository

To get started, clone this repository to your local machine:

```bash
git clone https://github.com/Aryanburnwal05/kuadrant-poc.git
cd kuadrant-poc
```

---

## Project Structure

Here are the important files in the repository:

1. `server.js`: The core Node.js backend. It acts as our mock Envoy gateway, Authorino policy engine, and the backend MCP server all in one.
2. `policies/default-policy.yaml`: The declarative policy configuration file where our rules are defined.
3. `public/index.html`: The main dashboard UI.
4. `public/css/style.css`: The styling for the dashboard.
5. `public/js/app.js`: The frontend client logic handling the interactive simulation and visual flows.
6. `package.json`: Contains project dependencies (`express`, `js-yaml`, `cors`).

---

## Local Setup

Follow these simple steps to get the POC running on your machine.

**Step 1: Clone repository**
If you haven't already, run `git clone https://github.com/Aryanburnwal05/kuadrant-poc.git` and `cd kuadrant-poc`.

**Step 2: Install dependencies**
Run the following command to download the required Node.js packages:
```bash
npm install
```
*Expected output*: npm will install `express`, `cors`, and `js-yaml`, creating a `node_modules` folder.

**Step 3: Build project**
*(Skip this step: Since this is a vanilla Node.js and static HTML project, no build step is required!)*

**Step 4: Deploy policy configuration**
The default policy is already provided at `policies/default-policy.yaml`. The server will automatically load this file when it starts. No manual deployment is needed.

**Step 5: Run MCP Gateway & Start required services**
Boot up the mock server:
```bash
node server.js
```
*Expected output*: `server listening on port 3000`

**Step 6: Verify installation**
Open your web browser and navigate to:
```
http://localhost:3000
```
*Expected output*: You should see the premium, sleek dashboard load successfully with the architecture diagram and metrics.

---

## Running the Demo

Here is a complete walkthrough to test the authorization engine.

1. **Start system**: Ensure your server is running (`node server.js`) and you have `http://localhost:3000` open in your browser.
2. **Send authorized request**: 
   - In the "Client Identity" dropdown, select `student-agent`.
   - In the "Tool to Call" dropdown, select `add`.
   - Click "Run Simulation Flow".
3. **Observe successful response**: The pipeline animation will light up green, and a banner will appear saying `Verdict: ALLOW (200 OK)`.
4. **Send unauthorized request**:
   - Keep the identity as `student-agent`.
   - Change the "Tool to Call" to `delete_database`.
   - Click "Run Simulation Flow".
5. **Observe denial response**: The pipeline animation will light up red at the Policy Engine step, and a banner will say `Verdict: DENY (403 Forbidden)`.
6. **View audit logs**: Scroll down to the bottom of the page to the "Live Audit Logs Terminal". You will see timestamped entries explaining exactly why the request was allowed or blocked.
7. **View metrics**: Look at the top banner. You will see the "Total Requests", "Denied Access", and "Protection Rate" numbers update in real-time.

---

## Example Policies

Our engine uses a custom Kubernetes-like YAML structure. Here are some examples of how it works.

### Tool-based and Agent-based Policy
This rule targets agents with the `student-agent` header and grants them explicit access to `add` and `subtract`.

```yaml
- name: student-agent-rules
  match: "request.headers['x-mcp-agent'] == 'student-agent'"
  allowedTools:
    - add
    - subtract
```
1. **name**: A unique identifier for the rule block.
2. **match**: The condition determining if this rule applies to the incoming request.
3. **allowedTools**: A strict list of tools the matched agent is allowed to execute.

### Allow Policy (Wildcard)
This grants total access to everything. Perfect for an admin.

```yaml
- name: admin-agent-rules
  match: "request.headers['x-mcp-agent'] == 'admin-agent'"
  allowedTools:
    - "*"
```

### Complex CEL Policy
You can restrict arguments dynamically using CEL.

```yaml
cel:
  - "tool.name == 'read_file' && tool.arguments.filepath.startsWith('public/')"
```
This means the agent is allowed to use `read_file`, but ONLY if the `filepath` argument starts with `public/`.

---

## Testing

**How to verify authorization behavior:**
Use the visual dashboard to swap between agents and run simulations. If you prefer the terminal, you can send raw HTTP requests to the simulation endpoint:

```bash
curl -X POST http://localhost:3000/api/simulate \
  -H "Content-Type: application/json" \
  -H "x-mcp-agent: admin-agent" \
  -d '{"method":"tools/call", "params":{"name":"delete_database", "arguments":{"confirm":true}}}'
```

**How to validate logs and metrics:**
Simply navigate to the respective API endpoints in your browser or via curl:
1. `http://localhost:3000/api/metrics`
2. `http://localhost:3000/api/audit-logs`

---

## Troubleshooting

Here are some common issues you might run into:

### Missing dependencies
1. **Symptoms**: Running `node server.js` throws an error like `Cannot find module 'express'`.
2. **Cause**: The npm packages were not installed.
3. **Fix**: Run `npm install` in the project root directory.

### Port already in use
1. **Symptoms**: Running `node server.js` throws an `EADDRINUSE: address already in use :::3000` error.
2. **Cause**: Another service is currently running on port 3000.
3. **Fix**: Find and kill the process using port 3000, or modify `PORT` in `server.js` to something like 8080.

### Policy loading issues
1. **Symptoms**: The UI matrix shows no tools allowed, or the server logs YAML parsing errors.
2. **Cause**: The `policies/default-policy.yaml` has invalid indentation or syntax.
3. **Fix**: Check your YAML formatting. You can use the "Interactive CEL Sandbox" and "Live YAML Editor" in the dashboard to test for syntax errors.

---

## Verification Checklist

Follow these steps to confirm everything is working:
1. [ ] `npm install` completes successfully.
2. [ ] `node server.js` starts without crashing.
3. [ ] `http://localhost:3000` loads the dashboard.
4. [ ] Selecting `admin-agent` allows execution of `delete_database`.
5. [ ] Selecting `student-agent` blocks execution of `delete_database`.
6. [ ] The CEL sandbox evaluates `tool.arguments.filepath.startsWith('public/')` correctly.
7. [ ] Audit logs and Metrics increment when simulations are run.

---

## Future Improvements

While this is a robust POC, future steps to bring this to production include:
1. Migrating the Node.js `ext_proc` simulation into a real Go-based Envoy filter.
2. Deploying the YAML `AccessPolicy` as a true Kubernetes CRD on a Kuadrant-enabled cluster.
3. Integrating with Authorino's official evaluation engine for real-time auth checks.

---

## Cleanup

To stop the server and clean up your environment:
1. Go to your terminal where `node server.js` is running.
2. Press `Ctrl + C` to stop the process.
3. If you wish to remove the project entirely, simply delete the cloned directory:
```bash
cd ..
rm -rf kuadrant-poc
```
