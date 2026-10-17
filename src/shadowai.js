// shadowai.js — find AI use by what the traffic says, not where it goes.
//
// Hostname lists only see the providers you already know. A script that talks
// to a LiteLLM gateway, OpenRouter, a corporate AI proxy, Groq, DeepSeek or a
// self-hosted vLLM is invisible to them. Every one of those still speaks one of
// a handful of protocols, so we fingerprint the protocol:
//   - path   /v1/chat/completions, /v1/messages, /v1/responses, :generateContent, /api/chat, /converse …
//   - body   model + messages, max_tokens / max_completion_tokens, temperature, stream, tools, contents + generationConfig …
//   - headers anthropic-version, x-api-key, openai-organization, api-key (Azure), x-goog-api-key, OpenRouter's HTTP-Referer / X-Title …
//   - response  text/event-stream with choices/delta or content_block_delta, usage with prompt/input tokens …
// Each signal has a weight; the sum is a confidence. Above the threshold it is an
// AI call. Then we name the provider (by host or by protocol family), say
// whether it went through a gateway, and whether it is approved.
//
// The same fingerprint belongs in the Ring Zero Security daemon's proxy, which
// sees the traffic (docs/shadow-ai-daemon-spec.md). Here it classifies the
// request metadata the daemon (or the simulator) sends as kind "http".

const KNOWN = [
  // [host pattern, provider, family, gateway?]
  [/(^|\.)api\.openai\.com$/, 'OpenAI', 'openai', false],
  [/\.openai\.azure\.com$/, 'Azure OpenAI', 'openai', false],
  [/(^|\.)api\.anthropic\.com$/, 'Anthropic', 'anthropic', false],
  [/(^|\.)(generativelanguage|aiplatform|cloudcode-pa)\.googleapis\.com$/, 'Google', 'gemini', false],
  [/^bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com$/, 'AWS Bedrock', 'bedrock', false],
  [/(^|\.)openrouter\.ai$/, 'OpenRouter', 'openai', true],
  [/(^|\.)api\.groq\.com$/, 'Groq', 'openai', false],
  [/(^|\.)api\.together\.(xyz|ai)$/, 'Together AI', 'openai', false],
  [/(^|\.)api\.mistral\.ai$/, 'Mistral', 'openai', false],
  [/(^|\.)api\.deepseek\.com$/, 'DeepSeek', 'openai', false],
  [/(^|\.)api\.fireworks\.ai$/, 'Fireworks', 'openai', false],
  [/(^|\.)api\.perplexity\.ai$/, 'Perplexity', 'openai', false],
  [/(^|\.)api\.x\.ai$/, 'xAI', 'openai', false],
  [/(^|\.)api\.cohere\.(ai|com)$/, 'Cohere', 'cohere', false],
  [/(^|\.)(api-inference|router)\.huggingface\.co$/, 'Hugging Face', 'openai', false],
  [/(^|\.)api\.replicate\.com$/, 'Replicate', 'replicate', false],
  [/(^|\.)gateway\.ai\.cloudflare\.com$/, 'Cloudflare AI Gateway', 'openai', true],
  [/(^|\.)api\.portkey\.ai$/, 'Portkey', 'openai', true],
  [/(^|\.)oai\.helicone\.ai$|(^|\.)gateway\.helicone\.ai$/, 'Helicone', 'openai', true],
];

// [regex, weight, family, label]
const PATHS = [
  [/\/chat\/completions\b/, 3, 'openai', 'OpenAI-style chat path'],
  [/\/v1\/completions\b/, 2, 'openai', 'completions path'],
  [/\/v1\/responses\b/, 3, 'openai', 'Responses API path'],
  [/\/v1\/embeddings\b/, 2, 'openai', 'embeddings path'],
  [/\/v1\/messages\b/, 3, 'anthropic', 'Anthropic messages path'],
  [/:(stream)?generateContent\b/i, 3, 'gemini', 'Gemini generateContent'],
  [/\/api\/(chat|generate)\b/, 2, 'ollama', 'Ollama API path'],
  [/\/model\/[^/]+\/(invoke|invoke-with-response-stream|converse|converse-stream)\b/, 3, 'bedrock', 'Bedrock invoke/converse'],
  [/\/openai\/deployments\//, 3, 'openai', 'Azure OpenAI deployment path'],
];
// body keys: [key, weight, family?]
const KEYS = {
  messages: 2, model: 1, max_tokens: 2, max_completion_tokens: 2, max_output_tokens: 2, max_new_tokens: 2, num_predict: 2,
  temperature: 1, top_p: 1, top_k: 1, stream: 1, tools: 1, tool_choice: 1, functions: 1, system: 1, prompt: 1,
  contents: 1, generationConfig: 3, safetySettings: 2, anthropic_version: 3, inferenceConfig: 3, stop_sequences: 1, response_format: 1,
};
const HEADERS = {
  'anthropic-version': [3, 'anthropic'], 'x-api-key': [1], 'openai-organization': [3, 'openai'], 'openai-project': [3, 'openai'],
  'api-key': [2, 'openai'], 'x-goog-api-key': [3, 'gemini'], 'http-referer': [0], 'x-title': [1], 'x-stainless-lang': [2, 'openai'],
  'helicone-auth': [3], 'cf-aig-authorization': [3], 'x-portkey-api-key': [3],
};
const RESP_KEYS = { choices: 2, usage: 1, prompt_tokens: 2, completion_tokens: 2, input_tokens: 2, output_tokens: 2, candidates: 2, usageMetadata: 2, content_block_delta: 3, message_start: 2, delta: 1, done_reason: 2, eval_count: 2 };

export const THRESHOLD = 5;

/**
 * req: { host, method, path, content_type, accept, req_headers: [names], body_keys: [names],
 *        resp_content_type, resp_keys: [names], streaming?, model? }
 * -> { ai, confidence 0..1, score, family, provider, gateway, self_hosted, streaming, signals[] }
 */
export function fingerprint(req) {
  const host = String(req.host || '').toLowerCase().replace(/:\d+$/, '');
  const path = String(req.path || '');
  const signals = []; const fam = {};
  let score = 0;
  const add = (w, label, family) => { if (!w) return; score += w; signals.push(label); if (family) fam[family] = (fam[family] || 0) + w; };

  for (const [re, w, family, label] of PATHS) if (re.test(path)) add(w, label, family);
  const keys = new Set((req.body_keys || []).map(String));
  for (const k of keys) if (KEYS[k]) add(KEYS[k], `body: ${k}`, k === 'generationConfig' || k === 'contents' ? 'gemini' : k === 'anthropic_version' ? 'anthropic' : k === 'inferenceConfig' ? 'bedrock' : null);
  if (keys.has('model') && (keys.has('messages') || keys.has('prompt') || keys.has('input'))) add(2, 'body: model + messages/prompt', null);
  for (const h of (req.req_headers || []).map((x) => String(x).toLowerCase())) { const v = HEADERS[h]; if (v) add(v[0], `header: ${h}`, v[1]); }
  const streamingReq = keys.has('stream') || /event-stream/i.test(req.accept || '');
  const sse = /event-stream/i.test(req.resp_content_type || '');
  if (sse && streamingReq) add(2, 'streamed response (text/event-stream)');
  for (const k of (req.resp_keys || []).map(String)) if (RESP_KEYS[k]) add(RESP_KEYS[k], `response: ${k}`, k === 'candidates' || k === 'usageMetadata' ? 'gemini' : k === 'content_block_delta' || k === 'message_start' ? 'anthropic' : k === 'choices' ? 'openai' : null);

  const known = KNOWN.find(([re]) => re.test(host));
  if (known) add(3, `known AI host: ${known[1]}`, known[2]);
  const family = known?.[2] || Object.entries(fam).sort((a, b) => b[1] - a[1])[0]?.[0] || (score >= THRESHOLD ? 'openai' : null);
  const local = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)|\.(internal|corp|local|lan)$/.test(host);
  const ai = score >= THRESHOLD;
  return {
    ai, score, confidence: Math.min(1, score / 12), family,
    provider: known?.[1] || (ai ? (local ? 'Self-hosted / internal gateway' : 'Unknown AI endpoint') : null),
    gateway: known ? known[3] : ai && local,
    self_hosted: ai && !known && local,
    streaming: streamingReq || sse,
    model: req.model || null,
    signals,
  };
}

// Approved AI services: providers by name and exact gateway hosts.
const APPROVED_PROVIDERS = new Set((process.env.APPROVED_AI || 'OpenAI,Anthropic,Google').split(',').map((s) => s.trim()));
const APPROVED_AI_HOSTS = new Set((process.env.APPROVED_AI_HOSTS || 'api.openai.com,api.anthropic.com').split(',').map((s) => s.trim()));
export function aiApproved(host, provider) {
  return APPROVED_AI_HOSTS.has(String(host).toLowerCase()) || (APPROVED_PROVIDERS.has(provider) && !/gateway|self-hosted|unknown/i.test(provider));
}

// Processes that are known AI agents. Anything else calling an AI API is an
// agent nobody registered: a script, a notebook, a plugin.
const AGENTS = /^(claude|claude-code|cursor|cursor-agent|codex|gemini|gemini-cli|copilot|aider|opencode|windsurf|cline|continue|goose|openclaw)/i;
export const isKnownAgent = (name) => AGENTS.test(String(name || ''));
