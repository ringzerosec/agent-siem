# Shadow AI: what the Ring Zero Security daemon needs to send

Agent SIEM recognizes AI traffic by protocol (`src/shadowai.js`). The console
cannot see traffic; the daemon's proxy can. Today the daemon recognizes LLM calls
only by hostname (`daemon/src/proxy/sse.rs`, `detect_llm_provider`: OpenAI/Azure,
Anthropic, Google, local Ollama), so a script talking to OpenRouter, a LiteLLM or
corporate gateway, Groq, DeepSeek or a self-hosted vLLM is invisible.

## Change

For every HTTPS request the proxy inspects (it already terminates TLS for
inspection), emit one event with request **metadata only** (no bodies, no values):

```json
{
  "kind": "http_request",
  "pid": 4242, "process": "python3", "ppid": 4000,
  "host": "llm-gw.internal.corp", "port": 443, "method": "POST",
  "path": "/v1/chat/completions",
  "req_headers": ["authorization", "x-stainless-lang"],
  "body_keys": ["model", "messages", "stream", "max_tokens", "temperature"],
  "model": "gpt-4o-mini",
  "accept": "text/event-stream",
  "resp_content_type": "text/event-stream",
  "resp_keys": ["choices", "delta"],
  "allowed": true
}
```

- `req_headers`: header **names** only, lower-cased.
- `body_keys`: top-level JSON keys of the request body (first 64 KB parsed; keys only).
- `model`: the value of a top-level `model` key if present (a model id, not user data).
- `resp_keys`: top-level keys of a JSON response, or of the first `data:` chunk of an SSE stream.

The console's adapter maps `http_request` to its `http` kind unchanged.

## Optional: classify in the daemon too

Port the fingerprint (paths, body keys, headers, response shape, weights,
threshold 5) into `detect_llm_provider` so the daemon can apply AI policy (for
example: block unapproved AI services, or route them through DLP) at the proxy,
in real time. The SIEM stays the fleet view: inventory, campaigns, governance.

## Privacy

Keys and names only. No prompt text, no header values, no tokens. Prompt text is
already handled separately (and redacted) for approved providers.
