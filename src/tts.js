// tts.js — local neural voice for the security engineer (Kokoro-82M, Apache-2.0).
//
// Runs on this machine's CPU through kokoro-js (ONNX). The model (~300 MB fp32)
// is fetched from Hugging Face on first use and cached. One sentence at a time:
// the browser asks for sentence 1, starts playing it, and prefetches sentence 2,
// so speech starts about a second after the engineer has something to say.
//
//   TTS_VOICE=af_heart   (default)    TTS_DTYPE=fp32 (default) | q8 | q4

const VOICE = process.env.TTS_VOICE || 'af_heart';
const DTYPE = process.env.TTS_DTYPE || 'fp32';

let ttsPromise = null;
function engine() {
  if (!ttsPromise) {
    ttsPromise = (async () => {
      const { KokoroTTS } = await import('kokoro-js');
      const tts = await KokoroTTS.from_pretrained('onnx-community/Kokoro-82M-v1.0-ONNX', { dtype: DTYPE, device: 'cpu' });
      await tts.generate('Ready.', { voice: VOICE });   // warm the graph so the first real line is fast
      return tts;
    })().catch((e) => { ttsPromise = null; throw e; });
  }
  return ttsPromise;
}
export function warmTts() { engine().then(() => console.log(`tts: Kokoro ${VOICE} (${DTYPE}) ready`), (e) => console.error('tts unavailable:', e.message)); }

// Serialize generations: two at once only slows both down on CPU.
let chain = Promise.resolve();
const cache = new Map();   // text -> wav Buffer (small LRU; the same phrases recur)

export async function synth(text, { cancelled = () => false } = {}) {
  const key = `${VOICE}|${text}`;
  if (cache.has(key)) { const v = cache.get(key); cache.delete(key); cache.set(key, v); return v; }
  const job = chain.then(async () => {
    if (cancelled()) return null;   // the listener moved on while this waited in line
    const tts = await engine();
    const audio = await tts.generate(text, { voice: VOICE });
    return Buffer.from(audio.toWav());
  });
  chain = job.catch(() => {});
  const wav = await job;
  if (!wav) return null;
  cache.set(key, wav);
  if (cache.size > 200) cache.delete(cache.keys().next().value);
  return wav;
}
