const aiEsc = nwEscapeHtml; // one shared escaper (core.js)

// Operations Assistant: chat-style, read-only questions about the live Mist network.
// Voice input uses the browser's Web Speech API (Edge/Chrome transcribe with their online
// speech service); answers read aloud use local speechSynthesis voices.
window.MistTools.aiEngineer = (() => {
  const STARTERS = [
    "What's broken?",
    "What's down?",
    'Top problems',
    'What changed today?',
    'Virtual chassis problems',
    'Which switches are down?',
  ];
  const KEY_SPEAK = 'nodewatch.assistant.speak';
  const KEY_NOTICE = 'nodewatch.assistant.voiceNoticeSeen';
  const KEY_HISTORY = 'nodewatch.assistant.history';
  const MAX_HISTORY = 40;
  let initd = false,
    busy = false,
    history = [],
    recognition = null,
    listening = false,
    voiceText = false,
    pressStarted = 0,
    ignoreUp = false;

  const $ = (sel) => document.querySelector(sel);
  // Browser storage can be missing or throw (private windows, blocked site data).
  const area = (kind) => (kind === 'session' ? window.sessionStorage : window.localStorage);
  const store = {
    get(key, kind = 'local') {
      try {
        return area(kind).getItem(key);
      } catch {
        return null;
      }
    },
    set(key, value, kind = 'local') {
      try {
        area(kind).setItem(key, value);
      } catch {}
    },
  };
  const clock = (iso) => {
    const d = iso ? new Date(iso) : new Date();
    return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  };
  const TONES = new Set(['critical', 'warning', 'ok', 'info']);
  const tone = (t) => (TONES.has(t) ? t : 'info');

  // ------------------------------------------------------------------ rendering
  function suggestionsHtml(list, label = 'Ask next') {
    if (!list?.length) return '';
    return `<div class="ai-followups"><span class="muted">${aiEsc(label)}:</span>${list
      .map((q) => `<button type="button" class="ai-suggest" data-ask="${aiEsc(q)}">${aiEsc(q)}</button>`)
      .join('')}</div>`;
  }
  function welcomeHtml() {
    const voice = speechRecognitionCtor() ? ' Hold the 🎤 button (or click it) to ask by voice.' : '';
    return `<div class="ai-msg ai-msg-bot ai-welcome"><div class="ai-card tone-info"><div class="ai-card-head"><span class="ai-dot" aria-hidden="true"></span><strong>Hi — ask me what's broken, how a site is doing, or where a device is.</strong></div><p class="muted">Partial site names and typos are fine. Each answer links to the page that shows the detail.${aiEsc(voice)}</p>${suggestionsHtml(STARTERS, 'Try')}</div></div>`;
  }
  function userHtml(entry) {
    return `<div class="ai-msg ai-msg-user"><div class="ai-bubble">${aiEsc(entry.text)}</div><time class="ai-time">${aiEsc(clock(entry.at))}</time></div>`;
  }
  function answerHtml(entry, index) {
    const d = entry.data || {};
    const facts = (d.facts || [])
      .map((f) => `<li class="tone-${tone(f.tone)}">${aiEsc(f.text)}</li>`)
      .join('');
    const chips = (d.chips || [])
      .map(
        (c, i) =>
          `<button type="button" class="ai-chip${c.tone ? ` tone-${tone(c.tone)}` : ''}" data-entry="${index}" data-chip="${i}">${aiEsc(c.label)} <span aria-hidden="true">→</span></button>`,
      )
      .join('');
    const meta = [
      d.interpreted_as ? `Understood as: ${d.interpreted_as}` : '',
      d.mode === 'preview' ? 'Preview data' : '',
      clock(d.generated_at || entry.at),
    ].filter(Boolean);
    return `<div class="ai-msg ai-msg-bot"><article class="ai-card tone-${tone(d.tone)}"><div class="ai-card-head"><span class="ai-dot" aria-hidden="true"></span><strong class="ai-headline">${aiEsc(d.headline || 'No answer')}</strong><button type="button" class="ai-replay hidden" data-speak="${index}" title="Read this answer aloud" aria-label="Read this answer aloud">🔊</button></div>${facts ? `<ul class="ai-facts">${facts}</ul>` : ''}${chips ? `<div class="ai-chips">${chips}</div>` : ''}<div class="ai-meta muted">${aiEsc(meta.join(' · '))}</div>${d.mode === 'preview' && d.note ? `<div class="ai-meta muted">${aiEsc(d.note)}</div>` : ''}${suggestionsHtml(d.suggestions)}</article></div>`;
  }
  function errorHtml(entry) {
    return `<div class="ai-msg ai-msg-bot"><div class="ai-card tone-warning"><div class="ai-card-head"><span class="ai-dot" aria-hidden="true"></span><strong>I couldn't get an answer.</strong></div><p class="muted">${aiEsc(entry.text)}</p>${suggestionsHtml(["What's broken?", 'Help'])}</div></div>`;
  }
  function render() {
    const host = $('#aiThread');
    if (!host) return;
    const parts = [welcomeHtml()];
    history.forEach((entry, i) => {
      if (entry.role === 'user') parts.push(userHtml(entry));
      else if (entry.role === 'assistant') parts.push(answerHtml(entry, i));
      else if (entry.role === 'error') parts.push(errorHtml(entry));
    });
    if (busy)
      parts.push(
        '<div class="ai-msg ai-msg-bot"><div class="ai-card ai-thinking" aria-label="Thinking"><span></span><span></span><span></span> <span class="muted">Checking Mist…</span></div></div>',
      );
    host.innerHTML = parts.join('');
    host.querySelectorAll('[data-ask]').forEach((b) => b.addEventListener('click', () => ask(b.dataset.ask)));
    host.querySelectorAll('[data-chip]').forEach((b) =>
      b.addEventListener('click', () => {
        const chip = history[Number(b.dataset.entry)]?.data?.chips?.[Number(b.dataset.chip)];
        if (chip) runAction(chip.action || {});
      }),
    );
    if (synth()) {
      host.querySelectorAll('[data-speak]').forEach((b) => {
        b.classList.remove('hidden');
        b.addEventListener('click', () => speak(history[Number(b.dataset.speak)]?.data, true));
      });
    }
    host.scrollTop = host.scrollHeight;
  }
  function saveHistory() {
    history = history.slice(-MAX_HISTORY);
    store.set(KEY_HISTORY, JSON.stringify(history), 'session');
  }
  function loadHistory() {
    try {
      const rows = JSON.parse(store.get(KEY_HISTORY, 'session') || '[]');
      history = Array.isArray(rows) ? rows.slice(-MAX_HISTORY) : [];
    } catch {
      history = [];
    }
  }

  // ------------------------------------------------------------------ asking
  async function ask(text) {
    const box = $('#aiQuestion');
    const q = String(text ?? box?.value ?? '').trim();
    if (!q || busy) return;
    if (box) box.value = '';
    stopSpeaking();
    history.push({ role: 'user', text: q, at: new Date().toISOString() });
    busy = true;
    setAskEnabled(false);
    render();
    try {
      const r = await fetch('/api/v1/ai-engineer/ask', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: q }),
      });
      let d = {};
      try {
        d = await r.json();
      } catch {}
      if (!r.ok) throw new Error(d.detail || r.statusText || `HTTP ${r.status}`);
      history.push({ role: 'assistant', data: d, at: new Date().toISOString() });
      if (speakEnabled()) speak(d);
    } catch (err) {
      history.push({ role: 'error', text: err.message || String(err), at: new Date().toISOString() });
    } finally {
      busy = false;
      setAskEnabled(true);
      saveHistory();
      render();
      box?.focus();
    }
  }
  function setAskEnabled(on) {
    const b = $('#aiAsk');
    if (b) {
      b.disabled = !on;
      b.textContent = on ? 'Ask' : 'Thinking…';
    }
  }

  // ------------------------------------------------------------------ navigation chips
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  async function waitFor(fn, timeout = 12000) {
    const started = Date.now();
    while (Date.now() - started < timeout) {
      const v = fn();
      if (v) return v;
      await sleep(120);
    }
    return null;
  }
  const hasOption = (sel, value) => {
    const e = $(sel);
    return e && [...e.options].some((o) => o.value === value) ? e : null;
  };
  async function openTool(id) {
    await window.MistApp?.openTool?.(id);
  }
  async function openDevice(query, siteId) {
    await openTool('detective');
    const input = await waitFor(() => $('#detectiveQuery'));
    if (!input) return;
    const site = $('#detectiveSite');
    if (site && siteId && hasOption('#detectiveSite', siteId)) site.value = siteId;
    else if (site) site.value = '';
    input.value = query;
    submitFinder();
  }
  async function openSite(siteId) {
    await openTool('detective');
    const site = await waitFor(() => hasOption('#detectiveSite', siteId));
    if (!site) return;
    site.value = siteId;
    site.dispatchEvent(new Event('change'));
    const input = $('#detectiveQuery');
    if (input) input.value = '';
    submitFinder();
  }
  function submitFinder() {
    const form = $('#detectiveSearchForm');
    if (form?.requestSubmit) form.requestSubmit();
    else if (form) form.dispatchEvent(new Event('submit', { cancelable: true }));
    else $('#detectiveSearchBtn')?.click();
  }
  async function openSwitch(action) {
    const page = action.tool === 'poe' ? 'poe' : 'operations';
    const prefix = page === 'poe' ? '#poe' : '#ops';
    await openTool(page);
    if (!action.site_id) return;
    const siteSel = await waitFor(() => hasOption(`${prefix}Site`, action.site_id));
    if (!siteSel) return;
    let deviceId = action.device_id;
    if (!deviceId && action.mac) {
      try {
        const rows = await getJSON(
          `/api/v1/operations/switches?site_id=${encodeURIComponent(action.site_id)}`,
        );
        const want = String(action.mac)
          .toLowerCase()
          .replace(/[^0-9a-f]/g, '');
        deviceId = (rows || []).find((r) => String(r.mac || '').toLowerCase() === want)?.id || '';
      } catch {}
    }
    if (siteSel.value !== action.site_id) {
      siteSel.value = action.site_id;
      siteSel.dispatchEvent(new Event('change'));
    }
    if (!deviceId) return;
    const swSel = await waitFor(() => hasOption(`${prefix}Switch`, deviceId));
    if (!swSel) return;
    // Let the page finish its own site-change load before choosing the switch.
    await sleep(150);
    if (swSel.value !== deviceId) {
      swSel.value = deviceId;
      swSel.dispatchEvent(new Event('change'));
    }
  }
  async function runAction(action) {
    try {
      if (action.type === 'ask') return ask(action.question);
      if (action.type === 'tool') return openTool(action.tool);
      if (action.type === 'device') return openDevice(action.query || '', action.site_id || '');
      if (action.type === 'site') return openSite(action.site_id || '');
      if (action.type === 'switch') return openSwitch(action);
    } catch (err) {
      console.warn('Assistant link failed', err);
    }
  }
  async function openMarvis() {
    let url = 'https://manage.mist.com/';
    try {
      const settings = await getJSON('/api/settings');
      const host = new URL(settings.api_host || 'https://api.mist.com');
      host.hostname = host.hostname.replace(/^api(?=\.|$)/, 'manage');
      host.pathname = '/admin/';
      host.search = settings.org_id ? `?org_id=${encodeURIComponent(settings.org_id)}` : '';
      host.hash = '';
      url = host.toString();
    } catch {}
    window.open(url, '_blank', 'noopener');
  }

  // ------------------------------------------------------------------ voice: speech output
  const synth = () => window.speechSynthesis || null;
  const speakEnabled = () => !!synth() && store.get(KEY_SPEAK) === '1';
  function stopSpeaking() {
    try {
      synth()?.cancel();
    } catch {}
  }
  function pickVoice() {
    const voices = synth()?.getVoices?.() || [];
    const lang = (navigator.language || 'en-US').toLowerCase();
    const base = lang.split('-')[0];
    return (
      voices.find((v) => v.localService && v.lang?.toLowerCase() === lang) ||
      voices.find((v) => v.localService && v.lang?.toLowerCase().startsWith(base)) ||
      voices.find((v) => v.localService) ||
      null
    );
  }
  function speak(d, force = false) {
    const s = synth();
    const Utterance = window.SpeechSynthesisUtterance;
    if (!s || !Utterance || !d || (!force && !speakEnabled())) return;
    const text = String(d.spoken || d.headline || '')
      .replace(/[“”]/g, '')
      .replace(/\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b/gi, 'that MAC address')
      .slice(0, 600);
    if (!text) return;
    stopSpeaking();
    try {
      const u = new Utterance(text);
      const voice = pickVoice();
      if (voice) u.voice = voice;
      u.rate = 1.03;
      s.speak(u);
    } catch {}
  }

  // ------------------------------------------------------------------ voice: speech input
  function speechRecognitionCtor() {
    return window.SpeechRecognition || window.webkitSpeechRecognition || null;
  }
  function voiceState(text) {
    const e = $('#aiVoiceState');
    if (e) e.textContent = text || '';
  }
  function showVoiceNotice() {
    if (store.get(KEY_NOTICE) === '1') return false;
    $('#aiVoiceNotice')?.classList.remove('hidden');
    return true;
  }
  function setListening(on) {
    listening = on;
    const mic = $('#aiMic');
    if (!mic) return;
    mic.classList.toggle('listening', on);
    mic.setAttribute('aria-pressed', on ? 'true' : 'false');
    const label = mic.querySelector('span');
    if (label) label.textContent = on ? 'Listening…' : 'Speak';
  }
  function startListening() {
    const Ctor = speechRecognitionCtor();
    if (!Ctor || listening) return;
    if (showVoiceNotice()) {
      voiceState('Read the note about voice input, then press the microphone again.');
      return;
    }
    stopSpeaking();
    const box = $('#aiQuestion');
    const base = box?.value.trim() ? `${box.value.trim()} ` : '';
    let finalText = '';
    try {
      recognition = new Ctor();
      recognition.lang = navigator.language || 'en-US';
      recognition.interimResults = true;
      recognition.continuous = true;
      recognition.maxAlternatives = 1;
    } catch {
      voiceState('Voice input is not available in this browser.');
      return;
    }
    recognition.onresult = (event) => {
      let interim = '';
      for (let i = event.resultIndex; i < event.results.length; i++) {
        const res = event.results[i];
        if (res.isFinal) finalText += res[0].transcript;
        else interim += res[0].transcript;
      }
      if (box) box.value = (base + finalText + interim).replace(/\s+/g, ' ').trimStart();
      voiceText = true;
    };
    recognition.onerror = (event) => {
      const messages = {
        'not-allowed':
          'Microphone access was blocked. Allow the microphone for this page in the browser’s site settings.',
        'service-not-allowed': 'The browser’s speech service is turned off or blocked on this PC.',
        network:
          'The browser’s online speech service could not be reached. You can still type your question.',
        'no-speech': "I didn't hear anything. Hold the microphone button and speak.",
        'audio-capture': 'No microphone was found.',
      };
      voiceState(messages[event.error] || `Voice input stopped (${event.error}).`);
    };
    recognition.onend = () => {
      setListening(false);
      recognition = null;
      const q = box?.value.trim();
      if (voiceText && q) {
        voiceText = false;
        voiceState('');
        ask(q);
      }
    };
    try {
      voiceText = false;
      recognition.start();
      setListening(true);
      voiceState('Listening… release (or click again) when you are done.');
    } catch {
      setListening(false);
    }
  }
  function stopListening() {
    try {
      recognition?.stop();
    } catch {}
  }
  function wireMic() {
    const mic = $('#aiMic');
    if (!mic) return;
    if (!speechRecognitionCtor()) {
      mic.classList.add('hidden');
      return;
    }
    mic.classList.remove('hidden');
    // Push-to-talk: hold to speak, release to send. A quick click toggles instead.
    mic.addEventListener('pointerdown', (e) => {
      if (e.button !== undefined && e.button !== 0) return;
      e.preventDefault();
      if (listening) {
        ignoreUp = true;
        stopListening();
        return;
      }
      ignoreUp = false;
      pressStarted = Date.now();
      startListening();
    });
    const release = () => {
      if (ignoreUp) {
        ignoreUp = false;
        return;
      }
      if (listening && Date.now() - pressStarted > 450) stopListening();
    };
    mic.addEventListener('pointerup', release);
    mic.addEventListener('pointerleave', () => {
      if (listening && Date.now() - pressStarted > 450) stopListening();
    });
    mic.addEventListener('click', (e) => {
      if (e.detail !== 0) return; // keyboard activation only; pointer handled above
      if (listening) stopListening();
      else startListening();
    });
  }
  function wireSpeak() {
    const row = $('#aiSpeakRow'),
      box = $('#aiSpeak');
    if (!row || !box) return;
    if (!synth() || !window.SpeechSynthesisUtterance) {
      row.classList.add('hidden');
      return;
    }
    row.classList.remove('hidden');
    box.checked = store.get(KEY_SPEAK) === '1';
    box.addEventListener('change', () => {
      store.set(KEY_SPEAK, box.checked ? '1' : '0');
      if (!box.checked) stopSpeaking();
    });
    // Some browsers load voices asynchronously.
    try {
      synth().getVoices();
    } catch {}
  }

  // ------------------------------------------------------------------ init
  function init() {
    if (initd) return;
    initd = true;
    loadHistory();
    $('#aiAsk')?.addEventListener('click', () => ask());
    $('#aiQuestion')?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
        e.preventDefault();
        ask();
      }
    });
    $('#aiClear')?.addEventListener('click', () => {
      history = [];
      stopSpeaking();
      saveHistory();
      render();
    });
    $('#aiMarvis')?.addEventListener('click', openMarvis);
    $('#aiVoiceNoticeOk')?.addEventListener('click', () => {
      store.set(KEY_NOTICE, '1');
      $('#aiVoiceNotice')?.classList.add('hidden');
      voiceState('Hold the microphone button and speak your question.');
    });
    wireMic();
    wireSpeak();
    render();
  }
  return { init, _test: { answerHtml, suggestionsHtml } };
})();
