/* Keep the existing renderer usable while replacing its desktop host. */
if (!window.ipfix && window.__TAURI__) {
  const listeners = new Set();
  const ready = window.__TAURI__.event.listen('network:state', (event) => {
    for (const listener of listeners) listener(event.payload);
  });
  window.ipfix = {
    async request(action, payload = {}) {
      try {
        await ready;
        return await window.__TAURI__.core.invoke('request', { action, payload });
      } catch (error) {
        throw error instanceof Error ? error : new Error(String(error));
      }
    },
    onState(listener) { listeners.add(listener); return () => listeners.delete(listener); },
    copyText(text) { return window.__TAURI__.core.invoke('copy_text', { text }); }
  };
}
