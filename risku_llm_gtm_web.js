<script>
(function(W) {
  'use strict';

  // ===== CONFIGURACIÓN =====
  var ENDPOINT = 'https://tracker.iacompliant.com/tracker';
  var PROJECT_ID = 'IACOMPLIANT';
  var PREVIEW_HEADER = 'ZW52LTd8MlhQQ20wbjBBdVk4ZVdqM0hjYnd6UXwxOWEyZWE2ODE1NjgwMzg4MjY3ODQ=';
  var DEBUG = false; // Cambiar a true para debug

  // ===== RECOLECCIÓN COMPLETA DE SEÑALES =====
  function gatherAllSignals() {
    var n = navigator || {};
    var d = document || {};
    var s = screen || {};
    var w = window || {};
    
    // Datos básicos
    var lang = (n.language || n.userLanguage || '');
    var langs = (n.languages && n.languages.join(',')) || lang;
    var vw = w.innerWidth || 0;
    var vh = w.innerHeight || 0;
    var dpr = w.devicePixelRatio || 1;
    
    // Plugins (crítico para detectar humanos)
    var pluginsLen = null;
    try {
      pluginsLen = (n.plugins && typeof n.plugins.length === 'number') ? n.plugins.length : null;
    } catch(e) {}
    
    // Features para detección
    var features = {
      // Automation detection
      webdriver: !!n.webdriver,
      has_phantom: !!w._phantom,
      has_nightmare: !!w.__nightmare,
      cdp_runtime: !!(w.chrome && w.chrome.runtime && !w.chrome.webstore),
      
      // LLM detection
      has_webassembly: typeof WebAssembly !== 'undefined',
      has_intl: typeof Intl !== 'undefined',
      has_battery: 'getBattery' in n,
      
      // Hardware
      hardware_concurrency: n.hardwareConcurrency || null,
      device_memory: n.deviceMemory || null,
      max_touch_points: n.maxTouchPoints || 0,
      
      // Browser capabilities
      has_chrome_obj: typeof w.chrome !== 'undefined',
      has_indexeddb: !!w.indexedDB,
      has_serviceworker: !!n.serviceWorker,
      has_webrtc: !!(w.RTCPeerConnection || w.webkitRTCPeerConnection),
      has_websocket: !!w.WebSocket,
      
      // Otros
      do_not_track: (n.doNotTrack == '1' || w.doNotTrack == '1'),
      cookies_enabled: n.cookieEnabled,
      online: n.onLine
    };
    
    // Performance (si está disponible)
    var perfTiming = null;
    if (w.performance && w.performance.timing) {
      var t = w.performance.timing;
      if (t.loadEventEnd > 0) {
        perfTiming = {
          load_time: t.loadEventEnd - t.navigationStart,
          dom_time: t.domContentLoadedEventEnd - t.domContentLoadedEventStart
        };
      }
    }
    
    // Storage test
    var canWriteStorage = false;
    try {
      localStorage.setItem('__risku_test', '1');
      localStorage.removeItem('__risku_test');
      canWriteStorage = true;
    } catch(e) {}
    
    return {
      // User Agent y lenguaje
      ua: (n.userAgent || ''),
      lang: lang,
      languages: langs,
      
      // Timezone
      tz_offset: new Date().getTimezoneOffset(),
      tz_name: (W.Intl && Intl.DateTimeFormat) ? 
                Intl.DateTimeFormat().resolvedOptions().timeZone : '',
      
      // Plugins (crítico)
      plugins_len: pluginsLen,
      
      // Screen
      screen: {
        w: s.width || 0,
        h: s.height || 0,
        cd: s.colorDepth || 0,
        availW: s.availWidth || null,
        availH: s.availHeight || null
      },
      
      // Viewport
      viewport: {
        w: vw,
        h: vh,
        dpr: dpr,
        outerW: w.outerWidth || null,
        outerH: w.outerHeight || null
      },
      
      // Features (todas las detecciones)
      features: features,
      
      // Performance
      performance: perfTiming,
      
      // Page info
      page: {
        url: location.href,
        ref: d.referrer || '',
        vis: d.visibilityState || '',
        hist_len: w.history ? w.history.length : 1
      },
      
      // Connection
      conn: n.connection ? {
        dl: n.connection.downlink || null,
        et: n.connection.effectiveType || '',
        rtt: n.connection.rtt || null
      } : null,
      
      // Storage
      storage_writable: canWriteStorage
    };
  }

  // ===== ENVÍO ÚNICO =====
  function sendToTracker() {
    var signals = gatherAllSignals();
    
    // Análisis rápido client-side (opcional)
    var quickCheck = {
      is_automated: signals.features.webdriver || signals.features.has_phantom,
      has_plugins: signals.plugins_len > 0,
      has_normal_screen: signals.screen.w > 0 && signals.screen.h > 0
    };
    
    var payload = {
      event_name: 'unified_risk_detection',  // Nombre unificado
      project_id: PROJECT_ID,
      client_ts: new Date().toISOString(),
      signals: signals,
      quick_check: quickCheck,
      event_id: Math.random().toString(36).substring(2) + Date.now()
    };
    
    if (DEBUG) {
      console.log('[RISKU] Sending unified signals:', payload);
    }
    
    // Headers
    var headers = { 'Content-Type': 'application/json' };
    if (PREVIEW_HEADER) {
      headers['X-Gtm-Server-Preview'] = PREVIEW_HEADER;
    }
    
    // Enviar con sendBeacon preferentemente
    if (navigator.sendBeacon) {
      try {
        navigator.sendBeacon(ENDPOINT, JSON.stringify(payload));
        if (DEBUG) console.log('[RISKU] Sent via sendBeacon');
      } catch(e) {
        // Fallback a fetch
        fetch(ENDPOINT, {
          method: 'POST',
          headers: headers,
          body: JSON.stringify(payload),
          keepalive: true
        }).catch(function() {});
      }
    } else {
      // Fallback directo a fetch
      fetch(ENDPOINT, {
        method: 'POST',
        headers: headers,
        body: JSON.stringify(payload),
        keepalive: true
      }).catch(function() {});
    }
  }

  // ===== EJECUTAR =====
  // Esperar un poco para tener timing data
  if (document.readyState === 'complete') {
    setTimeout(sendToTracker, 10);
  } else {
    window.addEventListener('load', function() {
      setTimeout(sendToTracker, 10);
    });
  }

})(window);
</script>