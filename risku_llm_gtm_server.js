// ========================================
// ANALIZADOR UNIFICADO DE RIESGOS v2.1 (Optimizado)
// Detecta: Humanos, Bots (con-JS), Scrapers/LLMs (sin-JS)
// ========================================

var getAllEventData = require('getAllEventData');
var getEventData = require('getEventData');
var getRequestHeader = require('getRequestHeader');
var makeString = require('makeString');
var logToConsole = require('logToConsole');
var JSON = require('JSON');

// ==== HELPERS ====
function min(a, b) {
  return a < b ? a : b;
}

function get(obj, path, def) {
  if (obj == null || path == null) return def;
  var parts = (path + '').split('.');
  var cur = obj;
  for (var i = 0; i < parts.length; i++) {
    if (cur == null) return def;
    cur = cur[parts[i]];
  }
  return (cur === undefined) ? def : cur;
}

function toBool(x){ return !!x; }

function _toStr(v){ return '' + (v == null ? '' : v); }
function trimStr(v){
  return _toStr(v).trim();
}

function isEmptyStr(v){ return trimStr(v) === ''; }

function log(label, value){
  if (data && data.enableLogging === false) return;
  var t = typeof value;
  if (value && (t === 'object')) {
    logToConsole('[RISK] ' + label + ': ' + JSON.stringify(value));
  } else {
    logToConsole('[RISK] ' + label + ': ' + makeString(value));
  }
}

// ==== PROCESADOR PRINCIPAL POR TIPO DE EVENTO ====
function processEventByType(evt) {
  var eventName = evt.event_name || '';
  
  // CASO 1: Evento server-side (PHP) - LLMs sin JavaScript
  if (eventName === 'server_side_visit' || eventName === 'srv_visit' || eventName === 'server_side_signals') {
    return processServerSideVisit(evt);
  }
  
  // CASO 2: Evento JavaScript unificado
  if (eventName === 'unified_risk_detection') {
    return processUnifiedDetection(evt);
  }
  
  // CASO 3: Eventos legacy (llm_signals, page_risk_probe)
  if (eventName === 'llm_signals' || eventName === 'page_risk_probe') {
    return processLegacySignals(evt);
  }
  
  // CASO 4: Evento desconocido
  return processUnknownEvent(evt);
}

// ==== PROCESADOR SERVER-SIDE (PHP) ====
function processServerSideVisit(evt) {
    var score = 0;
    var reasons = [];
    var visitor_type = 'unknown';
    var agent_name = 'unknown'; // <-- ¡NUEVA VARIABLE!

    // Obtener datos básicos
    var ua = evt.user_agent || evt.ua || '';
    var uaLower = ua.toLowerCase();
    var hasAcceptLang = !!(evt.accept_language || evt.al);
    var hasCookies = !!(evt.has_cookies || evt.c);

    // --- 1. DETECCIÓN DE LLMs (Prioridad Alta) ---
    var llmPatterns = [
        {pattern: 'google-extended', type: 'llm', score: 90, name: 'gemini'},
        {pattern: 'chatgpt-user',    type: 'llm', score: 90, name: 'chatgpt'},
        {pattern: 'claudebot',       type: 'llm', score: 90, name: 'claude'},
        {pattern: 'perplexitybot',   type: 'llm', score: 85, name: 'perplexity'},
        {pattern: 'grokbot',         type: 'llm', score: 85, name: 'grok'},
        {pattern: 'youbot',          type: 'llm', score: 80, name: 'you.com'},
        {pattern: 'anthropic',       type: 'llm', score: 90, name: 'claude_fallback'},
        {pattern: 'openai',          type: 'llm', score: 90, name: 'openai_fallback'},
        {pattern: 'bytespider',      type: 'llm_training', score: 75, name: 'bytespider'},
        {pattern: 'ccbot',           type: 'llm_training', score: 75, name: 'commoncrawl'}
    ];

    for (var i = 0; i < llmPatterns.length; i++) {
        if (uaLower.indexOf(llmPatterns[i].pattern) !== -1) {
            visitor_type = llmPatterns[i].type; // ej: 'llm'
            agent_name = llmPatterns[i].name;   // ej: 'gemini'
            score = llmPatterns[i].score;
            reasons.push(agent_name + '_ua_detected');
            
            return {
                visitor_type: visitor_type,
                agent_name: agent_name, // <-- CAMPO AÑADIDO
                score: score,
                level: score >= 60 ? 'high' : 'medium',
                reasons: reasons,
                event_source: 'php'
            };
        }
    }

    // --- 2. DETECCIÓN DE CRAWLERS CONOCIDOS (No-LLM) ---
    // (Convertido a objetos para tener 'name' y 'type')
    var knownBotPatterns = [
        {pattern: 'googlebot', type: 'bot_crawler', name: 'googlebot'},
        {pattern: 'bingbot', type: 'bot_crawler', name: 'bingbot'},
        {pattern: 'slurp', type: 'bot_crawler', name: 'yahoo_slurp'},
        {pattern: 'duckduckbot', type: 'bot_crawler', name: 'duckduckbot'},
        {pattern: 'baiduspider', type: 'bot_crawler', name: 'baidu'},
        {pattern: 'yandexbot', type: 'bot_crawler', name: 'yandex'},
        {pattern: 'ahrefsbot', type: 'bot_crawler', name: 'ahrefs'},
        {pattern: 'semrushbot', type: 'bot_crawler', name: 'semrush'},
        {pattern: 'applebot', type: 'bot_crawler', name: 'applebot'},
        {pattern: 'facebookexternalhit', type: 'bot_crawler', name: 'facebook'},
        {pattern: 'twitterbot', type: 'bot_crawler', name: 'twitter'},
        {pattern: 'linkedinbot', type: 'bot_crawler', name: 'linkedin'},
        {pattern: 'slackbot', type: 'bot_crawler', name: 'slack'}
    ];

    for (var j = 0; j < knownBotPatterns.length; j++) {
        if (uaLower.indexOf(knownBotPatterns[j].pattern) !== -1) {
            visitor_type = knownBotPatterns[j].type; // ej: 'bot_crawler'
            agent_name = knownBotPatterns[j].name;   // ej: 'googlebot'
            score = 60;
            reasons.push('known_crawler_' + agent_name);

            return {
                visitor_type: visitor_type,
                agent_name: agent_name, // <-- CAMPO AÑADIDO
                score: score,
                level: 'high',
                reasons: reasons,
                event_source: 'php'
            };
        }
    }

    // --- 3. DETECCIÓN DE BOTS HEURÍSTICOS (Scrapers, etc.) ---
    var heuristicBotPatterns = [
        {pattern: 'curl/', type: 'bot_script', score: 80, name: 'curl'},
        {pattern: 'wget/', type: 'bot_script', score: 80, name: 'wget'},
        {pattern: 'python-requests', type: 'bot_script', score: 80, name: 'python'},
        {pattern: 'postman', type: 'bot_tool', score: 80, name: 'postman'},
        {pattern: 'httpie', type: 'bot_script', score: 80, name: 'httpie'},
        {pattern: 'bot', type: 'bot_generic', score: 70, name: 'bot_ua'},
        {pattern: 'spider', type: 'bot_generic', score: 70, name: 'spider_ua'},
        {pattern: 'crawler', type: 'bot_generic', score: 70, name: 'crawler_ua'}
    ];

    for (var k = 0; k < heuristicBotPatterns.length; k++) {
        if (uaLower.indexOf(heuristicBotPatterns[k].pattern) !== -1) {
            visitor_type = heuristicBotPatterns[k].type;
            agent_name = heuristicBotPatterns[k].name;   // ej: 'curl'
            score = heuristicBotPatterns[k].score;
            reasons.push(agent_name);
            
            return {
                visitor_type: visitor_type,
                agent_name: agent_name, // <-- CAMPO AÑADIDO
                score: score,
                level: 'high',
                reasons: reasons,
                event_source: 'php'
            };
        }
    }

    // --- 4. HEURÍSTICAS DE CABECERA (Si no hay match de UA) ---
    if (!hasCookies && !hasAcceptLang) {
        visitor_type = 'bot_suspicious';
        agent_name = 'heuristic'; // Un nombre genérico para este caso
        score = 70;
        reasons.push('suspicious_no_cookies_no_lang');
    } else if (!hasCookies) {
        visitor_type = 'bot_suspicious';
        agent_name = 'heuristic';
        score = 50;
        reasons.push('suspicious_no_cookies');
    } else {
        visitor_type = 'possible_human_or_stealth_bot';
        agent_name = 'unknown'; // No tenemos suficiente info
        score = 20;
        reasons.push('has_cookies_no_js');
    }
    
    return {
        visitor_type: visitor_type,
        agent_name: agent_name, // <-- CAMPO AÑADIDO
        score: score,
        level: score >= 60 ? 'high' : (score >= 30 ? 'medium' : 'low'),
        reasons: reasons,
        event_source: 'php'
    };
}

// ==== PROCESADOR UNIFICADO (JavaScript) ====
function processUnifiedDetection(evt) {
  var sig = evt.signals || {};
  return scoreRisk(evt, sig);
}

// ==== PROCESADOR LEGACY ====
function processLegacySignals(evt) {
  var sig = evt.signals || {};
  return scoreRisk(evt, sig);
}

// ==== PROCESADOR EVENTO DESCONOCIDO ====
function processUnknownEvent(evt) {
  var hasClientId = !!evt.client_id;
  
  return {
    visitor_type: hasClientId ? 'possible_human' : 'bot',
    score: hasClientId ? 20 : 50,
    level: hasClientId ? 'low' : 'medium',
    reasons: hasClientId ? ['has_client_id'] : ['no_client_id'],
    event_source: 'unknown'
  };
}

// ==== SCORING FUNCTION COMPLETA (Optimizada) ====
// Esta función SÓLO se ejecuta para clientes con JS.
// Su objetivo es diferenciar 'human' vs 'bot' (automatización).
function scoreRisk(evt, sig) {
  // Extraer todas las señales
  var features    = get(sig, 'features', {});
  var screen      = get(sig, 'screen', {});
  var viewport    = get(sig, 'viewport', {});
  var page        = get(sig, 'page', {});
  var perf        = get(sig, 'performance', {});
  var conn        = get(sig, 'conn', null);
  
  // Señales específicas
  var apis        = get(sig, 'apis', {});
  var hardware    = get(sig, 'hardware', {});
  var navigator   = get(sig, 'navigator', {});
  var window      = get(sig, 'window', {});
  var document    = get(sig, 'document', {});
  var storage     = get(sig, 'storage', {});
  var automation  = get(sig, 'automation', {});
  var timing      = get(sig, 'timing', null);

  var ua          = _toStr(get(evt, 'user_agent', get(sig, 'ua', '')));
  var lang        = _toStr(get(sig, 'lang', get(evt, 'language', '')));
  var languages   = _toStr(get(sig, 'languages', ''));
  var tzName      = _toStr(get(sig, 'tz_name', ''));
  var pluginsLen  = get(sig, 'plugins_len', navigator.plugins_length);
  
  // Page data
  var pageUrl     = _toStr(get(page, 'url', ''));
  var ref         = _toStr(get(page, 'ref', document.referrer || ''));
  var vis         = _toStr(get(page, 'vis', document.visibility || ''));
  var histLen     = get(page, 'hist_len', window.history_length);

  var score_human = 0;
  var score_bot = 0; // *** MEJORA 2: score_llm eliminado ***
  var reasons = [];

  // ===== 1. DETECCIÓN DE WEBDRIVER Y AUTOMATION =====
  if (toBool(features.webdriver) || toBool(navigator.webdriver)) {  
    score_bot += 60;  
    reasons.push('webdriver_true');
  }

  if (toBool(features.has_phantom) || toBool(automation.phantom)) {
    score_bot += 60;
    reasons.push('phantom_detected');
  }
  
  if (toBool(features.has_nightmare) || toBool(automation.nightmare)) {
    score_bot += 60;
    reasons.push('nightmare_detected');
  }
  
  if (toBool(automation.puppeteer)) {
    score_bot += 40;
    reasons.push('puppeteer_detected');
  }
  
  if (toBool(automation.playwright)) {
    score_bot += 40;
    reasons.push('playwright_detected');
  }
  
  if (toBool(automation.selenium)) {
    score_bot += 40;
    reasons.push('selenium_detected');
  }
  
  // Chrome runtime con contexto
  if (toBool(features.cdp_runtime) || toBool(automation.chrome_runtime)) {
    var isGTMPreview = (ref && ref.indexOf('tagassistant.google.com') !== -1);
    var humanIndicators = 0;
    
    if (pluginsLen > 0) humanIndicators++;
    if (features.has_webassembly === true || apis.webassembly === true) humanIndicators++;
    if (features.has_battery === true || apis.battery === true) humanIndicators++;
    if (features.hardware_concurrency > 1 || hardware.cores > 1) humanIndicators++;
    if (histLen > 1) humanIndicators++;
    
    if (isGTMPreview) {
      reasons.push('gtm_preview_mode');
    } else if (humanIndicators >= 3) {
      score_human += 1;
      reasons.push('browser_with_extensions');
    } else {
      score_bot += 30;
      reasons.push('chrome_automation');
    }
  }

  // ===== 2. ANÁLISIS DE APIs (Penalizaciones a BOT) =====
  // *** MEJORA 3: Penalizaciones movidas de llm a bot ***
  
  // WebAssembly
  if (apis.webassembly === false || features.has_webassembly === false) {
    score_bot += 20; // <-- Movido de llm
    reasons.push('no_webassembly');
  } else if (apis.webassembly === true || features.has_webassembly === true) {
    score_human += 8;
  }
  
  // Battery API
  if (apis.battery === false || features.has_battery === false) {
    score_bot += 10; // <-- Movido de llm
    reasons.push('no_battery_api');
  } else if (apis.battery === true || features.has_battery === true) {
    score_human += 4;
  }
  
  // Intl API
  if (apis.intl === false || features.has_intl === false) {
    score_bot += 8; // <-- Movido de llm
    reasons.push('no_intl_api');
  } else if (apis.intl === true || features.has_intl === true) {
    score_human += 2;
  }
  
  // ServiceWorker
  if (apis.serviceworker === false || features.has_serviceworker === false) {
    score_bot += 6; // <-- Movido de llm
    reasons.push('no_serviceworker');
  } else if (apis.serviceworker === true || features.has_serviceworker === true) {
    score_human += 2;
  }

  // ===== 3. ANÁLISIS DE HARDWARE =====
  var cores = hardware.cores || features.hardware_concurrency;
  
  if (cores === null || cores === 0 || cores === undefined) {
    score_bot += 15; // <-- Movido de llm
    reasons.push('no_hardware_concurrency');
  } else if (cores >= 2 && cores <= 16) {
    score_human += 6;
  } else if (cores > 16) {
    score_bot += 3;
    reasons.push('unusual_cores');
  }
  
  var memory = hardware.memory || features.device_memory;
  
  if (memory === null || memory === undefined) {
    score_bot += 8; // <-- Movido de llm
    reasons.push('no_device_memory');
  } else if (memory >= 2) {
    score_human += 4;
  }
  
  // Touch
  if (hardware.max_touch > 0 || hardware.has_touch === true || features.max_touch_points > 0) {
    score_human += 3;
  }

  // ===== 4. ANÁLISIS DE NAVIGATOR Y PLUGINS =====
  
  // Plugins
  if (pluginsLen === 0 || pluginsLen === null) {
    score_bot += 18; // <-- Movido de llm
    reasons.push('no_plugins');
  } else if (pluginsLen >= 3) {
    score_human += 8;
  } else if (pluginsLen > 0) {
    score_human += 5;
  }
  
  // Languages
  var langsLen = navigator.languages_length || (languages ? languages.split(',').length : 0);
  
  if (langsLen === 0) {
    score_bot += 12; // <-- Movido de llm
    reasons.push('no_languages');
  } else if (langsLen > 0) {
    score_human += 4;
  }
  
  // Cookies
  if (navigator.cookies_enabled === false || features.cookies_enabled === false) {
    score_bot += 8; // <-- Movido de llm
    reasons.push('cookies_disabled');
  } else if (navigator.cookies_enabled === true || features.cookies_enabled === true) {
    score_human += 1;
  }

  // ===== 5. ANÁLISIS DE SCREEN =====
  var screenW = screen.w || screen.width || 0;
  var screenH = screen.h || screen.height || 0;
  
  if (screenW === 0 || screenH === 0) {
    score_bot += 25; // <-- Movido de llm
    reasons.push('zero_screen_size');
  } else if (screenW > 0 && screenH > 0) {
    score_human += 4;
    
    // Validar dimensiones
    var availW = screen.availW || screen.avail_width;
    var availH = screen.availH || screen.avail_height;
    
    if (availW !== null && availH !== null) {
      if (availW > screenW || availH > screenH) {
        score_bot += 15;
        reasons.push('impossible_screen_dimensions');
      }
    }
  }

  // ===== 6. ANÁLISIS DE WINDOW Y VIEWPORT =====
  var innerW = window.inner_width || viewport.w || 0;
  var innerH = window.inner_height || viewport.h || 0;
  
  if (innerW === 0 || innerH === 0) {
    score_bot += 15; // <-- Movido de llm
    reasons.push('zero_viewport');
  }
  
  var outerW = window.outer_width || viewport.outerW;
  var outerH = window.outer_height || viewport.outerH;
  
  if (outerW !== null && outerH !== null && outerW !== undefined && outerH !== undefined) {
    if (outerW < innerW || outerH < innerH) {
      score_bot += 15;
      reasons.push('impossible_window_dimensions');
    }
  }
  
  // History length con contexto
  if (histLen === 1) {
    var isGTMPreview = (ref && ref.indexOf('tagassistant.google.com') !== -1);
    if (!isGTMPreview) {
      score_bot += 12; // <-- Movido de llm
      reasons.push('history_length_one');
    } else {
      reasons.push('gtm_preview_mode');
    }
  } else if (histLen > 1) {
    score_human += 6;
  }

  // ===== 7. ANÁLISIS DE STORAGE =====
  if (storage.can_write_local === false && storage.can_write_session === false) {
    score_bot += 8; // <-- Movido de llm
    reasons.push('storage_write_failed');
  } else if (storage.can_write_local === true || storage.local_storage === true) {
    score_human += 2;
  }

  // ===== 8. ANÁLISIS DE TIMING =====
  var loadTime = null;
  
  if (timing && timing.load_time !== undefined) {
    loadTime = timing.load_time;
  } else if (perf && perf.load_time !== undefined) {
    loadTime = perf.load_time;
  }
  
  if (loadTime !== null) {
    if (loadTime < 100 && loadTime > 0) {
      score_bot += 15;
      reasons.push('impossible_load_time');
    }
  }
  
  var domTime = timing ? timing.dom_ready : (perf ? perf.dom_time : null);
  
  if (domTime !== null && domTime < 0) {
    score_bot += 10;
    reasons.push('negative_dom_time');
  }

  // ===== 9. USER-AGENT ANALYSIS =====
  var uaLower = ua.toLowerCase();
  
  // *** MEJORA 3: Lista de LLM UA eliminada de esta función ***
  
  // Bots tradicionales
  var botPatterns = [
    'googlebot', 'bingbot', 'facebookexternalhit',  
    'twitterbot', 'linkedinbot', 'slackbot',
    'bot/', 'bot-', 'crawler', 'spider', 'scraper'
  ];
  
  for (var j = 0; j < botPatterns.length; j++) {
    if (uaLower.indexOf(botPatterns[j]) !== -1) {
      score_bot += 25;
      reasons.push('known_bot_' + botPatterns[j].replace('/', ''));
      break;
    }
  }
  
  // Headless browsers
  if (uaLower.indexOf('headlesschrome') !== -1 ||  
      uaLower.indexOf('phantomjs') !== -1) {
    score_bot += 60;
    reasons.push('headless_browser');
  }

  // ===== 10. DECISIÓN FINAL =====
  // *** MEJORA 2: Lógica simplificada a human/bot ***
  
  var visitor_type = 'unknown';
  var confidence = 0;
  var final_score = 0;
  
  // Determinar tipo basado en scores
  if (score_bot >= 40) {
    visitor_type = 'bot';
    confidence = min(90, 40 + (score_bot * 0.6));
    final_score = score_bot;
  } else if (score_human >= 25) {
    visitor_type = 'human';
    confidence = min(85, 45 + (score_human * 0.5));
    final_score = score_human;
  } else {
    // Caso ambiguo (poca señal)
    if (score_human > score_bot) {
      visitor_type = 'human';
      confidence = min(75, 35 + (score_human * 0.8));
      final_score = score_human;
    } else if (score_bot > 0) {
      visitor_type = 'bot';
      confidence = min(70, 30 + (score_bot * 0.7));
      final_score = score_bot;
    } else {
      // Default a humano si no hay ninguna señal
      visitor_type = 'human';
      confidence = 40;
      final_score = score_human;
    }
  }
  
  // Risk level
  var level = 'low';
  if (visitor_type === 'bot') { // <-- Simplificado
    if (final_score >= 70) {
      level = 'high';
    } else if (final_score >= 45) {
      level = 'medium';
    }
  }
  
  return {
    visitor_type: visitor_type,
    confidence: confidence,
    score: final_score,
    level: level,
    suspect: visitor_type !== 'human',
    reasons: reasons,
    analysis: {
      score_human: score_human,
      score_bot: score_bot // <-- 'score_llm' eliminado
    }
  };
}

// ==== MAIN EXECUTION ====
var evt = getAllEventData() || {};

log('=== Risk Detection Start ===');
log('Event Name', evt.event_name || '(none)');

// Procesar según tipo de evento
var result = processEventByType(evt);

log('Result', result);

// Obtener tipo de output configurado
var outputType = (data && data.output) ? data.output : 'visitor_type';

// Devolver según el tipo solicitado
switch(outputType) {
  case 'score':
    return result.score || 0;
  case 'level':
    return result.level || 'low';
  case 'confidence':
    return result.confidence || 0;
  case 'suspect':
    return result.suspect || false;
  case 'visitor_type':
    return result.visitor_type || 'human';

  // --- ¡NUEVO CAMPO AÑADIDO! ---
  case 'agent_name':
    return result.agent_name || 'unknown'; 
  // -----------------------------

  case 'reasons':
    return (result.reasons && result.reasons.length > 0) ? result.reasons.join('|') : '';
  case 'full':
    return result;
  default:
    return result.visitor_type || 'human';
}