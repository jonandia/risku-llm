// ========================================
// ANALIZADOR UNIFICADO DE RIESGOS v3.0
// Detecta:
// 1. (PHP) Bots de IA y Crawlers (Google-Extended, ChatGPT-User, etc.)
// 2. (JS) Humanos referidos por IA (Clics desde ChatGPT, Gemini, etc.)
// 3. (JS) Bots automatizados (Puppeteer, Selenium)
// 4. (JS) Humanos
// ========================================

var getAllEventData = require('getAllEventData');
var getRequestHeader = require('getRequestHeader');
var makeString = require('makeString');
var logToConsole = require('logToConsole');
var JSON = require('JSON');
var getRequestBody = require('getRequestBody');
var getRemoteAddress = require('getRemoteAddress');
var sha256Sync = require('sha256Sync');

// ==== HELPERS ====
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
function _toStr(v){ return '' + (v == null ? '' : v); }
function trimStr(v){ return _toStr(v).trim(); }
function log(label, value){
  if (data && data.enableLogging === false) return;
  var t = typeof value;
  if (value && (t === 'object')) {
    logToConsole('[RISK] ' + label + ': ' + JSON.stringify(value));
  } else {
    logToConsole('[RISK] ' + label + ': ' + makeString(value));
  }
}

// ==== LISTAS DE PATRONES (Inspirado en Spyglasses) ====

// Lista de CRAWLERS CONOCIDOS (No-IA).
// ¡Debe ir PRIMERO para que 'googlebot' no sea pillado por 'google'!
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

// Lista de BOTS DE IA (LLMs)
var llmPatterns = [
    // --- Agentes de IA (Responden preguntas) ---
    {pattern: 'ChatGPT-User', agent_name: 'chatgpt-user', category: 'AI Agent', subcategory: 'AI Assistants', company: 'OpenAI', isAiModelTrainer: false, intent: 'UserQuery'},
    {pattern: 'Perplexity-User', agent_name: 'perplexity-user', category: 'AI Agent', subcategory: 'AI Assistants', company: 'Perplexity AI', isAiModelTrainer: false, intent: 'UserQuery'},
    {pattern: 'Gemini-User', agent_name: 'gemini-user', category: 'AI Agent', subcategory: 'AI Assistants', company: 'Google', isAiModelTrainer: false, intent: 'UserQuery'},
    {pattern: 'Claude-User', agent_name: 'claude-user', category: 'AI Agent', subcategory: 'AI Assistants', company: 'Anthropic', isAiModelTrainer: false, intent: 'UserQuery'},
    
    // --- Crawlers de IA (Entrenan modelos) ---
    {pattern: 'CCBot', agent_name: 'ccbot', category: 'AI Crawler', subcategory: 'Model Training Crawlers', company: 'Common Crawl', isAiModelTrainer: true, intent: 'DataCollection'},
    {pattern: 'ClaudeBot', agent_name: 'claudebot', category: 'AI Crawler', subcategory: 'Model Training Crawlers', company: 'Anthropic', isAiModelTrainer: true, intent: 'DataCollection'},
    {pattern: 'GPTBot', agent_name: 'gptbot', category: 'AI Crawler', subcategory: 'Model Training Crawlers', company: 'OpenAI', isAiModelTrainer: true, intent: 'DataCollection'},
    {pattern: 'meta-externalagent', agent_name: 'meta-externalagent', category: 'AI Crawler', subcategory: 'Model Training Crawlers', company: 'Meta', isAiModelTrainer: true, intent: 'DataCollection'},
    {pattern: 'Applebot-Extended', agent_name: 'applebot-extended', category: 'AI Crawler', subcategory: 'Model Training Crawlers', company: 'Apple', isAiModelTrainer: true, intent: 'DataCollection'},
    {pattern: 'Google-Extended', agent_name: 'gemini_crawler', category: 'AI Crawler', subcategory: 'Model Training Crawlers', company: 'Google', isAiModelTrainer: true, intent: 'DataCollection'},
    {pattern: 'GrokBot', agent_name: 'grok', category: 'AI Crawler', subcategory: 'Model Training Crawlers', company: 'xAI', isAiModelTrainer: true, intent: 'DataCollection'},
    {pattern: 'Bytespider', agent_name: 'bytespider', category: 'AI Crawler', subcategory: 'Model Training Crawlers', company: 'ByteDance', isAiModelTrainer: true, intent: 'DataCollection'},
    {pattern: 'YouBot', agent_name: 'youbot', category: 'AI Crawler', subcategory: 'AI Assistants', company: 'You.com', isAiModelTrainer: false, intent: 'DataCollection'},

    // --- Patrones Especiales (Nuestros hallazgos) ---
    {pattern: 'Google', agent_name: 'gemini_browsing', category: 'AI Agent', subcategory: 'AI Assistants', company: 'Google', isAiModelTrainer: false, intent: 'UserQuery'} // El UA: "Google"
];

// Lista de BOTS HEURÍSTICOS (Scrapers, scripts)
var heuristicBotPatterns = [
    {pattern: 'curl/', type: 'bot_script', name: 'curl'},
    {pattern: 'wget/', type: 'bot_script', name: 'wget'},
    {pattern: 'python-requests', type: 'bot_script', name: 'python'},
    {pattern: 'postman', type: 'bot_tool', name: 'postman'},
    {pattern: 'go-http-client', type: 'bot_script', name: 'go_script'},
    {pattern: 'bot', type: 'bot_generic', name: 'bot_ua'},
    {pattern: 'spider', type: 'bot_generic', name: 'spider_ua'},
    {pattern: 'crawler', type: 'bot_generic', name: 'crawler_ua'}
];

// Lista de REFERENTES DE IA (Tráfico humano desde IA)
var aiReferrerPatterns = [
    {id: 'chatgpt', name: 'ChatGPT', company: 'OpenAI', patterns: ['chat.openai.com', 'chatgpt.com']},
    {id: 'claude', name: 'Claude', company: 'Anthropic', patterns: ['claude.ai']},
    {id: 'perplexity', name: 'Perplexity', company: 'Perplexity AI', patterns: ['perplexity.ai']},
    {id: 'gemini', name: 'Gemini', company: 'Google', patterns: ['gemini.google.com', 'bard.google.com']},
    {id: 'copilot', name: 'Microsoft Copilot', company: 'Microsoft', patterns: ['copilot.microsoft.com', 'bing.com/chat']}
];

// ==== PROCESADOR PRINCIPAL POR TIPO DE EVENTO ====
function processEventByType(evt) {
  var eventName = evt.event_name || '';
  
  // --- CASO 1: Evento server-side (PHP) - LLMs sin JavaScript ---
  if (eventName === 'server_side_signals') {
    return processServerSideVisit(evt);
  }
  
  // --- CASO 2: Evento JavaScript unificado ---
  if (eventName === 'unified_risk_detection' || eventName === 'llm_signals' || eventName === 'page_risk_probe') {
    // Es un cliente con JS. ¿Es un humano referido por IA?
    var referrerResult = processAiReferrer(evt);
    if (referrerResult) {
      return referrerResult;
    }
    
    // Si no es un referente de IA, es un humano o un bot automatizado (Puppeteer, etc.)
    return processUnifiedDetection(evt);
  }
  
  // --- CASO 3: Evento desconocido ---
  return processUnknownEvent(evt);
}

// ==== PROCESADOR 1: SERVER-SIDE (PHP) ====
function processServerSideVisit(evt) {
    var ua = evt.user_agent || evt.ua || '';
    var uaLower = ua.toLowerCase();
    var hasAcceptLang = !!(evt.accept_language || evt.al);
    var hasCookies = !!(evt.has_cookies || evt.c);

    // --- 1. DETECCIÓN DE CRAWLERS CONOCIDOS (No-IA) ---
    for (var j = 0; j < knownBotPatterns.length; j++) {
        if (uaLower.indexOf(knownBotPatterns[j].pattern) !== -1) {
            return {
                visitor_type: knownBotPatterns[j].type,
                agent_name: knownBotPatterns[j].name,
                category: 'Bot',
                subcategory: 'Known Crawler',
                company: 'Unknown',
                intent: 'Crawling',
                is_ai_model_trainer: false,
                score: 60,
                level: 'high',
                reasons: ['known_crawler_' + knownBotPatterns[j].name],
                event_source: 'php'
            };
        }
    }

    // --- 2. DETECCIÓN DE BOTS DE IA (LLMs) ---
    for (var i = 0; i < llmPatterns.length; i++) {
        var currentPattern = llmPatterns[i];
        if (uaLower.indexOf(currentPattern.pattern.toLowerCase()) !== -1) {
            return {
                visitor_type: currentPattern.isAiModelTrainer ? 'llm_crawler' : 'llm_agent',
                agent_name: currentPattern.agent_name,
                category: currentPattern.category,
                subcategory: currentPattern.subcategory,
                company: currentPattern.company,
                intent: currentPattern.intent,
                is_ai_model_trainer: currentPattern.isAiModelTrainer,
                score: currentPattern.isAiModelTrainer ? 75 : 90,
                level: 'high',
                reasons: [currentPattern.agent_name + '_ua_detected'],
                event_source: 'php'
            };
        }
    }

    // --- 3. DETECCIÓN DE BOTS HEURÍSTICOS (Scrapers, etc.) ---
    for (var k = 0; k < heuristicBotPatterns.length; k++) {
        if (uaLower.indexOf(heuristicBotPatterns[k].pattern) !== -1) {
            return {
                visitor_type: heuristicBotPatterns[k].type,
                agent_name: heuristicBotPatterns[k].name,
                category: 'Bot',
                subcategory: 'Heuristic Bot',
                company: 'Unknown',
                intent: 'Crawling',
                is_ai_model_trainer: false,
                score: 80,
                level: 'high',
                reasons: [heuristicBotPatterns[k].name],
                event_source: 'php'
            };
        }
    }

    // --- 4. HEURÍSTICAS DE CABECERA (Si no hay match de UA) ---
    var visitor_type = 'unknown';
    var agent_name = 'unknown';
    var score = 0;
    var reasons = [];
    
    if (!hasCookies && !hasAcceptLang) {
        visitor_type = 'bot_suspicious';
        agent_name = 'heuristic_no_lang';
        score = 70;
        reasons.push('suspicious_no_cookies_no_lang');
    } else if (!hasCookies) {
        visitor_type = 'bot_suspicious';
        agent_name = 'heuristic_no_cookies';
        score = 50;
        reasons.push('suspicious_no_cookies');
    } else {
        // Tiene cookies, pero no User-Agent de navegador y no ejecutó JS
        // Este es el caso de "Comet" (un humano)
        visitor_type = 'human_no_js';
        agent_name = 'human_no_js';
        score = 20;
        reasons.push('has_cookies_no_js');
    }
    
    return {
        visitor_type: visitor_type,
        agent_name: agent_name,
        category: visitor_type.indexOf('bot') !== -1 ? 'Bot' : 'Human',
        subcategory: 'Heuristic',
        company: 'Unknown',
        intent: 'Unknown',
        is_ai_model_trainer: false,
        score: score,
        level: score >= 60 ? 'high' : (score >= 30 ? 'medium' : 'low'),
        reasons: reasons,
        event_source: 'php'
    };
}

// ==== PROCESADOR 2: REFERENTES DE IA (JS) ====
function processAiReferrer(evt) {
    var referrer = get(evt, 'page.ref', get(evt, 'signals.page.ref', ''));
    if (!referrer) {
        return null;
    }

    var refLower = referrer.toLowerCase();
    
    for (var i = 0; i < aiReferrerPatterns.length; i++) {
        var refInfo = aiReferrerPatterns[i];
        for (var j = 0; j < refInfo.patterns.length; j++) {
            if (refLower.indexOf(refInfo.patterns[j]) !== -1) {
                // ¡Match! Es un humano referido por IA
                return {
                    visitor_type: 'human_ai_referred',
                    agent_name: refInfo.id, // ej: 'chatgpt', 'gemini'
                    category: 'Human',
                    subcategory: 'AI Referrer',
                    company: refInfo.company,
                    intent: 'UserQuery',
                    is_ai_model_trainer: false,
                    score: 10,
                    level: 'low',
                    reasons: ['ai_referrer_' + refInfo.id],
                    event_source: 'js'
                };
            }
        }
    }
    
    // No es un referente de IA
    return null;
}

// ==== PROCESADOR 3: DETECCIÓN UNIFICADA (JS) ====
function processUnifiedDetection(evt) {
  var sig = evt.signals || {};
  return scoreRisk(evt, sig); // Llamar a la función de scoring de JS
}

// ==== PROCESADOR 4: EVENTO DESCONOCIDO ====
function processUnknownEvent(evt) {
  return {
    visitor_type: 'unknown',
    agent_name: 'unknown',
    category: 'Unknown',
    score: 0,
    level: 'low',
    reasons: ['unknown_event_name'],
    event_source: 'unknown'
  };
}


// ==== SCORING FUNCTION DE JS (Modificada para devolver agent_name) ====
function scoreRisk(evt, sig) {
  // ( ... Tu código de 'scoreRisk' de 500 líneas va aquí ... )
  // ...
  // ...
  // Hacia el final, en "===== 10. DECISIÓN FINAL ====="
  
  // Vamos a simular que el código de 500 líneas existe y
  // solo modificamos la parte del return.
  
  // --- Simulación de tu lógica de scoreRisk ---
  var score_human = 0;
  var score_bot = 0;
  var reasons = [];
  var automation_agent = 'unknown'; // Variable para guardar el bot de JS

  // Tu lógica para detectar webdriver, puppeteer, etc. iría aquí
  // Por ejemplo:
  if (get(sig, 'automation.puppeteer') === true) {
      score_bot += 40;
      reasons.push('puppeteer_detected');
      automation_agent = 'puppeteer';
  } else if (get(sig, 'automation.playwright') === true) {
      score_bot += 40;
      reasons.push('playwright_detected');
      automation_agent = 'playwright';
  } else if (get(sig, 'features.webdriver') === true) {
      score_bot += 60;
      reasons.push('webdriver_true');
      automation_agent = 'webdriver';
  }
  // ... etc ...
  
  if (get(sig, 'screen.w') === 0) {
      score_bot += 25;
      reasons.push('zero_screen_size');
  } else {
      score_human += 4;
  }
  
  // --- Fin de la simulación ---

  
  // ===== 10. DECISIÓN FINAL (Modificada) =====
  
  var visitor_type = 'unknown';
  var agent_name = 'unknown';
  var category = 'Unknown';
  var final_score = 0;

  if (score_bot >= 40) {
      visitor_type = 'bot';
      agent_name = automation_agent !== 'unknown' ? automation_agent : 'automation_bot';
      category = 'Bot';
      final_score = score_bot;
  } else {
      visitor_type = 'human';
      agent_name = 'human';
      category = 'Human';
      final_score = score_human;
  }

  var level = 'low';
  if (visitor_type === 'bot') {
      if (final_score >= 70) level = 'high';
      else if (final_score >= 45) level = 'medium';
  }

  return {
      visitor_type: visitor_type,
      agent_name: agent_name,
      category: category,
      subcategory: (visitor_type === 'bot') ? 'Automated Browser' : 'Standard',
      company: 'Unknown',
      intent: 'Unknown',
      is_ai_model_trainer: false,
      score: final_score,
      level: level,
      reasons: reasons,
      event_source: 'js'
  };
}


// ==== MAIN EXECUTION (Modificado para generar visit_hash) ====
var evt = getAllEventData() || {};
var ua = getRequestHeader('User-Agent') || evt.user_agent || '';
var ip = getRemoteAddress() || evt.ip_real_unificada || '';

log('=== Risk Detection Start ===');
log('Event Name', evt.event_name || '(none)');

// Procesar según tipo de evento
var result = processEventByType(evt);

// --- Inyección de datos clave ---
if (result && typeof result === 'object') {
    
    // Generar visit_hash si no viene del PHP
    // Usamos sha256Sync en lugar de md5 para GTM SS
    result.visit_hash = evt.visit_hash || sha256Sync(ip + ua);
    
    // Re-inyectar otros datos útiles
    result.original_event_name = evt.event_name || 'unknown';
    result.page_full_url = evt.page_full_url || get(evt, 'page.url', '');
    result.page_path = evt.page_path || get(evt, 'page.path', '');
    result.ip_real_unificada = ip;
    result.user_agent = ua;
    result.referer = evt.referer || get(evt, 'page.ref', '');
}

log('Result', result);

// Devolver según el tipo solicitado
var outputType = (data && data.output) ? data.output : 'visitor_type';

switch(outputType) {
  case 'score':
    return result.score || 0;
  case 'level':
    return result.level || 'low';
  case 'agent_name':
    return result.agent_name || 'unknown';
  case 'visitor_type':
    return result.visitor_type || 'human';
  case 'reasons':
    return (result.reasons && result.reasons.length > 0) ? result.reasons.join('|') : '';
  case 'full':
    return result;
  default:
    return result.visitor_type || 'human';
}