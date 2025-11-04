// ============================================
// RISKU - SOLO RECOLECTAR Y ENVIAR
// Versión con filtro anti-assets para bots
// ============================================

/**
 * Hook en 'init' para capturar señales server-side.
 * Optimizado para ejecutarse UNA SOLA VEZ por página vista real.
 */
add_action('init', function() {

    // Guardián anti-duplicados (Buena práctica)
    static $has_run = false;
    if ($has_run) {
        return;
    }

    // --- FILTRADO DE PETICIONES ---

    // 1. Ignorar admin, cron, ajax y API REST
    if (is_admin() || wp_doing_cron() || wp_doing_ajax() || (defined('REST_REQUEST') && REST_REQUEST)) {
        return;
    }

    // 2. Solo queremos peticiones 'GET' (las páginas vistas)
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
        return;
    }

    // 3. ¡NUEVO FILTRO ANTI-BOTS!
    // Filtra peticiones de assets comunes por extensión.
    // Esto bloquea /favicon.ico, /robots.txt, /sitemap.xml, etc.
    $request_uri = $_SERVER['REQUEST_URI'] ?? '/';
    $path = parse_url($request_uri, PHP_URL_PATH);
    if ($path && preg_match('/\.(js|css|jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot|xml|json|map|txt)$/i', $path)) {
        return; // ¡No registrar! Es un recurso.
    }

    // 4. EL FILTRO ORIGINAL (Sigue siendo útil para navegadores)
    // Solo continuar si el navegador está pidiendo el 'document' (el HTML principal).
    if (isset($_SERVER['HTTP_SEC_FETCH_DEST']) && $_SERVER['HTTP_SEC_FETCH_DEST'] !== 'document') {
        return;
    }
    
    // Si la petición llega hasta aquí, es una visita de página real (humano o bot)
    $has_run = true; // Marcar como ejecutado

    // --- FIN DEL FILTRADO ---


    // --- UNIFICACIÓN DE PARÁMETROS ---
    
    // 1. Unificar IP Real (priorizando Cloudflare y proxies)
    $real_ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $real_ip = $_SERVER['HTTP_CF_CONNECTING_IP']; // Prioridad 1: Cloudflare
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $real_ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]; // Prioridad 2: Proxies
    } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        $real_ip = $_SERVER['HTTP_X_REAL_IP']; // Prioridad 3: Nginx/Proxies
    }

    // 2. Unificar URL
    // (Usamos la $request_uri que ya definimos arriba en el filtro 3)
    $full_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'unknown_host') . $request_uri;

	// Crear un hash único para la combinación de IP + User-Agent
    $visit_hash = md5( ($real_ip ?? '') . ($_SERVER['HTTP_USER_AGENT'] ?? '') );

    // --- RECOLECCIÓN Y ENVÍO DE DATOS ---
    
    $endpoint = 'https://tracker.iacompliant.com/tracker';
    
    $data = [
        'event_name' => 'server_side_signals',
        'project_id' => 'IACOMPLIANT',
        'timestamp' => date('c'),
        'event_id' => uniqid('srv_', true),
        
        // ===== PÁGINA Y URL (Unificado) =====
        'page_full_url' => $full_url,
        'page_path' => parse_url($request_uri, PHP_URL_PATH),
        'query_string' => $_SERVER['QUERY_STRING'] ?? '',
        
        // ===== IP (Unificada Y Crudas) =====
        'ip_real_unificada' => $real_ip,
        'ip_remote' => $_SERVER['REMOTE_ADDR'] ?? '',
        'ip_forwarded' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '',
        'ip_real' => $_SERVER['HTTP_X_REAL_IP'] ?? '',
        'ip_cloudflare' => $_SERVER['HTTP_CF_CONNECTING_IP'] ?? '',
        'ip_client' => $_SERVER['HTTP_CLIENT_IP'] ?? '',
		'visit_hash' => $visit_hash,
        
        // User Agent (La clave para tu endpoint)
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        
        // Headers HTTP importantes
        'accept' => $_SERVER['HTTP_ACCEPT'] ?? '',
        'accept_language' => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
        'accept_encoding' => $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
        'accept_charset' => $_SERVER['HTTP_ACCEPT_CHARSET'] ?? '',
        
        // Headers de seguridad/fetch
        'sec_fetch_dest' => $_SERVER['HTTP_SEC_FETCH_DEST'] ?? '',
        'sec_fetch_mode' => $_SERVER['HTTP_SEC_FETCH_MODE'] ?? '',
        'sec_fetch_site' => $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '',
        'sec_fetch_user' => $_SERVER['HTTP_SEC_FETCH_USER'] ?? '',
        'sec_ch_ua' => $_SERVER['HTTP_SEC_CH_UA'] ?? '',
        'sec_ch_ua_mobile' => $_SERVER['HTTP_SEC_CH_UA_MOBILE'] ?? '',
        'sec_ch_ua_platform' => $_SERVER['HTTP_SEC_CH_UA_PLATFORM'] ?? '',
        
        // Otros headers
        'dnt' => $_SERVER['HTTP_DNT'] ?? '',
        'connection' => $_SERVER['HTTP_CONNECTION'] ?? '',
        'cache_control' => $_SERVER['HTTP_CACHE_CONTROL'] ?? '',
        'upgrade_insecure' => $_SERVER['HTTP_UPGRADE_INSECURE_REQUESTS'] ?? '',
        
        // Datos de la request
        'method' => $_SERVER['REQUEST_METHOD'] ?? '', // Debería ser 'GET' por el filtro
        'protocol' => $_SERVER['SERVER_PROTOCOL'] ?? '',
        'host' => $_SERVER['HTTP_HOST'] ?? '',
        'referer' => $_SERVER['HTTP_REFERER'] ?? '',
        
        // Cookies y sesión
        'has_cookies' => !empty($_COOKIE),
        'cookies_count' => count($_COOKIE),
        'php_session_id' => session_id() ?: null,
        
        // Info del servidor
        'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? '',
        'server_port' => $_SERVER['SERVER_PORT'] ?? '',
        'https' => $_SERVER['HTTPS'] ?? '',
    ];
    
    // Enviar TODO al servidor
    wp_remote_post($endpoint, [
        'body' => json_encode($data),
        'headers' => ['Content-Type' => 'application/json'],
        'timeout' => 1,
        'blocking' => false
    ]);
});