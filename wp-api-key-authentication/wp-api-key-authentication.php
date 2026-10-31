<?php
/**
 * Plugin Name: WP API Key Authentication
 * Plugin URI: https://github.com/hklcf/wp-api-key-authentication
 * Description: API key authentication for the WordPress REST API. Keys are tied to a WordPress user, stored only as bcrypt hashes, and shown once. By default every REST request requires a key; admins can open public reads or allowlist selected GET routes instead.
 * Version: 1.1.0
 * Author: HKLCF
 * Author URI: https://github.com/hklcf
 * License: GPLv2 or later
 * Requires at least: 5.8
 * Requires PHP: 7.4
 */

if (!defined('ABSPATH')) {
    exit;
}

define('WPAKA_PREFIX', 'wp_api_key_');
define('WPAKA_SETTINGS_OPTION', 'wpaka_settings');

function wpaka_default_settings() {
    return array(
        'access_mode' => 'require_all',
        'public_routes' => "/wp/v2\n/wp/v2/posts\n/wp/v2/posts/*\n/wp/v2/pages\n/wp/v2/pages/*\n/wp/v2/media\n/wp/v2/media/*\n/wp/v2/categories\n/wp/v2/categories/*\n/wp/v2/tags\n/wp/v2/tags/*\n/wp/v2/search",
        'allow_x_api_key' => 1,
        'disable_xmlrpc' => 0,
    );
}

function wpaka_xmlrpc_enabled($enabled) {
    $settings = wpaka_get_settings();
    return empty($settings['disable_xmlrpc']) ? $enabled : false;
}
add_filter('xmlrpc_enabled', 'wpaka_xmlrpc_enabled');

function wpaka_xmlrpc_methods($methods) {
    $settings = wpaka_get_settings();
    return empty($settings['disable_xmlrpc']) ? $methods : array();
}
add_filter('xmlrpc_methods', 'wpaka_xmlrpc_methods');

function wpaka_remove_pingback_header($headers) {
    $settings = wpaka_get_settings();
    if (!empty($settings['disable_xmlrpc'])) {
        unset($headers['X-Pingback']);
    }
    return $headers;
}
add_filter('wp_headers', 'wpaka_remove_pingback_header');

function wpaka_get_settings() {
    $saved = get_option(WPAKA_SETTINGS_OPTION, array());
    if (!is_array($saved)) {
        $saved = array();
    }
    return array_merge(wpaka_default_settings(), $saved);
}

function wpaka_get_all_headers() {
    if (function_exists('getallheaders')) {
        $headers = getallheaders();
        if (is_array($headers)) {
            return $headers;
        }
    }
    $headers = array();
    foreach ($_SERVER as $key => $value) {
        if (strpos($key, 'HTTP_') === 0) {
            $name = str_replace('_', '-', substr($key, 5));
            $headers[$name] = $value;
        }
    }
    return $headers;
}

function wpaka_get_authorization_header() {
    $headers = wpaka_get_all_headers();
    foreach ($headers as $name => $value) {
        if (strtolower($name) === 'authorization') {
            return $value;
        }
    }
    if (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
        return sanitize_text_field(wp_unslash($_SERVER['HTTP_AUTHORIZATION']));
    }
    if (!empty($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
        return sanitize_text_field(wp_unslash($_SERVER['REDIRECT_HTTP_AUTHORIZATION']));
    }
    return '';
}

function wpaka_get_api_key() {
    $header = wpaka_get_authorization_header();
    if (!empty($header) && strpos($header, 'Bearer ') === 0) {
        $key = trim(substr($header, 7));
        if (!empty($key)) {
            return $key;
        }
    }
    $settings = wpaka_get_settings();
    if (empty($settings['allow_x_api_key'])) {
        return '';
    }
    $headers = wpaka_get_all_headers();
    foreach ($headers as $name => $value) {
        if (strtolower($name) === 'x-api-key' && !empty($value)) {
            return trim($value);
        }
    }
    if (!empty($_SERVER['HTTP_X_API_KEY'])) {
        return sanitize_text_field(wp_unslash($_SERVER['HTTP_X_API_KEY']));
    }
    return '';
}

function wpaka_find_key($api_key) {
    global $wpdb;
    $rows = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s",
            $wpdb->esc_like(WPAKA_PREFIX) . '%'
        ),
        ARRAY_A
    );
    if (!is_array($rows)) {
        return null;
    }
    foreach ($rows as $row) {
        $data = json_decode($row['option_value'], true);
        if (!is_array($data) || empty($data['hash']) || empty($data['user_id'])) {
            continue;
        }
        if (password_verify($api_key, $data['hash'])) {
            if (empty($data['scope']) || !in_array($data['scope'], array('full', 'read_only'), true)) {
                continue;
            }
            $data['option_name'] = $row['option_name'];
            $data['expired'] = false;
            if (!empty($data['expires_at'])) {
                $expires = strtotime($data['expires_at'] . ' 23:59:59');
                if ($expires && $expires < current_time('timestamp')) {
                    $data['expired'] = true;
                }
            }
            return $data;
        }
    }
    return null;
}

function wpaka_touch_last_used($found) {
    if (empty($found['option_name'])) {
        return;
    }
    $last_used = isset($found['last_used']) ? strtotime($found['last_used']) : 0;
    if ($last_used && (current_time('timestamp') - $last_used) < 3600) {
        return;
    }
    $data = $found;
    unset($data['option_name'], $data['expired']);
    $data['last_used'] = current_time('mysql');
    update_option($found['option_name'], wp_json_encode($data));
}

function wpaka_determine_current_user($user) {
    if ($user) {
        return $user;
    }
    $api_key = wpaka_get_api_key();
    if (empty($api_key)) {
        return $user;
    }
    $found = wpaka_find_key($api_key);
    if (!$found) {
        $GLOBALS['wpaka_invalid_bearer'] = true;
        return false;
    }
    if (!empty($found['expired'])) {
        $GLOBALS['wpaka_expired_key'] = true;
        return false;
    }
    $wp_user = get_user_by('id', (int) $found['user_id']);
    if (!$wp_user) {
        return $user;
    }
    $GLOBALS['wpaka_key_found'] = true;
    $GLOBALS['wpaka_key_scope'] = $found['scope'];
    wpaka_touch_last_used($found);
    return $wp_user->ID;
}
add_filter('determine_current_user', 'wpaka_determine_current_user', 20);

function wpaka_request_method() {
    if (empty($_SERVER['REQUEST_METHOD'])) {
        return 'GET';
    }
    return strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'])));
}

function wpaka_current_rest_route() {
    if (!empty($_GET['rest_route'])) {
        $route = sanitize_text_field(wp_unslash($_GET['rest_route']));
        return '/' . trim($route, '/');
    }
    if (empty($_SERVER['REQUEST_URI'])) {
        return '';
    }
    $uri = strtok(wp_unslash($_SERVER['REQUEST_URI']), '?');
    $prefix = rest_get_url_prefix();
    $needle = '/' . $prefix . '/';
    $pos = strpos($uri, $needle);
    if ($pos === false) {
        return '';
    }
    $rest = substr($uri, $pos + strlen($needle));
    return '/' . trim($rest, '/');
}

function wpaka_route_is_public($route, $patterns) {
    foreach ($patterns as $pattern) {
        $pattern = trim($pattern);
        if (empty($pattern)) {
            continue;
        }
        if (substr($pattern, -1) === '*') {
            $prefix = rtrim($pattern, '*');
            if (strpos($route, $prefix) === 0) {
                return true;
            }
        } elseif ($route === $pattern) {
            return true;
        }
    }
    return false;
}

function wpaka_rest_authentication_errors($result) {
    if (!empty($result)) {
        return $result;
    }
    if (!empty($GLOBALS['wpaka_expired_key'])) {
        return new WP_Error('api_key_expired', 'API key has expired.', array('status' => 403));
    }
    if (!empty($GLOBALS['wpaka_invalid_bearer'])) {
        return new WP_Error('api_key_invalid', 'Invalid API key.', array('status' => 403));
    }
    if (!empty($GLOBALS['wpaka_key_found']) && isset($GLOBALS['wpaka_key_scope']) && $GLOBALS['wpaka_key_scope'] === 'read_only') {
        if (!in_array(wpaka_request_method(), array('GET', 'HEAD', 'OPTIONS'), true)) {
            return new WP_Error('api_key_read_only', 'This API key is read-only.', array('status' => 403));
        }
    }
    if (get_current_user_id()) {
        return $result;
    }
    $settings = wpaka_get_settings();
    $mode = isset($settings['access_mode']) ? $settings['access_mode'] : 'open';
    if ($mode === 'require_all') {
        return new WP_Error('rest_not_logged_in', 'REST API requires authentication.', array('status' => 401));
    }
    if ($mode === 'allowlist') {
        $routes = isset($settings['public_routes']) ? preg_split("/\r\n|\r|\n/", $settings['public_routes']) : array();
        if (wpaka_request_method() === 'GET' && wpaka_route_is_public(wpaka_current_rest_route(), $routes)) {
            return $result;
        }
        return new WP_Error('rest_not_logged_in', 'REST API requires authentication.', array('status' => 401));
    }
    return $result;
}
add_filter('rest_authentication_errors', 'wpaka_rest_authentication_errors', 20);

function wpaka_register_admin_menu() {
    add_menu_page(
        'API Keys',
        'API Keys',
        'manage_options',
        'wpaka-api-keys',
        'wpaka_render_admin_page',
        'dashicons-admin-network',
        80
    );
}
add_action('admin_menu', 'wpaka_register_admin_menu');

function wpaka_list_keys($prefix) {
    global $wpdb;
    $rows = $wpdb->get_results(
        $wpdb->prepare(
            "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s ORDER BY option_name",
            $wpdb->esc_like($prefix) . '%'
        ),
        ARRAY_A
    );
    return is_array($rows) ? $rows : array();
}

function wpaka_render_admin_page() {
    if (!current_user_can('manage_options')) {
        wp_die('You do not have permission to manage API keys.');
    }
    $notice = '';
    $generated_key = '';
    $settings = wpaka_get_settings();

    if (isset($_POST['wpaka_save_settings']) && check_admin_referer('wpaka_settings_nonce')) {
        $mode = isset($_POST['wpaka_access_mode']) ? sanitize_key(wp_unslash($_POST['wpaka_access_mode'])) : 'open';
        if (!in_array($mode, array('open', 'require_all', 'allowlist'), true)) {
            $mode = 'open';
        }
        $routes = isset($_POST['wpaka_public_routes']) ? sanitize_textarea_field(wp_unslash($_POST['wpaka_public_routes'])) : '';
        $allow_x = isset($_POST['wpaka_allow_x_api_key']) ? 1 : 0;
        $disable_xmlrpc = isset($_POST['wpaka_disable_xmlrpc']) ? 1 : 0;
        update_option(WPAKA_SETTINGS_OPTION, array(
            'access_mode' => $mode,
            'public_routes' => $routes,
            'allow_x_api_key' => $allow_x,
            'disable_xmlrpc' => $disable_xmlrpc,
        ));
        $settings = wpaka_get_settings();
        $notice = 'Settings saved.';
    }

    if (isset($_POST['wpaka_generate']) && check_admin_referer('wpaka_generate_nonce')) {
        $name = sanitize_text_field(wp_unslash($_POST['wpaka_name']));
        $user_id = (int) $_POST['wpaka_user_id'];
        $scope = isset($_POST['wpaka_scope']) && sanitize_key(wp_unslash($_POST['wpaka_scope'])) === 'read_only' ? 'read_only' : 'full';
        $expires_at = '';
        if (!empty($_POST['wpaka_expires_at'])) {
            $raw_expires = sanitize_text_field(wp_unslash($_POST['wpaka_expires_at']));
            if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $raw_expires)) {
                $expires_at = $raw_expires;
            }
        }
        $wp_user = get_user_by('id', $user_id);
        if (empty($name)) {
            $notice = 'Please enter a key name.';
        } elseif (!$wp_user || !$wp_user->has_cap('edit_posts')) {
            $notice = 'Please choose a user who can edit posts.';
        } else {
            $raw_key = wp_generate_password(32, false);
            $data = array(
                'name' => $name,
                'hash' => password_hash($raw_key, PASSWORD_BCRYPT),
                'user_id' => $user_id,
                'scope' => $scope,
                'expires_at' => $expires_at,
                'last_used' => '',
                'created' => current_time('mysql'),
            );
            $option_name = WPAKA_PREFIX . bin2hex(random_bytes(8));
            global $wpdb;
            $inserted = $wpdb->insert($wpdb->options, array(
                'option_name' => $option_name,
                'option_value' => wp_json_encode($data),
                'autoload' => 'no',
            ));
            if ($inserted) {
                $generated_key = $raw_key;
                $notice = 'Key generated. Copy it now, it will not be shown again.';
            } else {
                $notice = 'Failed to generate a key. Please try again.';
            }
        }
    }

    if (isset($_POST['wpaka_delete']) && check_admin_referer('wpaka_delete_nonce')) {
        // New keys are wp_api_key_ plus 16 hex characters, so the
        // exact stored name is enough. There is no urldecode fallback:
        // that only existed to delete the old plugin's percent-encoded
        // Chinese key name, and those keys are already gone.
        $option_name = isset($_POST['wpaka_option_name']) ? sanitize_text_field(wp_unslash($_POST['wpaka_option_name'])) : '';
        if (empty($option_name) || strpos($option_name, WPAKA_PREFIX) !== 0) {
            $notice = 'No key was selected for deletion.';
        } else {
            global $wpdb;
            $deleted = $wpdb->delete($wpdb->options, array('option_name' => $option_name));
            if ($deleted === false) {
                $notice = 'Deletion failed with a database error.';
            } elseif ($deleted === 0) {
                $notice = 'Deletion failed: no key matched that exact name.';
            } else {
                $notice = 'Key deleted.';
            }
        }
    }

    $keys = wpaka_list_keys(WPAKA_PREFIX);
    $users = get_users(array('capability' => 'edit_posts', 'orderby' => 'display_name'));
    echo '<div class="wrap"><h1>Manage API Keys</h1>';
    echo '<p>Keys are tied to a WordPress user. A valid Bearer key signs requests in as that user, so reads and post creation use that user\'s permissions. By default every REST request requires a key. Normal website browsing is not affected: this only controls the REST API.</p>';
    if ($notice) {
        echo '<div class="notice notice-info"><p>' . esc_html($notice) . '</p></div>';
    }
    if ($generated_key) {
        echo '<div class="notice notice-success"><p><strong>New API key (copy now, shown only once):</strong></p><p><code>' . esc_html($generated_key) . '</code></p></div>';
    }
    echo '<h2>Access Settings</h2><form method="post">';
    wp_nonce_field('wpaka_settings_nonce');
    echo '<table class="form-table">';
    echo '<tr><th scope="row">Public REST API access</th><td>';
    echo '<label><input type="radio" name="wpaka_access_mode" value="open"' . checked($settings['access_mode'], 'open', false) . ' /> Public read stays public</label><br />';
    echo '<label><input type="radio" name="wpaka_access_mode" value="require_all"' . checked($settings['access_mode'], 'require_all', false) . ' /> Require a key for every REST request (default)</label><br />';
    echo '<label><input type="radio" name="wpaka_access_mode" value="allowlist"' . checked($settings['access_mode'], 'allowlist', false) . ' /> Require a key, except GET requests to the routes listed below</label>';
    echo '<p class="description">Require a key for every request also blocks unauthenticated reads, so any public app or front-end that reads this site through the REST API will stop working until it sends a key. Requests already signed in with a cookie or another WordPress authentication method are not blocked by these modes.</p></td></tr>';
    echo '<tr><th scope="row"><label for="wpaka_public_routes">Public routes (allowlist mode only)</label></th><td><textarea name="wpaka_public_routes" id="wpaka_public_routes" rows="10" cols="50" class="large-text code">' . esc_textarea($settings['public_routes']) . '</textarea>';
    echo '<p class="description">One route per line. A line ending in * matches everything under it, for example /wp/v2/posts/* matches a single post. Only GET requests to these routes are public in allowlist mode.</p></td></tr>';
    echo '<tr><th scope="row">X-API-Key header</th><td><label><input type="checkbox" name="wpaka_allow_x_api_key" value="1"' . checked($settings['allow_x_api_key'], 1, false) . ' /> Allow X-API-Key as well as Authorization: Bearer</label></td></tr>';
    echo '<tr><th scope="row">XML-RPC</th><td><label><input type="checkbox" name="wpaka_disable_xmlrpc" value="1"' . checked($settings['disable_xmlrpc'], 1, false) . ' /> Disable XML-RPC</label>';
    echo '<p class="description">Off by default. When on, XML-RPC authentication and methods are blocked and the X-Pingback header is removed. Jetpack, old mobile apps and pingbacks will stop working. This does not affect the REST API, and it is not a server-level block: xmlrpc.php itself is still reachable, so use server configuration as well for a hard block.</p></td></tr>';
    echo '</table>';
    submit_button('Save Settings', 'primary', 'wpaka_save_settings');
    echo '</form>';

    echo '<h2>Generate API Key</h2><form method="post">';
    wp_nonce_field('wpaka_generate_nonce');
    echo '<table class="form-table"><tr><th><label for="wpaka_name">API Key Name</label></th><td><input type="text" name="wpaka_name" id="wpaka_name" required /></td></tr>';
    echo '<tr><th><label for="wpaka_user_id">WordPress User</label></th><td><select name="wpaka_user_id" id="wpaka_user_id" required>';
    foreach ($users as $u) {
        echo '<option value="' . esc_attr($u->ID) . '">' . esc_html($u->display_name . ' (' . $u->user_login . ')') . '</option>';
    }
    echo '</select></td></tr>';
    echo '<tr><th><label for="wpaka_scope">Scope</label></th><td><select name="wpaka_scope" id="wpaka_scope"><option value="full">Full access (same permissions as the user)</option><option value="read_only">Read-only (GET, HEAD and OPTIONS only)</option></select></td></tr>';
    echo '<tr><th><label for="wpaka_expires_at">Expiry date (optional)</label></th><td><input type="date" name="wpaka_expires_at" id="wpaka_expires_at" /><p class="description">Leave blank for a key that never expires. An expired key returns a 403 error.</p></td></tr></table>';
    submit_button('Generate API Key', 'primary', 'wpaka_generate');
    echo '</form>';

    echo '<h2>Existing API Keys</h2><table class="widefat"><thead><tr><th>Name</th><th>User</th><th>Scope</th><th>Created</th><th>Expires</th><th>Last used</th><th>Actions</th></tr></thead><tbody>';
    if (empty($keys)) {
        echo '<tr><td colspan="7">No API keys yet.</td></tr>';
    }
    foreach ($keys as $row) {
        $data = json_decode($row['option_value'], true);
        $u = is_array($data) && !empty($data['user_id']) ? get_user_by('id', (int) $data['user_id']) : null;
        $scope = '';
        if (is_array($data) && isset($data['scope']) && $data['scope'] === 'read_only') {
            $scope = 'Read-only';
        } elseif (is_array($data) && isset($data['scope']) && $data['scope'] === 'full') {
            $scope = 'Full';
        }
        $expires_text = 'Never';
        if (is_array($data) && !empty($data['expires_at'])) {
            $expires_text = $data['expires_at'];
            if (strtotime($data['expires_at'] . ' 23:59:59') < current_time('timestamp')) {
                $expires_text .= ' (expired)';
            }
        }
        echo '<tr><td>' . esc_html(is_array($data) ? $data['name'] : '') . '</td>';
        echo '<td>' . esc_html($u ? $u->user_login : '') . '</td>';
        echo '<td>' . esc_html($scope) . '</td>';
        echo '<td>' . esc_html(is_array($data) ? $data['created'] : '') . '</td>';
        echo '<td>' . esc_html($expires_text) . '</td>';
        echo '<td>' . esc_html(is_array($data) && !empty($data['last_used']) ? $data['last_used'] : 'Never') . '</td><td>';
        echo '<form method="post" style="display:inline;">';
        wp_nonce_field('wpaka_delete_nonce');
        echo '<input type="hidden" name="wpaka_option_name" value="' . esc_attr($row['option_name']) . '" />';
        submit_button('Delete', 'delete', 'wpaka_delete', false);
        echo '</form></td></tr>';
    }
    echo '</tbody></table>';

    echo '</div>';
}
