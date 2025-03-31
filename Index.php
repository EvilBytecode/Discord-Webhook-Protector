<?php
/*
 * Webhook Protector
 * -----------------
 * This class is designed to prevent spam and abuse by implementing various security features, including:
 * - Rate limiting to control request frequency
 * - Blacklisting of suspicious IPs
 * - Detection of VPNs and proxies
 * - Duplicate request prevention
 * - Secure request validation using API keys
 * - Blacklisted Words
 * - Attacker cannot delete webhook remotely
 * -----------------
 * How to use? 
 * ------------
 * - Replace your API key on line 282 with your actual API key.
 * - Replace your webhook URL on line 283 with your actual webhook.
 * - Replace your custom request header on line 286 with your preferred custom request header.
*/
class RateLimiter {
    private $api_key;
    private $webhook_url;
    private $time_window;
    private $default_rate_limit;
    private $suspicious_rate_limit;
    private $instant_blacklist_threshold;
    private $client_ip;
    private $ip_data_file;
    private $blacklisted_ips_file;
    private $blacklisted_words;

    public function __construct($api_key, $webhook_url, $ip_data_file, $blacklisted_ips_file, $request_custom) {
        $this->api_key = $api_key;
        $this->webhook_url = $webhook_url;
        $this->time_window = 60;
        $this->default_rate_limit = 5;
        $this->suspicious_rate_limit = 1;
        $this->instant_blacklist_threshold = 2;
        $this->client_ip = $_SERVER['REMOTE_ADDR'];
        $this->ip_data_file = $ip_data_file;
        $this->blacklisted_ips_file = $blacklisted_ips_file;
        $this->blacklisted_words = ['wizzed', 'spammed', 'ez'];
        $this->request_custom = strtoupper($request_custom);
    }

    private function ensureIpDataFileWritable() {
        if (!file_exists($this->ip_data_file)) {
            if (!touch($this->ip_data_file)) {
                echo "Error: Could not create the IP data file.";
                exit();
            }
        }

        if (!is_writable($this->ip_data_file)) {
            chmod($this->ip_data_file, 0666);
            if (!is_writable($this->ip_data_file)) {
                echo "Error: IP data file is not writable.";
                exit();
            }
        }
    }

    private function isBlacklisted($ip) {
        if (file_exists($this->blacklisted_ips_file)) {
            $blacklisted_ips = json_decode(file_get_contents($this->blacklisted_ips_file), true);
            if (!is_array($blacklisted_ips)) {
                $blacklisted_ips = [];
            }
             if (isset($blacklisted_ips[$ip])) {
                $blacklist_data = $blacklisted_ips[$ip];
                $current_time = time();
                $blacklist_expiry = $blacklist_data['timestamp'] + $blacklist_data['duration'];
                
                if ($current_time < $blacklist_expiry) {
                    return true; 
                } else {
                    unset($blacklisted_ips[$ip]);
                    file_put_contents($this->blacklisted_ips_file, json_encode($blacklisted_ips, JSON_PRETTY_PRINT));
                }
            }
        }
        return false;
    }
    

    private function isValidIp($ip) {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    private function isVpnOrProxy($ip) {
        $response = @file_get_contents("http://ip-api.com/json/$ip?fields=proxy");
        if ($response) {
            $data = json_decode($response, true);
            return !empty($data['proxy']) && $data['proxy'] === true;
        }
        return false;
    }

    private function checkInstantBlacklist($ip, &$ip_data) {
        $current_time = time();
        if (!isset($ip_data[$ip])) {
            $ip_data[$ip] = [];
        }
        $ip_data[$ip] = array_filter($ip_data[$ip], function ($timestamp) use ($current_time) {
            return $timestamp > ($current_time - 3);
        });
        if (count($ip_data[$ip]) >= $this->instant_blacklist_threshold) {
            $blacklisted_ips = file_exists($this->blacklisted_ips_file) ? json_decode(file_get_contents($this->blacklisted_ips_file), true) : [];
            if (!is_array($blacklisted_ips)) {
                $blacklisted_ips = [];
            }
            $blacklisted_ips[$ip] = ['timestamp' => time(), 'duration' => 3600]; // 1 hour
            file_put_contents($this->blacklisted_ips_file, json_encode($blacklisted_ips, JSON_PRETTY_PRINT));
            return true; 
        }
        $ip_data[$ip][] = $current_time;
        file_put_contents($this->ip_data_file, json_encode($ip_data, JSON_PRETTY_PRINT));
        return false;  
    }

    private function getRateLimit($message) {
        foreach ($this->blacklisted_words as $word) {
            if (stripos($message, $word) !== false) {
                return $this->suspicious_rate_limit;
            }
        }
        return $this->default_rate_limit;
    }

    private function slidingWindowRateLimit($ip, $rate_limit, &$ip_data) {
        $current_time = time();

        if (!isset($ip_data[$ip])) {
            $ip_data[$ip] = [];
        }
        $ip_data[$ip] = array_filter($ip_data[$ip], function ($timestamp) use ($current_time) {
            return $timestamp > ($current_time - $this->time_window);
        });
        if (count($ip_data[$ip]) >= $rate_limit) {
            return false; 
        }
        $ip_data[$ip][] = $current_time;
        file_put_contents($this->ip_data_file, json_encode($ip_data, JSON_PRETTY_PRINT));
        return true;
    }

    private function logAudit($action, $status, $reason, $message = '') {
        $log_entry = [
            'timestamp' => time(),
            'ip' => $this->client_ip,
            'action' => $action,
            'status' => $status,
            'reason' => $reason, // reason , imo important
            'message' => $message,
        ];
        $audit_log = file_exists('audit_log.json') ? json_decode(file_get_contents('audit_log.json'), true) : [];
        if (!is_array($audit_log)) {
            $audit_log = [];
        }
        $audit_log[] = $log_entry;
        file_put_contents('audit_log.json', json_encode($audit_log, JSON_PRETTY_PRINT));
    }

    private function validateRequestMethod() {
        if (strtolower($_SERVER['REQUEST_METHOD']) !== strtolower($this->request_custom)) {
            http_response_code(405);
            $this->logAudit("Invalid Request", "Fail", "Invalid Request Method");
            exit();
        }
    }
    
    private function isDuplicateRequest($payload) {
        $hash_file = 'request_hashes.json';
        $hashes = file_exists($hash_file) ? json_decode(file_get_contents($hash_file), true) : [];
        $hash = md5($payload);

        if (isset($hashes[$hash]) && (time() - $hashes[$hash]) < 30) {
            return true;
        }

        $hashes[$hash] = time();
        file_put_contents($hash_file, json_encode($hashes, JSON_PRETTY_PRINT));
        return false;
    }

    private function validateRequestHeaders() {
        if ($_SERVER['CONTENT_TYPE'] !== 'application/json') {
            http_response_code(400);
            echo "Unauthorized";
            $this->logAudit("Invalid Request", "Fail", "Invalid Content-Type");
            exit();
        }

        if (empty($_SERVER['HTTP_USER_AGENT'])) {
            http_response_code(400);
            echo "Unauthorized";
            $this->logAudit("Invalid Request", "Fail", "Missing User-Agent header");
            exit();
        }

        if (empty($_SERVER['HTTP_ACCEPT']) || strpos($_SERVER['HTTP_ACCEPT'], 'application/json') === false) {
            http_response_code(400);
            echo "Unauthorized";
            $this->logAudit("Invalid Request", "Fail", "Invalid Accept header");
            exit();
        }
    }

    public function processRequest() {
        $this->validateRequestMethod();
        $this->ensureIpDataFileWritable();
        $this->validateRequestHeaders();
    
        if (!$this->isValidIp($this->client_ip)) {
            echo "Unauthorized";
            $this->logAudit("Rate Limiting", "Fail", "Invalid IP address", "The IP address is invalid.");
            exit;
        }
        if ($this->isVpnOrProxy($this->client_ip)) {
            echo "Unauthorized";
            $this->logAudit("Rate Limiting", "Fail", "VPN/Proxy detected", "Request was made from a VPN or Proxy IP.");
            exit;
        }
        if ($this->isBlacklisted($this->client_ip)) {
            echo "Unauthorized";
            $this->logAudit("Rate Limiting", "Fail", "Blacklisted IP", "The IP address is blacklisted.");
            exit;
        }
        $ip_data = file_exists($this->ip_data_file) ? json_decode(file_get_contents($this->ip_data_file), true) : [];
        if (!is_array($ip_data)) {
            $ip_data = [];
        }
        if ($this->checkInstantBlacklist($this->client_ip, $ip_data)) {
            echo "Unauthorized";
            $this->logAudit("Rate Limiting", "Fail", "Instant blacklist triggered", "IP address triggered instant blacklist due to suspicious activity.");
            exit();
        }
        $input_data = json_decode(file_get_contents("php://input"), true);
        if (!isset($input_data['api_key']) || $input_data['api_key'] !== $this->api_key) {
            http_response_code(403);
            echo "Unauthorized";
            $this->logAudit("Authorization", "Fail", "Invalid API key", "The provided API key is invalid.");
            exit();
        }
    
        $message = $input_data['message'] ?? '';
        $embeds = $input_data['embeds'] ?? [];
    
        $rate_limit = $this->getRateLimit($message);
        if (!$this->slidingWindowRateLimit($this->client_ip, $rate_limit, $ip_data)) {
            http_response_code(429);
            echo "Unauthorized";
            $this->logAudit("Rate Limiting", "Fail", "Rate limit exceeded", "The rate limit for this IP address has been exceeded.");
            exit();
        }
        $this->logAudit("Message Sent", "Success", "Message sent successfully", "The message was successfully sent to the webhook.");
        $payload = json_encode([
            "content" => $message,
            "embeds" => $embeds
        ]);
        if ($this->isDuplicateRequest($payload)) {
           // echo "Duplicate request detected";
            exit();
        }
        $ch = curl_init($this->webhook_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        $response = curl_exec($ch);
        curl_close($ch);
    
        if ($response === false) {
            http_response_code(500);
            echo "Error sending message";
            $this->logAudit("Message Sending", "Fail", "Error sending message", "Error occurred while sending message.");
            exit();
        }
    
        echo "Message sent successfully";
    }    
}

$api_key = "your-api-key"; // replace with your api key, you can get one by opening cmd  and doing echo %random%%random% output : 3111120476 -> include in your request
$webhook_url = ""; // replace webhook
$ip_data_file = __DIR__ . '/ip_data.json';
$blacklisted_ips_file = __DIR__ . '/blacklisted_ips.json';
$request_custom = "SIGMA"; // custom request - replace  -> include in your request

$rateLimiter = new RateLimiter($api_key, $webhook_url, $ip_data_file, $blacklisted_ips_file,$request_custom);
$rateLimiter->processRequest();

?>
