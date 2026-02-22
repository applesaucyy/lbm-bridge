<?php
// --- LBM SECURE GATEKEEPER v3.9 ---
// Allows generic hosting while securing individual user API keys via Tokenization.

// 1. SERVER CONFIGURATION

//change this, obivously
$MASTER_KEY = "test"; 

// 2. HEADERS
ini_set('display_errors', 0);
header('Content-Type: application/json');
$origin = $_SERVER['HTTP_ORIGIN'] ?? '*';
header("Access-Control-Allow-Origin: $origin");
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Credentials: true');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit(0); }

// 3. CRYPTO HELPERS
function server_encrypt($data) {
    global $MASTER_KEY;
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
    $encrypted = openssl_encrypt(json_encode($data), 'aes-256-cbc', $MASTER_KEY, 0, $iv);
    return base64_encode($encrypted . '::' . base64_encode($iv));
}

function server_decrypt($token) {
    global $MASTER_KEY;
    $raw = base64_decode($token);
    if (strpos($raw, '::') === false) return null;
    list($encrypted_data, $encoded_iv) = explode('::', $raw, 2);
    $decrypted = openssl_decrypt($encrypted_data, 'aes-256-cbc', $MASTER_KEY, 0, base64_decode($encoded_iv));
    return json_decode($decrypted, true);
}

// 4. MAIN LOGIC
try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') throw new Exception('Invalid method');
    $action = $_POST['action'] ?? 'upload';

    // --- ACTION: TOKENIZE ---
    if ($action === 'tokenize') {
        $rawKey = $_POST['raw_key'] ?? '';
        $rawPass = $_POST['admin_pass'] ?? '';
        
        if (!$rawKey || !$rawPass) throw new Exception("Missing key or password.");

        // Aggressive Sanitization: Hex chars only.
        $cleanKey = preg_replace('/[^a-fA-F0-9]/', '', trim($rawKey));

        $payload = ['k' => $cleanKey, 'h' => hash('sha256', $rawPass)];
        $token = server_encrypt($payload);
        echo json_encode(['result' => 'success', 'token' => $token]);
        exit;
    }

    // --- ACTION: UPLOAD ---
    if ($action === 'upload') {
        $token = $_POST['auth_token'] ?? '';
        if (!$token) throw new Exception("Missing Auth Token.");

        $creds = server_decrypt($token);
        if (!$creds || !isset($creds['k']) || !isset($creds['h'])) {
            throw new Exception("Invalid or Corrupted Token.");
        }

        $realApiKey = $creds['k'];
        $storedPassHash = $creds['h'];
        $targetName = $_POST['upload_name'] ?? '';
        $mediaName = $_POST['media_name'] ?? '';
        
        $isPublicAction = ($targetName === 'interactions.js') || 
                          (strpos($mediaName, 'img/asks/') === 0);

        if (!$isPublicAction) {
            $providedPass = $_POST['password_check'] ?? '';
            if (hash('sha256', $providedPass) !== $storedPassHash) {
                usleep(300000); 
                throw new Exception("Access Denied: Invalid Admin Password.");
            }
        } else {
            if (strpos($mediaName, '..') !== false) {
                throw new Exception("Security Violation: Path traversal detected.");
            }
            if ($mediaName) {
                $ext = strtolower(pathinfo($mediaName, PATHINFO_EXTENSION));
                $allowed = ['png', 'jpg', 'jpeg', 'gif', 'webp'];
                if (!in_array($ext, $allowed)) {
                    throw new Exception("Security Violation: Invalid file type for public upload.");
                }
            }
        }

        // PREPARE UPLOAD
        $postFields = [];
        
        function attach_file(&$fields, $fileKey, $targetName, $mime) {
            if (!isset($_FILES[$fileKey]) || $_FILES[$fileKey]['error'] !== UPLOAD_ERR_OK) return false;
            $fields[$targetName] = new CURLFile($_FILES[$fileKey]['tmp_name'], $mime, $targetName);
            return true;
        }

        $hasFile = false;
        if (isset($_POST['upload_name'])) {
            if (attach_file($postFields, 'upload_file', $_POST['upload_name'], 'text/javascript')) $hasFile = true;
        }
        
        // Handle Media Uploads
        if (isset($_POST['media_name'])) {
            // Safety check: Ensure media name isn't trying to overwrite critical files
            if (strpos($mediaName, 'system.js') !== false || strpos($mediaName, '.php') !== false) {
                 throw new Exception("Forbidden filename.");
            }
            
            $mime = $_FILES['media_file']['type'] ?? 'application/octet-stream';
            if (attach_file($postFields, 'media_file', $_POST['media_name'], $mime)) $hasFile = true;
        }

        if (!$hasFile) throw new Exception('No file received.');

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'https://neocities.org/api/upload');
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Authorization: Bearer ' . $realApiKey]);
        curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postFields);
        curl_setopt($ch, CURLOPT_TIMEOUT, 60);

        $response = curl_exec($ch);
        
        if (curl_errno($ch)) throw new Exception('Bridge Error: ' . curl_error($ch));
        
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        // DIAGNOSTIC THINGY
        // If Neocities says invalid credentials, this'll append debug info to help diagnose.
        $json = json_decode($response, true);
        if ($json && isset($json['error_type']) && $json['error_type'] === 'invalid_auth') {
            $debugInfo = " [Debug: KeyLen=" . strlen($realApiKey) . 
                         ", Start=" . substr($realApiKey, 0, 4) . 
                         ", End=" . substr($realApiKey, -4) . "]";
            
            $json['message'] .= $debugInfo;
            echo json_encode($json);
        } else {
            // Normal behavior
            http_response_code(200); 
            echo $response;
        }
    }

} catch (Exception $e) {
    http_response_code(403);
    echo json_encode(['result' => 'error', 'message' => $e->getMessage()]);
}
?>