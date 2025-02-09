![Screenshot 2025-02-09 164640](https://github.com/user-attachments/assets/f90c7bb0-f603-4f5b-b520-7c1ca6380eb5)


# or0toshell

or0toshell is an advanced PHP web shell designed for penetration testers, bug bounty hunters, and security researchers. It provides a powerful terminal interface and an intuitive file explorer that lets you execute commands, manage files, and navigate directories directly from your web browser. Engineered to bypass common upload restrictions and server blocks, or0toshell is your tool of choice for testing server defenses in controlled, authorized environments.

## Overview

or0toshell offers a robust set of features in a single, easy-to-use tool. Whether you're executing system commands, managing files, or exploring directories, or0toshell delivers real-time output and immediate feedback—all without reloading the page.

## Key Features

- **Interactive Terminal:**  
  Execute a wide range of commands (such as `help`, `sysinfo`, `pwd`, `cd`, `cat`, `mkdir`, `rm`, `cp`, `mv`, `chmod`, `history`, `search`) with real-time output and immediate feedback.

- **Robust File Explorer:**  
  Navigate your file system using a clickable interface. Browse directories, open files, and download content with ease.

- **Advanced Upload Bypass:**  
  Overcome standard file upload restrictions and server blocks using advanced PHP file handling techniques. This feature allows you to upload files even when conventional methods are blocked.

- **Bypass Server Blocks:**  
  Test server defenses by working around common limitations imposed on uploads and command executions. or0toshell is engineered to work around these obstacles (only in authorized testing scenarios).

- **Dark/Light Theme Toggle:**  
  Switch seamlessly between dark and light modes for optimal readability in any environment.

- **Command History & Real-Time Feedback:**  
  Access a built-in command history (navigable with the arrow keys) and enjoy smooth, animated feedback during operations.

## UI/UX Enhancements

or0toshell offers a modern, responsive design that adapts to desktops, tablets, and mobile devices. AJAX-powered interactions ensure that commands, file uploads, and directory navigations occur instantly without page reloads, providing a smooth and intuitive user experience.

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/dragonked2/or0toshell.git
   cd or0toshell
   ```

2. **Configure Your Web Server:**

   Set your web server’s document root to the or0toshell directory or deploy the files in your chosen location. Ensure your server supports PHP (version 7.4 or higher) and that file uploads are enabled if you plan to use the upload bypass feature.

3. **Access the Web Shell:**

   Open your browser and navigate to:

   ```
   http://localhost/or0toshell.php
   ```

## Usage

- **Executing Commands:**  
  Type your command in the terminal prompt and press Enter (or click the Send button). Use the `help` command to view all supported commands.

- **Navigating Directories:**  
  Use commands like `cd` and `pwd` to change and view your current directory, or click on directories in the file explorer for quick navigation.

- **Uploading Files:**  
  Use the integrated file upload form to bypass typical file upload restrictions. or0toshell’s advanced upload bypass allows file transfers even when conventional methods are blocked.

- **Bypassing Restrictions:**  
  Designed for authorized testing, or0toshell can work around common server-imposed limitations on uploads and file access.

## Security Notice

or0toshell is intended exclusively for authorized penetration testing, security research, and educational purposes. Do not deploy or use this tool on publicly accessible servers without strict security measures. Unauthorized use is illegal and may result in severe consequences.

## Contributing

Contributions are welcome! If you have ideas for new features, UI/UX enhancements, or bug fixes, please open an issue or submit a pull request. All contributions should adhere to ethical guidelines and be used only for authorized testing.

## License

or0toshell is licensed under the MIT License. See the LICENSE file for full details.

---

Happy Testing! — Built with passion by [Ali Essam](https://www.linkedin.com/in/dragonked2)
```

