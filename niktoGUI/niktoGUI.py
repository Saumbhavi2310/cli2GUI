import subprocess
import sys
import threading
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox, QCheckBox, QScrollArea

class NiktoGUIApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
    
    def initUI(self):
        self.setWindowTitle('Nikto GUI')
        self.setGeometry(100, 100, 800, 600)
        
        main_layout = QVBoxLayout()
        
        # Target URL input
        target_layout = QHBoxLayout()
        target_label = QLabel('Target URL:')
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText('https://example.com')
        target_layout.addWidget(target_label)
        target_layout.addWidget(self.target_input)
        
        # Advanced Options Layout
        advanced_layout = QVBoxLayout()
        
        port_layout = QHBoxLayout()
        port_label = QLabel('Port:')
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText('80 or 443')
        port_layout.addWidget(port_label)
        port_layout.addWidget(self.port_input)
        
        ssl_layout = QHBoxLayout()
        ssl_label = QLabel('SSL Scan:')
        self.ssl_check = QCheckBox()
        ssl_layout.addWidget(ssl_label)
        ssl_layout.addWidget(self.ssl_check)
        
        tuning_layout = QHBoxLayout()
        tuning_label = QLabel('Tuning Level:')
        self.tuning_spinner = QComboBox()
        self.tuning_spinner.addItems(['Normal', 'Level 1', 'Level 2', 'Level 3'])
        tuning_layout.addWidget(tuning_label)
        tuning_layout.addWidget(self.tuning_spinner)
        
        format_layout = QHBoxLayout()
        format_label = QLabel('Output Format:')
        self.format_spinner = QComboBox()
        self.format_spinner.addItems(['Text', 'XML', 'CSV'])
        format_layout.addWidget(format_label)
        format_layout.addWidget(self.format_spinner)
        
        proxy_layout = QHBoxLayout()
        proxy_label = QLabel('Use Proxy:')
        self.proxy_input = QLineEdit()
        self.proxy_input.setPlaceholderText('http://proxy:port')
        proxy_layout.addWidget(proxy_label)
        proxy_layout.addWidget(self.proxy_input)
        
        user_agent_layout = QHBoxLayout()
        user_agent_label = QLabel('User Agent:')
        self.user_agent_input = QLineEdit()
        self.user_agent_input.setPlaceholderText('Custom User Agent')
        user_agent_layout.addWidget(user_agent_label)
        user_agent_layout.addWidget(self.user_agent_input)
        
        timeout_layout = QHBoxLayout()
        timeout_label = QLabel('Timeout (seconds):')
        self.timeout_input = QLineEdit()
        self.timeout_input.setPlaceholderText('Timeout in seconds')
        timeout_layout.addWidget(timeout_label)
        timeout_layout.addWidget(self.timeout_input)
        
        advanced_layout.addLayout(port_layout)
        advanced_layout.addLayout(ssl_layout)
        advanced_layout.addLayout(tuning_layout)
        advanced_layout.addLayout(format_layout)
        advanced_layout.addLayout(proxy_layout)
        advanced_layout.addLayout(user_agent_layout)
        advanced_layout.addLayout(timeout_layout)
        
        # Scan Button
        scan_button = QPushButton('Run Nikto Scan')
        scan_button.clicked.connect(self.run_nikto_scan)
        
        # Results Area
        results_label = QLabel('Scan Results:')
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(self.results_text)
        
        # Assemble Main Layout
        main_layout.addLayout(target_layout)
        main_layout.addLayout(advanced_layout)
        main_layout.addWidget(scan_button)
        main_layout.addWidget(results_label)
        main_layout.addWidget(scroll_area)
        
        self.setLayout(main_layout)
    
    def run_nikto_scan(self):
        # Clear previous results
        self.results_text.clear()
        
        # Validate target
        target = self.target_input.text().strip()
        if not target:
            self.results_text.setText('Error: Please enter a target URL')
            return
        
        # Prepare Nikto command
        nikto_cmd = ['nikto', '-h', target]
        
        # Add port if specified
        port = self.port_input.text().strip()
        if port:
            nikto_cmd.extend(['-p', port])
        
        # Add SSL flag if checked
        if self.ssl_check.isChecked():
            nikto_cmd.append('-ssl')
        
        # Add tuning level
        tuning_map = {
            'Normal': '',
            'Level 1': '-Tuning 1',
            'Level 2': '-Tuning 2',
            'Level 3': '-Tuning 3'
        }
        tuning_option = tuning_map.get(self.tuning_spinner.currentText(), '')
        if tuning_option:
            nikto_cmd.append(tuning_option)
        
        # Add output format
        format_map = {
            'Text': '',
            'XML': '-Format xml',
            'CSV': '-Format csv'
        }
        format_option = format_map.get(self.format_spinner.currentText(), '')
        if format_option:
            nikto_cmd.extend(format_option.split())
        
        # Add proxy if specified
        proxy = self.proxy_input.text().strip()
        if proxy:
            nikto_cmd.extend(['-useproxy', proxy])
        
        # Add user agent if specified
        user_agent = self.user_agent_input.text().strip()
        if user_agent:
            nikto_cmd.extend(['-useragent', user_agent])
        
        # Add timeout if specified
        timeout = self.timeout_input.text().strip()
        if timeout:
            nikto_cmd.extend(['-timeout', timeout])
        
        def run_scan():
            try:
                # Run Nikto scan
                process = subprocess.Popen(
                    nikto_cmd, 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    text=True
                )
                
                # Live update the output box
                for line in iter(process.stdout.readline, ''):
                    self.results_text.append(line)
                
                process.stdout.close()
                process.wait()
                
                # Display any errors
                if process.returncode != 0:
                    self.results_text.append(process.stderr.read())
                
            except subprocess.TimeoutExpired:
                self.results_text.setText('Scan timed out. Target may be unresponsive.')
            except PermissionError:
                self.results_text.setText('Error: Nikto requires root/sudo privileges.')
            except FileNotFoundError:
                self.results_text.setText('Error: Nikto is not installed. Please install using:\nsudo apt-get install nikto')
            except Exception as e:
                self.results_text.setText(f'Error: {str(e)}')
        
        # Run the scan in a separate thread to avoid blocking the UI
        threading.Thread(target=run_scan).start()

def main():
    app = QApplication(sys.argv)
    window = NiktoGUIApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()

# Test website
# https://www.hackthebox.com/