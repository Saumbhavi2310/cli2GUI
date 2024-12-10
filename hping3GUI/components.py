import ipaddress
import socket
import subprocess

from kivy.app import App
from kivy.clock import Clock
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.checkbox import CheckBox
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.spinner import Spinner
from kivy.uix.textinput import TextInput
from kivy.uix.togglebutton import ToggleButton


class Hping3GUIApp(App):
    def build(self):
        # Main vertical layout
        main_layout = BoxLayout(orientation="vertical", padding=10, spacing=10)

        # Target Configuration
        target_layout = GridLayout(cols=2, size_hint_y=None, height=200)

        # Target IP/Hostname
        target_layout.add_widget(Label(text="Target:"))
        self.target_input = TextInput(
            multiline=False, hint_text="IP or Hostname", size_hint_x=0.8
        )
        self.target_input.bind(text=self.on_input_change)
        target_layout.add_widget(self.target_input)

        # Scan Type Selection
        target_layout.add_widget(Label(text="Scan Type:"))
        self.scan_type_spinner = Spinner(
            text="TCP SYN Ping",
            values=(
                "TCP SYN Ping",
                "UDP Ping",
                "ICMP Echo Ping",
                "TCP ACK Ping",
                "SYN Flood",
                "UDP Flood",
            ),
            size_hint_x=0.8,
        )
        self.scan_type_spinner.bind(text=self.on_input_change)
        target_layout.add_widget(self.scan_type_spinner)

        # Port Configuration
        target_layout.add_widget(Label(text="Port:"))
        self.port_input = TextInput(
            multiline=False, hint_text="Target Port (e.g., 80, 443)", size_hint_x=0.8
        )
        self.port_input.bind(text=self.on_input_change)
        target_layout.add_widget(self.port_input)

        # Packet Count
        target_layout.add_widget(Label(text="Packet Count:"))
        self.packet_count_input = TextInput(
            multiline=False, hint_text="Number of packets (default: 5)", size_hint_x=0.8
        )
        self.packet_count_input.bind(text=self.on_input_change)
        target_layout.add_widget(self.packet_count_input)

        # Advanced Options
        advanced_layout = GridLayout(cols=2, size_hint_y=None, height=150)

        # Flood Option
        advanced_layout.add_widget(Label(text="Flood Mode:", size_hint_x=0.55))
        self.flood_check = CheckBox(size_hint_x=0.45)
        self.flood_check.bind(active=self.on_input_change)
        advanced_layout.add_widget(self.flood_check)

        # Random Source IP
        advanced_layout.add_widget(Label(text="Spoof Source IP:", size_hint_x=0.55))
        self.spoof_check = CheckBox(size_hint_x=0.45)
        self.spoof_check.bind(active=self.on_input_change)
        advanced_layout.add_widget(self.spoof_check)

        # Verbosity Level
        advanced_layout.add_widget(Label(text="Verbosity:", size_hint_x=0.55))
        self.verbosity_spinner = Spinner(
            text="Normal", values=("Quiet", "Normal", "Verbose"), size_hint_x=0.45
        )
        self.verbosity_spinner.bind(text=self.on_input_change)
        advanced_layout.add_widget(self.verbosity_spinner)

        # Show Command Toggle Button and Command Preview Layout
        cmd_layout = GridLayout(cols=3, size_hint_y=None, height=40)
        self.show_cmd_button = ToggleButton(
            text="Show Command",
            on_press=self.toggle_command_visibility,
            size_hint_x=0.3
        )
        spacer = Label(size_hint_x=0.01)  # Add empty space
        self.cmd_preview_text = TextInput(
            readonly=False,
            multiline=False,
            background_color=[1, 1, 1, 0.1],
            foreground_color=[1, 1, 1, 1],
            opacity=0,
            height=40,
            size_hint_y=None,
            size_hint_x=0.69,
            padding=(20, 11, 0, 5),
            allow_copy=True,
        )
        self.cmd_preview_text.bind(text=self.on_cmd_preview_change)
        cmd_layout.add_widget(self.show_cmd_button)
        cmd_layout.add_widget(spacer)
        cmd_layout.add_widget(self.cmd_preview_text)

        # Buttons Layout
        buttons_layout = BoxLayout(size_hint_y=None, height=50, spacing=10)

        # Run Command Button
        run_cmd_button = Button(
            text="Run Command",
            on_press=self.run_hping3_command,
            size_hint_x=0.7,
            background_color=[0.2, 0.8, 0.2, 1],
        )
        buttons_layout.add_widget(run_cmd_button)

        # Clear Output Button
        clear_output_button = Button(
            text="Clear Output",
            on_press=self.clear_output,
            size_hint_x=0.3,
            background_color=[0.8, 0.2, 0.2, 1],
        )
        buttons_layout.add_widget(clear_output_button)

        # Results Area
        results_label = Label(text="Scan Results:", size_hint_y=None, height=20)
        scroll_view = ScrollView()
        self.results_text = TextInput(
            readonly=True,
            multiline=True,
            background_color=[1, 1, 1, 0.1],
            foreground_color=[1, 1, 1, 1],
        )
        scroll_view.add_widget(self.results_text)

        # Assemble Main Layout
        main_layout.add_widget(target_layout)
        main_layout.add_widget(advanced_layout)
        main_layout.add_widget(cmd_layout)  # Show Command button and Command Preview
        main_layout.add_widget(buttons_layout)
        main_layout.add_widget(results_label)
        main_layout.add_widget(scroll_view)

        # Generate initial command
        Clock.schedule_once(lambda dt: self.generate_command_string(None), 0.1)

        return main_layout

    def on_input_change(self, instance, value):
        """Called whenever any input changes"""
        self.generate_command_string(None)

    def on_cmd_preview_change(self, instance, value):
        """Called whenever the command preview text changes"""
        self.hping_cmd = value.split()

    def clear_output(self, instance):
        """Clear the results text area"""
        self.results_text.text = ""

    def validate_input(self, target):
        """Validate target input"""
        try:
            # Try to validate as IP
            ipaddress.ip_address(target)
            return True
        except ValueError:
            try:
                # Attempt to resolve hostname
                socket.gethostbyname(target)
                return True
            except:
                return False

    def scan_type_options(self, hping_cmd, scan_type, port):
        if scan_type == "TCP SYN Ping":
            hping_cmd.extend(["-S", "-p", port])
        elif scan_type == "UDP Ping":
            hping_cmd.extend(["-2", "-p", port])
        elif scan_type == "ICMP Echo Ping":
            hping_cmd.append("-1")
        elif scan_type == "TCP ACK Ping":
            hping_cmd.extend(["-A", "-p", port])
        elif scan_type == "SYN Flood":
            hping_cmd.extend(["-S", "-p", port, "--flood"])
        elif scan_type == "UDP Flood":
            hping_cmd.extend(["-2", "-p", port, "--flood"])

        return hping_cmd

    def generate_command_string(self, instance):
        """Generate the hping3 command string without validation"""
        # Start with base command
        hping_cmd = ["sudo", "hping3"]

        # Get target
        target = self.target_input.text.strip()

        # Get scan type options
        scan_type = self.scan_type_spinner.text
        port = self.port_input.text.strip() or "80"  # Default to port 80 if empty

        # Add scan type specific options
        hping_cmd = self.scan_type_options(hping_cmd, scan_type, port)

        # Add packet count if specified
        packet_count = self.packet_count_input.text.strip()
        if packet_count:
            hping_cmd.extend(["-c", packet_count])
        else:
            hping_cmd.extend(["-c", "5"])  # Default 5 packets

        # Add flood mode if checked
        if self.flood_check.active:
            hping_cmd.append("--flood")

        # Add source IP spoofing if checked
        if self.spoof_check.active:
            hping_cmd.append("--rand-source")

        # Add verbosity setting
        verbosity = self.verbosity_spinner.text
        if verbosity == "Quiet":
            hping_cmd.append("-q")
        elif verbosity == "Verbose":
            hping_cmd.append("-V")

        # Add target at the end
        if target:
            hping_cmd.append(target)

        # Update the command preview text
        self.hping_cmd = hping_cmd
        self.cmd_preview_text.text = " ".join(hping_cmd)

    def toggle_command_visibility(self, instance):
        """Toggle visibility of the command preview"""
        if self.show_cmd_button.state == "down":
            self.cmd_preview_text.opacity = 1  # Show command
        else:
            self.cmd_preview_text.opacity = 0  # Hide command

    def run_hping3_command(self, instance):
        """Run the hping3 command from the preview text"""
       
        # Clear previous results
        self.results_text.text = ""

        # Extract target from the command list
        try:
            target = self.hping_cmd[-1] if self.hping_cmd else self.target_input.text.strip()
            if not target or not self.validate_input(target):
                self.results_text.text = "Error: Invalid target IP or hostname"
                return

            # Use the command from the preview text
            hping_cmd = self.hping_cmd

            # Run Hping3 scan
            result = subprocess.run(hping_cmd, capture_output=True, text=True, timeout=120)

            # Display results
            self.results_text.text = result.stdout or result.stderr

        except subprocess.TimeoutExpired:
            self.results_text.text = "Scan timed out. Target may be unresponsive."
        except PermissionError:
            self.results_text.text = "Error: Hping3 requires root/sudo privileges."
        except FileNotFoundError:
            self.results_text.text = "Error: Hping3 is not installed. Please install using:\n  sudo apt-get install hping3\n"
        except Exception as e:
            self.results_text.text = f"Error: {str(e)}"