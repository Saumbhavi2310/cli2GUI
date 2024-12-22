from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.core.window import Window
import subprocess
import sys
from pathlib import Path

class MenuLauncher(App):
    def build(self):
        # Set window size
        Window.size = (400, 500)
        
        # Create main layout
        layout = BoxLayout(orientation='vertical', padding=10, spacing=10)
        
        # Add title
        title = Label(
            text='Tool Launcher',
            size_hint_y=None,
            height=50,
            font_size='24sp'
        )
        layout.add_widget(title)
        
        # Tool configurations
        self.tools = [
            {
                'name': 'Hping3',
                'script': Path('hping3GUI/hping3GUI.py')
            },
            {
                'name': 'Nikto',
                'script': Path('niktoGUI/niktoGUI.py')
            },
            {
                'name': 'IDS',
                'script': Path('IDS/IDS.py')
            },
            {
                'name': 'Tool 4',
                'script': Path('path/to/tool4.py')
            },
            {
                'name': 'Tool 5',
                'script': Path('path/to/tool5.py')
            }
        ]
        
        # Create buttons for each tool
        for tool in self.tools:
            btn = Button(
                text=tool['name'],
                size_hint_y=None,
                height=60,
                background_color=(0.2, 0.6, 0.8, 1)
            )
            btn.bind(on_press=lambda x, script=tool['script']: self.launch_tool(script))
            layout.add_widget(btn)
        
        # Add exit button
        exit_btn = Button(
            text='Exit',
            size_hint_y=None,
            height=60,
            background_color=(0.8, 0.2, 0.2, 1)
        )
        exit_btn.bind(on_press=self.stop)
        layout.add_widget(exit_btn)
        
        return layout
    
    def launch_tool(self, script_path):
        try:
            # Get the Python executable path
            python_exe = sys.executable
            
            # Launch the tool in a new process
            subprocess.Popen([python_exe, script_path])
            
        except Exception as e:
            print(f"Error launching tool: {str(e)}")

if __name__ == '__main__':
    MenuLauncher().run()
    