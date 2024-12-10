from kivy.core.window import Window
from components import Hping3GUIApp
    
def main():
    # Set the window background to a dark theme
    Window.clearcolor = (0.1, 0.1, 0.1, 1)
    Window.size = (1000, 900)
    Hping3GUIApp().run()

if __name__ == '__main__':
    main()