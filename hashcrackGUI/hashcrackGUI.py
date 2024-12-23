import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import threading


class HashCrackerApp:
    def __init__(self, root):  # Corrected constructor method name
        self.root = root
        self.root.title("Hash Cracker")
        self.root.geometry("700x800")
        self.root.resizable(False, False)

        # File paths
        self.hash_file = None
        self.wordlist_file = None

        # Selected hash method
        self.hash_method = tk.StringVar(value="MD5")

        # UI Components
        self.header_frame = tk.Frame(root, bg="#343a40")
        self.header_frame.pack(fill=tk.X, pady=10)
        self.title_label = tk.Label(self.header_frame, text="Hash Cracker", font=(
            "Arial", 24, "bold"), bg="#343a40", fg="white")
        self.title_label.pack()

        self.options_frame = tk.Frame(root, bg="#f8f9fa")
        self.options_frame.pack(pady=20, padx=20, fill=tk.X)

        tk.Label(self.options_frame, text="Select Hash Method:", font=("Arial", 12, "bold"),
                 bg="#f8f9fa", anchor="w").grid(row=0, column=0, sticky="w", padx=10, pady=5)

        # Radio buttons for hash methods
        hash_methods = ["MD5", "SHA-1", "SHA-256", "SHA-512"]
        for idx, method in enumerate(hash_methods):
            tk.Radiobutton(
                self.options_frame,
                text=method,
                variable=self.hash_method,
                value=method,
                font=("Arial", 10),
                bg="#f8f9fa",
                anchor="w"
            ).grid(row=1, column=idx, padx=5, pady=5, sticky="w")

        button_frame = tk.Frame(self.options_frame, bg="#f8f9fa")
        button_frame.grid(row=2, column=0, columnspan=4, pady=10)

        self.hash_button = tk.Button(button_frame, text="Select Hash File", width=20,
                                     command=self.load_hash_file, bg="#007bff", fg="white", font=("Arial", 10, "bold"))
        self.hash_button.pack(side=tk.LEFT, padx=20)

        self.wordlist_button = tk.Button(button_frame, text="Select Wordlist File", width=20,
                                         command=self.load_wordlist_file, bg="#007bff", fg="white", font=("Arial", 10, "bold"))
        self.wordlist_button.pack(side=tk.LEFT, padx=20)

        self.hash_status_label = tk.Label(
            self.options_frame, text="", font=("Arial", 10), fg="green", bg="#f8f9fa")
        self.hash_status_label.grid(
            row=3, column=0, pady=5, padx=10, columnspan=4)

        self.wordlist_status_label = tk.Label(
            self.options_frame, text="", font=("Arial", 10), fg="green", bg="#f8f9fa")
        self.wordlist_status_label.grid(
            row=4, column=0, pady=5, padx=10, columnspan=4)

        self.crack_button = tk.Button(root, text="Crack Hash", width=20, command=self.start_crack_thread,
                                      state=tk.DISABLED, bg="#28a745", fg="white", font=("Arial", 12, "bold"))
        self.crack_button.pack(pady=20)

        result_frame = tk.Frame(root, bg="#f8f9fa")
        result_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        self.result_text = tk.Text(result_frame, height=15, width=85, state=tk.DISABLED, font=(
            "Courier", 10), bg="#ffffff", fg="#000000", relief=tk.FLAT, wrap=tk.WORD)
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH,
                              expand=True, padx=5, pady=5)

        self.result_text_scroll = tk.Scrollbar(
            result_frame, command=self.result_text.yview)
        self.result_text_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.result_text.configure(yscrollcommand=self.result_text_scroll.set)

        self.save_button = tk.Button(root, text="Save Results", width=20, command=self.save_results,
                                     state=tk.DISABLED, bg="#69995D", fg="white", font=("Arial", 12, "bold"))
        self.save_button.pack(pady=10)

    def load_hash_file(self):
        self.hash_file = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt")])
        if self.hash_file:
            self.update_crack_button_state()
            self.hash_status_label.config(text="Hash file selected")

    def load_wordlist_file(self):
        self.wordlist_file = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt")])
        if self.wordlist_file:
            self.update_crack_button_state()
            self.wordlist_status_label.config(text="Wordlist file selected")

    def update_crack_button_state(self):
        if self.hash_file and self.wordlist_file:
            self.crack_button.config(state=tk.NORMAL)

    def start_crack_thread(self):
        self.crack_button.config(state=tk.DISABLED)
        threading.Thread(target=self.crack_hash).start()

    def crack_hash(self):
        try:
            with open(self.hash_file, "r") as hf:
                target_hashes = [line.strip() for line in hf if line.strip()]

            results = []
            with open(self.wordlist_file, "r", encoding="utf-8", errors="ignore") as wf:
                wordlist = [line.strip() for line in wf]

                for target_hash in target_hashes:
                    found = False
                    for word in wordlist:
                        hashed_word = self.compute_hash(word)
                        if hashed_word == target_hash:
                            results.append(
                                f"Hash: {target_hash[::10]} -> Password: {word}")
                            found = True
                            break
                    if not found:
                        results.append(
                            f"Hash: {target_hash[::10]} -> Password not found")

            self.display_result("\n".join(results))
            self.save_button.config(state=tk.NORMAL)
        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            self.crack_button.config(state=tk.NORMAL)

    def compute_hash(self, word):
        method = self.hash_method.get()
        if method in ["MD5", "SHA-1", "SHA-256", "SHA-512"]:
            hasher = hashlib.new(method.replace("-", "").lower())
            hasher.update(word.encode())
            return hasher.hexdigest()
        else:
            raise ValueError("Unsupported hash method selected.")

    def display_result(self, message):
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, message)
        self.result_text.config(state=tk.DISABLED)

    def save_results(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(self.result_text.get(1.0, tk.END))
                messagebox.showinfo("Success", "Results saved successfully.")
            except Exception as e:
                messagebox.showerror("Error", str(e))


# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    app = HashCrackerApp(root)
    root.mainloop()