import os
import tkinter as tk
from tkinter import filedialog, messagebox
from elftools.elf.elffile import ELFFile

def analyze_elf(file_path):
    try:
        with open(file_path, 'rb') as f:
            elf = ELFFile(f)
            imports = []
            if not elf.has_dwarf_info():
                messagebox.showerror("Error", "No DWARF info found!")
                return
            for section in elf.iter_sections():
                if isinstance(section, elftools.elf.sections.ImportSection):
                    for entry in section.iter_entries():
                        imports.append(f"{entry.name} from {entry.library}")
            return imports
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")
        return []

def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("ELF Files", "*.elf")])
    if file_path:
        imports = analyze_elf(file_path)
        display_imports(imports)

def display_imports(imports):
    if not imports:
        result_text.set("No imports found or file is not a valid ELF.")
    else:
        result_text.set("\n".join(imports))

if __name__ == "__main__":
    root = tk.Tk()
    root.title("ELF Import Analyzer")
    open_button = tk.Button(root, text="Open ELF File", command=open_file)
    open_button.pack(pady=20)
    result_text = tk.StringVar()
    result_label = tk.Label(root, textvariable=result_text, justify=tk.LEFT)
    result_label.pack(pady=20)

    root.mainloop()