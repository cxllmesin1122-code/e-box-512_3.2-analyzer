"""
GUI Enhancements — Copy-to-Clipboard, Context Menus, Accuracy Metrics
"""

import tkinter as tk
from tkinter import messagebox
import threading
import time


# ─────────────────────────────────────────────────────────────────────────────
#  Context Menu for Copy functionality
# ─────────────────────────────────────────────────────────────────────────────

class ContextMenu(tk.Menu):
    """Right-click context menu for text widgets."""
    
    def __init__(self, parent):
        super().__init__(parent, tearoff=False, 
                        bg="#161b22", fg="#e6edf3",
                        activebackground="#58a6ff", 
                        activeforeground="#0d1117",
                        font=("Consolas", 9))
        self.parent = parent
    
    def show(self, event, text_widget):
        """Show context menu at cursor position."""
        try:
            self.delete(0, 'end')
            
            # Get selected text
            try:
                selected = text_widget.get('sel.first', 'sel.last')
            except tk.TclError:
                selected = None
            
            # Add menu items
            if selected:
                self.add_command(label="Copy", 
                               command=lambda: self._copy(selected, event))
            
            self.add_command(label="Copy All", 
                           command=lambda: self._copy_all(text_widget, event))
            self.add_separator()
            self.add_command(label="Select All", 
                           command=lambda: text_widget.tag_add(tk.SEL, '1.0', tk.END) 
                                        or text_widget.event_generate('<<Copy>>'))
            
            # Show menu
            try:
                self.tk_popup(event.x_root, event.y_root)
            finally:
                self.grab_release()
        except Exception as e:
            print(f"Context menu error: {e}")
    
    def _copy(self, text: str, event):
        """Copy selected text to clipboard."""
        try:
            event.widget.clipboard_clear()
            event.widget.clipboard_append(text)
            event.widget.update()
        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to copy: {e}")
    
    def _copy_all(self, text_widget, event):
        """Copy all text to clipboard."""
        try:
            all_text = text_widget.get('1.0', 'end-1c')
            text_widget.clipboard_clear()
            text_widget.clipboard_append(all_text)
            text_widget.update()
            messagebox.showinfo("Copy", "All text copied to clipboard")
        except Exception as e:
            messagebox.showerror("Copy Error", f"Failed to copy: {e}")


# ─────────────────────────────────────────────────────────────────────────────
#  Enhanced Progress Bar with Accuracy Display
# ─────────────────────────────────────────────────────────────────────────────

class AdvancedProgressBar(tk.Frame):
    """Progress bar with accuracy percentage display."""
    
    def __init__(self, master, height=30, **kw):
        super().__init__(master, height=height, **kw)
        self.pack_propagate(False)
        
        # Progress bar
        from tkinter import ttk
        self._var = tk.DoubleVar(value=0.0)
        self._bar = ttk.Progressbar(self, variable=self._var, 
                                    maximum=100, mode='determinate')
        self._bar.pack(side='left', fill='both', expand=True, padx=4, pady=4)
        
        # Status label
        self._status_var = tk.StringVar(value="Ready")
        self._status_label = tk.Label(self, textvariable=self._status_var,
                                     font=("Consolas", 9), fg="#8b949e",
                                     bg="#161b22")
        self._status_label.pack(side='left', padx=8)
        
        # Accuracy percentage
        self._accuracy_var = tk.StringVar(value="0%")
        self._accuracy_label = tk.Label(self, textvariable=self._accuracy_var,
                                       font=("Consolas", 10, "bold"), 
                                       fg="#3fb950", bg="#161b22")
        self._accuracy_label.pack(side='right', padx=8)
    
    def set_progress(self, value: float, accuracy: float = 0.0, 
                    status: str = ""):
        """Update progress and accuracy."""
        self._var.set(min(100.0, max(0.0, value)))
        if status:
            self._status_var.set(status)
        if accuracy > 0:
            self._accuracy_var.set(f"{accuracy:.1f}%")
    
    def set_status(self, status: str):
        """Update status message."""
        self._status_var.set(status)
    
    def set_accuracy(self, accuracy: float):
        """Update accuracy percentage."""
        self._accuracy_var.set(f"{accuracy:.1f}%")
    
    def reset(self):
        """Reset progress bar."""
        self._var.set(0.0)
        self._status_var.set("Ready")
        self._accuracy_var.set("0%")


# ─────────────────────────────────────────────────────────────────────────────
#  Decompilation Context Menu
# ─────────────────────────────────────────────────────────────────────────────

class DecompileContextMenu(tk.Menu):
    """Right-click context menu for decompilation at offset."""
    
    def __init__(self, parent, decompile_callback=None):
        super().__init__(parent, tearoff=False,
                        bg="#161b22", fg="#e6edf3",
                        activebackground="#58a6ff",
                        activeforeground="#0d1117",
                        font=("Consolas", 9))
        self.decompile_callback = decompile_callback
    
    def show(self, event, hex_value: str = ""):
        """Show decompile context menu."""
        try:
            self.delete(0, 'end')
            
            if hex_value:
                self.add_command(
                    label=f"Decompile @ {hex_value}",
                    command=lambda: self._decompile_at_offset(hex_value, event)
                )
                self.add_separator()
            
            self.add_command(label="Decompile All",
                           command=lambda: self._decompile_all(event))
            self.add_command(label="Show Disassembly",
                           command=lambda: self._show_disasm(event))
            
            self.tk_popup(event.x_root, event.y_root)
        finally:
            self.grab_release()
    
    def _decompile_at_offset(self, offset: str, event):
        """Decompile at specific offset."""
        if self.decompile_callback:
            self.decompile_callback({'action': 'decompile_offset', 'offset': offset})
    
    def _decompile_all(self, event):
        """Decompile entire binary."""
        if self.decompile_callback:
            self.decompile_callback({'action': 'decompile_all'})
    
    def _show_disasm(self, event):
        """Show disassembly view."""
        if self.decompile_callback:
            self.decompile_callback({'action': 'show_disasm'})


# ─────────────────────────────────────────────────────────────────────────────
#  Copy Helper for Text Widgets
# ─────────────────────────────────────────────────────────────────────────────

def make_text_copyable(text_widget: tk.Text) -> None:
    """Add copy-to-clipboard functionality to a text widget."""
    context_menu = ContextMenu(text_widget)
    
    def right_click(event):
        context_menu.show(event, text_widget)
    
    text_widget.bind('<Button-3>', right_click)  # Right-click
    text_widget.bind('<Control-Button-1>', right_click)  # Ctrl+Click


# ─────────────────────────────────────────────────────────────────────────────
#  Analysis Progress Tracker
# ─────────────────────────────────────────────────────────────────────────────

class AnalysisProgressTracker:
    """Track analysis progress with multiple stages."""
    
    def __init__(self, total_stages: int = 5):
        self.total_stages = total_stages
        self.current_stage = 0
        self.stage_accuracy = {}
        
    def start_stage(self, stage_name: str):
        """Start a new analysis stage."""
        self.current_stage += 1
        self.stage_accuracy[stage_name] = 0.0
        return self.get_progress()
    
    def update_stage(self, stage_name: str, accuracy: float):
        """Update accuracy for current stage."""
        self.stage_accuracy[stage_name] = min(100.0, accuracy)
        return self.get_progress()
    
    def get_progress(self) -> tuple:
        """Get (progress_percent, accuracy_percent)."""
        if not self.stage_accuracy:
            return 0.0, 0.0
        
        progress = (self.current_stage / self.total_stages) * 100
        accuracy = sum(self.stage_accuracy.values()) / len(self.stage_accuracy)
        
        return min(100.0, progress), accuracy
    
    def reset(self):
        """Reset tracker."""
        self.current_stage = 0
        self.stage_accuracy.clear()


# ─────────────────────────────────────────────────────────────────────────────
#  Notification Toast
# ─────────────────────────────────────────────────────────────────────────────

class Toast:
    """Simple notification toast message."""
    
    @staticmethod
    def show(parent, message: str, duration: int = 2000, 
            color: str = "#3fb950"):
        """Show a toast notification."""
        toast = tk.Toplevel(parent)
        toast.wm_overrideredirect(True)
        toast.attributes('-alpha', 0.9)
        
        label = tk.Label(toast, text=message, 
                        bg=color, fg="#000000",
                        font=("Consolas", 10, "bold"),
                        padx=20, pady=10)
        label.pack()
        
        # Position at bottom-right
        toast.update_idletasks()
        x = parent.winfo_screenwidth() - toast.winfo_width() - 20
        y = parent.winfo_screenheight() - toast.winfo_height() - 60
        toast.geometry(f"+{x}+{y}")
        
        # Auto-close
        def close():
            toast.destroy()
        
        toast.after(duration, close)
        return toast
