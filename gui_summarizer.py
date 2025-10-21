import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import json
import threading
from pathlib import Path


from pipeline import JSONSummarizer, HostSummaryConfig 

class JSONSummarizerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Security JSON Summarizer")
        self.root.geometry("1200x700")
        
        # Configure grid weight for responsive layout
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=2)
        
        # Initialize variables
        self.file_path = tk.StringVar()
        self.processing_strategy = tk.StringVar(value="prioritize_vulns")
        self.summarizer = None
        
        # Create main frames
        self.create_left_panel()
        self.create_right_panel()
        
    def create_left_panel(self):
        """Create the left control panel"""
        left_frame = ttk.Frame(self.root, padding="10")
        left_frame.grid(row=0, column=0, sticky="nsew")
        
        # Title
        title_label = ttk.Label(left_frame, text="JSON Summarizer Controls", 
                                font=('Arial', 14, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # File selection section
        ttk.Label(left_frame, text="Select JSON File:", 
                 font=('Arial', 10)).grid(row=1, column=0, sticky="w", pady=(0, 5))
        
        # File path entry
        file_entry = ttk.Entry(left_frame, textvariable=self.file_path, width=30)
        file_entry.grid(row=2, column=0, sticky="ew", padx=(0, 5))
        
        # Browse button
        browse_btn = ttk.Button(left_frame, text="Browse", 
                               command=self.browse_file, width=10)
        browse_btn.grid(row=2, column=1, sticky="w")
        
        # Selected file display
        self.file_label = ttk.Label(left_frame, text="No file selected", 
                                   foreground="gray", wraplength=250)
        self.file_label.grid(row=3, column=0, columnspan=2, sticky="w", pady=(5, 20))
        
        # Strategy selection section
        ttk.Label(left_frame, text="Processing Strategy:", 
                 font=('Arial', 10)).grid(row=4, column=0, sticky="w", pady=(0, 5))
        
        # Strategy dropdown
        strategies = [
            ("Prioritize Vulnerabilities", "prioritize_vulns"),
            ("Group by ASN", "group_by_asn"),
            ("Sequential Processing", "sequential")
        ]
        
        strategy_combo = ttk.Combobox(left_frame, 
                                      textvariable=self.processing_strategy,
                                      values=[s[1] for s in strategies],
                                      state="readonly", width=28)
        strategy_combo.grid(row=5, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        
        # Create display names mapping
        self.strategy_display = {s[1]: s[0] for s in strategies}
        strategy_combo.set("prioritize_vulns")
        
        # Strategy description
        self.strategy_desc = ttk.Label(left_frame, 
                                      text="Groups hosts by vulnerability severity",
                                      foreground="gray", wraplength=250,
                                      font=('Arial', 9))
        self.strategy_desc.grid(row=6, column=0, columnspan=2, sticky="w", pady=(0, 20))
        
        # Bind strategy change event
        strategy_combo.bind('<<ComboboxSelected>>', self.on_strategy_change)
        
        # Process button
        self.process_btn = ttk.Button(left_frame, text="Process JSON", 
                                     command=self.process_json,
                                     style="Accent.TButton")
        self.process_btn.grid(row=7, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        
        # Clear button
        clear_btn = ttk.Button(left_frame, text="Clear Output", 
                              command=self.clear_output)
        clear_btn.grid(row=8, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        
        # Status label
        self.status_label = ttk.Label(left_frame, text="Ready", 
                                     foreground="green", font=('Arial', 9))
        self.status_label.grid(row=9, column=0, columnspan=2, sticky="w", pady=(20, 0))
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(left_frame, text="Statistics", padding="10")
        stats_frame.grid(row=10, column=0, columnspan=2, sticky="ew", pady=(20, 0))
        
        self.stats_text = tk.Text(stats_frame, height=8, width=35, 
                                  wrap=tk.WORD, state="disabled",
                                  font=('Courier', 9))
        self.stats_text.grid(row=0, column=0, sticky="ew")
        
        # Configure column weight
        left_frame.grid_columnconfigure(0, weight=1)
        
    def create_right_panel(self):
        """Create the right output panel"""
        right_frame = ttk.Frame(self.root, padding="10")
        right_frame.grid(row=0, column=1, sticky="nsew")
        
        # Title
        output_label = ttk.Label(right_frame, text="Summary Output", 
                                font=('Arial', 14, 'bold'))
        output_label.pack(pady=(0, 10))
        
        # Tab control for different outputs
        self.tab_control = ttk.Notebook(right_frame)
        
        # Executive Summary tab
        self.exec_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.exec_tab, text="Executive Summary")
        
        self.exec_text = scrolledtext.ScrolledText(self.exec_tab, 
                                                   wrap=tk.WORD, 
                                                   font=('Arial', 10),
                                                   padx=10, pady=10)
        self.exec_text.pack(fill="both", expand=True)
        
        # Chunk Details tab
        self.chunk_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.chunk_tab, text="Chunk Details")
        
        self.chunk_text = scrolledtext.ScrolledText(self.chunk_tab, 
                                                    wrap=tk.WORD,
                                                    font=('Courier', 9),
                                                    padx=10, pady=10)
        self.chunk_text.pack(fill="both", expand=True)
        
        # Raw JSON tab
        self.raw_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.raw_tab, text="Raw Output")
        
        self.raw_text = scrolledtext.ScrolledText(self.raw_tab, 
                                                  wrap=tk.WORD,
                                                  font=('Courier', 9),
                                                  padx=10, pady=10)
        self.raw_text.pack(fill="both", expand=True)
        
        self.tab_control.pack(fill="both", expand=True)
        
        # Export button
        export_btn = ttk.Button(right_frame, text="Export Summary", 
                               command=self.export_summary)
        export_btn.pack(pady=(10, 0))
        
    def browse_file(self):
        """Open file dialog to select JSON file"""
        filename = filedialog.askopenfilename(
            title="Select JSON file",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialdir=Path.home()
        )
        
        if filename:
            self.file_path.set(filename)
            # Update file label with just the filename
            self.file_label.config(text=f"Selected: {Path(filename).name}", 
                                 foreground="black")
            self.status_label.config(text="File selected", foreground="blue")
            
    def on_strategy_change(self, event=None):
        """Update description when strategy changes"""
        strategy = self.processing_strategy.get()
        descriptions = {
            "prioritize_vulns": "Groups hosts by vulnerability severity - critical hosts are processed first",
            "group_by_asn": "Groups hosts by Autonomous System Number for network-based analysis",
            "sequential": "Processes hosts in sequential order without special grouping"
        }
        self.strategy_desc.config(text=descriptions.get(strategy, ""))
        
    def process_json(self):
        """Process the selected JSON file"""
        if not self.file_path.get():
            messagebox.showerror("Error", "Please select a JSON file first")
            return
        
        # Disable button during processing
        self.process_btn.config(state="disabled")
        self.status_label.config(text="Processing...", foreground="orange")
        
        # Clear previous output
        self.clear_output()
        
        # Run processing in separate thread to prevent GUI freeze
        thread = threading.Thread(target=self._process_json_thread)
        thread.daemon = True
        thread.start()
        
    def _process_json_thread(self):
        """Thread function for processing JSON"""
        try:
            # Configure summarizer based on selected strategy
            config = HostSummaryConfig()
            strategy = self.processing_strategy.get()
            
            if strategy == "prioritize_vulns":
                config.prioritize_vulns = True
                config.group_by_asn = False
            elif strategy == "group_by_asn":
                config.prioritize_vulns = False
                config.group_by_asn = True
            else:  # sequential
                config.prioritize_vulns = False
                config.group_by_asn = False
            
            # Initialize summarizer
            self.summarizer = JSONSummarizer(config=config)
            
            # Process JSON
            result = self.summarizer.process_json(self.file_path.get())
            
            # Update GUI in main thread
            self.root.after(0, self._update_output, result)
            
        except Exception as e:
            self.root.after(0, self._show_error, str(e))
            
    def _update_output(self, result):
        """Update the output displays with results"""
        # Update Executive Summary tab
        self.exec_text.config(state="normal")
        self.exec_text.delete(1.0, tk.END)
        
        # Format executive summary
        exec_summary = "=" * 50 + "\n"
        exec_summary += "EXECUTIVE SUMMARY\n"
        exec_summary += "=" * 50 + "\n\n"
        exec_summary += result.get('executive_summary', 'No summary generated')
        
        self.exec_text.insert(1.0, exec_summary)
        self.exec_text.config(state="disabled")
        
        # Update Chunk Details tab
        self.chunk_text.config(state="normal")
        self.chunk_text.delete(1.0, tk.END)
        
        chunk_details = "=" * 50 + "\n"
        chunk_details += "CHUNK PROCESSING DETAILS\n"
        chunk_details += "=" * 50 + "\n\n"
        
        for i, chunk in enumerate(result.get('chunk_details', []), 1):
            chunk_details += f"Chunk {i} ({chunk['type']}):\n"
            chunk_details += f"  Hosts: {chunk['host_count']}\n"
            chunk_details += f"  ID: {chunk['chunk_id']}\n"
            chunk_details += f"  Summary: {chunk['summary'][:200]}...\n"
            chunk_details += "-" * 40 + "\n\n"
        
        self.chunk_text.insert(1.0, chunk_details)
        self.chunk_text.config(state="disabled")
        
        # Update Raw JSON tab
        self.raw_text.config(state="normal")
        self.raw_text.delete(1.0, tk.END)
        self.raw_text.insert(1.0, json.dumps(result, indent=2))
        self.raw_text.config(state="disabled")
        
        # Update statistics
        self._update_statistics(result.get('statistics', {}))
        
        # Update status
        self.status_label.config(text="Processing complete!", foreground="green")
        self.process_btn.config(state="normal")
        
    def _update_statistics(self, stats):
        """Update the statistics display"""
        self.stats_text.config(state="normal")
        self.stats_text.delete(1.0, tk.END)
        
        stats_display = f"""Total Hosts: {stats.get('total_hosts', 0)}
Chunks Created: {stats.get('chunks_created', 0)}
Tokens Used: {stats.get('total_tokens_used', 0):,}

Processing Strategy:
{json.dumps(stats.get('processing_strategy', {}), indent=2)}"""
        
        self.stats_text.insert(1.0, stats_display)
        self.stats_text.config(state="disabled")
        
    def _show_error(self, error_message):
        """Show error message"""
        messagebox.showerror("Processing Error", f"An error occurred:\n{error_message}")
        self.status_label.config(text="Error occurred", foreground="red")
        self.process_btn.config(state="normal")
        
    def clear_output(self):
        """Clear all output fields"""
        for text_widget in [self.exec_text, self.chunk_text, self.raw_text]:
            text_widget.config(state="normal")
            text_widget.delete(1.0, tk.END)
            text_widget.config(state="disabled")
        
        self.stats_text.config(state="normal")
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.config(state="disabled")
        
    def export_summary(self):
        """Export the summary to a file"""
        if not self.exec_text.get(1.0, tk.END).strip():
            messagebox.showwarning("Warning", "No summary to export")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Save Summary",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    # Export full result as JSON
                    with open(filename, 'w') as f:
                        json.dump(self.summarizer.last_result if hasattr(self.summarizer, 'last_result') else {}, f, indent=2)
                else:
                    # Export as text
                    with open(filename, 'w') as f:
                        f.write(self.exec_text.get(1.0, tk.END))
                
                messagebox.showinfo("Success", f"Summary exported to {Path(filename).name}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export: {str(e)}")


def main():
    root = tk.Tk()
    app = JSONSummarizerGUI(root)
    
    # Style configuration
    style = ttk.Style()
    style.configure("Accent.TButton", foreground="blue")
    
    root.mainloop()


if __name__ == "__main__":
    main()