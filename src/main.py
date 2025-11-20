import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import random
import string

import pandas as pd
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from parsers import parse_apache_log, parse_ssh_log
from detection import (
    detect_bruteforce_ssh,
    detect_scanning_apache,
    detect_dos_apache,
    cross_reference_blacklist,
)
from reporting import export_alerts_to_csv

# Try to import winsound for sound effects (Windows)
try:
    import winsound
    HAS_WINSOUND = True
except ImportError:
    HAS_WINSOUND = False


# ===================================================
#  STARTUP BOOT SCREEN WITH MATRIX FALLING CODE
# ===================================================

class BootScreen(tk.Toplevel):
    def __init__(self, master, on_complete):
        super().__init__(master)
        self.on_complete = on_complete
        self.configure(bg="#000000")
        self.overrideredirect(True)  # borderless window
        self.geometry("720x420+300+200")  # roughly centered

        # Title
        self.title_label = tk.Label(
            self,
            text="NEON LOG INTRUSION ANALYZER BOOT SEQUENCE",
            fg="#00f5ff",
            bg="#000000",
            font=("Consolas", 14, "bold")
        )
        self.title_label.pack(pady=10)

        # Status text
        self.status_label = tk.Label(
            self,
            text="[BOOT] Initializing...",
            fg="#00f5ff",
            bg="#000000",
            font=("Consolas", 11)
        )
        self.status_label.pack(pady=5)

        # Matrix canvas
        self.canvas = tk.Canvas(self, bg="#000000", highlightthickness=0)
        self.canvas.pack(fill="both", expand=True, padx=10, pady=10)

        self.matrix_chars = string.ascii_uppercase + string.digits
        self.columns = 80
        self.font_size = 12

        self.steps = [
            "[BOOT] Loading detection engine...",
            "[BOOT] Initializing neon UI modules...",
            "[BOOT] Parsing rule sets...",
            "[BOOT] Establishing console link...",
            "[BOOT] ACCESS GRANTED. Launching interface..."
        ]
        self.step_index = 0

        self.after(50, self.animate_matrix)
        self.after(800, self.advance_boot)

    def animate_matrix(self):
        """Simple 'falling code' style effect."""
        self.canvas.delete("all")
        width = self.canvas.winfo_width() or 700
        height = self.canvas.winfo_height() or 300
        col_width = width / self.columns

        for col in range(self.columns):
            x = col * col_width + col_width / 2
            y = random.randint(0, height)
            ch = random.choice(self.matrix_chars)
            color = random.choice(["#00f5ff", "#00ffe0", "#00d0ff"])
            self.canvas.create_text(
                x, y,
                text=ch,
                fill=color,
                font=("Consolas", self.font_size, "bold")
            )

        self.after(80, self.animate_matrix)

    def advance_boot(self):
        if self.step_index < len(self.steps):
            self.status_label.config(text=self.steps[self.step_index])
            self.step_index += 1
            self.after(900, self.advance_boot)
        else:
            # ACCESS GRANTED beep on Windows
            if HAS_WINSOUND:
                try:
                    winsound.MessageBeep(winsound.MB_ICONASTERISK)
                except Exception:
                    pass
            self.destroy()
            self.on_complete()


# ===================================================
#  MAIN NEON HACKER APP (BLUE/CYAN THEME)
# ===================================================

class LogAnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("NEON Log Intrusion Analyzer")
        self.geometry("1200x750")
        self.configure(bg="#000000")

        # Theme colors similar to your screenshot
        self.neon_main = "#00f5ff"   # bright cyan
        self.neon_dim = "#008b99"    # darker teal
        self.bg_dark = "#000000"

        # Data holders
        self.apache_log_path = tk.StringVar()
        self.ssh_log_path = tk.StringVar()
        self.alerts_df = pd.DataFrame()
        self.apache_df = pd.DataFrame()
        self.ssh_df = pd.DataFrame()

        # Animation state
        self.pulse_state = False

        # Setup UI
        self._create_styles()
        self._build_layout()

        # Boot sequence
        self.withdraw()
        self.after(100, self._show_boot_screen)

    # ------------------------------
    #  STYLE ENGINE
    # ------------------------------
    def _create_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        # Frames with thick cyan borders (fake glow)
        style.configure(
            "Neon.TFrame",
            background=self.bg_dark,
            borderwidth=4,
            relief="ridge"
        )

        # Labels
        style.configure(
            "Neon.TLabel",
            background=self.bg_dark,
            foreground=self.neon_main,
            font=("Consolas", 12, "bold")
        )

        style.configure(
            "NeonTitle.TLabel",
            background=self.bg_dark,
            foreground=self.neon_main,
            font=("Consolas", 20, "bold")
        )

        # Buttons
        style.configure(
            "Neon.TButton",
            background="#00171c",
            foreground=self.neon_main,
            borderwidth=3,
            focusthickness=4,
            focuscolor=self.neon_main,
            padding=8,
            font=("Consolas", 12, "bold")
        )
        style.map(
            "Neon.TButton",
            background=[("active", "#00363f")],
            foreground=[("active", "#e0ffff")]
        )

        # Treeview (table)
        style.configure(
            "Neon.Treeview",
            background=self.bg_dark,
            foreground=self.neon_main,
            rowheight=26,
            fieldbackground=self.bg_dark,
            borderwidth=2
        )
        style.configure(
            "Neon.Treeview.Heading",
            background="#00171c",
            foreground=self.neon_main,
            borderwidth=2,
            font=("Consolas", 12, "bold")
        )

    # ------------------------------
    #  LAYOUT
    # ------------------------------
    def _build_layout(self):
        # Top banner
        self.banner = ttk.Frame(self, style="Neon.TFrame")
        self.banner.pack(fill="x", padx=10, pady=10)

        title_lbl = ttk.Label(
            self.banner,
            text="NEON LOG INTRUSION ANALYZER – BLUE TEAM CONSOLE",
            style="NeonTitle.TLabel"
        )
        title_lbl.pack(padx=10, pady=10)

        # File selection
        files_frame = ttk.Frame(self, style="Neon.TFrame")
        files_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(files_frame, text="Apache Log:", style="Neon.TLabel").grid(
            row=0, column=0, padx=8, pady=8, sticky="e")
        ttk.Entry(files_frame, textvariable=self.apache_log_path,
                  width=70).grid(row=0, column=1, padx=8, pady=8)
        ttk.Button(files_frame, text="Browse", style="Neon.TButton",
                   command=self.browse_apache).grid(row=0, column=2, padx=8, pady=8)

        ttk.Label(files_frame, text="SSH Log (auth.log):", style="Neon.TLabel").grid(
            row=1, column=0, padx=8, pady=8, sticky="e")
        ttk.Entry(files_frame, textvariable=self.ssh_log_path,
                  width=70).grid(row=1, column=1, padx=8, pady=8)
        ttk.Button(files_frame, text="Browse", style="Neon.TButton",
                   command=self.browse_ssh).grid(row=1, column=2, padx=8, pady=8)

        # Actions
        actions_frame = ttk.Frame(self, style="Neon.TFrame")
        actions_frame.pack(fill="x", padx=10, pady=10)

        self.btn_analyze = ttk.Button(
            actions_frame, text="⚡ Analyze Logs", style="Neon.TButton",
            command=self.analyze_logs
        )
        self.btn_export = ttk.Button(
            actions_frame, text="📤 Export Alerts to CSV", style="Neon.TButton",
            command=self.export_alerts
        )
        self.btn_chart = ttk.Button(
            actions_frame, text="📊 Show IP Activity Chart", style="Neon.TButton",
            command=self.show_charts
        )

        self.btn_analyze.pack(side="left", padx=10)
        self.btn_export.pack(side="left", padx=10)
        self.btn_chart.pack(side="left", padx=10)

        # Alerts table
        table_frame = ttk.Frame(self, style="Neon.TFrame")
        table_frame.pack(fill="both", expand=True, padx=10, pady=10)

        cols = ("time", "ip", "category", "details", "blacklisted")
        self.tree = ttk.Treeview(
            table_frame,
            columns=cols,
            show="headings",
            style="Neon.Treeview"
        )
        for col in cols:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=200, anchor="w")

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)

        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Status bar
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(
            self,
            textvariable=self.status_var,
            style="Neon.TLabel"
        ).pack(fill="x", padx=10, pady=5, anchor="w")

        # Start border + button pulse animation
        self.after(600, self._animate_neon)

    # ------------------------------
    #  BOOT SPLASH
    # ------------------------------
    def _show_boot_screen(self):
        def on_boot_complete():
            self.deiconify()
        BootScreen(self, on_boot_complete)

    # ------------------------------
    #  FILE BROWSERS
    # ------------------------------
    def browse_apache(self):
        path = filedialog.askopenfilename(
            filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")]
        )
        if path:
            self.apache_log_path.set(path)

    def browse_ssh(self):
        path = filedialog.askopenfilename(
            filetypes=[("Log files", "*.log *.txt"), ("All files", "*.*")]
        )
        if path:
            self.ssh_log_path.set(path)

    # ------------------------------
    #  ANALYSIS
    # ------------------------------
    def analyze_logs(self):
        apache_path = self.apache_log_path.get()
        ssh_path = self.ssh_log_path.get()

        if not apache_path and not ssh_path:
            messagebox.showwarning("Missing Logs", "Select at least one log file!")
            return

        try:
            self.status_var.set("Parsing logs...")
            self.update_idletasks()

            apache_df = parse_apache_log(apache_path) if apache_path else pd.DataFrame()
            ssh_df = parse_ssh_log(ssh_path) if ssh_path else pd.DataFrame()

            self.apache_df = apache_df
            self.ssh_df = ssh_df

            alerts_list = []

            if not ssh_df.empty:
                alerts_list.append(detect_bruteforce_ssh(ssh_df))

            if not apache_df.empty:
                alerts_list.append(detect_scanning_apache(apache_df))
                alerts_list.append(detect_dos_apache(apache_df))

            alerts_df = pd.concat(alerts_list, ignore_index=True) if alerts_list else pd.DataFrame()

            blacklist_ips = self._load_blacklist()
            alerts_df = cross_reference_blacklist(alerts_df, blacklist_ips)

            self.alerts_df = alerts_df
            self._populate_table()

            self.status_var.set(f"Analysis complete. {len(alerts_df)} alerts detected.")

            if HAS_WINSOUND:
                try:
                    winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
                except Exception:
                    pass

        except Exception as e:
            messagebox.showerror("Error", f"Analysis failed:\n{e}")
            self.status_var.set("Error occurred.")

    def _load_blacklist(self):
        path = Path("../blacklist_ips.txt")
        if not path.exists():
            return set()
        return {line.strip() for line in path.read_text().splitlines() if line.strip()}

    # ------------------------------
    #  TABLE POPULATION
    # ------------------------------
    def _populate_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        if self.alerts_df.empty:
            return

        for _, r in self.alerts_df.iterrows():
            self.tree.insert(
                "",
                "end",
                values=(
                    str(r["time"]) if pd.notna(r["time"]) else "",
                    r.get("ip", ""),
                    r.get("category", ""),
                    r.get("details", ""),
                    "YES" if r.get("blacklisted") else "NO",
                ),
            )

    # ------------------------------
    #  EXPORT REPORT
    # ------------------------------
    def export_alerts(self):
        if self.alerts_df.empty:
            messagebox.showinfo("Empty", "No alerts to export!")
            return

        path = export_alerts_to_csv(self.alerts_df, reports_dir="../reports")
        messagebox.showinfo("Exported", f"Report saved:\n{path}")

    # ------------------------------
    #  VERTICAL BAR CHARTS (STYLE B)
    # ------------------------------
    def show_charts(self):
        if self.apache_df.empty and self.ssh_df.empty:
            messagebox.showwarning("No Data", "Analyze logs first!")
            return

        chart_window = tk.Toplevel(self)
        chart_window.title("IP Activity Charts")
        chart_window.configure(bg="#000000")
        chart_window.geometry("1000x500")

        fig = Figure(figsize=(10, 4), dpi=120)
        fig.patch.set_facecolor("#ffffff")  # white background for report style

        # ---------- Apache ----------
        if not self.apache_df.empty:
            ax1 = fig.add_subplot(1, 2, 1)
            ip_counts = self.apache_df["ip"].value_counts().head(4)  # top 4 like example
            ips = list(ip_counts.index)
            values = list(ip_counts.values)
            x_pos = range(len(ips))

            bars = ax1.bar(x_pos, values, width=0.6, color="#00cfe8")

            # Value labels above bars
            max_val = max(values) if values else 0
            offset = max_val * 0.03 if max_val else 0.5
            for bar, val in zip(bars, values):
                height = bar.get_height()
                ax1.text(
                    bar.get_x() + bar.get_width() / 2,
                    height + offset,
                    f"{val}",
                    ha="center",
                    va="bottom",
                    fontsize=9,
                    color="#006170",
                    fontweight="bold"
                )

            ax1.set_xticks(list(x_pos))
            ax1.set_xticklabels(ips, rotation=0, fontsize=8)  # actual IPs, not diagonal
            ax1.set_ylabel("Request Count", fontsize=10)
            ax1.set_title("Top Apache IPs", fontsize=11, fontweight="bold")

            # Light grid for professional look
            ax1.grid(axis="y", linestyle="--", alpha=0.4)
        else:
            ax1 = fig.add_subplot(1, 2, 1)
            ax1.text(0.5, 0.5, "No Apache Data", ha="center", va="center")
            ax1.axis("off")

        # ---------- SSH ----------
        if not self.ssh_df.empty:
            ax2 = fig.add_subplot(1, 2, 2)
            ip_counts_ssh = self.ssh_df["ip"].value_counts().head(4)
            ips2 = list(ip_counts_ssh.index)
            values2 = list(ip_counts_ssh.values)
            x2 = range(len(ips2))

            bars2 = ax2.bar(x2, values2, width=0.6, color="#00cfe8")

            max_val2 = max(values2) if values2 else 0
            offset2 = max_val2 * 0.03 if max_val2 else 0.5
            for bar, val in zip(bars2, values2):
                height = bar.get_height()
                ax2.text(
                    bar.get_x() + bar.get_width() / 2,
                    height + offset2,
                    f"{val}",
                    ha="center",
                    va="bottom",
                    fontsize=9,
                    color="#006170",
                    fontweight="bold"
                )

            ax2.set_xticks(list(x2))
            ax2.set_xticklabels(ips2, rotation=0, fontsize=8)
            ax2.set_ylabel("Failed Logins", fontsize=10)
            ax2.set_title("Top SSH Failed Login IPs", fontsize=11, fontweight="bold")
            ax2.grid(axis="y", linestyle="--", alpha=0.4)
        else:
            ax2 = fig.add_subplot(1, 2, 2)
            ax2.text(0.5, 0.5, "No SSH Data", ha="center", va="center")
            ax2.axis("off")

        fig.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=chart_window)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)

    # ------------------------------
    #  NEON ANIMATION (BORDERS + BUTTONS)
    # ------------------------------
    def _animate_neon(self):
        style = ttk.Style(self)

        if self.pulse_state:
            # brighter cyan
            style.configure("Neon.TButton", background="#00252b", foreground="#e0ffff")
            self.banner.configure(style="Neon.TFrame")
        else:
            # darker cyan
            style.configure("Neon.TButton", background="#00171c", foreground=self.neon_main)
            self.banner.configure(style="Neon.TFrame")

        self.pulse_state = not self.pulse_state
        self.after(600, self._animate_neon)


# ===================================================
#  RUN APP
# ===================================================
if __name__ == "__main__":
    app = LogAnalyzerApp()
    app.mainloop()
