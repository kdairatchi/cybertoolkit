
Like this ? Is this debugged and make a automate sh installing all requirements etc


import os
import json
import time
import requests
import sqlite3
import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
from bs4 import BeautifulSoup
import openai
import schedule
import logging
from telegram import Update, ParseMode
from telegram.ext import Updater, CommandHandler, CallbackContext
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options

# Set up logging
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

# OpenAI API and Telegram Token
openai.api_key = "YOUR_OPENAI_API_KEY"
TELEGRAM_BOT_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"

# SQLite Database Setup
DATABASE = 'cybersecurity_data.db'

def setup_database():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS payloads (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  payload TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  category TEXT,
                  content TEXT
                )''')
    conn.commit()
    conn.close()

# Scraping Sources
SOURCES = {
    "xss_payloads": "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#onanimationstart",
    "directory_listing": [
        "https://portswigger.net/kb/issues/00600100_directory-listing",
        "https://www.invicti.com/learn/directory-listing/"
    ],
    "vulnerabilities": [
        "https://cwe.mitre.org/data/index.html",
        "https://www.cvedetails.com",
        "https://nvd.nist.gov/vuln/",
        "https://cve.mitre.org",
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    ]
}

# Function to fetch and update XSS payloads and other data
def fetch_data():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    for name, urls in SOURCES.items():
        if isinstance(urls, str):
            urls = [urls]

        for url in urls:
            try:
                response = requests.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                text = soup.get_text(strip=True)[:500]  # Save first 500 chars to avoid overload
                c.execute('INSERT INTO vulnerabilities (category, content) VALUES (?, ?)', (name, text))
            except requests.RequestException as e:
                logging.error(f"Failed to fetch data from {url}: {e}")

    conn.commit()
    conn.close()

# GUI Setup with Tkinter
class CyberToolkitApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cybersecurity Toolkit")

        # Setup Tabs
        self.tab_control = ttk.Notebook(root)
        self.setup_tabs()
        self.tab_control.pack(expand=1, fill='both')

    def setup_tabs(self):
        # Tab 1: XSS Testing
        self.xss_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.xss_tab, text="XSS Testing")
        self.output = scrolledtext.ScrolledText(self.xss_tab, wrap=tk.WORD, width=100, height=20)
        self.output.grid(column=0, row=0, padx=10, pady=10)
        self.start_button = tk.Button(self.xss_tab, text="Start XSS Testing", command=self.run_tests)
        self.start_button.grid(column=0, row=1, pady=10)

        # Tab 2: Payload Management
        self.payload_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.payload_tab, text="Payload Management")
        self.payload_output = scrolledtext.ScrolledText(self.payload_tab, wrap=tk.WORD, width=100, height=20)
        self.payload_output.grid(column=0, row=0, padx=10, pady=10)
        self.load_payloads()
        self.add_payload_button = tk.Button(self.payload_tab, text="Add Payload", command=self.add_payload)
        self.add_payload_button.grid(column=0, row=1, pady=10)

        # Tab 3: Vulnerability Updates
        self.vuln_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.vuln_tab, text="Vulnerability Updates")
        self.vuln_output = scrolledtext.ScrolledText(self.vuln_tab, wrap=tk.WORD, width=100, height=20)
        self.vuln_output.grid(column=0, row=0, padx=10, pady=10)
        self.fetch_vuln_button = tk.Button(self.vuln_tab, text="Fetch Vulnerability Updates", command=self.update_vulnerabilities)
        self.fetch_vuln_button.grid(column=0, row=1, pady=10)

        # Tab 4: Exploit Reports
        self.report_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.report_tab, text="Exploit Reports")
        self.report_output = scrolledtext.ScrolledText(self.report_tab, wrap=tk.WORD, width=100, height=20)
        self.report_output.grid(column=0, row=0, padx=10, pady=10)
        self.generate_report_button = tk.Button(self.report_tab, text="Generate Report", command=self.generate_report)
        self.generate_report_button.grid(column=0, row=1, pady=10)

        # Tab 5: Settings
        self.settings_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.settings_tab, text="Settings")
        self.settings_info = scrolledtext.ScrolledText(self.settings_tab, wrap=tk.WORD, width=100, height=10)
        self.settings_info.insert(tk.END, "Configure your API keys and bot token here.")
        self.settings_info.grid(column=0, row=0, padx=10, pady=10)

    def run_tests(self):
        payloads = self.get_payloads()
        for payload in payloads:
            response = requests.post("https://example.com/vulnerable_endpoint", data={'input': payload}, headers={'User-Agent': 'Mozilla/5.0'})
            soup = BeautifulSoup(response.text, 'html.parser')
            if payload in soup.text:
                result = f"Possible XSS vulnerability detected with payload: {payload}\n"
            else:
                result = f"Payload: {payload} did not trigger XSS\n"
            self.output.insert(tk.END, result)
            self.output.see(tk.END)
            self.root.update_idletasks()
            if "Possible XSS vulnerability" in result:
                self.generate_ai_analysis(payload, response.text)

    def generate_ai_analysis(self, payload, response):
        try:
            analysis_prompt = (
                f"The following response may contain an XSS vulnerability caused by the payload: {payload}\n"
                f"Response:\n{response}\n"
                "Explain the potential impact and possible fixes for this vulnerability."
            )
            response = openai.Completion.create(
                engine="text-davinci-003",
                prompt=analysis_prompt,
                max_tokens=150
            )
            analysis_result = f"AI Analysis: {response.choices[0].text.strip()}\n"
            self.output.insert(tk.END, analysis_result)
            self.output.see(tk.END)
            self.root.update_idletasks()
        except Exception as e:
            self.output.insert(tk.END, f"Error with OpenAI API: {str(e)}\n")
            self.output.see(tk.END)
            self.root.update_idletasks()

    def get_payloads(self):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('SELECT payload FROM payloads')
        rows = c.fetchall()
        conn.close()
        return [row[0] for row in rows]

    def load_payloads(self):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('SELECT id, payload FROM payloads')
        rows = c.fetchall()
        conn.close()
        self.payload_output.delete('1.0', tk.END)
        for row in rows:
            self.payload_output.insert(tk.END, f"ID: {row[0]}, Payload: {row[1][:100]}...\n")

    def add_payload(self):
        new_payload = tk.simpledialog.askstring("Add Payload", "Enter new XSS payload:")
        if new_payload:
            conn = sqlite3.connect(DATABASE)
            c = conn.cursor()
            c.execute('INSERT INTO payloads (payload) VALUES (?)', (new_payload,))
            conn.commit()
            conn.close()
            messagebox.showinfo("Success", "New payload has been added successfully!")
            self.load_payloads()

    def update_vulnerabilities(self):
        try:
            fetch_data()
            self.load_vulnerabilities()
            messagebox.showinfo("Success", "Vulnerability data has been updated successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update vulnerabilities: {str(e)}")

    def load_vulnerabilities(self):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('SELECT id, category, content FROM vulnerabilities')
        rows = c.fetchall()
        conn.close()
        self.vuln_output.delete('1.0', tk.END)
        for row in rows:
            self.vuln_output.insert(tk.END, f"ID: {row[0]}, Category: {row[1]}, Content: {row[2][:100]}...\n")

    def generate_report(self):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('SELECT category, content FROM vulnerabilities')
        vulnerabilities = c.fetchall()
        c.execute('SELECT payload FROM payloads')
        payloads = c.fetchall()
        conn.close()

        report_text = "==== Cybersecurity Report ====\n\n"

        # Adding vulnerabilities to the report
        report_text += "Vulnerabilities:\n"
        for vuln in vulnerabilities:
            report_text += f"Category: {vuln[0]}, Content: {vuln[1][:100]}...\n"

        # Adding payloads to the report
        report_text += "\nPayloads:\n"
        for payload in payloads:
            report_text += f"Payload: {payload[0][:100]}...\n"

        self.report_output.delete('1.0', tk.END)
        self.report_output.insert(tk.END, report_text)
        messagebox.showinfo("Report Generated", "The cybersecurity report has been generated.")

# Telegram Bot Integration
def start(update: Update, _: CallbackContext) -> None:
    update.message.reply_text('Hello! I am your cybersecurity bot. Use /fetch to see vulnerabilities or /list_payloads to view XSS payloads.')

def fetch_command(update: Update, _: CallbackContext) -> None:
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT id, category, content FROM vulnerabilities')
    rows = c.fetchall()
    conn.close()

    response_text = "🔒 *Latest Cybersecurity Information* 🔒\n\n"
    for row in rows:
        response_text += f"ID: {row[0]}, *{row[1].capitalize()}*\n{row[2][:300]}...\n\n"

    update.message.reply_text(response_text, parse_mode=ParseMode.MARKDOWN)

def list_payloads_command(update: Update, _: CallbackContext) -> None:
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT id, payload FROM payloads')
    rows = c.fetchall()
    conn.close()

    response_text = "💥 *Stored XSS Payloads* 💥\n\n"
    for row in rows:
        response_text += f"ID: {row[0]}, Payload: {row[1][:100]}...\n"

    update.message.reply_text(response_text, parse_mode=ParseMode.MARKDOWN)

def add_payload_command(update: Update, context: CallbackContext) -> None:
    if len(context.args) == 0:
        update.message.reply_text('Usage: /add_payload <payload>')
        return

    new_payload = " ".join(context.args)
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('INSERT INTO payloads (payload) VALUES (?)', (new_payload,))
    conn.commit()
    conn.close()

    update.message.reply_text('New payload has been added successfully!')

def delete_payload_command(update: Update, context: CallbackContext) -> None:
    if len(context.args) == 0:
        update.message.reply_text('Usage: /delete_payload <id>')
        return

    payload_id = context.args[0]
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('DELETE FROM payloads WHERE id = ?', (payload_id,))
    conn.commit()
    conn.close()

    update.message.reply_text('Payload has been deleted successfully!')

# Telegram Bot Setup
def main():
    setup_database()

    updater = Updater(TELEGRAM_BOT_TOKEN)
    dispatcher = updater.dispatcher

    # Define bot commands
    dispatcher.add_handler(CommandHandler("start", start))
    dispatcher.add_handler(CommandHandler("fetch", fetch_command))
    dispatcher.add_handler(CommandHandler("list_payloads", list_payloads_command))
    dispatcher.add_handler(CommandHandler("add_payload", add_payload_command))
    dispatcher.add_handler(CommandHandler("delete_payload", delete_payload_command))

    updater.start_polling()
    logging.info("Bot is now polling for commands...")
    updater.idle()

# Main Program Setup
if __name__ == "__main__":
    root = tk.Tk()
    app = CyberToolkitApp(root)
    main()  # Start the Telegram bot in parallel
    root.mainloop()
