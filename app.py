import sqlite3
import requests
import tkinter as tk
import base64
from tkinter import messagebox
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from datetime import datetime

# Define your VirusTotal API key here
API_KEY = "faf49b69c11e099784c4e2d6f78610e9efb2230dfb2766f4a592eff40bb765e2"

# Check if IP or URL is malicious using VirusTotal API
def check_ip_or_url(api_key, ip=None, url=None):
    try:
        if url:
            # Encode the URL in base64 format for VirusTotal API
            encoded_url = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            vt_url = f'https://www.virustotal.com/api/v3/urls/{encoded_url}'
        elif ip:
            vt_url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
        else:
            raise ValueError("Either IP or URL must be provided.")

        headers = {'x-apikey': api_key, 'accept': 'application/json'}
        response = requests.get(vt_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            analysis_results = data['data']['attributes']['last_analysis_results']

            # Identify suspicious or malicious engines
            suspicious_engines = [
                result["engine_name"] for result in analysis_results.values()
                if result["category"] in ["malicious", "suspicious"]
            ]
            message = "Suspicious" if suspicious_engines else "Clean"
            
            return {
                "message": f"The URL/IP is {message}.",
                "suspicious_engines": suspicious_engines,
                "analysis_summary": data['data']['attributes']['last_analysis_stats']
            }
        else:
            messagebox.showerror("API Error", f"Error {response.status_code}: {response.json().get('error', {}).get('message', 'Unknown error')}")
            return None
    except requests.RequestException as e:
        messagebox.showerror("Network Error", str(e))
        return None

# Register a new user
def register_user(username, password):
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        messagebox.showinfo("Success", "Registration successful! Please login.")
        show_login()  # Redirect to login after successful registration
    except sqlite3.IntegrityError:
        messagebox.showerror("Error", "Username already exists!")
    conn.close()

# User login
def login_user(username, password):
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    user = c.fetchone()
    conn.close()
    if user:
        show_main_menu(user[0])  # Open main menu if login is successful
    else:
        messagebox.showerror("Login Error", "Invalid username or password.")

# Show homepage with options to register or login
def show_homepage():
    clear_frame()
    tk.Label(window, text="Welcome to Data Breach Checker", font=("Arial", 16)).pack(pady=20)
    tk.Button(window, text="Register", command=show_register).pack(pady=10)
    tk.Button(window, text="Login", command=show_login).pack(pady=10)

# Show registration page
def show_register():
    clear_frame()
    tk.Label(window, text="Register", font=("Arial", 14)).pack(pady=10)
    tk.Label(window, text="Username").pack()
    entry_username = tk.Entry(window)
    entry_username.pack()
    tk.Label(window, text="Password").pack()
    entry_password = tk.Entry(window, show="*")
    entry_password.pack()
    tk.Button(window, text="Register", command=lambda: register_user(entry_username.get(), entry_password.get())).pack(pady=10)
    tk.Button(window, text="Back to Home", command=show_homepage).pack(pady=5)

# Show login page
def show_login():
    clear_frame()
    tk.Label(window, text="Login", font=("Arial", 14)).pack(pady=10)
    tk.Label(window, text="Username").pack()
    entry_username = tk.Entry(window)
    entry_username.pack()
    tk.Label(window, text="Password").pack()
    entry_password = tk.Entry(window, show="*")
    entry_password.pack()
    tk.Button(window, text="Login", command=lambda: login_user(entry_username.get(), entry_password.get())).pack(pady=10)
    tk.Button(window, text="Back to Home", command=show_homepage).pack(pady=5)

# Main menu after login
def show_main_menu(user_id):
    clear_frame()
    tk.Label(window, text="Main Menu", font=("Arial", 14)).pack(pady=10)
    tk.Button(window, text="Check IP Address", command=lambda: show_ip_check(user_id)).pack(pady=10)
    tk.Button(window, text="Check URL", command=lambda: show_url_check(user_id)).pack(pady=10)
    tk.Button(window, text="Update Profile", command=lambda: create_update_profile_page(user_id)).pack(pady=10)
    tk.Button(window, text="Search Checks by Date", command=lambda: create_search_checks_page(user_id)).pack(pady=10)
    tk.Button(window, text="Logout", command=show_homepage).pack(pady=5)

# Show IP check page
def show_ip_check(user_id):
    clear_frame()
    tk.Label(window, text="IP Check", font=("Arial", 14)).pack(pady=10)
    tk.Label(window, text="Enter IP Address").pack()
    entry_ip = tk.Entry(window)
    entry_ip.pack()
    tk.Button(window, text="Check IP", command=lambda: check_and_store(user_id, entry_ip.get(), None)).pack(pady=10)
    tk.Button(window, text="Back to Menu", command=lambda: show_main_menu(user_id)).pack(pady=5)

# Show URL check page
def show_url_check(user_id):
    clear_frame()
    tk.Label(window, text="URL Check", font=("Arial", 14)).pack(pady=10)
    tk.Label(window, text="Enter URL").pack()
    entry_url = tk.Entry(window)
    entry_url.pack()
    tk.Button(window, text="Check URL", command=lambda: check_and_store(user_id, None, entry_url.get())).pack(pady=10)
    tk.Button(window, text="Back to Menu", command=lambda: show_main_menu(user_id)).pack(pady=5)

# Clear the window
def clear_frame():
    for widget in window.winfo_children():
        widget.destroy()

# Check and store result
def check_and_store(user_id, ip, url):
    result = check_ip_or_url(API_KEY, ip=ip, url=url)
    if result:
        if ip:
            messagebox.showinfo("IP Check Result", f"IP {ip} has analysis: {result}")
        elif url:
            messagebox.showinfo("URL Check Result", f"URL {url} has analysis: {result}")
        store_check_result(user_id, ip, url, result)

# Store check results in the database
def store_check_result(user_id, ip, url, result):
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('INSERT INTO checks (user_id, ip_address, url, result) VALUES (?, ?, ?, ?)', (user_id, ip, url, str(result)))
    conn.commit()
    conn.close()

# Display the search results
def display_search_results(results, user_id):
    clear_frame()
    tk.Label(window, text="Search Results", font=("Arial", 14)).pack(pady=10)
    for result in results:
        ip, url, analysis, timestamp = result
        result_text = f"IP: {ip}\nURL: {url}\nAnalysis: {analysis}\nChecked on: {timestamp}\n\n"
        tk.Label(window, text=result_text).pack()

    tk.Button(window, text="Back to Menu", command=lambda: show_main_menu(user_id)).pack(pady=5)

# Search checks by date
def search_checks_by_date(user_id, date):
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('''SELECT ip_address, url, result, timestamp 
                 FROM checks 
                 WHERE user_id = ? AND DATE(timestamp) = ?''', (user_id, date))
    results = c.fetchall()
    conn.close()

    if results:
        display_search_results(results, user_id)  # Pass user_id here
    else:
        messagebox.showinfo("No Results", f"No IPs or URLs checked on {date}.")


# Create the search page
def create_search_checks_page(user_id):
    clear_frame()
    tk.Label(window, text="Search Checks by Date", font=("Arial", 14)).pack(pady=10)
    tk.Label(window, text="Enter Date (YYYY-MM-DD)").pack()
    entry_date = tk.Entry(window)
    entry_date.pack()
    tk.Button(window, text="Search", command=lambda: search_checks_by_date(user_id, entry_date.get())).pack(pady=10)
    tk.Button(window, text="Back to Menu", command=lambda: show_main_menu(user_id)).pack(pady=5)

# Create the database tables
def create_db_tables():
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE,
                    password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS checks (
                    id INTEGER PRIMARY KEY,
                    user_id INTEGER,
                    ip_address TEXT,
                    url TEXT,
                    result TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()


# Function to fetch data from the database for the report
def fetch_report_data(user_id, start_date, end_date, include_ip, include_url):
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()

    query = "SELECT ip_address, url, result, timestamp FROM checks WHERE user_id = ?"
    parameters = [user_id]
    
    if start_date:
        query += " AND timestamp >= ?"
        parameters.append(start_date)
    
    if end_date:
        query += " AND timestamp <= ?"
        parameters.append(end_date)

    c.execute(query, parameters)
    data = c.fetchall()
    conn.close()

    # Filter by IP or URL if required
    filtered_data = []
    for row in data:
        ip, url, result, timestamp = row
        if (include_ip and ip) or (include_url and url):
            filtered_data.append((ip, url, result, timestamp))
    
    return filtered_data

# Function to generate the PDF report
def generate_pdf_report(user_id, start_date, end_date, include_ip, include_url):
    report_data = fetch_report_data(user_id, start_date, end_date, include_ip, include_url)
    if not report_data:
        messagebox.showerror("No Data", "No data found for the given criteria.")
        return

    filename = f"report_{user_id}_{start_date}_{end_date}.pdf"
    c = canvas.Canvas(filename, pagesize=letter)
    c.setFont("Helvetica", 12)
    
    c.drawString(100, 750, f"Report for User ID: {user_id}")
    c.drawString(100, 730, f"Date Range: {start_date} to {end_date}")
    c.drawString(100, 710, f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    c.drawString(100, 690, "---------------------------------------------")
    
    y_position = 670
    for row in report_data:
        ip, url, result, timestamp = row
        c.drawString(100, y_position, f"Timestamp: {timestamp}")
        if ip:
            c.drawString(100, y_position - 20, f"IP Address: {ip}")
        if url:
            c.drawString(100, y_position - 40, f"URL: {url}")
        c.drawString(100, y_position - 60, f"Result: {result}")
        y_position -= 80  # Move down for the next entry
        
        if y_position < 100:
            c.showPage()
            y_position = 750

    c.save()
    messagebox.showinfo("Report Generated", f"Report saved as {filename}.")

# Function to create the update profile page
def create_update_profile_page(user_id):
    clear_frame()
    
    tk.Label(window, text="Update Profile", font=("Arial", 14)).pack(pady=10)

    # Fetch user data for pre-filling the fields
    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()
    c.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    current_user = c.fetchone()
    conn.close()

    # Create fields for updating the profile
    if current_user:
        tk.Label(window, text="Current Username").pack()
        tk.Label(window, text=current_user[0]).pack()  # Display current username (non-editable)

        tk.Label(window, text="New Username").pack()
        entry_new_username = tk.Entry(window)
        entry_new_username.pack()

        tk.Label(window, text="New Password").pack()
        entry_new_password = tk.Entry(window, show="*")
        entry_new_password.pack()

        # Button to update profile
        tk.Button(window, text="Update Profile", command=lambda: update_profile(user_id, entry_new_username.get(), entry_new_password.get())).pack(pady=10)
    
    tk.Button(window, text="Back to Menu", command=lambda: show_main_menu(user_id)).pack(pady=5)

# Function to update the profile in the database
def update_profile(user_id, new_username, new_password):
    if not new_username or not new_password:
        messagebox.showerror("Error", "Both username and password must be provided!")
        return

    conn = sqlite3.connect('user_data.db')
    c = conn.cursor()

    try:
        c.execute('UPDATE users SET username = ?, password = ? WHERE id = ?', (new_username, new_password, user_id))
        conn.commit()
        messagebox.showinfo("Success", "Profile updated successfully!")
        show_main_menu(user_id)  # Return to main menu after update
    except sqlite3.Error as e:
        messagebox.showerror("Error", f"Failed to update profile: {str(e)}")
    finally:
        conn.close()


# Function to create the report page where user can select the date range and what to include
def create_report_page(user_id):
    clear_frame()

    tk.Label(window, text="Generate Report", font=("Arial", 14)).pack(pady=10)

    tk.Label(window, text="Start Date (YYYY-MM-DD):").pack()
    entry_start_date = tk.Entry(window)
    entry_start_date.pack()

    tk.Label(window, text="End Date (YYYY-MM-DD):").pack()
    entry_end_date = tk.Entry(window)
    entry_end_date.pack()

    tk.Label(window, text="Include IP Addresses?").pack()
    var_ip = tk.BooleanVar(value=True)
    tk.Checkbutton(window, text="Include IP", variable=var_ip).pack()

    tk.Label(window, text="Include URLs?").pack()
    var_url = tk.BooleanVar(value=True)
    tk.Checkbutton(window, text="Include URL", variable=var_url).pack()

    tk.Button(window, text="Generate Report", 
              command=lambda: generate_pdf_report(
                  user_id,
                  entry_start_date.get(),
                  entry_end_date.get(),
                  var_ip.get(),
                  var_url.get()
              )).pack(pady=10)
    
    tk.Button(window, text="Back to Menu", command=lambda: show_main_menu(user_id)).pack(pady=5)

# Function to update the main menu page to include the "Generate Report" button
def show_main_menu(user_id):
    clear_frame()
    tk.Label(window, text="Main Menu", font=("Arial", 14)).pack(pady=10)
    
    tk.Button(window, text="Check IP Address", command=lambda: show_ip_check(user_id)).pack(pady=10)
    tk.Button(window, text="Check URL", command=lambda: show_url_check(user_id)).pack(pady=10)
    tk.Button(window, text="Update Profile", command=lambda: create_update_profile_page(user_id)).pack(pady=10)
    tk.Button(window, text="Search Checks by Date", command=lambda: create_search_checks_page(user_id)).pack(pady=10)
    tk.Button(window, text="Generate Report", command=lambda: create_report_page(user_id)).pack(pady=10)
    tk.Button(window, text="Logout", command=show_homepage).pack(pady=5)



# Main window setup
window = tk.Tk()
window.title("Data Breach Checker")
window.geometry("300x300")

# Start the application
if __name__ == "__main__":
    create_db_tables()  # Ensure database is created before app starts
    show_homepage()     # Open homepage

window.mainloop()
