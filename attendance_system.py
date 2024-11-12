import tkinter as tk
from tkinter import messagebox, ttk
from tkcalendar import DateEntry
import sqlite3
import hashlib
from datetime import datetime

# -----------------------------#
#       Database Setup          #
# -----------------------------#

# Initialize and connect to SQLite database
conn = sqlite3.connect('attendance_system.db')
c = conn.cursor()

# Create Users table
c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )
''')

# Create Students table
c.execute('''
    CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL
    )
''')

# Create Attendance table
c.execute('''
    CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id TEXT NOT NULL,
        date TEXT NOT NULL,
        status TEXT NOT NULL,
        FOREIGN KEY(student_id) REFERENCES students(student_id)
    )
''')

conn.commit()

# -----------------------------#
#       Utility Functions      #
# -----------------------------#

def hash_password(password):
    """
    Hashes a password using SHA-256 algorithm.
    """
    return hashlib.sha256(password.encode()).hexdigest()

def add_user(username, password, role):
    """
    Adds a new user to the Users table.
    """
    try:
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  (username, hash_password(password), role))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def verify_user(username, password):
    """
    Verifies user credentials.
    Returns the role if successful, else None.
    """
    c.execute("SELECT password, role FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    if result and result[0] == hash_password(password):
        return result[1]  # Return role
    return None

def add_student(student_id, name):
    """
    Adds a new student to the Students table.
    """
    try:
        c.execute("INSERT INTO students (student_id, name) VALUES (?, ?)", (student_id, name))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def get_all_students():
    """
    Retrieves all students from the Students table.
    """
    c.execute("SELECT student_id, name FROM students")
    return c.fetchall()

def record_attendance(student_id, status):
    """
    Records attendance for a student on the current date.
    If an attendance record for today exists, it updates the status.
    Otherwise, it creates a new record.
    """
    date_str = datetime.now().strftime("%Y-%m-%d")
    c.execute("SELECT * FROM attendance WHERE student_id = ? AND date = ?", (student_id, date_str))
    if c.fetchone():
        # Update existing record
        c.execute("UPDATE attendance SET status = ? WHERE student_id = ? AND date = ?", (status, student_id, date_str))
    else:
        # Insert new record
        c.execute("INSERT INTO attendance (student_id, date, status) VALUES (?, ?, ?)", (student_id, date_str, status))
    conn.commit()

def get_attendance_reports():
    """
    Generates attendance reports for all students.
    """
    c.execute('''
        SELECT students.student_id, students.name, COUNT(attendance.status) as total_classes,
        SUM(CASE WHEN attendance.status = 'Present' THEN 1 ELSE 0 END) as present_count
        FROM students
        LEFT JOIN attendance ON students.student_id = attendance.student_id
        GROUP BY students.student_id
    ''')
    return c.fetchall()

def get_attendance_reports_date_range(from_date, to_date):
    """
    Generates attendance reports for all students within a specific date range.
    """
    c.execute('''
        SELECT students.student_id, students.name, COUNT(attendance.status) as total_classes,
        SUM(CASE WHEN attendance.status = 'Present' THEN 1 ELSE 0 END) as present_count
        FROM students
        LEFT JOIN attendance ON students.student_id = attendance.student_id
            AND attendance.date BETWEEN ? AND ?
        GROUP BY students.student_id
    ''', (from_date, to_date))
    return c.fetchall()

# -----------------------------#
#     Initial User Setup       #
# -----------------------------#

def setup_default_user():
    """
    Sets up a default instructor account if no users exist.
    """
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        # Add default instructor
        success = add_user("admin", "admin123", "Instructor")
        if success:
            print("Default instructor account created.\nUsername: admin\nPassword: admin123")
        else:
            print("Failed to create default user.")

setup_default_user()

# -----------------------------#
#     Authentication Module    #
# -----------------------------#

class LoginWindow:
    def __init__(self, master):
        self.master = master
        master.title("Attendance System - Login")
        master.geometry("400x350")  # Increased size for better layout
        master.resizable(False, False)
        master.configure(bg='#6c757d')  # Background color

        # Apply a theme
        style = ttk.Style()
        style.theme_use('clam')  # You can choose other themes like 'alt', 'default', 'classic'

        # Heading
        heading = tk.Label(master, text="Login", font=('Helvetica', 18, 'bold'), bg='#6c757d', fg='white')
        heading.pack(pady=20)

        # Username Label and Entry
        self.label_username = tk.Label(master, text="Username", font=('Helvetica', 12), bg='#6c757d', fg='white')
        self.label_username.pack(pady=10)

        self.entry_username = tk.Entry(master, width=30, font=('Helvetica', 12))
        self.entry_username.pack(pady=5)

        # Password Label and Entry
        self.label_password = tk.Label(master, text="Password", font=('Helvetica', 12), bg='#6c757d', fg='white')
        self.label_password.pack(pady=10)

        self.entry_password = tk.Entry(master, show="*", width=30, font=('Helvetica', 12))
        self.entry_password.pack(pady=5)

        # Login Button
        self.login_button = tk.Button(master, text="Login", width=15, bg='#007bff', fg='white', font=('Helvetica', 12, 'bold'), command=self.login)
        self.login_button.pack(pady=20)

    def login(self):
        """
        Handles user login.
        """
        username = self.entry_username.get()
        password = self.entry_password.get()
        role = verify_user(username, password)
        if role:
            self.master.destroy()
            if role == "Instructor":
                root = tk.Tk()
                InstructorDashboard(root)
                root.mainloop()
            # Future implementation: Student interface
        else:
            messagebox.showerror("Error", "Invalid credentials")

# -----------------------------#
#    Instructor Dashboard      #
# -----------------------------#

class InstructorDashboard:
    def __init__(self, master):
        self.master = master
        master.title("Instructor Dashboard")
        master.geometry("800x600")  # Increased size for better layout
        master.resizable(False, False)
        master.configure(bg='#f8f9fa')  # Light background color

        # Apply a theme
        style = ttk.Style()
        style.theme_use('clam')  # You can choose other themes like 'alt', 'default', 'classic'

        # Create Notebook for Tabs
        self.tab_control = ttk.Notebook(master)

        # Create Tabs using tk.Frame instead of ttk.Frame to allow bg configuration
        self.tab_register = tk.Frame(self.tab_control, bg='#4a7abc')
        self.tab_record = tk.Frame(self.tab_control, bg='#f0f8ff')
        self.tab_reports = tk.Frame(self.tab_control, bg='#fffaf0')

        self.tab_control.add(self.tab_register, text='Register Students')
        self.tab_control.add(self.tab_record, text='Record Attendance')
        self.tab_control.add(self.tab_reports, text='View Reports')

        self.tab_control.pack(expand=1, fill='both')

        # Initialize Tabs
        self.create_register_tab()
        self.create_record_tab()
        self.create_reports_tab()

    # -----------------------------#
    #      Register Students Tab   #
    # -----------------------------#

    def create_register_tab(self):
        frame = self.tab_register

        # Heading
        heading = tk.Label(frame, text="Register New Student", font=('Helvetica', 16, 'bold'), bg='#4a7abc', fg='white')
        heading.grid(row=0, column=0, columnspan=2, pady=10, sticky='nsew')

        # Student ID
        label_student_id = tk.Label(frame, text="Student ID", font=('Helvetica', 12), bg='#4a7abc', fg='white')
        label_student_id.grid(row=1, column=0, padx=20, pady=10, sticky='e')
        self.entry_student_id = tk.Entry(frame, width=30, font=('Helvetica', 12))
        self.entry_student_id.grid(row=1, column=1, padx=20, pady=10)

        # Student Name
        label_name = tk.Label(frame, text="Name", font=('Helvetica', 12), bg='#4a7abc', fg='white')
        label_name.grid(row=2, column=0, padx=20, pady=10, sticky='e')
        self.entry_name = tk.Entry(frame, width=30, font=('Helvetica', 12))
        self.entry_name.grid(row=2, column=1, padx=20, pady=10)

        # Add Student Button
        self.button_add_student = tk.Button(frame, text="Add Student", width=15, bg='#28a745', fg='white', font=('Helvetica', 12, 'bold'), command=self.add_student)
        self.button_add_student.grid(row=3, column=0, columnspan=2, pady=20)

    def add_student(self):
        """
        Adds a new student to the database.
        """
        student_id = self.entry_student_id.get().strip()
        name = self.entry_name.get().strip()
        if student_id and name:
            success = add_student(student_id, name)
            if success:
                messagebox.showinfo("Success", "Student registered successfully.")
                self.entry_student_id.delete(0, tk.END)
                self.entry_name.delete(0, tk.END)
                self.load_students()
            else:
                messagebox.showerror("Error", "Student ID already exists.")
        else:
            messagebox.showerror("Error", "Please enter both Student ID and Name.")

    # -----------------------------#
    #     Record Attendance Tab    #
    # -----------------------------#

    def create_record_tab(self):
        frame = self.tab_record

        # Heading
        heading = tk.Label(frame, text="Record Attendance", font=('Helvetica', 16, 'bold'), bg='#f0f8ff', fg='#333333')
        heading.pack(pady=10)

        # Current Date Label
        current_date = datetime.now().strftime("%Y-%m-%d")
        label_date = tk.Label(frame, text=f"Date: {current_date}", font=('Helvetica', 14, 'bold'), bg='#f0f8ff', fg='#333333')
        label_date.pack(pady=10)

        # Treeview for displaying students
        self.tree = ttk.Treeview(frame, columns=("ID", "Name", "Status"), show='headings', height=15)
        self.tree.heading("ID", text="Student ID")
        self.tree.heading("Name", text="Name")
        self.tree.heading("Status", text="Status")

        self.tree.column("ID", width=200, anchor='center')
        self.tree.column("Name", width=300, anchor='w')
        self.tree.column("Status", width=150, anchor='center')

        self.tree.pack(pady=20, padx=20, fill='x')

        # Scrollbar for Treeview
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side='right', fill='y')

        # Load Students into Treeview
        self.load_students()

        # Buttons Frame
        buttons_frame = tk.Frame(frame, bg='#f0f8ff')
        buttons_frame.pack(pady=20)

        # Mark Present Button
        self.button_mark_present = tk.Button(buttons_frame, text="Mark Present", width=15, bg='#28a745', fg='white', font=('Helvetica', 12, 'bold'), command=lambda: self.mark_attendance("Present"))
        self.button_mark_present.grid(row=0, column=0, padx=20)

        # Mark Absent Button
        self.button_mark_absent = tk.Button(buttons_frame, text="Mark Absent", width=15, bg='#dc3545', fg='white', font=('Helvetica', 12, 'bold'), command=lambda: self.mark_attendance("Absent"))
        self.button_mark_absent.grid(row=0, column=1, padx=20)

    def load_students(self):
        """
        Loads all registered students into the Treeview.
        """
        for row in self.tree.get_children():
            self.tree.delete(row)
        students = get_all_students()
        for student in students:
            # Check today's attendance status
            date_str = datetime.now().strftime("%Y-%m-%d")
            c.execute("SELECT status FROM attendance WHERE student_id = ? AND date = ?", (student[0], date_str))
            result = c.fetchone()
            status = result[0] if result else "Absent"
            self.tree.insert("", tk.END, values=(student[0], student[1], status))

    def mark_attendance(self, status):
        """
        Marks attendance for selected students.
        """
        selected_items = self.tree.selection()
        if not selected_items:
            messagebox.showerror("Error", "No student selected.")
            return
        for item in selected_items:
            student_id = self.tree.item(item)['values'][0]
            record_attendance(student_id, status)
            self.tree.set(item, "Status", status)
        messagebox.showinfo("Success", f"Marked selected students as {status}.")

    # -----------------------------#
    #      View Reports Tab        #
    # -----------------------------#

    def create_reports_tab(self):
        frame = self.tab_reports
        frame.configure(bg='#fffaf0')  # Light background color

        # Heading
        heading = tk.Label(frame, text="Attendance Reports", font=('Helvetica', 16, 'bold'), bg='#fffaf0', fg='#333333')
        heading.pack(pady=10)

        # Date Range Selection
        date_frame = tk.Frame(frame, bg='#fffaf0')
        date_frame.pack(pady=10)

        # From Date
        label_from = tk.Label(date_frame, text="From Date:", font=('Helvetica', 12), bg='#fffaf0', fg='#333333')
        label_from.grid(row=0, column=0, padx=10, pady=5, sticky='e')
        self.from_date_entry = DateEntry(date_frame, width=12, background='darkblue',
                                         foreground='white', borderwidth=2, date_pattern='yyyy-mm-dd', font=('Helvetica', 12))
        self.from_date_entry.grid(row=0, column=1, padx=10, pady=5)

        # To Date
        label_to = tk.Label(date_frame, text="To Date:", font=('Helvetica', 12), bg='#fffaf0', fg='#333333')
        label_to.grid(row=0, column=2, padx=10, pady=5, sticky='e')
        self.to_date_entry = DateEntry(date_frame, width=12, background='darkblue',
                                       foreground='white', borderwidth=2, date_pattern='yyyy-mm-dd', font=('Helvetica', 12))
        self.to_date_entry.grid(row=0, column=3, padx=10, pady=5)

        # Generate Report Button
        self.button_generate_report = tk.Button(frame, text="Generate Report", width=15, bg='#007bff', fg='white', font=('Helvetica', 12, 'bold'), command=self.generate_report)
        self.button_generate_report.pack(pady=10)

        # Text Widget to Display Report
        self.report_text = tk.Text(frame, width=90, height=20, wrap='none', bg='#f8f9fa', fg='#212529', font=('Courier', 10))
        self.report_text.pack(pady=10, padx=20)

        # Scrollbars for Text Widget
        scrollbar_y = ttk.Scrollbar(frame, orient="vertical", command=self.report_text.yview)
        scrollbar_y.pack(side='right', fill='y')
        self.report_text.configure(yscrollcommand=scrollbar_y.set)

        scrollbar_x = ttk.Scrollbar(frame, orient="horizontal", command=self.report_text.xview)
        scrollbar_x.pack(side='bottom', fill='x')
        self.report_text.configure(xscrollcommand=scrollbar_x.set)

    def generate_report(self):
        """
        Generates and displays the attendance report based on the selected date range.
        """
        from_date = self.from_date_entry.get()
        to_date = self.to_date_entry.get()

        try:
            # Validate date format
            datetime.strptime(from_date, "%Y-%m-%d")
            datetime.strptime(to_date, "%Y-%m-%d")
        except ValueError:
            messagebox.showerror("Error", "Invalid date format. Please use YYYY-MM-DD.")
            return

        # Ensure from_date is not after to_date
        if from_date > to_date:
            messagebox.showerror("Error", "From Date cannot be after To Date.")
            return

        reports = get_attendance_reports_date_range(from_date, to_date)
        self.report_text.delete(1.0, tk.END)
        report_str = f"Attendance Report from {from_date} to {to_date}:\n\n"
        report_str += f"{'Student ID':<15}{'Name':<30}{'Total Classes':<15}{'Present':<10}{'Attendance %':<15}\n"
        report_str += "-"*85 + "\n"
        for report in reports:
            student_id, name, total, present = report
            total = total if total else 0
            present = present if present else 0
            attendance_pct = (present / total * 100) if total > 0 else 0
            report_str += f"{student_id:<15}{name:<30}{total:<15}{present:<10}{attendance_pct:<15.2f}\n"
        self.report_text.insert(tk.END, report_str)

# -----------------------------#
#      Main Application        #
# -----------------------------#

def main():
    root = tk.Tk()
    app = LoginWindow(root)
    root.mainloop()

if __name__ == "__main__":
    main()
