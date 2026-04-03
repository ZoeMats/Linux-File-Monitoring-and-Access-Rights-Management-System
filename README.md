#  File Monitoring & Access Rights Management System

This project is a **File Monitoring and Access Rights Management System** developed in **Python** and designed to run on **Linux (Ubuntu)**.

It provides real-time monitoring of file system activity, along with tools for managing file permissions and detecting integrity violations. The system includes a graphical user interface (GUI) for ease of use and an external logging mechanism for auditing.

---

## Features

### File Monitoring

* Tracks file **creation, modification, and deletion**
* Real-time updates displayed in the GUI
* Logs all activity to an external log file

### Access Rights Management

* Modify standard permissions:

  * Read (r)
  * Write (w)
  * Execute (x)
* Supports special permissions:

  * Sticky Bit
  * SetUID
  * SetGID
* User-friendly GUI for permission selection (no need to input octal manually)

### Data Integrity Protection

* Uses **SHA256 hashing** to detect file modifications
* Generates **integrity alerts** when file content changes
* Alerts are logged as warnings for easy identification

### Graphical User Interface

* Built with **Tkinter**
* Add/remove directories to monitor
* View logs in real-time
* Manage permissions through tab-based controls

### Logging System

* Dual logging:

  * GUI log display
  * External log file (`file_monitor.log`)
* Ensures activity history is محفوظ even after closing the application

---

## Technologies Used

* Python 3
* Tkinter (GUI)
* Watchdog (file monitoring)
* OS, stat, pwd, grp (system-level operations)
* hashlib (SHA256 hashing)
* logging, datetime (logging system)

---

## Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/ZoeMats/secure-communication-project.git
cd secure-communication-project
```

### 2. Install dependencies

```bash
pip install watchdog
```

### 3. Run the application

```bash
python main.py
```

---

## How It Works

1. Launch the application → GUI opens
2. Add directories to monitor
3. System tracks:

   * File creation
   * File deletion
   * File modifications
4. Modify file permissions via GUI
5. Integrity alerts triggered when file hashes change
6. Logs stored both in GUI and external file

---

## Security Notes

* Access to logs is restricted using Linux file permissions
* No authentication system implemented yet (planned improvement)

---

## Example Use Cases

* Monitor sensitive directories for unauthorized changes
* Enforce access control policies
* Detect tampering via hash comparison
* Audit file activity over time

---

## Limitations

* No user authentication system
* GUI design is basic (Tkinter limitations)

---

## Future Improvements

* Add **user authentication system**
* Improve GUI using **PyQt**
* Enhance logging and alerting features

---

## 📄 License

This project is for educational purposes.
