import logging
import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import hashlib
import tkinter as tk
from tkinter import filedialog, ttk, scrolledtext
from datetime import datetime
import pwd
import grp
import stat

#GUI to monitor everything (5)
class FileMonitorEventHandler(FileSystemEventHandler):
    def __init__(self, gui):
        super().__init__()
        self.gui = gui
        self.file_hashes = {}
       
    ###access ownership info to store in log (1)   
    def get_file_info(self, path):
        try:
            stat_info = os.stat(path)
            owner_name = pwd.getpwuid(stat_info.st_uid).pw_name
            owner_group = grp.getgrgid(stat_info.st_gid).gr_name
            current_uid = os.geteuid()
            current_gid = os.getegid()
            perms = oct(stat_info.st_mode)[-4:]
            permissions = f"{perms}"
            return f"Owner: {owner_name}:{owner_group} | Permissions: {permissions}"
        except Exception as e:
            return f"Isn't accessible: {str(e)}"

    def log_event(self, event_type, path):
        file_info = "File no longer exists" if event_type == "deleted" else self.get_file_info(path)
        log_msg = f"File {event_type}: {path} | {file_info}"
        logging.info(log_msg)
        self.gui.update_log(log_msg)

##Calculate file hash to include alert features in activity log (4)
    def calculate_file_hash(self, path):
        if os.path.exists(path) and os.path.isfile(path):
            try:
                with open(path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                self.file_hashes[path] = file_hash  
                return file_hash
            except Exception as e:
                self.gui.update_log(f"ERROR - Can't calculate hash for {path}: {str(e)}")
        return None

    def check_integrity(self, path):
        if path in self.file_hashes and os.path.exists(path) and os.path.isfile(path):
            old_hash = self.file_hashes[path]
            new_hash = self.calculate_file_hash(path)
            if new_hash and old_hash != new_hash:
                alert_message = f"INTEGRITY ALERT - File CONTENT modified: {path}"
                logging.warning(alert_message)
                self.gui.update_log(alert_message)
                self.file_hashes[path] = new_hash
##distringuish event type between created, modified, and deleted
    def on_modified(self, event):
        if event.is_directory:
            return
        self.log_event("modified", event.src_path)
        self.check_integrity(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.log_event("created", event.src_path)
            self.calculate_file_hash(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.log_event("deleted", event.src_path)
            self.file_hashes.pop(event.src_path, None)

class FileMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Monitor")
        self.root.geometry("1000x700")
        
        ##log modifications in GUI AND in externaml log for later analysis (1)
        logging.basicConfig(
            filename='file_monitor.log',
            level=logging.INFO,
            format='%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        self.monitored_dirs = []
        self.event_handler = FileMonitorEventHandler(self)
        self.observer = Observer()
        
        self.create_gui()
        
        self.observer.start()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_gui(self):
        
        monitor_frame = ttk.LabelFrame(self.root, text="Monitoring Controls", padding=5)
        monitor_frame.pack(fill=tk.X, padx=5, pady=5)
        
        #feature to add file path and remove (multiple allowed) (2)
        ttk.Button(monitor_frame, text="Add directory", command=self.add_directory).pack(side=tk.LEFT, padx=5)
        ttk.Button(monitor_frame, text="Remove directory", command=self.remove_directory).pack(side=tk.LEFT, padx=5)
        
        self.dir_list = tk.Listbox(monitor_frame, height=3)
        self.dir_list.pack(fill=tk.X, padx=5, pady=5)
        
        #access permissions (1)
        permissions_frame = ttk.LabelFrame(self.root, text="Set Permissions", padding=5)
        permissions_frame.pack(fill=tk.X, padx=5, pady=5)
        
        path_frame = ttk.Frame(permissions_frame)
        path_frame.pack(fill=tk.X, padx=5, pady=5)
        
        #allow permissions to be set for files and directories (3)
        ttk.Label(path_frame, text="File/Directory Path:").pack(side=tk.LEFT, padx=5)
        self.path_entry = ttk.Entry(path_frame, width=50)
        self.path_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(path_frame, text="Browse File", command=self.browse_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(path_frame, text="Browse Directory", command=self.browse_directory).pack(side=tk.LEFT, padx=5)
        
        perm_controls = ttk.Frame(permissions_frame)
        perm_controls.pack(fill=tk.X, padx=5, pady=5)
        
        #standard and special permissions can be selected (3)
        self.permissions = {}
        for user_type in ['User', 'Group', 'Other']:
            user_frame = ttk.LabelFrame(perm_controls, text=user_type)
            user_frame.pack(side=tk.LEFT, padx=10, pady=5, fill=tk.X, expand=True)
            
            self.permissions[user_type] = {
                'read': tk.BooleanVar(),
                'write': tk.BooleanVar(),
                'execute': tk.BooleanVar()
            }
            
            ttk.Checkbutton(user_frame, text="Read", variable=self.permissions[user_type]['read']).pack(anchor=tk.W)
            ttk.Checkbutton(user_frame, text="Write", variable=self.permissions[user_type]['write']).pack(anchor=tk.W)
            ttk.Checkbutton(user_frame, text="Execute", variable=self.permissions[user_type]['execute']).pack(anchor=tk.W)

        special_frame = ttk.LabelFrame(perm_controls, text="Special")
        special_frame.pack(side=tk.LEFT, padx=10, pady=5, fill=tk.X, expand=True)
        
        self.special_permissions = {
            'sticky_bit': tk.BooleanVar(),
            'setuid': tk.BooleanVar(),
            'setgid': tk.BooleanVar()
        }
        
        ttk.Checkbutton(special_frame, text="Sticky Bit", variable=self.special_permissions['sticky_bit']).pack(anchor=tk.W)
        ttk.Checkbutton(special_frame, text="SUID", variable=self.special_permissions['setuid']).pack(anchor=tk.W)
        ttk.Checkbutton(special_frame, text="SGID", variable=self.special_permissions['setgid']).pack(anchor=tk.W)
        
        ttk.Button(permissions_frame, text="Set permissions", command=self.set_permissions).pack(pady=5)
        
        #Log section (1)
        log_frame = ttk.LabelFrame(self.root, text="Log", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def calculate_permissions(self):
        mode = 0
        
        if self.special_permissions['sticky_bit'].get():
            mode |= stat.S_ISVTX
        if self.special_permissions['setuid'].get():
            mode |= stat.S_ISUID
        if self.special_permissions['setgid'].get():
            mode |= stat.S_ISGID
            
        if self.permissions['User']['read'].get():
            mode |= stat.S_IRUSR
        if self.permissions['User']['write'].get():
            mode |= stat.S_IWUSR
        if self.permissions['User']['execute'].get():
            mode |= stat.S_IXUSR

        if self.permissions['Group']['read'].get():
            mode |= stat.S_IRGRP
        if self.permissions['Group']['write'].get():
            mode |= stat.S_IWGRP
        if self.permissions['Group']['execute'].get():
            mode |= stat.S_IXGRP

        if self.permissions['Other']['read'].get():
            mode |= stat.S_IROTH
        if self.permissions['Other']['write'].get():
            mode |= stat.S_IWOTH
        if self.permissions['Other']['execute'].get():
            mode |= stat.S_IXOTH
            
        return mode
#log if a permission is changed (1)
    def set_permissions(self):
        path = self.path_entry.get()
        try:
            mode = self.calculate_permissions()
            os.chmod(path, mode)
            self.update_log(f"Permissions updated for {path}")
        except Exception as e:
            self.update_log(f"CANNOT SET PERMISSION FOR {path}: {str(e)}")


#notify system admin which direcories are being monitored & store in log
    def add_directory(self):
        path = filedialog.askdirectory()
        if path and path not in self.monitored_dirs:
            self.observer.schedule(self.event_handler, path, recursive=True)
            self.monitored_dirs.append(path)
            self.dir_list.insert(tk.END, path)
            self.update_log(f"Started monitoring directory: {path}")
            for root, _, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    self.event_handler.calculate_file_hash(file_path)

    def remove_directory(self):
        selection = self.dir_list.curselection()
        if selection:
            path = self.monitored_dirs[selection[0]]
            self.observer.unschedule_all()
            self.monitored_dirs.remove(path)
            self.dir_list.delete(selection)
            for dir in self.monitored_dirs:
                self.observer.schedule(self.event_handler, dir, recursive=True)
            self.update_log(f"Stopped monitoring directory: {path}")

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, path)

    def browse_directory(self):
        path = filedialog.askdirectory()
        if path:
            self.path_entry.delete(0, tk.END)
            self.path_entry.insert(0, path)

    def update_log(self, message):
        self.log_text.configure(state='normal')
        self.log_text.insert(tk.END, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | {message}\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state='disabled')

    def on_closing(self):
        self.observer.stop()
        self.observer.join()
        self.root.destroy()

if __name__ == '__main__':
    root = tk.Tk()
    app = FileMonitorGUI(root)
    root.mainloop()