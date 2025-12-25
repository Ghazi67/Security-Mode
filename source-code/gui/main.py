import gi
gi.require_version('Gtk', '4.0')
from gi.repository import Gtk, Gio, GLib
import subprocess
import sys
import os
import json
from threading import Thread, Lock
import queue
import yaml
import time
import random  # for mock

class Task:
    def __init__(self, id, command, args, output_view):
        self.id = id
        self.command = command
        self.args = args
        self.status = 'pending'
        self.output_view = output_view
        self.process = None
        self.output = ''
        self.start_time = None
        self.end_time = None

class SecurityGUI(Gtk.Application):
    def __init__(self):
        super().__init__(application_id='org.hackeros.security')
        self.session_mode = '--session' in sys.argv
        self.connect('activate', self.on_activate)
        self.task_queue = queue.Queue()
        self.tasks = []
        self.task_lock = Lock()
        self.task_id_counter = 0
        self.task_manager_thread = Thread(target=self.task_manager)
        self.task_manager_thread.daemon = True
        self.task_manager_thread.start()
        self.policy_engine_path = os.path.expanduser('~/.hackeros/Security-Mode/policy-engine')

    def on_activate(self, app):
        self.window = Gtk.Window(application=app)
        self.window.set_title('HackerOS Security Mode')
        self.window.set_default_size(1000, 800)
        if self.session_mode:
            self.window.fullscreen()
            self.window.set_decorated(False)
        notebook = Gtk.Notebook()
        self.window.set_child(notebook)

        # Dashboard Tab
        dashboard_page = self.create_dashboard_page()
        notebook.append_page(dashboard_page, Gtk.Label(label='Dashboard'))

        # Policy Tab
        policy_page = self.create_policy_page()
        notebook.append_page(policy_page, Gtk.Label(label='Policy'))

        # Pentest Tab
        pentest_page = self.create_pentest_page()
        notebook.append_page(pentest_page, Gtk.Label(label='Pentest'))

        # Analysis Tab
        analysis_page = self.create_analysis_page()
        notebook.append_page(analysis_page, Gtk.Label(label='Analysis'))

        # Report Tab
        report_page = self.create_report_page()
        notebook.append_page(report_page, Gtk.Label(label='Report'))

        # Education Tab
        edu_page = self.create_edu_page()
        notebook.append_page(edu_page, Gtk.Label(label='Education'))

        # Env Management Tab
        env_page = self.create_env_page()
        notebook.append_page(env_page, Gtk.Label(label='Env Management'))

        # Timeline Tab
        timeline_page = self.create_timeline_page()
        notebook.append_page(timeline_page, Gtk.Label(label='Timeline'))

        self.window.present()

    def create_dashboard_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)
        label = Gtk.Label(label='Dashboard')
        box.append(label)

        # Active Tasks
        tasks_label = Gtk.Label(label='Active Tasks')
        box.append(tasks_label)
        self.dashboard_tasks_list = Gtk.ListBox()
        scrolled_tasks = Gtk.ScrolledWindow()
        scrolled_tasks.set_child(self.dashboard_tasks_list)
        scrolled_tasks.set_vexpand(True)
        box.append(scrolled_tasks)

        # Alerts
        alerts_label = Gtk.Label(label='Alerts')
        box.append(alerts_label)
        self.alerts_text = Gtk.TextView()
        self.alerts_text.set_editable(False)
        scrolled_alerts = Gtk.ScrolledWindow()
        scrolled_alerts.set_child(self.alerts_text)
        scrolled_alerts.set_vexpand(True)
        box.append(scrolled_alerts)

        # System Status
        status_label = Gtk.Label(label='System Status')
        box.append(status_label)
        self.status_text = Gtk.TextView()
        self.status_text.set_editable(False)
        scrolled_status = Gtk.ScrolledWindow()
        scrolled_status.set_child(self.status_text)
        scrolled_status.set_vexpand(True)
        box.append(scrolled_status)

        # Refresh button
        refresh_button = Gtk.Button(label='Refresh')
        refresh_button.connect('clicked', self.on_refresh_dashboard)
        box.append(refresh_button)

        return box

    def on_refresh_dashboard(self, button):
        self.update_dashboard()

    def update_dashboard(self):
        # Update tasks list
        self.dashboard_tasks_list.foreach(lambda child: self.dashboard_tasks_list.remove(child))
        with self.task_lock:
            for task in self.tasks:
                if task.status in ['pending', 'running']:
                    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
                    label = Gtk.Label(label=f'Task {task.id}: {task.command} - {task.status}')
                    row.append(label)
                    kill_button = Gtk.Button(label='Kill')
                    kill_button.connect('clicked', lambda b, t=task: self.kill_task(t))
                    row.append(kill_button)
                    self.dashboard_tasks_list.append(row)

        # Update alerts and status (mock for now)
        buffer = self.alerts_text.get_buffer()
        buffer.set_text('No alerts')
        buffer = self.status_text.get_buffer()
        buffer.set_text('System nominal')

    def create_policy_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)
        label = Gtk.Label(label='Policy Management')
        box.append(label)

        # Policy file entry
        policy_file_label = Gtk.Label(label='Policy File:')
        box.append(policy_file_label)
        self.policy_file_entry = Gtk.Entry()
        self.policy_file_entry.set_placeholder_text('~/.hackeros/Security-Mode/policy-security/pentest.yaml')
        box.append(self.policy_file_entry)

        # Load button
        load_button = Gtk.Button(label='Load Policy')
        load_button.connect('clicked', self.on_load_policy)
        box.append(load_button)

        # Policy editor
        self.policy_editor = Gtk.TextView()
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_child(self.policy_editor)
        scrolled.set_vexpand(True)
        box.append(scrolled)

        # Validate button
        validate_button = Gtk.Button(label='Validate Policy')
        validate_button.connect('clicked', self.on_validate_policy)
        box.append(validate_button)

        # Save button
        save_button = Gtk.Button(label='Save Policy')
        save_button.connect('clicked', self.on_save_policy)
        box.append(save_button)

        # Output
        self.policy_output = Gtk.TextView()
        self.policy_output.set_editable(False)
        scrolled_output = Gtk.ScrolledWindow()
        scrolled_output.set_child(self.policy_output)
        scrolled_output.set_vexpand(True)
        box.append(scrolled_output)

        return box

    def on_load_policy(self, button):
        file_path = os.path.expanduser(self.policy_file_entry.get_text())
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                content = f.read()
            buffer = self.policy_editor.get_buffer()
            buffer.set_text(content)
            self.update_policy_output('Policy loaded.')
        else:
            self.update_policy_output('File not found.')

    def on_save_policy(self, button):
        file_path = os.path.expanduser(self.policy_file_entry.get_text())
        buffer = self.policy_editor.get_buffer()
        start, end = buffer.get_bounds()
        content = buffer.get_text(start, end, True)
        with open(file_path, 'w') as f:
            f.write(content)
        self.update_policy_output('Policy saved.')

    def on_validate_policy(self, button):
        file_path = os.path.expanduser(self.policy_file_entry.get_text())
        try:
            result = subprocess.run([self.policy_engine_path, 'validate', file_path], capture_output=True, text=True)
            if result.returncode == 0:
                self.update_policy_output('Validation successful: ' + result.stdout)
            else:
                self.update_policy_output('Validation failed: ' + result.stderr)
        except Exception as e:
            self.update_policy_output(str(e))

    def update_policy_output(self, text):
        buffer = self.policy_output.get_buffer()
        buffer.insert(buffer.get_end_iter(), text + '\n')

    def create_pentest_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)
        label = Gtk.Label(label='Pentest Tools')
        box.append(label)

        # Target
        target_label = Gtk.Label(label='Target (IP/URL/Hostname):')
        box.append(target_label)
        self.pentest_target_entry = Gtk.Entry()
        box.append(self.pentest_target_entry)

        # Type
        type_label = Gtk.Label(label='Type:')
        box.append(type_label)
        self.pentest_type_combo = Gtk.ComboBoxText()
        self.pentest_type_combo.append_text('scan_port')
        self.pentest_type_combo.append_text('scan_vuln')
        self.pentest_type_combo.append_text('recon_dns')
        self.pentest_type_combo.append_text('recon_headers')
        self.pentest_type_combo.append_text('recon_tls')
        self.pentest_type_combo.append_text('recon_robots')
        self.pentest_type_combo.append_text('recon_fingerprint')
        self.pentest_type_combo.append_text('web_sql')
        self.pentest_type_combo.append_text('web_xss')
        self.pentest_type_combo.append_text('web_crawl')
        self.pentest_type_combo.append_text('web_param_discovery')
        self.pentest_type_combo.append_text('web_reflected')
        self.pentest_type_combo.append_text('web_csp_cors')
        self.pentest_type_combo.append_text('web_auth_headers')
        self.pentest_type_combo.set_active(0)
        box.append(self.pentest_type_combo)

        # Additional args
        args_label = Gtk.Label(label='Additional Arguments:')
        box.append(args_label)
        self.pentest_args_entry = Gtk.Entry()
        self.pentest_args_entry.set_placeholder_text('--ports 1-1024 for scan, etc.')
        box.append(self.pentest_args_entry)

        # Run button
        run_button = Gtk.Button(label='Queue Pentest Task')
        run_button.connect('clicked', self.on_queue_pentest)
        box.append(run_button)

        # Output
        self.pentest_output = Gtk.TextView()
        self.pentest_output.set_editable(False)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_child(self.pentest_output)
        scrolled.set_vexpand(True)
        box.append(scrolled)

        return box

    def on_queue_pentest(self, button):
        target = self.pentest_target_entry.get_text()
        type_ = self.pentest_type_combo.get_active_text()
        args = self.pentest_args_entry.get_text().split()
        cmd_args = ['pentest', type_, '--target', target] + args
        self.queue_task('security', cmd_args, self.pentest_output)

    def create_analysis_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)
        label = Gtk.Label(label='Analysis Tools')
        box.append(label)

        # File
        file_label = Gtk.Label(label='File Path:')
        box.append(file_label)
        self.analysis_file_entry = Gtk.Entry()
        box.append(self.analysis_file_entry)

        # Type
        type_label = Gtk.Label(label='Type (malware/windows/static/behavioral):')
        box.append(type_label)
        self.analysis_type_entry = Gtk.Entry()
        self.analysis_type_entry.set_placeholder_text('malware or windows or static')
        box.append(self.analysis_type_entry)

        # Env
        env_label = Gtk.Label(label='Environment:')
        box.append(env_label)
        self.analysis_env_entry = Gtk.Entry()
        self.analysis_env_entry.set_placeholder_text('default')
        box.append(self.analysis_env_entry)

        # Options
        self.analysis_behavioral_check = Gtk.CheckButton(label='Behavioral Analysis')
        box.append(self.analysis_behavioral_check)
        self.analysis_static_check = Gtk.CheckButton(label='Static Analysis')
        box.append(self.analysis_static_check)

        # Run button
        run_button = Gtk.Button(label='Queue Analysis Task')
        run_button.connect('clicked', self.on_queue_analysis)
        box.append(run_button)

        # Output
        self.analysis_output = Gtk.TextView()
        self.analysis_output.set_editable(False)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_child(self.analysis_output)
        scrolled.set_vexpand(True)
        box.append(scrolled)

        return box

    def on_queue_analysis(self, button):
        file = self.analysis_file_entry.get_text()
        type_ = self.analysis_type_entry.get_text()
        env = self.analysis_env_entry.get_text()
        args = ['analyze', '--file', file, '--type', type_, '--env', env]
        if self.analysis_behavioral_check.get_active():
            args.append('--behavioral')
        if self.analysis_static_check.get_active():
            args.append('--static')
        self.queue_task('security', args, self.analysis_output)

    def create_report_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)
        label = Gtk.Label(label='Generate Report')
        box.append(label)

        # Type
        type_label = Gtk.Label(label='Type (json/pdf):')
        box.append(type_label)
        self.report_type_entry = Gtk.Entry()
        self.report_type_entry.set_placeholder_text('json or pdf')
        box.append(self.report_type_entry)

        # Data
        data_label = Gtk.Label(label='Data (JSON):')
        box.append(data_label)
        self.report_data_entry = Gtk.TextView()
        scrolled_data = Gtk.ScrolledWindow()
        scrolled_data.set_child(self.report_data_entry)
        box.append(scrolled_data)

        # Gen button
        gen_button = Gtk.Button(label='Generate Report')
        gen_button.connect('clicked', self.on_generate_report)
        box.append(gen_button)

        # Output
        self.report_output = Gtk.TextView()
        self.report_output.set_editable(False)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_child(self.report_output)
        scrolled.set_vexpand(True)
        box.append(scrolled)

        return box

    def on_generate_report(self, button):
        type_ = self.report_type_entry.get_text()
        buffer = self.report_data_entry.get_buffer()
        start, end = buffer.get_bounds()
        data = buffer.get_text(start, end, True)
        args = ['report', '--type', type_, '--data', data]
        self.queue_task('security', args, self.report_output)

    def create_edu_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)
        label = Gtk.Label(label='Educational Mode')
        box.append(label)

        # Lab selection
        lab_label = Gtk.Label(label='Select Lab:')
        box.append(lab_label)
        self.edu_lab_combo = Gtk.ComboBoxText()
        self.edu_lab_combo.append_text('Find XSS')
        self.edu_lab_combo.append_text('Identify Malware')
        self.edu_lab_combo.append_text('DNS Recon')
        self.edu_lab_combo.set_active(0)
        box.append(self.edu_lab_combo)

        # Run button
        run_button = Gtk.Button(label='Start Lab')
        run_button.connect('clicked', self.on_start_edu_lab)
        box.append(run_button)

        # Checklist and hints
        checklist_label = Gtk.Label(label='Checklist:')
        box.append(checklist_label)
        self.edu_checklist = Gtk.TextView()
        self.edu_checklist.set_editable(False)
        scrolled_check = Gtk.ScrolledWindow()
        scrolled_check.set_child(self.edu_checklist)
        box.append(scrolled_check)

        hints_label = Gtk.Label(label='Hints:')
        box.append(hints_label)
        self.edu_hints = Gtk.TextView()
        self.edu_hints.set_editable(False)
        scrolled_hints = Gtk.ScrolledWindow()
        scrolled_hints.set_child(self.edu_hints)
        box.append(scrolled_hints)

        # Output
        self.edu_output = Gtk.TextView()
        self.edu_output.set_editable(False)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_child(self.edu_output)
        scrolled.set_vexpand(True)
        box.append(scrolled)

        return box

    def on_start_edu_lab(self, button):
        lab = self.edu_lab_combo.get_active_text()
        args = ['edu', '--lab', lab]
        self.queue_task('security', args, self.edu_output)
        # Mock checklist and hints
        buffer = self.edu_checklist.get_buffer()
        buffer.set_text('1. Step one\n2. Step two')
        buffer = self.edu_hints.get_buffer()
        buffer.set_text('Hint: Use tool X')

    def create_env_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)
        label = Gtk.Label(label='Environment Management')
        box.append(label)

        # Subcommand
        subcmd_label = Gtk.Label(label='Subcommand (create/run):')
        box.append(subcmd_label)
        self.env_subcmd_entry = Gtk.Entry()
        self.env_subcmd_entry.set_placeholder_text('create or run')
        box.append(self.env_subcmd_entry)

        # Args
        args_label = Gtk.Label(label='Arguments:')
        box.append(args_label)
        self.env_args_entry = Gtk.Entry()
        self.env_args_entry.set_placeholder_text('env_name [command args]')
        box.append(self.env_args_entry)

        # Advanced options
        cgroups_check = Gtk.CheckButton(label='Apply Cgroups Limits')
        box.append(cgroups_check)
        seccomp_check = Gtk.CheckButton(label='Apply Seccomp Profile')
        box.append(seccomp_check)

        # Run button
        run_button = Gtk.Button(label='Queue Env Command')
        run_button.connect('clicked', lambda b: self.on_queue_env(cgroups_check, seccomp_check))
        box.append(run_button)

        # Output
        self.env_output = Gtk.TextView()
        self.env_output.set_editable(False)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_child(self.env_output)
        scrolled.set_vexpand(True)
        box.append(scrolled)

        return box

    def on_queue_env(self, cgroups_check, seccomp_check):
        subcmd = self.env_subcmd_entry.get_text()
        args = self.env_args_entry.get_text().split()
        cmd_args = ['env', subcmd] + args
        if cgroups_check.get_active():
            cmd_args.append('--cgroups')
        if seccomp_check.get_active():
            cmd_args.append('--seccomp')
        self.queue_task('security', cmd_args, self.env_output)

    def create_timeline_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)
        label = Gtk.Label(label='Timeline / History')
        box.append(label)

        self.timeline_list = Gtk.ListBox()
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_child(self.timeline_list)
        scrolled.set_vexpand(True)
        box.append(scrolled)

        refresh_button = Gtk.Button(label='Refresh')
        refresh_button.connect('clicked', self.on_refresh_timeline)
        box.append(refresh_button)

        return box

    def on_refresh_timeline(self, button):
        self.timeline_list.foreach(lambda child: self.timeline_list.remove(child))
        with self.task_lock:
            for task in reversed(self.tasks):
                if task.status == 'finished' or task.status == 'killed':
                    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
                    duration = (task.end_time - task.start_time) if task.end_time and task.start_time else 0
                    label = Gtk.Label(label=f'Task {task.id}: {task.command} - {task.status} - Duration: {duration}s')
                    row.append(label)
                    view_button = Gtk.Button(label='View Output')
                    view_button.connect('clicked', lambda b, t=task: self.show_task_output(t))
                    row.append(view_button)
                    self.timeline_list.append(row)

    def show_task_output(self, task):
        dialog = Gtk.Dialog(transient_for=self.window, title=f'Task {task.id} Output')
        dialog.add_button('Close', Gtk.ResponseType.CLOSE)
        text_view = Gtk.TextView()
        text_view.set_editable(False)
        buffer = text_view.get_buffer()
        buffer.set_text(task.output)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_child(text_view)
        scrolled.set_size_request(600, 400)
        content_area = dialog.get_content_area()
        content_area.append(scrolled)
        dialog.show()

    def queue_task(self, cli, args, output_view):
        with self.task_lock:
            task_id = self.task_id_counter
            self.task_id_counter += 1
            task = Task(task_id, ' '.join([cli] + args), args, output_view)
            self.tasks.append(task)
            self.task_queue.put(task)
            self.update_output(output_view, f'Task {task_id} queued.\n')
        self.update_dashboard()

    def task_manager(self):
        while True:
            task = self.task_queue.get()
            with self.task_lock:
                task.status = 'running'
                task.start_time = time.time()
            self.update_dashboard()
            try:
                # Check policy before running
                policy_file = os.path.expanduser('~/.hackeros/Security-Mode/policy-security/default.yaml')  # mock
                tool = args[0] if args else ''
                check_tool = subprocess.run([self.policy_engine_path, 'check-tool', policy_file, tool], capture_output=True, text=True)
                if check_tool.returncode != 0:
                    raise Exception('Tool not allowed by policy')
                # TODO: check network, etc.

                process = subprocess.Popen([cli] + task.args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                task.process = process
                stdout, stderr = process.communicate()
                output = stdout + '\n' + stderr
                task.output = output
                GLib.idle_add(self.update_output, task.output_view, output)
            except Exception as e:
                output = str(e)
                task.output = output
                GLib.idle_add(self.update_output, task.output_view, output)
            finally:
                with self.task_lock:
                    task.status = 'finished' if task.status != 'killed' else 'killed'
                    task.end_time = time.time()
                    task.process = None
                GLib.idle_add(self.update_dashboard)
            self.task_queue.task_done()

    def kill_task(self, task):
        with self.task_lock:
            if task.process and task.status == 'running':
                task.process.kill()
                task.status = 'killed'
                task.end_time = time.time()
                self.update_output(task.output_view, '\nTask killed.')
        self.update_dashboard()

    def update_output(self, view, text):
        buffer = view.get_buffer()
        buffer.insert(buffer.get_end_iter(), text + '\n')
        return False

    def run_command(self, cli, args, output_view):
        # Deprecated, use queue
        pass

if __name__ == '__main__':
    app = SecurityGUI()
    app.run(sys.argv)
