import gi
gi.require_version('Gtk', '4.0')
from gi.repository import Gtk, Gio, GLib
import subprocess
import sys
import os
import json
from threading import Thread

class SecurityGUI(Gtk.Application):
    def __init__(self):
        super().__init__(application_id='org.hackeros.security')
        self.session_mode = '--session' in sys.argv
        self.connect('activate', self.on_activate)

    def on_activate(self, app):
        self.window = Gtk.Window(application=app)
        self.window.set_title('HackerOS Security Mode')
        self.window.set_default_size(800, 600)

        if self.session_mode:
            self.window.fullscreen()
            self.window.set_decorated(False)  # Remove window decorations for session-like mode

        notebook = Gtk.Notebook()
        self.window.set_child(notebook)

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

        self.window.present()

    def create_pentest_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)

        label = Gtk.Label(label='Pentest Tools')
        box.append(label)

        self.pentest_args_entry = Gtk.Entry()
        self.pentest_args_entry.set_placeholder_text('Enter pentest arguments')
        box.append(self.pentest_args_entry)

        run_button = Gtk.Button(label='Run Pentest')
        run_button.connect('clicked', self.on_run_pentest)
        box.append(run_button)

        self.pentest_output = Gtk.TextView()
        self.pentest_output.set_editable(False)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_child(self.pentest_output)
        scrolled.set_vexpand(True)
        box.append(scrolled)

        return box

    def on_run_pentest(self, button):
        args = self.pentest_args_entry.get_text().split()
        Thread(target=self.run_command, args=('security', ['pentest'] + args, self.pentest_output)).start()

    def create_analysis_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)

        label = Gtk.Label(label='Malware / Windows Binary Analysis')
        box.append(label)

        file_label = Gtk.Label(label='File:')
        box.append(file_label)
        self.analysis_file_entry = Gtk.Entry()
        self.analysis_file_entry.set_placeholder_text('Path to file')
        box.append(self.analysis_file_entry)

        type_label = Gtk.Label(label='Type (malware/windows):')
        box.append(type_label)
        self.analysis_type_entry = Gtk.Entry()
        self.analysis_type_entry.set_placeholder_text('malware or windows')
        box.append(self.analysis_type_entry)

        env_label = Gtk.Label(label='Environment:')
        box.append(env_label)
        self.analysis_env_entry = Gtk.Entry()
        self.analysis_env_entry.set_placeholder_text('default')
        box.append(self.analysis_env_entry)

        self.behavioral_check = Gtk.CheckButton(label='Behavioral Analysis')
        box.append(self.behavioral_check)

        run_button = Gtk.Button(label='Run Analysis')
        run_button.connect('clicked', self.on_run_analysis)
        box.append(run_button)

        self.analysis_output = Gtk.TextView()
        self.analysis_output.set_editable(False)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_child(self.analysis_output)
        scrolled.set_vexpand(True)
        box.append(scrolled)

        return box

    def on_run_analysis(self, button):
        file = self.analysis_file_entry.get_text()
        type_ = self.analysis_type_entry.get_text()
        env = self.analysis_env_entry.get_text()
        behavioral = self.behavioral_check.get_active()

        args = ['analyze', '--file', file, '--type', type_, '--env', env]
        if behavioral:
            args.append('--behavioral')

        Thread(target=self.run_command, args=('security', args, self.analysis_output)).start()

    def create_report_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)

        label = Gtk.Label(label='Generate Report')
        box.append(label)

        type_label = Gtk.Label(label='Type (json/pdf):')
        box.append(type_label)
        self.report_type_entry = Gtk.Entry()
        self.report_type_entry.set_placeholder_text('json or pdf')
        box.append(self.report_type_entry)

        data_label = Gtk.Label(label='Data:')
        box.append(data_label)
        self.report_data_entry = Gtk.Entry()
        self.report_data_entry.set_placeholder_text('Report data')
        box.append(self.report_data_entry)

        gen_button = Gtk.Button(label='Generate Report')
        gen_button.connect('clicked', self.on_generate_report)
        box.append(gen_button)

        self.report_output = Gtk.TextView()
        self.report_output.set_editable(False)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_child(self.report_output)
        scrolled.set_vexpand(True)
        box.append(scrolled)

        return box

    def on_generate_report(self, button):
        type_ = self.report_type_entry.get_text()
        data = self.report_data_entry.get_text()
        args = ['report', type_, data]
        Thread(target=self.run_command, args=('security', args, self.report_output)).start()

    def create_edu_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)

        label = Gtk.Label(label='Educational Mode')
        box.append(label)

        sample_label = Gtk.Label(label='Sample Number:')
        box.append(sample_label)
        self.edu_sample_entry = Gtk.Entry()
        self.edu_sample_entry.set_placeholder_text('e.g., 1')
        box.append(self.edu_sample_entry)

        run_button = Gtk.Button(label='Run Educational Analysis')
        run_button.connect('clicked', self.on_run_edu)
        box.append(run_button)

        self.edu_output = Gtk.TextView()
        self.edu_output.set_editable(False)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_child(self.edu_output)
        scrolled.set_vexpand(True)
        box.append(scrolled)

        return box

    def on_run_edu(self, button):
        sample = self.edu_sample_entry.get_text()
        args = ['edu', sample]
        Thread(target=self.run_command, args=('security', args, self.edu_output)).start()

    def create_env_page(self):
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)

        label = Gtk.Label(label='Environment Management')
        box.append(label)

        subcmd_label = Gtk.Label(label='Subcommand (create/run):')
        box.append(subcmd_label)
        self.env_subcmd_entry = Gtk.Entry()
        self.env_subcmd_entry.set_placeholder_text('create or run')
        box.append(self.env_subcmd_entry)

        args_label = Gtk.Label(label='Arguments:')
        box.append(args_label)
        self.env_args_entry = Gtk.Entry()
        self.env_args_entry.set_placeholder_text('e.g., env_name [command args]')
        box.append(self.env_args_entry)

        run_button = Gtk.Button(label='Execute Env Command')
        run_button.connect('clicked', self.on_run_env)
        box.append(run_button)

        self.env_output = Gtk.TextView()
        self.env_output.set_editable(False)
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_child(self.env_output)
        scrolled.set_vexpand(True)
        box.append(scrolled)

        return box

    def on_run_env(self, button):
        subcmd = self.env_subcmd_entry.get_text()
        args = self.env_args_entry.get_text().split()
        cmd_args = ['env', subcmd] + args
        Thread(target=self.run_command, args=('security', cmd_args, self.env_output)).start()

    def run_command(self, cli, args, output_view):
        try:
            process = subprocess.Popen([cli] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            GLib.idle_add(self.update_output, output_view, stdout + '\n' + stderr)
        except Exception as e:
            GLib.idle_add(self.update_output, output_view, str(e))

    def update_output(self, view, text):
        buffer = view.get_buffer()
        buffer.insert(buffer.get_end_iter(), text + '\n')
        return False

if __name__ == '__main__':
    app = SecurityGUI()
    app.run(sys.argv)
