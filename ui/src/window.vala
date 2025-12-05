using Gtk;
using Json;
using GLib;

public class SecurityModeWindow : Gtk.Window {
    private const string TMP_DIR = "/tmp/Security-Mode";

    private Gtk.ComboBoxText profile_combo;
    private Gtk.Button start_button;
    private Gtk.Button stop_button;
    private Gtk.Button status_button;
    private Gtk.Button logs_button;
    private Gtk.TextView log_view;

    public SecurityModeWindow () {
        Object (
            title: "Security Mode UI",
            default_width: 600,
            default_height: 400
        );

        var vbox = new Gtk.Box (Gtk.Orientation.VERTICAL, 10);
        add (vbox);

        // Profile selection
        var profile_label = new Gtk.Label ("Select Profile:");
        vbox.pack_start (profile_label, false, false, 0);

        profile_combo = new Gtk.ComboBoxText ();
        profile_combo.append_text ("agresywny");
        profile_combo.append_text ("bezpieczny");
        profile_combo.append_text ("monitor-only");
        profile_combo.active = 1; // Default to "bezpieczny"
        vbox.pack_start (profile_combo, false, false, 0);

        // Buttons
        var button_box = new Gtk.Box (Gtk.Orientation.HORIZONTAL, 10);
        vbox.pack_start (button_box, false, false, 0);

        start_button = new Gtk.Button.with_label ("Start");
        start_button.clicked.connect (on_start_clicked);
        button_box.pack_start (start_button, true, true, 0);

        stop_button = new Gtk.Button.with_label ("Stop");
        stop_button.clicked.connect (on_stop_clicked);
        button_box.pack_start (stop_button, true, true, 0);

        status_button = new Gtk.Button.with_label ("Status");
        status_button.clicked.connect (on_status_clicked);
        button_box.pack_start (status_button, true, true, 0);

        logs_button = new Gtk.Button.with_label ("Request Logs");
        logs_button.clicked.connect (on_logs_clicked);
        button_box.pack_start (logs_button, true, true, 0);

        // Log view
        var scrolled_window = new Gtk.ScrolledWindow (null, null);
        vbox.pack_start (scrolled_window, true, true, 0);

        log_view = new Gtk.TextView ();
        log_view.editable = false;
        scrolled_window.add (log_view);

        // Initial status
        update_status ();
    }

    private void on_start_clicked () {
        string profile = profile_combo.get_active_text ();
        if (profile != null) {
            var data = new Json.Builder ()
                .begin_object ()
                .set_member_name ("command").add_string_value ("start")
                .set_member_name ("profile").add_string_value (profile)
                .set_member_name ("timestamp").add_string_value (new DateTime.now_utc ().to_string ())
                .end_object ();

            write_json_file ("start.json", data.get_root ().get_object ());
            update_log ("Started with profile: " + profile);
        }
    }

    private void on_stop_clicked () {
        var data = new Json.Builder ()
            .begin_object ()
            .set_member_name ("command").add_string_value ("stop")
            .set_member_name ("timestamp").add_string_value (new DateTime.now_utc ().to_string ())
            .end_object ();

        write_json_file ("stop.json", data.get_root ().get_object ());
        update_log ("Stopped Security Mode");
    }

    private void on_status_clicked () {
        update_status ();
    }

    private void on_logs_clicked () {
        var data = new Json.Builder ()
            .begin_object ()
            .set_member_name ("command").add_string_value ("logs")
            .set_member_name ("timestamp").add_string_value (new DateTime.now_utc ().to_string ())
            .end_object ();

        write_json_file ("logs_request.json", data.get_root ().get_object ());
        update_log ("Logs requested. Check logs.json later.");
    }

    private void update_status () {
        var status_obj = read_json_file ("status.json");
        if (status_obj != null) {
            var status_str = "";
            foreach (var key in status_obj.get_members ()) {
                var val = status_obj.get_member (key);
                status_str += @"$key: $(val.get_string ())\n";
            }
            update_log ("Current Status:\n" + status_str);
        } else {
            update_log ("No status available.");
        }
    }

    private void update_log (string message) {
        var buffer = log_view.get_buffer ();
        buffer.insert_at_cursor (message + "\n", -1);
    }

    private void write_json_file (string filename, Json.Object data) {
        ensure_tmp_dir ();
        var path = Path.build_filename (TMP_DIR, filename);
        var generator = new Json.Generator ();
        generator.set_root (new Json.Node.alloc ().set_object (data));
        try {
            generator.to_file (path);
            stdout.printf ("Wrote JSON to %s\n", path);
        } catch (Error e) {
            stderr.printf ("Error writing JSON: %s\n", e.message);
        }
    }

    private Json.Object? read_json_file (string filename) {
        ensure_tmp_dir ();
        var path = Path.build_filename (TMP_DIR, filename);
        if (FileUtils.test (path, FileTest.EXISTS)) {
            try {
                var parser = new Json.Parser ();
                parser.load_from_file (path);
                return parser.get_root ().get_object ();
            } catch (Error e) {
                stderr.printf ("Error reading JSON: %s\n", e.message);
                return null;
            }
        }
        return null;
    }

    private void ensure_tmp_dir () {
        if (!FileUtils.test (TMP_DIR, FileTest.IS_DIR)) {
            DirUtils.create_with_parents (TMP_DIR, 0755);
        }
    }
}
