require "json"
require "file_utils"
require "process"
# Define the temporary directory for JSON communication
TMP_DIR = "/tmp/Security-Mode"
# Ensure the tmp directory exists
def ensure_tmp_dir
  FileUtils.mkdir_p(TMP_DIR) unless Dir.exists?(TMP_DIR)
end
# Write a JSON file to the tmp directory
def write_json_file(filename : String, data : Hash(String, JSON::Any))
  ensure_tmp_dir
  path = File.join(TMP_DIR, filename)
  File.write(path, data.to_json)
  puts "Wrote JSON to #{path}"
rescue ex
  puts "Error writing JSON: #{ex.message}"
end
# Read a JSON file from the tmp directory
def read_json_file(filename : String) : Hash(String, JSON::Any)?
  ensure_tmp_dir
  path = File.join(TMP_DIR, filename)
  if File.exists?(path)
    json_str = File.read(path)
    JSON.parse(json_str).as_h
  else
    nil
  end
rescue ex
  puts "Error reading JSON: #{ex.message}"
  nil
end
# Launch the UI binary
def launch_ui
  ui_path = File.expand_path("~/.hackeros/Security-Mode/bin/ui")
  if File.exists?(ui_path) && LibC.access(ui_path.to_unsafe, LibC::X_OK) == 0
    # Launch using cage or gamescope, as per description. Assuming cage for simplicity.
    # You may need to adjust based on installed tools.
    Process.run("cage", args: [ui_path], output: STDOUT, error: STDERR)
  else
    puts "UI binary not found or not executable: #{ui_path}"
  end
end
# Handle 'start' command: start a profile
def handle_start(profile : String)
  valid_profiles = ["agresywny", "bezpieczny", "monitor-only"]
  if valid_profiles.includes?(profile)
    data = {
      "command" => JSON::Any.new("start"),
      "profile" => JSON::Any.new(profile),
      "timestamp" => JSON::Any.new(Time.utc.to_s),
    }
    write_json_file("start.json", data)
  else
    puts "Invalid profile: #{profile}. Valid: #{valid_profiles.join(", ")}"
  end
end
# Handle 'stop' command
def handle_stop
  data = {
    "command" => JSON::Any.new("stop"),
    "timestamp" => JSON::Any.new(Time.utc.to_s),
  }
  write_json_file("stop.json", data)
end
# Handle 'status' command: read status from JSON
def handle_status
  status_data = read_json_file("status.json")
  if status_data
    puts "Current Status:"
    status_data.each do |key, value|
      puts "#{key}: #{value}"
    end
  else
    puts "No status available."
  end
end
# Handle 'logs' command: request logs
def handle_logs
  data = {
    "command" => JSON::Any.new("logs"),
    "timestamp" => JSON::Any.new(Time.utc.to_s),
  }
  write_json_file("logs_request.json", data)
  puts "Logs requested. Check logs.json later."
end
# Main CLI parser
def main
  if ARGV.empty?
    puts "Usage: security <command> [args]"
    puts "Commands:"
    puts " ui - Launch the UI"
    puts " start <profile> - Start Security Mode with profile (agresywny, bezpieczny, monitor-only)"
    puts " stop - Stop Security Mode"
    puts " status - Get current status"
    puts " logs - Request logs"
    exit(1)
  end
  command = ARGV[0].downcase
  case command
  when "ui"
    launch_ui
  when "start"
    if ARGV.size > 1
      handle_start(ARGV[1])
    else
      puts "Missing profile for start command."
    end
  when "stop"
    handle_stop
  when "status"
    handle_status
  when "logs"
    handle_logs
  else
    puts "Unknown command: #{command}"
  end
end
main if __FILE__ == Process.executable_path
