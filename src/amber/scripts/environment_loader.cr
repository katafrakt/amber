require "yaml"
require "secure_random"
require "../support/message_encryptor"

class EnvironmentParser
  property env_path : String? = ["./config/environments", "./spec/support/config"].find { |p| File.exists?(p) }
  property settings_regex = /#{env_path.to_s.gsub("/", "\/")}\/\.?(\w+)\.(?:enc|yml)/
  property secret_key : String? = ENV["AMBER_SECRET_KEY"]? || begin
    File.open(".amber_secret_key").gets_to_end.to_s if File.exists?(".amber_secret_key")
  end

  private def file_to_yaml(env_file : String)
    if (env_file).includes?(".yml")
      File.read(env_file)
    elsif env_file.includes?(".enc") && secret_key
      enc = Amber::Support::MessageEncryptor.new(secret_key.not_nil!)
      String.new(enc.decrypt(File.open(env_file).gets_to_end.to_slice))
    else
      "env: #{env_from_filename(env_file)}"
    end
  end

  private def env_from_filename(env_file : String)
    env_file.match(settings_regex).try(&.[1])
  end

  private def add_fetch_helper(env_files, s)
    s.puts "class Amber::Settings"
    s.puts "  def self.fetch(env : String | Symbol)"
    s.puts "    case env"
    env_files.each do |env_file|
      environment = env_file.match(settings_regex).try(&.[1])
      s.puts %(    when "#{environment}")
      s.puts "      #{environment}"
    end
    if ENV["AMBER_ENV"]?
      s.puts "    else"
      s.puts "      #{ENV["AMBER_ENV"]?}"
    end
    s.puts "    end"
    s.puts "  end"
    s.puts "end"
  end

  def build_settings
    env_files = Dir.glob("#{env_path}/{.*.enc,*.yml}")
    puts env_files
    puts env_path
    str = String.build do |s|
      add_fetch_helper(env_files, s)
      env_files.each do |env_file|
        settings = YAML.parse(file_to_yaml(env_file))
        environment = env_file.match(settings_regex).try(&.[1]).not_nil!
        s.puts <<-SETTINGS
        class Amber::Settings
          self.def #{environment}
            @@#{environment} ||= #{environment.capitalize}.new
          end
        end

        class Amber::Settings::#{environment.capitalize} < Amber::Settings"
          @name = "#{settings["name"]? || "Amber_App"}"
          @port_reuse = #{settings["port_reuse"]? == nil ? true : settings["port_reuse"]}
          @process_count = #{settings["process_count"]? || 1}
          @log = #{settings["log"]? || "::Logger.new(STDOUT)"}.tap{|l| l.level = #{settings["log_level"]? || "::Logger::INFO"}}
          @color = #{settings["color"]? == nil ? true : settings["color"]}
          @redis_url = "#{settings["redis_url"]? || "redis://localhost:6379"}"
          @port = #{settings["port"]? || 3000}
          @host = "#{settings["host"]? || "127.0.0.1"}"
          @secret_key_base = "#{settings["secret_key_base"]? || SecureRandom.urlsafe_base64(32)}"
        SETTINGS
        # TODO: move to private methods
        unless settings["ssl_key_file"]?.to_s.empty?
          s.puts %(  @ssl_key_file = "#{settings["ssl_key_file"]?}")
        end

        unless settings["ssl_cert_file"]?.to_s.empty?
          s.puts %(  @ssl_cert_file = "#{settings["ssl_cert_file"]?}")
        end

        if settings["session"]? && settings["session"].raw.is_a?(Hash(YAML::Type, YAML::Type))
          s.puts <<-SESSION
            @session = {
              :key => "#{settings["session"]["key"]? ? settings["session"]["key"] : "amber.session"}",
              :store => #{settings["session"]["store"]? ? settings["session"]["store"] : ":signed_cookie"},
              :expires => #{settings["session"]["expires"]? ? settings["session"]["expires"] : 0}, 
            }
          SESSION
        else
          s.puts %(  @session = {:key => "amber.session", :store => :signed_cookie, :expires => 0})
        end

        if settings["secrets"]? && settings["secrets"].raw.is_a?(Hash(YAML::Type, YAML::Type))
          s.puts "  getter secrets = #{settings["secrets"].inspect.gsub(/(\"[^\"]+\") \=\>/) { "#{$1}:" }}"
        else
          s.puts %(  getter secrets = {description: "Store your #{environment} secrets credentials and settings here."})
        end
        s.puts "end" 
      end
    end
  end
end

puts EnvironmentParser.new.build_settings
