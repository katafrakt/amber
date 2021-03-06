require "http"
require "logger"
require "json"
require "colorize"
require "secure_random"
require "kilt"
require "kilt/slang"
require "redis"
require "./amber/version"
require "./amber/controller/**"
require "./amber/dsl/**"
require "./amber/exceptions/**"
require "./amber/extensions/**"
require "./amber/router/**"
require "./amber/server/**"
require "./amber/validations/**"
require "./amber/websockets/**"

module Amber
  class Server
    include Amber::DSL::Server
    include Amber::Configuration
    alias WebSocketAdapter = WebSockets::Adapters::RedisAdapter.class | WebSockets::Adapters::MemoryAdapter.class
    property pubsub_adapter : WebSocketAdapter = WebSockets::Adapters::MemoryAdapter
    getter handler = Pipe::Pipeline.new
    getter router = Router::Router.new

    def initialize
      settings.log.level = ::Logger::INFO
    end

    def project_name
      @project_name ||= settings.name.gsub(/\W/, "_").downcase
    end

    def run
      thread_count = settings.process_count
      if Cluster.master? && thread_count > 1
        while (thread_count > 0)
          Cluster.fork ({"id" => thread_count.to_s})
          thread_count -= 1
        end
        sleep
      else
        start
      end
    end

    def start
      time = Time.now
      settings.log.info "#{version} serving application \"#{settings.name}\" at #{host_url}".to_s
      handler.prepare_pipelines
      server = HTTP::Server.new(settings.host, settings.port, handler)
      server.tls = Amber::SSL.new(settings.ssl_key_file.not_nil!, settings.ssl_cert_file.not_nil!).generate_tls if ssl_enabled?

      Signal::INT.trap do
        settings.log.info "Shutting down Amber"
        server.close
        exit
      end

      settings.log.info "Server started in #{colorize(Amber.env, :yellow)}."
      settings.log.info colorize("Startup Time #{Time.now - time}\n\n", :white)
      server.listen(settings.port_reuse)
    end

    private def version
      colorize("[Amber #{Amber::VERSION}]", :light_cyan)
    end

    private def host_url
      colorize("#{scheme}://#{settings.host}:#{settings.port}", :light_cyan, :underline)
    end

    private def ssl_enabled?
      settings.ssl_key_file && settings.ssl_cert_file
    end

    private def scheme
      ssl_enabled? ? "https" : "http"
    end

    def colorize(text, color)
      text.colorize(color).toggle(settings.color).to_s
    end

    def colorize(text, color, mode)
      text.colorize(color).toggle(settings.color).mode(mode).to_s
    end
  end
end
