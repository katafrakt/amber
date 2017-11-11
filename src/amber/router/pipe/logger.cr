require "colorize"

module Amber
  module Pipe
    class Logger < Base
      def colorize(text, color)
        text.colorize(color).toggle(Amber::Server.settings.color).to_s
      end

      def initialize(io : IO = STDOUT)
        @io = io
      end

      def call(context : HTTP::Server::Context)
        time = Time.now
        call_next(context)
        status = context.response.status_code
        elapsed = elapsed_text(Time.now - time)
        @io.puts "#{http_status(status)} | #{method(context)} #{path(context)} | #{elapsed}"
        @io.puts "Params: #{colorize(filtered_params_hash(context.params), :yellow)}"
        context
      end

      def method(context)
        colorize(context.request.method, :light_red) + " "
      end

      def path(context)
        "\"" + colorize(context.request.path.to_s, :yellow) + "\" "
      end

      def http_status(status)
        case status
        when 200
          text = colorize("200 ", :green)
        when 404
          text = colorize("404 ", :red)
        end
        "#{text}"
      end

      private def filtered_params_hash(params)
        params_hash = params.to_h
        Amber::Server.settings.filter_parameters.each do |param|
          params.keys.each { |k| params_hash[k] = "[FILTERED]" if params_hash[k].includes?(param) }
        end
        params_hash
      end

      private def elapsed_text(elapsed)
        millis = elapsed.total_milliseconds
        return "#{millis.round(2)}ms" if millis >= 1
        "#{(millis * 1000).round(2)}µs"
      end
    end
  end
end
