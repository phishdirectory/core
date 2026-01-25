# frozen_string_literal: true

# Custom resolver that checks multiple env vars
class ConsoleUsernameResolver
  include Console1984::Freezeable

  def current
    ENV["CONSOLE_USER"] || ENV["USER"] || ENV["USERNAME"] || `whoami`.strip
  end
end

Console1984.config.username_resolver = ConsoleUsernameResolver.new
