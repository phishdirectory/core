# frozen_string_literal: true

Console1984.config.username_resolver = -> { ENV["USER"] || ENV["USERNAME"] || `whoami`.strip }
