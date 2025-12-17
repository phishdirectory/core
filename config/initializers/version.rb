# frozen_string_literal: true

# Capture version info at boot time
module PhishDirectory
  VERSION = "1.0.0"
  GIT_SHA = `git rev-parse --short HEAD 2>/dev/null`.strip.presence || "dev"
  GIT_BRANCH = `git rev-parse --abbrev-ref HEAD 2>/dev/null`.strip.presence || "unknown"
end
