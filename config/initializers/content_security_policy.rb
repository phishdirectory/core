# frozen_string_literal: true

# Content Security Policy (CSP) configuration
# Protects against XSS, clickjacking, and other injection attacks
#
# Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP

# Paths for mounted admin engines that use inline scripts/styles
# These need relaxed CSP since they don't use our nonces
CSP_RELAXED_PATHS = %w[
  /admin/flipper
  /admin/blazer
  /admin/pghero
  /admin/jobs
  /admin/console_audits
  /letter_opener
].freeze

Rails.application.configure do
  config.content_security_policy do |policy|
    # Default: only allow content from same origin
    policy.default_src :self

    # Scripts: self only (nonce required for inline, unless on relaxed path)
    policy.script_src  :self

    # Styles: self + unsafe-inline for Tailwind's dynamic styles
    policy.style_src   :self, :unsafe_inline

    # Fonts: self + data URIs for embedded fonts
    policy.font_src    :self, :data

    # Images: self + data URIs + blob for dynamic images
    policy.img_src     :self, :data, :blob, "https:"

    # Connections: self + WebSockets for live updates
    policy.connect_src :self, :wss

    # Objects (Flash, etc.): block entirely
    policy.object_src  :none

    # Frames: allow self (for admin UIs like Flipper, Blazer)
    policy.frame_src   :self

    # Prevent embedding in iframes (clickjacking protection)
    policy.frame_ancestors :self

    # Form submissions: only to same origin
    policy.form_action :self

    # Base URI: restrict base tag manipulation
    policy.base_uri    :self
  end

  # Generate nonces for inline scripts (provides XSS protection)
  # Returns nil for admin engine paths so they can use unsafe-inline fallback
  config.content_security_policy_nonce_generator = ->(request) {
    if CSP_RELAXED_PATHS.any? { |path| request.path.start_with?(path) }
      nil
    else
      request.session.id.to_s
    end
  }

  # Apply nonces to script tags only
  config.content_security_policy_nonce_directives = %w[script-src]
end

# Middleware to add unsafe-inline for admin engine paths
# These engines use inline scripts that don't have our nonces
class CspRelaxerMiddleware
  def initialize(app)
    @app = app
  end

  def call(env)
    status, headers, response = @app.call(env)

    if CSP_RELAXED_PATHS.any? { |path| env["PATH_INFO"].to_s.start_with?(path) }
      if (csp = headers["Content-Security-Policy"])
        headers["Content-Security-Policy"] = csp.gsub(
          /script-src 'self'/,
          "script-src 'self' 'unsafe-inline'"
        )
      end
    end

    [status, headers, response]
  end
end

Rails.application.config.middleware.use CspRelaxerMiddleware
