# frozen_string_literal: true

# Lockbox configuration for field-level encryption
# Documentation: https://github.com/ankane/lockbox

Lockbox.master_key = Rails.application.credentials.dig(:lockbox, :master_key) ||
                     ENV["LOCKBOX_MASTER_KEY"] ||
                     (raise "Missing Lockbox master key! Set credentials.lockbox.master_key or LOCKBOX_MASTER_KEY env var")

# Enable key rotation support
# Lockbox.default_options = { previous_versions: [{ master_key: ENV["LOCKBOX_MASTER_KEY_PREVIOUS"] }] }
