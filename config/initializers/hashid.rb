# frozen_string_literal: true

# Hashid::Rails configuration
# Generates URL-safe, obfuscated IDs for models
#
# These IDs prevent enumeration attacks and make sequential IDs non-guessable
# Example: Instead of /users/1, /users/2, /users/3
#          You get: /users/k5x8Jm, /users/nP2qW9, /users/bL4mRt

Hashid::Rails.configure do |config|
  # Salt for ID generation - MUST be unique per environment
  # Use credentials or fall back to secret_key_base
  config.salt = Rails.application.credentials.dig(:hashid, :salt) ||
                Rails.application.secret_key_base

  # Minimum length of generated IDs (default: 6)
  # Longer = more unique but less URL-friendly
  config.min_hash_length = 8

  # Custom alphabet for URL-safe IDs
  # Lowercase + numbers, excluding ambiguous characters (0, o, l, 1)
  config.alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
end
