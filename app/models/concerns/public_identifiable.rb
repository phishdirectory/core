# frozen_string_literal: true

# PublicIdentifiable: Provides prefixed public IDs for UUID-based models
#
# Generates API-friendly IDs like "usr_4k8xJm2pN9qW" instead of raw UUIDs.
# This improves API ergonomics and makes IDs easier to identify by type.
#
# Since UUIDs are already non-sequential and random, this concern focuses on:
# 1. Adding a type prefix for easy identification
# 2. Shortening the ID for better URL/API ergonomics
# 3. Maintaining bi-directional conversion (public_id <-> UUID)
#
# Usage:
#   class User < ApplicationRecord
#     include PublicIdentifiable
#     set_public_id_prefix "usr"
#   end
#
# Then:
#   user.public_id          # => "usr_4k8xJm2pN9qW"
#   User.find_by_public_id("usr_4k8xJm2pN9qW")  # => User instance
#   User.find_by_public_id!("usr_invalid")      # => raises RecordNotFound

module PublicIdentifiable
  extend ActiveSupport::Concern

  SEPARATOR = "_"

  # Base62 alphabet for compact, URL-safe encoding
  BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

  included do
    class_attribute :public_id_prefix, default: nil
  end

  # Returns the full public ID with prefix
  # Example: "usr_4k8xJm2pN9qW"
  def public_id
    prefix = self.class.get_public_id_prefix
    encoded = self.class.encode_uuid(id)
    "#{prefix}#{SEPARATOR}#{encoded}"
  end

  # Override to_param so Rails uses public_id in URLs
  # This makes link_to, redirect_to, etc. use public_id automatically
  def to_param
    public_id
  end

  # Alias for Rails conventions
  alias_method :to_public_param, :public_id

  class_methods do
    # Set the prefix for this model's public IDs
    # @param prefix [String] Short prefix (3-4 chars recommended)
    def set_public_id_prefix(prefix)
      self.public_id_prefix = prefix.to_s.freeze
    end

    # Get the configured prefix, with validation
    def get_public_id_prefix
      raise "Public ID prefix not set for #{name}. Call set_public_id_prefix in your model." if public_id_prefix.blank?
      public_id_prefix
    end

    # Find a record by its public ID
    # @param public_id [String] The full public ID (e.g., "usr_4k8xJm2pN9qW")
    # @return [ActiveRecord::Base, nil] The found record or nil
    def find_by_public_id(public_id)
      return nil if public_id.blank?

      prefix = get_public_id_prefix
      return nil unless public_id.to_s.start_with?("#{prefix}#{SEPARATOR}")

      encoded = public_id.to_s.sub("#{prefix}#{SEPARATOR}", "")
      uuid = decode_to_uuid(encoded)
      return nil unless uuid

      find_by(id: uuid)
    end

    # Find a record by its public ID, raising RecordNotFound if not found
    # @param public_id [String] The full public ID
    # @return [ActiveRecord::Base] The found record
    # @raise [ActiveRecord::RecordNotFound] If no record found
    def find_by_public_id!(public_id)
      find_by_public_id(public_id) || raise(ActiveRecord::RecordNotFound, "Couldn't find #{name} with public_id=#{public_id}")
    end

    # Check if a string looks like a valid public ID for this model
    def valid_public_id?(public_id)
      return false if public_id.blank?
      public_id.to_s.start_with?("#{get_public_id_prefix}#{SEPARATOR}")
    end

    # Encode a UUID to a shorter base62 string
    # @param uuid [String] The UUID to encode
    # @return [String] Base62 encoded string (~22 chars)
    def encode_uuid(uuid)
      return nil if uuid.blank?

      # Remove hyphens and convert to integer
      hex = uuid.to_s.delete("-")
      num = hex.to_i(16)

      # Convert to base62
      return "0" if num.zero?

      result = ""
      while num > 0
        result = BASE62_ALPHABET[num % 62] + result
        num /= 62
      end

      result
    end

    # Decode a base62 string back to UUID format
    # @param encoded [String] The base62 encoded string
    # @return [String, nil] The UUID or nil if invalid
    def decode_to_uuid(encoded)
      return nil if encoded.blank?

      # Convert from base62 to integer
      num = 0
      encoded.each_char do |char|
        index = BASE62_ALPHABET.index(char)
        return nil if index.nil? # Invalid character
        num = num * 62 + index
      end

      # Convert to hex and format as UUID
      hex = num.to_s(16).rjust(32, "0")
      return nil if hex.length > 32 # Overflow protection

      # Format as UUID: 8-4-4-4-12
      "#{hex[0..7]}-#{hex[8..11]}-#{hex[12..15]}-#{hex[16..19]}-#{hex[20..31]}"
    rescue StandardError
      nil
    end
  end
end
