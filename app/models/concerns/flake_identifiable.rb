# frozen_string_literal: true

# FlakeIdentifiable: Generates case-insensitive IDs for email ticketing systems
#
# Based on Phish Report's approach: https://phish.report/blog/flake-ids-and-insensitive-ticketing-systems
# Uses base36 encoding (digits + lowercase only) to ensure IDs survive
# case-insensitive email systems that might lowercase the address.
#
# Usage:
#   class Report::Case < ApplicationRecord
#     include FlakeIdentifiable
#     set_flake_prefix "case"
#     set_flake_column :case_number
#   end
#
# Then:
#   case.case_number  # => "case_chqrg05u4agw"
#   Report::Case.find_by_flake_id("case_chqrg05u4agw")
#
module FlakeIdentifiable
  extend ActiveSupport::Concern

  SEPARATOR = "_"
  BASE36_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"

  included do
    class_attribute :flake_prefix, default: nil
    class_attribute :flake_column, default: :flake_id

    before_validation :generate_flake_id, on: :create
  end

  class_methods do
    # Set the prefix for flake IDs (e.g., "case")
    def set_flake_prefix(prefix)
      self.flake_prefix = prefix.to_s.downcase.freeze
    end

    # Set which column stores the flake ID
    def set_flake_column(column)
      self.flake_column = column.to_sym
    end

    # Get the configured prefix
    def get_flake_prefix
      raise "Flake prefix not set for #{name}. Call set_flake_prefix in your model." if flake_prefix.blank?
      flake_prefix
    end

    # Find a record by its flake ID (case-insensitive)
    def find_by_flake_id(flake_id)
      return nil if flake_id.blank?

      # Normalize to lowercase for comparison
      normalized = flake_id.to_s.downcase
      prefix = get_flake_prefix

      return nil unless normalized.start_with?("#{prefix}#{SEPARATOR}")

      # Use Arel to safely reference the column (avoids SQL injection warning)
      column = arel_table[flake_column]
      where(column.lower.eq(normalized)).first
    end

    # Find a record by flake ID, raising if not found
    def find_by_flake_id!(flake_id)
      find_by_flake_id(flake_id) || raise(ActiveRecord::RecordNotFound, "Couldn't find #{name} with #{flake_column}=#{flake_id}")
    end

    # Generate a new flake ID
    def generate_flake_id_value
      prefix = get_flake_prefix

      # Timestamp component (seconds since epoch, base36)
      # This provides rough time-ordering
      timestamp_part = Time.current.to_i.to_s(36)

      # Random component for uniqueness (8 chars of base36)
      random_hex = SecureRandom.hex(8)
      random_part = random_hex.to_i(16).to_s(36)[0, 8]

      "#{prefix}#{SEPARATOR}#{timestamp_part}#{random_part}"
    end
  end

  private

  def generate_flake_id
    return if self[self.class.flake_column].present?

    self[self.class.flake_column] = self.class.generate_flake_id_value
  end
end
