# frozen_string_literal: true

require "csv"

module Report
  # Service for importing abuse contacts from CSV
  # Handles duplicates by smart merging (updates existing records, preserves non-null values)
  class AbuseContactImporter
    attr_reader :file_path, :logger, :stats

    # Map CSV types to our enum values
    TYPE_MAPPING = {
      "Registrar" => "registrar",
      "Hosting Service" => "hosting",
      "Link Shortener" => "other", # Treat as "other" for now
      "Other" => "other",
      "" => "other"
    }.freeze

    # Map CSV methods to our enum values
    METHOD_MAPPING = {
      "Email" => "email",
      "Contact Form" => "web_form",
      "MULTIPLE" => "email", # Default to email when multiple
      "Unknown" => "email",  # Default to email
      "Other" => "email",    # Default to email
      "" => "email"
    }.freeze

    def initialize(file_path_or_io, logger: Rails.logger)
      @file_path = file_path_or_io
      @logger = logger
      @stats = { created: 0, updated: 0, skipped: 0, errors: [] }
    end

    def import!
      csv_data = read_csv

      log_info("Starting import of #{csv_data.length} contacts")

      csv_data.each_with_index do |row, index|
        import_row(row, index + 2) # +2 for header row and 1-based line numbers
      end

      log_info("Import complete: #{stats[:created]} created, #{stats[:updated]} updated, #{stats[:skipped]} skipped, #{stats[:errors].length} errors")

      stats
    end

    private

    def read_csv
      if file_path.respond_to?(:read)
        CSV.parse(file_path.read, headers: true)
      else
        CSV.read(file_path, headers: true)
      end
    end

    def import_row(row, line_number)
      name = row["Name"]&.strip

      if name.blank?
        log_debug("Skipping row #{line_number}: empty name")
        stats[:skipped] += 1
        return
      end

      # Find existing contact by name (case-insensitive)
      existing = Report::AbuseContact.with_discarded.find_by("LOWER(name) = ?", name.downcase)

      if existing
        update_contact(existing, row, line_number)
      else
        create_contact(row, line_number)
      end
    rescue StandardError => e
      log_error("Error importing row #{line_number}", e)
      stats[:errors] << { line: line_number, name: row["Name"], error: e.message }
    end

    def create_contact(row, line_number)
      attrs = build_attributes(row)

      contact = Report::AbuseContact.create!(attrs)

      log_info("Created contact: #{contact.name} (line #{line_number})")
      stats[:created] += 1
    end

    def update_contact(existing, row, line_number)
      attrs = build_attributes(row)

      # Smart merge: only update non-blank values, don't overwrite existing non-blank values with blank
      changes = {}

      attrs.each do |key, new_value|
        current_value = existing.send(key)

        # Skip if new value is blank/empty
        next if new_value.blank? || (new_value.is_a?(Array) && new_value.empty?)

        # Update if current value is blank or new value is different
        if current_value.blank? || (current_value != new_value && should_update?(key, current_value, new_value))
          changes[key] = new_value
        end
      end

      if changes.any?
        existing.update!(changes)
        log_info("Updated contact: #{existing.name} with #{changes.keys.join(', ')} (line #{line_number})")
        stats[:updated] += 1
      else
        log_debug("No changes for: #{existing.name} (line #{line_number})")
        stats[:skipped] += 1
      end
    end

    def should_update?(key, current_value, new_value)
      # For certain fields, prefer to not overwrite existing data
      case key
      when :notes
        # Append notes rather than replace
        false
      when :registrar_patterns, :nameserver_patterns, :ip_ranges
        # Merge arrays
        false
      else
        true
      end
    end

    def build_attributes(row)
      contact_type = TYPE_MAPPING[row["Type"]] || "other"
      method = determine_method(row)

      {
        name: row["Name"]&.strip,
        contact_type: contact_type,
        method: method,
        email: extract_email(row),
        web_form_url: row["Report Contact Form"]&.strip.presence,
        organization: extract_organization(row["Name"]),
        notes: row["Notes"]&.strip.presence,
        active: true,
        # Set priority based on type
        priority: priority_for_type(contact_type)
      }.compact
    end

    def determine_method(row)
      csv_method = row["Report Method"]&.strip

      # If MULTIPLE, prefer web form if available, else email
      if csv_method == "MULTIPLE"
        return "web_form" if row["Report Contact Form"].present?
        return "email" if row["Report Email"].present?
      end

      METHOD_MAPPING[csv_method] || "email"
    end

    def extract_email(row)
      email = row["Report Email"]&.strip.presence

      # Validate email format
      return nil unless email
      return nil unless email.match?(URI::MailTo::EMAIL_REGEXP)

      email
    end

    def extract_organization(name)
      # Try to extract organization from name in parentheses
      # e.g., "Deno Deploy (deno.dev domains)" -> nil (it's a description not org)
      # For now, return nil - organization can be set manually
      nil
    end

    def priority_for_type(contact_type)
      case contact_type
      when "registrar"
        10
      when "hosting"
        30
      when "security_vendor"
        20
      else
        50
      end
    end

    def log_info(message)
      logger.info("[AbuseContactImporter] #{message}")
    end

    def log_debug(message)
      logger.debug("[AbuseContactImporter] #{message}")
    end

    def log_error(message, error)
      logger.error("[AbuseContactImporter] #{message}: #{error.message}")
    end
  end
end
