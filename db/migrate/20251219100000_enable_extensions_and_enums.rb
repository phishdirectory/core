# frozen_string_literal: true

class EnableExtensionsAndEnums < ActiveRecord::Migration[8.1]
  def change
    # Enable PostgreSQL extensions
    enable_extension "pgcrypto" unless extension_enabled?("pgcrypto")
    enable_extension "fuzzystrmatch" unless extension_enabled?("fuzzystrmatch")

    # User enums
    create_enum "access_level", %w[owner superadmin admin trusted user]
    create_enum "status", %w[active suspended deactivated]

    # Service enums
    create_enum "service_status", %w[active suspended decommissioned]
    create_enum "service_key_status", %w[active deprecated revoked]

    # Report system enums
    create_enum "report_contact_type", %w[registrar hosting security_vendor other]
    create_enum "report_contact_method", %w[email web_form api]
    create_enum "report_case_status", %w[pending submitting awaiting_response partially_resolved resolved escalated]
    create_enum "report_submission_status", %w[pending queued sent acknowledged resolved failed skipped]
    create_enum "report_email_direction", %w[inbound outbound]
  end
end
