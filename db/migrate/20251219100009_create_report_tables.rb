# frozen_string_literal: true

class CreateReportTables < ActiveRecord::Migration[8.1]
  def change
    # Abuse contacts - organizations that receive abuse reports
    create_table :report_abuse_contacts, id: :uuid, default: -> { "gen_random_uuid()" } do |t|
      # Organization info
      t.string :name, null: false
      t.column :contact_type, :report_contact_type, null: false
      t.string :organization

      # Contact method
      t.column :method, :report_contact_method, null: false

      # Email contact
      t.string :email

      # Web form contact
      t.string :web_form_url
      t.jsonb :web_form_fields, default: {}

      # API contact (encrypted)
      t.text :api_endpoint_ciphertext
      t.text :api_key_ciphertext

      # Reporter status
      t.boolean :trusted_reporter, default: false, null: false
      t.boolean :accepts_bulk, default: false, null: false
      t.integer :priority, default: 50, null: false

      # Matching patterns for auto-discovery
      t.jsonb :registrar_patterns, default: []
      t.jsonb :nameserver_patterns, default: []
      t.jsonb :ip_ranges, default: []

      # Stats
      t.integer :reports_sent, default: 0, null: false
      t.integer :reports_acknowledged, default: 0, null: false
      t.float :avg_response_hours

      # Notes
      t.text :notes

      t.boolean :active, default: true, null: false
      t.datetime :discarded_at
      t.timestamps
    end

    add_index :report_abuse_contacts, :name
    add_index :report_abuse_contacts, :contact_type
    add_index :report_abuse_contacts, :active
    add_index :report_abuse_contacts, :discarded_at

    # Cases - groups reports for a single phishing domain/URL
    create_table :report_cases, id: :uuid, default: -> { "gen_random_uuid()" } do |t|
      t.string :case_number, null: false # Flake ID: case_chqrg05u4agw

      # Polymorphic link to Phish::Domain or Phish::Url
      t.string :reportable_type, null: false
      t.uuid :reportable_id, null: false

      # Snapshot of verdict at case creation
      t.uuid :verdict_snapshot_id, null: false
      t.float :confidence_at_creation, null: false

      # AASM status
      t.column :status, :report_case_status, default: "pending", null: false

      # Tracking
      t.integer :submissions_count, default: 0, null: false
      t.datetime :first_submitted_at
      t.datetime :last_activity_at
      t.datetime :resolved_at

      # Manual review flag
      t.boolean :requires_manual_review, default: false, null: false

      # Cached domain info from WHOIS/RDAP
      t.jsonb :domain_info, default: {}
      t.text :notes

      t.datetime :discarded_at
      t.timestamps
    end

    add_index :report_cases, :case_number, unique: true
    add_index :report_cases, [:reportable_type, :reportable_id]
    add_index :report_cases, :status
    add_index :report_cases, :requires_manual_review
    add_index :report_cases, :discarded_at
    safety_assured { add_foreign_key :report_cases, :verdicts, column: :verdict_snapshot_id }

    # Submissions - individual reports to abuse contacts
    create_table :report_submissions, id: :uuid, default: -> { "gen_random_uuid()" } do |t|
      t.uuid :case_id, null: false
      t.uuid :abuse_contact_id, null: false

      # AASM status
      t.column :status, :report_submission_status, default: "pending", null: false

      # External reference from destination
      t.string :submission_reference

      # Timestamps
      t.datetime :queued_at
      t.datetime :sent_at
      t.datetime :acknowledged_at
      t.datetime :resolved_at

      # Payload
      t.jsonb :payload, default: {}
      t.string :payload_hash

      # Response
      t.jsonb :response, default: {}
      t.text :response_body
      t.integer :response_status_code

      # Retry logic
      t.integer :attempts, default: 0, null: false
      t.integer :max_attempts, default: 5, null: false
      t.datetime :last_attempt_at
      t.datetime :next_retry_at
      t.text :last_error

      # Ordering dependencies
      t.uuid :depends_on_submission_id

      t.datetime :discarded_at
      t.timestamps
    end

    add_index :report_submissions, :case_id
    add_index :report_submissions, :abuse_contact_id
    add_index :report_submissions, :status
    add_index :report_submissions, :depends_on_submission_id
    add_index :report_submissions, [:case_id, :abuse_contact_id], unique: true
    add_index :report_submissions, :discarded_at
    safety_assured do
      add_foreign_key :report_submissions, :report_cases, column: :case_id
      add_foreign_key :report_submissions, :report_abuse_contacts, column: :abuse_contact_id
      add_foreign_key :report_submissions, :report_submissions, column: :depends_on_submission_id
    end

    # Domain lookups - WHOIS/RDAP cache
    create_table :report_domain_lookups, id: :uuid, default: -> { "gen_random_uuid()" } do |t|
      t.string :domain, null: false

      # WHOIS/RDAP data
      t.string :registrar_name
      t.string :registrar_iana_id
      t.string :registrar_abuse_email
      t.string :registrar_abuse_phone
      t.datetime :domain_created_at
      t.datetime :domain_expires_at
      t.jsonb :nameservers, default: []
      t.jsonb :raw_whois, default: {}
      t.jsonb :raw_rdap, default: {}

      # Hosting info
      t.jsonb :a_records, default: []
      t.string :hosting_provider
      t.uuid :matched_hosting_contact_id
      t.uuid :matched_registrar_contact_id

      t.string :lookup_source
      t.datetime :looked_up_at
      t.datetime :expires_at

      t.timestamps
    end

    add_index :report_domain_lookups, :domain, unique: true
    add_index :report_domain_lookups, :expires_at
    add_index :report_domain_lookups, :registrar_iana_id
    safety_assured do
      add_foreign_key :report_domain_lookups, :report_abuse_contacts, column: :matched_hosting_contact_id
      add_foreign_key :report_domain_lookups, :report_abuse_contacts, column: :matched_registrar_contact_id
    end

    # Case emails - inbound/outbound email history
    create_table :report_case_emails, id: :uuid, default: -> { "gen_random_uuid()" } do |t|
      t.uuid :case_id, null: false
      t.uuid :submission_id
      t.uuid :action_mailbox_inbound_email_id

      t.column :direction, :report_email_direction, null: false

      t.string :from_address
      t.jsonb :to_addresses, default: []
      t.jsonb :cc_addresses, default: []
      t.string :subject
      t.text :body_text
      t.text :body_html
      t.datetime :received_at

      # Parsed data from email content
      t.jsonb :parsed_data, default: {}

      t.timestamps
    end

    add_index :report_case_emails, :case_id
    add_index :report_case_emails, :submission_id
    add_index :report_case_emails, :action_mailbox_inbound_email_id
    add_index :report_case_emails, :direction
    safety_assured do
      add_foreign_key :report_case_emails, :report_cases, column: :case_id
      add_foreign_key :report_case_emails, :report_submissions, column: :submission_id
      add_foreign_key :report_case_emails, :action_mailbox_inbound_emails, column: :action_mailbox_inbound_email_id
    end
  end
end
