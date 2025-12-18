# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.1].define(version: 2025_12_17_233644) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "fuzzystrmatch"
  enable_extension "pg_catalog.plpgsql"
  enable_extension "pg_stat_statements"
  enable_extension "pgcrypto"

  # Custom types defined in this database.
  # Note that some types may not work with other database engines. Be careful if changing database.
  create_enum "access_level", ["owner", "superadmin", "admin", "trusted", "user"]
  create_enum "report_case_status", ["pending", "submitting", "awaiting_response", "partially_resolved", "resolved", "escalated"]
  create_enum "report_contact_method", ["email", "web_form", "api"]
  create_enum "report_contact_type", ["registrar", "hosting", "security_vendor", "other"]
  create_enum "report_email_direction", ["inbound", "outbound"]
  create_enum "report_submission_status", ["pending", "queued", "sent", "acknowledged", "resolved", "failed", "skipped"]
  create_enum "service_key_status", ["active", "deprecated", "revoked"]
  create_enum "service_status", ["active", "suspended", "decommissioned"]
  create_enum "status", ["active", "suspended", "deactivated"]

  create_table "action_mailbox_inbound_emails", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "message_checksum", null: false
    t.string "message_id", null: false
    t.integer "status", default: 0, null: false
    t.datetime "updated_at", null: false
    t.index ["message_id", "message_checksum"], name: "index_action_mailbox_inbound_emails_uniqueness", unique: true
  end

  create_table "active_storage_attachments", force: :cascade do |t|
    t.bigint "blob_id", null: false
    t.datetime "created_at", null: false
    t.string "name", null: false
    t.bigint "record_id", null: false
    t.string "record_type", null: false
    t.index ["blob_id"], name: "index_active_storage_attachments_on_blob_id"
    t.index ["record_type", "record_id", "name", "blob_id"], name: "index_active_storage_attachments_uniqueness", unique: true
  end

  create_table "active_storage_blobs", force: :cascade do |t|
    t.bigint "byte_size", null: false
    t.string "checksum"
    t.string "content_type"
    t.datetime "created_at", null: false
    t.string "filename", null: false
    t.string "key", null: false
    t.text "metadata"
    t.string "service_name", null: false
    t.index ["key"], name: "index_active_storage_blobs_on_key", unique: true
  end

  create_table "active_storage_variant_records", force: :cascade do |t|
    t.bigint "blob_id", null: false
    t.string "variation_digest", null: false
    t.index ["blob_id", "variation_digest"], name: "index_active_storage_variant_records_uniqueness", unique: true
  end

  create_table "ahoy_clicks", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.string "campaign"
    t.string "token"
    t.index ["campaign"], name: "index_ahoy_clicks_on_campaign"
  end

  create_table "ahoy_events", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.string "name"
    t.jsonb "properties"
    t.datetime "time"
    t.uuid "user_id"
    t.uuid "visit_id"
    t.index ["name", "time"], name: "index_ahoy_events_on_name_and_time"
    t.index ["properties"], name: "index_ahoy_events_on_properties", opclass: :jsonb_path_ops, using: :gin
    t.index ["user_id"], name: "index_ahoy_events_on_user_id"
    t.index ["visit_id"], name: "index_ahoy_events_on_visit_id"
  end

  create_table "ahoy_messages", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.string "campaign"
    t.string "mailer"
    t.datetime "sent_at"
    t.text "subject"
    t.string "to_bidx"
    t.text "to_ciphertext"
    t.uuid "user_id"
    t.string "user_type"
    t.index ["campaign"], name: "index_ahoy_messages_on_campaign"
    t.index ["to_bidx"], name: "index_ahoy_messages_on_to_bidx"
    t.index ["user_type", "user_id"], name: "index_ahoy_messages_on_user_type_and_user_id"
  end

  create_table "ahoy_visits", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.string "app_version"
    t.string "browser"
    t.string "city"
    t.string "country"
    t.string "device_type"
    t.string "ip"
    t.text "landing_page"
    t.float "latitude"
    t.float "longitude"
    t.string "os"
    t.string "os_version"
    t.string "platform"
    t.text "referrer"
    t.string "referring_domain"
    t.string "region"
    t.datetime "started_at"
    t.text "user_agent"
    t.uuid "user_id"
    t.string "utm_campaign"
    t.string "utm_content"
    t.string "utm_medium"
    t.string "utm_source"
    t.string "utm_term"
    t.string "visit_token"
    t.string "visitor_token"
    t.index ["user_id"], name: "index_ahoy_visits_on_user_id"
    t.index ["visit_token"], name: "index_ahoy_visits_on_visit_token", unique: true
    t.index ["visitor_token", "started_at"], name: "index_ahoy_visits_on_visitor_token_and_started_at"
  end

  create_table "audits1984_audits", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.uuid "auditor_id", null: false
    t.datetime "created_at", null: false
    t.text "notes"
    t.uuid "session_id", null: false
    t.integer "status", default: 0, null: false
    t.datetime "updated_at", null: false
    t.index ["auditor_id"], name: "index_audits1984_audits_on_auditor_id"
    t.index ["session_id"], name: "index_audits1984_audits_on_session_id"
  end

  create_table "blazer_audits", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at"
    t.string "data_source"
    t.uuid "query_id"
    t.text "statement"
    t.uuid "user_id"
    t.index ["query_id"], name: "index_blazer_audits_on_query_id"
    t.index ["user_id"], name: "index_blazer_audits_on_user_id"
  end

  create_table "blazer_checks", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.string "check_type"
    t.datetime "created_at", null: false
    t.uuid "creator_id"
    t.text "emails"
    t.datetime "last_run_at"
    t.text "message"
    t.uuid "query_id"
    t.string "schedule"
    t.text "slack_channels"
    t.string "state"
    t.datetime "updated_at", null: false
    t.index ["creator_id"], name: "index_blazer_checks_on_creator_id"
    t.index ["query_id"], name: "index_blazer_checks_on_query_id"
  end

  create_table "blazer_dashboard_queries", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.uuid "dashboard_id"
    t.integer "position"
    t.uuid "query_id"
    t.datetime "updated_at", null: false
    t.index ["dashboard_id"], name: "index_blazer_dashboard_queries_on_dashboard_id"
    t.index ["query_id"], name: "index_blazer_dashboard_queries_on_query_id"
  end

  create_table "blazer_dashboards", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.uuid "creator_id"
    t.string "name"
    t.datetime "updated_at", null: false
    t.index ["creator_id"], name: "index_blazer_dashboards_on_creator_id"
  end

  create_table "blazer_queries", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.uuid "creator_id"
    t.string "data_source"
    t.text "description"
    t.string "name"
    t.text "statement"
    t.string "status"
    t.datetime "updated_at", null: false
    t.index ["creator_id"], name: "index_blazer_queries_on_creator_id"
  end

  create_table "blazer_uploads", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.uuid "creator_id"
    t.text "description"
    t.string "table"
    t.datetime "updated_at", null: false
    t.index ["creator_id"], name: "index_blazer_uploads_on_creator_id"
  end

  create_table "console1984_commands", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.uuid "sensitive_access_id"
    t.uuid "session_id", null: false
    t.text "statements"
    t.datetime "updated_at", null: false
    t.index ["sensitive_access_id"], name: "index_console1984_commands_on_sensitive_access_id"
    t.index ["session_id", "created_at", "sensitive_access_id"], name: "on_session_and_sensitive_chronologically"
  end

  create_table "console1984_sensitive_accesses", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.text "justification"
    t.uuid "session_id", null: false
    t.datetime "updated_at", null: false
    t.index ["session_id"], name: "index_console1984_sensitive_accesses_on_session_id"
  end

  create_table "console1984_sessions", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.text "reason"
    t.datetime "updated_at", null: false
    t.uuid "user_id", null: false
    t.index ["created_at"], name: "index_console1984_sessions_on_created_at"
    t.index ["user_id", "created_at"], name: "index_console1984_sessions_on_user_id_and_created_at"
  end

  create_table "console1984_users", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.string "username", null: false
    t.index ["username"], name: "index_console1984_users_on_username"
  end

  create_table "flipper_features", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "key", null: false
    t.datetime "updated_at", null: false
    t.index ["key"], name: "index_flipper_features_on_key", unique: true
  end

  create_table "flipper_gates", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "feature_key", null: false
    t.string "key", null: false
    t.datetime "updated_at", null: false
    t.text "value"
    t.index ["feature_key", "key", "value"], name: "index_flipper_gates_on_feature_key_and_key_and_value", unique: true
  end

  create_table "friendly_id_slugs", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at"
    t.string "scope"
    t.string "slug", null: false
    t.uuid "sluggable_id", null: false
    t.string "sluggable_type", limit: 50
    t.index ["slug", "sluggable_type", "scope"], name: "index_friendly_id_slugs_on_slug_and_sluggable_type_and_scope", unique: true
    t.index ["sluggable_type", "sluggable_id"], name: "index_friendly_id_slugs_on_sluggable_type_and_sluggable_id"
  end

  create_table "lockbox_audits", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.string "context"
    t.datetime "created_at"
    t.jsonb "data"
    t.string "ip"
    t.uuid "subject_id"
    t.string "subject_type"
    t.uuid "viewer_id"
    t.string "viewer_type"
    t.index ["subject_type", "subject_id"], name: "index_lockbox_audits_on_subject_type_and_subject_id"
    t.index ["viewer_type", "viewer_id"], name: "index_lockbox_audits_on_viewer_type_and_viewer_id"
  end

  create_table "oauth_access_grants", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.uuid "application_id", null: false
    t.datetime "created_at", null: false
    t.integer "expires_in", null: false
    t.text "redirect_uri", null: false
    t.uuid "resource_owner_id", null: false
    t.datetime "revoked_at"
    t.string "scopes", default: "", null: false
    t.string "token", null: false
    t.datetime "updated_at", null: false
    t.index ["application_id"], name: "index_oauth_access_grants_on_application_id"
    t.index ["resource_owner_id"], name: "index_oauth_access_grants_on_resource_owner_id"
    t.index ["token"], name: "index_oauth_access_grants_on_token", unique: true
  end

  create_table "oauth_access_tokens", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.uuid "application_id", null: false
    t.datetime "created_at", null: false
    t.integer "expires_in"
    t.string "previous_refresh_token", default: "", null: false
    t.string "refresh_token"
    t.uuid "resource_owner_id"
    t.datetime "revoked_at"
    t.string "scopes"
    t.string "token", null: false
    t.datetime "updated_at", null: false
    t.index ["application_id"], name: "index_oauth_access_tokens_on_application_id"
    t.index ["refresh_token"], name: "index_oauth_access_tokens_on_refresh_token", unique: true
    t.index ["resource_owner_id"], name: "index_oauth_access_tokens_on_resource_owner_id"
    t.index ["token"], name: "index_oauth_access_tokens_on_token", unique: true
  end

  create_table "oauth_applications", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.boolean "confidential", default: true, null: false
    t.datetime "created_at", null: false
    t.string "name", null: false
    t.text "redirect_uri", null: false
    t.string "scopes", default: "", null: false
    t.string "secret", null: false
    t.string "uid", null: false
    t.datetime "updated_at", null: false
    t.index ["uid"], name: "index_oauth_applications_on_uid", unique: true
  end

  create_table "pg_search_documents", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.text "content"
    t.datetime "created_at", null: false
    t.uuid "searchable_id"
    t.string "searchable_type"
    t.datetime "updated_at", null: false
    t.index ["searchable_type", "searchable_id"], name: "index_pg_search_documents_on_searchable_type_and_searchable_id"
  end

  create_table "phish_domains", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.datetime "discarded_at"
    t.string "domain", null: false
    t.datetime "last_checked_at"
    t.datetime "updated_at", null: false
    t.uuid "verdict_id"
    t.index ["discarded_at"], name: "index_phish_domains_on_discarded_at"
    t.index ["domain"], name: "index_phish_domains_on_domain", unique: true
    t.index ["last_checked_at"], name: "index_phish_domains_on_last_checked_at"
    t.index ["verdict_id"], name: "index_phish_domains_on_verdict_id"
  end

  create_table "phish_urls", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.datetime "discarded_at"
    t.datetime "last_checked_at"
    t.datetime "updated_at", null: false
    t.string "url", null: false
    t.uuid "verdict_id"
    t.index ["discarded_at"], name: "index_phish_urls_on_discarded_at"
    t.index ["last_checked_at"], name: "index_phish_urls_on_last_checked_at"
    t.index ["url"], name: "index_phish_urls_on_url", unique: true
    t.index ["verdict_id"], name: "index_phish_urls_on_verdict_id"
  end

  create_table "report_abuse_contacts", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.boolean "accepts_bulk", default: false, null: false
    t.boolean "active", default: true, null: false
    t.text "api_endpoint_ciphertext"
    t.text "api_key_ciphertext"
    t.float "avg_response_hours"
    t.enum "contact_type", null: false, enum_type: "report_contact_type"
    t.datetime "created_at", null: false
    t.datetime "discarded_at"
    t.string "email"
    t.jsonb "ip_ranges", default: []
    t.enum "method", null: false, enum_type: "report_contact_method"
    t.string "name", null: false
    t.jsonb "nameserver_patterns", default: []
    t.string "organization"
    t.integer "priority", default: 50, null: false
    t.jsonb "registrar_patterns", default: []
    t.integer "reports_acknowledged", default: 0, null: false
    t.integer "reports_sent", default: 0, null: false
    t.boolean "trusted_reporter", default: false, null: false
    t.datetime "updated_at", null: false
    t.jsonb "web_form_fields", default: {}
    t.string "web_form_url"
    t.index ["active"], name: "index_report_abuse_contacts_on_active"
    t.index ["contact_type"], name: "index_report_abuse_contacts_on_contact_type"
    t.index ["discarded_at"], name: "index_report_abuse_contacts_on_discarded_at"
    t.index ["name"], name: "index_report_abuse_contacts_on_name"
  end

  create_table "report_case_emails", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.uuid "action_mailbox_inbound_email_id"
    t.text "body_html"
    t.text "body_text"
    t.uuid "case_id", null: false
    t.jsonb "cc_addresses", default: []
    t.datetime "created_at", null: false
    t.enum "direction", null: false, enum_type: "report_email_direction"
    t.string "from_address"
    t.jsonb "parsed_data", default: {}
    t.datetime "received_at"
    t.string "subject"
    t.uuid "submission_id"
    t.jsonb "to_addresses", default: []
    t.datetime "updated_at", null: false
    t.index ["action_mailbox_inbound_email_id"], name: "index_report_case_emails_on_action_mailbox_inbound_email_id"
    t.index ["case_id"], name: "index_report_case_emails_on_case_id"
    t.index ["direction"], name: "index_report_case_emails_on_direction"
    t.index ["submission_id"], name: "index_report_case_emails_on_submission_id"
  end

  create_table "report_cases", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.string "case_number", null: false
    t.float "confidence_at_creation", null: false
    t.datetime "created_at", null: false
    t.datetime "discarded_at"
    t.jsonb "domain_info", default: {}
    t.datetime "first_submitted_at"
    t.datetime "last_activity_at"
    t.text "notes"
    t.uuid "reportable_id", null: false
    t.string "reportable_type", null: false
    t.boolean "requires_manual_review", default: false, null: false
    t.datetime "resolved_at"
    t.enum "status", default: "pending", null: false, enum_type: "report_case_status"
    t.integer "submissions_count", default: 0, null: false
    t.datetime "updated_at", null: false
    t.uuid "verdict_snapshot_id", null: false
    t.index ["case_number"], name: "index_report_cases_on_case_number", unique: true
    t.index ["discarded_at"], name: "index_report_cases_on_discarded_at"
    t.index ["reportable_type", "reportable_id"], name: "index_report_cases_on_reportable_type_and_reportable_id"
    t.index ["requires_manual_review"], name: "index_report_cases_on_requires_manual_review"
    t.index ["status"], name: "index_report_cases_on_status"
  end

  create_table "report_domain_lookups", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.jsonb "a_records", default: []
    t.datetime "created_at", null: false
    t.string "domain", null: false
    t.datetime "domain_created_at"
    t.datetime "domain_expires_at"
    t.datetime "expires_at"
    t.string "hosting_provider"
    t.datetime "looked_up_at"
    t.string "lookup_source"
    t.uuid "matched_hosting_contact_id"
    t.uuid "matched_registrar_contact_id"
    t.jsonb "nameservers", default: []
    t.jsonb "raw_rdap", default: {}
    t.jsonb "raw_whois", default: {}
    t.string "registrar_abuse_email"
    t.string "registrar_abuse_phone"
    t.string "registrar_iana_id"
    t.string "registrar_name"
    t.datetime "updated_at", null: false
    t.index ["domain"], name: "index_report_domain_lookups_on_domain", unique: true
    t.index ["expires_at"], name: "index_report_domain_lookups_on_expires_at"
    t.index ["registrar_iana_id"], name: "index_report_domain_lookups_on_registrar_iana_id"
  end

  create_table "report_submissions", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.uuid "abuse_contact_id", null: false
    t.datetime "acknowledged_at"
    t.integer "attempts", default: 0, null: false
    t.uuid "case_id", null: false
    t.datetime "created_at", null: false
    t.uuid "depends_on_submission_id"
    t.datetime "discarded_at"
    t.datetime "last_attempt_at"
    t.text "last_error"
    t.integer "max_attempts", default: 5, null: false
    t.datetime "next_retry_at"
    t.jsonb "payload", default: {}
    t.string "payload_hash"
    t.datetime "queued_at"
    t.datetime "resolved_at"
    t.jsonb "response", default: {}
    t.text "response_body"
    t.integer "response_status_code"
    t.datetime "sent_at"
    t.enum "status", default: "pending", null: false, enum_type: "report_submission_status"
    t.string "submission_reference"
    t.datetime "updated_at", null: false
    t.index ["abuse_contact_id"], name: "index_report_submissions_on_abuse_contact_id"
    t.index ["case_id", "abuse_contact_id"], name: "index_report_submissions_on_case_id_and_abuse_contact_id", unique: true
    t.index ["case_id"], name: "index_report_submissions_on_case_id"
    t.index ["depends_on_submission_id"], name: "index_report_submissions_on_depends_on_submission_id"
    t.index ["discarded_at"], name: "index_report_submissions_on_discarded_at"
    t.index ["status"], name: "index_report_submissions_on_status"
  end

  create_table "rollups", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.jsonb "dimensions", default: {}, null: false
    t.string "interval", null: false
    t.string "name", null: false
    t.datetime "time", null: false
    t.float "value"
    t.index ["name", "interval", "time", "dimensions"], name: "index_rollups_on_name_and_interval_and_time_and_dimensions", unique: true
  end

  create_table "service_key_usages", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.integer "duration_ms"
    t.string "ip_address"
    t.uuid "key_id", null: false
    t.text "request_body"
    t.text "request_headers"
    t.string "request_method"
    t.string "request_path"
    t.datetime "requested_at"
    t.text "response_body"
    t.integer "response_code"
    t.text "response_headers"
    t.datetime "updated_at", null: false
    t.text "user_agent"
    t.uuid "user_id"
    t.index ["duration_ms"], name: "index_service_key_usages_on_duration_ms"
    t.index ["key_id"], name: "index_service_key_usages_on_key_id"
    t.index ["requested_at"], name: "index_service_key_usages_on_requested_at"
    t.index ["user_id"], name: "index_service_key_usages_on_user_id"
  end

  create_table "service_keys", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.string "api_key", null: false
    t.datetime "created_at", null: false
    t.datetime "discarded_at"
    t.string "hash_key", null: false
    t.text "notes"
    t.uuid "service_id", null: false
    t.enum "status", default: "active", null: false, enum_type: "service_key_status"
    t.datetime "updated_at", null: false
    t.index ["api_key"], name: "index_service_keys_on_api_key", unique: true
    t.index ["discarded_at"], name: "index_service_keys_on_discarded_at"
    t.index ["service_id"], name: "index_service_keys_on_service_id"
  end

  create_table "service_webhooks", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.datetime "discarded_at"
    t.string "secret", null: false
    t.uuid "service_id", null: false
    t.datetime "updated_at", null: false
    t.string "url", null: false
    t.index ["discarded_at"], name: "index_service_webhooks_on_discarded_at"
    t.index ["service_id"], name: "index_service_webhooks_on_service_id"
    t.index ["url"], name: "index_service_webhooks_on_url", unique: true
  end

  create_table "services", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.datetime "discarded_at"
    t.integer "keys_count", default: 0, null: false
    t.string "name", null: false
    t.enum "status", default: "active", null: false, enum_type: "service_status"
    t.datetime "updated_at", null: false
    t.index ["discarded_at"], name: "index_services_on_discarded_at"
    t.index ["name"], name: "index_services_on_name", unique: true
  end

  create_table "sessions", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.text "data"
    t.string "session_id", null: false
    t.datetime "updated_at", null: false
    t.index ["session_id"], name: "index_sessions_on_session_id", unique: true
    t.index ["updated_at"], name: "index_sessions_on_updated_at"
  end

  create_table "user_api_keys", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.boolean "active", default: true, null: false
    t.datetime "created_at", null: false
    t.datetime "discarded_at"
    t.datetime "expires_at"
    t.string "key_digest", null: false
    t.datetime "last_used_at"
    t.string "name", null: false
    t.datetime "updated_at", null: false
    t.uuid "user_id", null: false
    t.index ["discarded_at"], name: "index_user_api_keys_on_discarded_at"
    t.index ["expires_at"], name: "index_user_api_keys_on_expires_at"
    t.index ["key_digest"], name: "index_user_api_keys_on_key_digest", unique: true
    t.index ["user_id", "active"], name: "index_user_api_keys_on_user_id_and_active"
  end

  create_table "user_sessions", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at", null: false
    t.string "device_info"
    t.datetime "expiration_at", null: false
    t.string "fingerprint"
    t.uuid "impersonated_by_id"
    t.string "ip"
    t.datetime "last_seen_at"
    t.float "latitude"
    t.float "longitude"
    t.string "os_info"
    t.string "session_token_bidx"
    t.string "session_token_ciphertext"
    t.datetime "signed_out_at"
    t.string "timezone"
    t.datetime "updated_at", null: false
    t.uuid "user_id", null: false
    t.index ["impersonated_by_id"], name: "index_user_sessions_on_impersonated_by_id"
    t.index ["session_token_bidx"], name: "index_user_sessions_on_session_token_bidx"
    t.index ["user_id"], name: "index_user_sessions_on_user_id"
  end

  create_table "users", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.enum "access_level", default: "user", null: false, enum_type: "access_level"
    t.datetime "created_at", null: false
    t.datetime "discarded_at"
    t.string "email", null: false
    t.boolean "email_verified", default: false
    t.datetime "email_verified_at"
    t.string "first_name", null: false
    t.string "last_name", null: false
    t.datetime "locked_at"
    t.datetime "magic_link_expires_at"
    t.string "magic_link_token"
    t.datetime "magic_link_token_sent_at"
    t.datetime "magic_link_used_at"
    t.boolean "pd_dev", default: false, null: false
    t.string "pd_id", null: false
    t.boolean "pretend_is_not_admin", default: false, null: false
    t.integer "session_duration_seconds", default: 2592000, null: false
    t.boolean "staff", default: false, null: false
    t.enum "status", default: "active", null: false, enum_type: "status"
    t.datetime "updated_at", null: false
    t.string "username", null: false
    t.index ["discarded_at"], name: "index_users_on_discarded_at"
    t.index ["email"], name: "index_users_on_email", unique: true
    t.index ["locked_at"], name: "index_users_on_locked_at"
    t.index ["magic_link_token"], name: "index_users_on_magic_link_token", unique: true
    t.index ["pd_id"], name: "index_users_on_pd_id", unique: true
    t.index ["username"], name: "index_users_on_username", unique: true
  end

  create_table "verdicts", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.string "classification"
    t.float "confidence_score"
    t.datetime "created_at", null: false
    t.jsonb "metadata"
    t.jsonb "sources"
    t.datetime "updated_at", null: false
  end

  create_table "versions", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.datetime "created_at"
    t.string "event", null: false
    t.uuid "item_id", null: false
    t.string "item_type", null: false
    t.text "object"
    t.text "object_changes"
    t.string "whodunnit"
    t.index ["created_at"], name: "index_versions_on_created_at"
    t.index ["item_type", "item_id"], name: "index_versions_on_item_type_and_item_id"
  end

  create_table "webhook_deliveries", id: :uuid, default: -> { "gen_random_uuid()" }, force: :cascade do |t|
    t.integer "attempts"
    t.datetime "created_at", null: false
    t.string "event"
    t.datetime "last_attempt_at"
    t.text "payload"
    t.jsonb "response"
    t.string "status"
    t.datetime "updated_at", null: false
    t.string "url"
    t.index ["event"], name: "index_webhook_deliveries_on_event"
    t.index ["status"], name: "index_webhook_deliveries_on_status"
  end

  add_foreign_key "active_storage_attachments", "active_storage_blobs", column: "blob_id"
  add_foreign_key "active_storage_variant_records", "active_storage_blobs", column: "blob_id"
  add_foreign_key "oauth_access_grants", "oauth_applications", column: "application_id"
  add_foreign_key "oauth_access_grants", "users", column: "resource_owner_id"
  add_foreign_key "oauth_access_tokens", "oauth_applications", column: "application_id"
  add_foreign_key "oauth_access_tokens", "users", column: "resource_owner_id"
  add_foreign_key "phish_domains", "verdicts"
  add_foreign_key "phish_urls", "verdicts"
  add_foreign_key "report_case_emails", "action_mailbox_inbound_emails"
  add_foreign_key "report_case_emails", "report_cases", column: "case_id"
  add_foreign_key "report_case_emails", "report_submissions", column: "submission_id"
  add_foreign_key "report_cases", "verdicts", column: "verdict_snapshot_id"
  add_foreign_key "report_domain_lookups", "report_abuse_contacts", column: "matched_hosting_contact_id"
  add_foreign_key "report_domain_lookups", "report_abuse_contacts", column: "matched_registrar_contact_id"
  add_foreign_key "report_submissions", "report_abuse_contacts", column: "abuse_contact_id"
  add_foreign_key "report_submissions", "report_cases", column: "case_id"
  add_foreign_key "report_submissions", "report_submissions", column: "depends_on_submission_id"
  add_foreign_key "service_key_usages", "service_keys", column: "key_id"
  add_foreign_key "service_key_usages", "users", on_delete: :nullify
  add_foreign_key "service_keys", "services"
  add_foreign_key "service_webhooks", "services"
  add_foreign_key "user_api_keys", "users"
  add_foreign_key "user_sessions", "users"
  add_foreign_key "user_sessions", "users", column: "impersonated_by_id"
end
