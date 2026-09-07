# frozen_string_literal: true

# Soft deleting a record permanently burned its natural key.
#
# The unique indexes below ignored discarded_at, so discarding a user burned
# their email and username forever, discarding a service burned its name, and
# discarding a domain made every later lookup of it fail. user_service_roles
# already had this right with a partial index; this brings the rest in line.
#
# Only natural keys are scoped. System-generated identifiers and secrets
# (users.pd_id, the auth tokens, service_keys.api_key, user_api_keys.key_digest,
# report_cases.case_number) stay globally unique, because reusing one of those
# would be a collision rather than a legitimate re-registration.
#
# Index names are given explicitly: PostgreSQL truncates identifiers at 63
# characters, and the derived name for phish_protections overflowed. The
# if_not_exists / if_exists guards let the migration resume safely, since
# disable_ddl_transaction! means a mid-run failure cannot roll back.
class ScopeUniqueIndexesToKeptRecords < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  # table, columns, existing index name, replacement index name
  NATURAL_KEYS = [
    [ :phish_carriers,             %i[name],                     "index_phish_carriers_on_name",                     "index_phish_carriers_on_name_kept" ],
    [ :phish_domain_registrations, %i[domain],                   "index_phish_domain_registrations_on_domain",        "index_phish_domain_regs_on_domain_kept" ],
    [ :phish_domains,              %i[domain],                   "index_phish_domains_on_domain",                    "index_phish_domains_on_domain_kept" ],
    [ :phish_emails,               %i[email],                    "index_phish_emails_on_email",                      "index_phish_emails_on_email_kept" ],
    [ :phish_phone_numbers,        %i[phone_number],             "index_phish_phone_numbers_on_phone_number",         "index_phish_phones_on_number_kept" ],
    [ :phish_protections,          %i[protectable_type protectable_value], "index_protections_on_type_and_value",     "index_protections_on_type_and_value_kept" ],
    [ :phish_tlds,                 %i[name],                     "index_phish_tlds_on_name",                         "index_phish_tlds_on_name_kept" ],
    [ :phish_urls,                 %i[url],                      "index_phish_urls_on_url",                          "index_phish_urls_on_url_kept" ],
    [ :report_submissions,         %i[case_id abuse_contact_id], "index_report_submissions_on_case_id_and_abuse_contact_id", "index_report_submissions_on_case_and_contact_kept" ],
    [ :saml_service_providers,     %i[entity_id],                "index_saml_service_providers_on_entity_id",         "index_saml_sps_on_entity_id_kept" ],
    [ :service_webhooks,           %i[url],                      "index_service_webhooks_on_url",                    "index_service_webhooks_on_url_kept" ],
    [ :services,                   %i[name],                     "index_services_on_name",                           "index_services_on_name_kept" ],
    [ :users,                      %i[email],                    "index_users_on_email",                             "index_users_on_email_kept" ],
    [ :users,                      %i[username],                 "index_users_on_username",                          "index_users_on_username_kept" ]
  ].freeze

  def up
    NATURAL_KEYS.each do |table, columns, old_name, new_name|
      # Add the replacement first so the uniqueness guarantee is never dropped.
      add_index table, columns,
                unique: true,
                where: "discarded_at IS NULL",
                name: new_name,
                algorithm: :concurrently,
                if_not_exists: true

      remove_index table, name: old_name, algorithm: :concurrently, if_exists: true
    end
  end

  def down
    NATURAL_KEYS.each do |table, columns, old_name, new_name|
      add_index table, columns,
                unique: true,
                name: old_name,
                algorithm: :concurrently,
                if_not_exists: true

      remove_index table, name: new_name, algorithm: :concurrently, if_exists: true
    end
  end
end
