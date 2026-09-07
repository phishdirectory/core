# frozen_string_literal: true

# Admin search and the command palette match with leading-wildcard ILIKE
# ("%term%"), which a btree index cannot serve. Every keystroke against the
# palette ran a sequential scan over users, domains, urls, emails and phone
# numbers. Trigram GIN indexes are the standard fix.
class AddTrigramSearchIndexes < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  SEARCHED_COLUMNS = {
    users: %i[email username first_name last_name pd_id],
    services: %i[name],
    phish_domains: %i[domain],
    phish_urls: %i[url],
    phish_emails: %i[email],
    phish_phone_numbers: %i[phone_number],
    report_cases: %i[case_number],
    report_abuse_contacts: %i[name]
  }.freeze

  def up
    enable_extension "pg_trgm" unless extension_enabled?("pg_trgm")

    SEARCHED_COLUMNS.each do |table, columns|
      columns.each do |column|
        add_index table, column,
                  using: :gin,
                  opclass: :gin_trgm_ops,
                  name: trigram_index_name(table, column),
                  algorithm: :concurrently
      end
    end
  end

  def down
    SEARCHED_COLUMNS.each do |table, columns|
      columns.each do |column|
        remove_index table, name: trigram_index_name(table, column), algorithm: :concurrently
      end
    end
  end

  private

  def trigram_index_name(table, column)
    "index_#{table}_on_#{column}_trgm"
  end
end
