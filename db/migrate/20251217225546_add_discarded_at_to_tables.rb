# frozen_string_literal: true

# Adds soft delete support via the Discard gem
# Records are marked as discarded rather than permanently deleted,
# allowing for recovery and audit trails.
#
# The discarded_at column stores when a record was soft-deleted.
# Records with discarded_at = NULL are "kept" (not deleted).

class AddDiscardedAtToTables < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    # Users - allow recovery of accidentally deleted accounts
    add_column :users, :discarded_at, :datetime, if_not_exists: true
    add_index :users, :discarded_at, algorithm: :concurrently, if_not_exists: true

    # Services - preserve service history
    add_column :services, :discarded_at, :datetime, if_not_exists: true
    add_index :services, :discarded_at, algorithm: :concurrently, if_not_exists: true

    # Phishing domains - preserve phishing intelligence
    add_column :phish_domains, :discarded_at, :datetime, if_not_exists: true
    add_index :phish_domains, :discarded_at, algorithm: :concurrently, if_not_exists: true

    # Phishing URLs - preserve phishing intelligence
    add_column :phish_urls, :discarded_at, :datetime, if_not_exists: true
    add_index :phish_urls, :discarded_at, algorithm: :concurrently, if_not_exists: true

    # User API keys - audit trail for key lifecycle
    add_column :user_api_keys, :discarded_at, :datetime, if_not_exists: true
    add_index :user_api_keys, :discarded_at, algorithm: :concurrently, if_not_exists: true

    # Service keys - audit trail for key lifecycle
    add_column :service_keys, :discarded_at, :datetime, if_not_exists: true
    add_index :service_keys, :discarded_at, algorithm: :concurrently, if_not_exists: true

    # Service webhooks - preserve webhook history
    add_column :service_webhooks, :discarded_at, :datetime, if_not_exists: true
    add_index :service_webhooks, :discarded_at, algorithm: :concurrently, if_not_exists: true
  end
end
