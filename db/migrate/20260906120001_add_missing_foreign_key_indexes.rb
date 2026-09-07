# frozen_string_literal: true

# Three foreign keys had no index, so every cascade check and every join on
# them fell back to a sequential scan. webhook_deliveries is ordered by
# created_at in the admin UI with nothing to support the sort.
class AddMissingForeignKeyIndexes < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    add_index :report_cases, :verdict_snapshot_id, algorithm: :concurrently

    add_index :report_domain_lookups, :matched_hosting_contact_id, algorithm: :concurrently
    add_index :report_domain_lookups, :matched_registrar_contact_id, algorithm: :concurrently

    add_index :webhook_deliveries, :created_at, algorithm: :concurrently
  end
end
