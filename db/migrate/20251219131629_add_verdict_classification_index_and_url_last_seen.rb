# frozen_string_literal: true

class AddVerdictClassificationIndexAndUrlLastSeen < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    # Add index on verdicts.classification for faster scope queries
    add_index :verdicts, :classification,
              name: "index_verdicts_on_classification",
              if_not_exists: true,
              algorithm: :concurrently

    # Add last_seen_at to phish_urls for parity with phish_domains
    add_column :phish_urls, :last_seen_at, :datetime, if_not_exists: true

    add_index :phish_urls, :last_seen_at,
              name: "index_phish_urls_on_last_seen_at",
              if_not_exists: true,
              algorithm: :concurrently
  end
end
