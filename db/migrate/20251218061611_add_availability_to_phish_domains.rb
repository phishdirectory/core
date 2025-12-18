# frozen_string_literal: true

class AddAvailabilityToPhishDomains < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    add_column :phish_domains, :last_seen_at, :datetime
    add_column :phish_domains, :dns_resolvable, :boolean
    add_column :phish_domains, :http_reachable, :boolean
    add_column :phish_domains, :availability_checked_at, :datetime

    add_index :phish_domains, :last_seen_at, algorithm: :concurrently
    add_index :phish_domains, :availability_checked_at, algorithm: :concurrently
  end
end
