# frozen_string_literal: true

class CreatePhishTables < ActiveRecord::Migration[8.1]
  def change
    # Verdicts table (the phishing verdict/classification)
    create_table :verdicts, id: :uuid do |t|
      t.string :classification  # e.g., "phishing", "clean", "suspicious"
      t.float :confidence_score
      t.jsonb :sources          # Which services flagged it
      t.jsonb :metadata

      t.timestamps
    end

    # Phish TLDs table
    create_table :phish_tlds, id: :uuid do |t|
      t.string :name, null: false
      t.boolean :cleandns_supported, default: false, null: false
      t.jsonb :registrars, default: []
      t.jsonb :resellers, default: []
      t.datetime :cleandns_synced_at
      t.integer :domains_count, default: 0, null: false

      # Soft delete
      t.datetime :discarded_at

      t.timestamps
    end

    add_index :phish_tlds, :name, unique: true
    add_index :phish_tlds, :cleandns_supported
    add_index :phish_tlds, :discarded_at
    add_index :phish_tlds, :domains_count

    # Phish domains table
    create_table :phish_domains, id: :uuid do |t|
      t.string :domain, null: false
      t.datetime :last_checked_at
      t.uuid :verdict_id
      t.uuid :tld_id

      # Availability tracking
      t.datetime :last_seen_at
      t.boolean :dns_resolvable
      t.boolean :http_reachable
      t.datetime :availability_checked_at

      # Soft delete
      t.datetime :discarded_at

      t.timestamps
    end

    add_index :phish_domains, :domain, unique: true
    add_index :phish_domains, :verdict_id
    add_index :phish_domains, :tld_id
    add_index :phish_domains, :last_checked_at
    add_index :phish_domains, :last_seen_at
    add_index :phish_domains, :availability_checked_at
    add_index :phish_domains, :discarded_at

    safety_assured do
      add_foreign_key :phish_domains, :verdicts
      add_foreign_key :phish_domains, :phish_tlds, column: :tld_id
    end

    # Phish URLs table
    create_table :phish_urls, id: :uuid do |t|
      t.string :url, null: false
      t.datetime :last_checked_at
      t.uuid :verdict_id

      # Soft delete
      t.datetime :discarded_at

      t.timestamps
    end

    add_index :phish_urls, :url, unique: true
    add_index :phish_urls, :verdict_id
    add_index :phish_urls, :last_checked_at
    add_index :phish_urls, :discarded_at

    safety_assured { add_foreign_key :phish_urls, :verdicts }

    # Phish protections table (protected domains that should never be flagged)
    create_table :phish_protections, id: :uuid do |t|
      t.string :protectable_type, null: false
      t.string :protectable_value, null: false
      t.text :reason
      t.uuid :protected_by_id, null: false

      # Soft delete
      t.datetime :discarded_at

      t.timestamps
    end

    add_index :phish_protections, [ :protectable_type, :protectable_value ], unique: true, name: "index_protections_on_type_and_value"
    add_index :phish_protections, :protected_by_id
    add_index :phish_protections, :discarded_at

    safety_assured { add_foreign_key :phish_protections, :users, column: :protected_by_id }
  end
end
