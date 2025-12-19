# frozen_string_literal: true

class CreatePhishTlds < ActiveRecord::Migration[8.1]
  disable_ddl_transaction!

  def change
    create_table :phish_tlds, id: :uuid do |t|
      t.string :name, null: false
      t.boolean :cleandns_supported, default: false, null: false
      t.jsonb :registrars, default: []
      t.jsonb :resellers, default: []
      t.datetime :cleandns_synced_at
      t.integer :domains_count, default: 0, null: false
      t.datetime :discarded_at

      t.timestamps
    end

    add_index :phish_tlds, :name, unique: true
    add_index :phish_tlds, :cleandns_supported
    add_index :phish_tlds, :discarded_at
    add_index :phish_tlds, :domains_count

    # Add tld_id column to phish_domains with concurrent index
    add_reference :phish_domains, :tld, type: :uuid, index: { algorithm: :concurrently }
  end
end
