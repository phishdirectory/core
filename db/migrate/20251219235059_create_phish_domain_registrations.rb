# frozen_string_literal: true

class CreatePhishDomainRegistrations < ActiveRecord::Migration[8.1]
  def change
    create_table :phish_domain_registrations, id: :uuid do |t|
      t.string :domain, null: false

      # Registrar info
      t.string :registrar
      t.string :registrar_url

      # Registration dates
      t.datetime :registered_at
      t.datetime :updated_at_registry
      t.datetime :expires_at

      # Domain info
      t.jsonb :nameservers, default: []
      t.jsonb :status, default: []
      t.boolean :dnssec, default: false

      # Raw response storage
      t.jsonb :raw_data
      t.string :source                # "rdap" or "whois"

      # Cache management
      t.datetime :queried_at, null: false

      # Soft delete
      t.datetime :discarded_at

      t.timestamps
    end

    add_index :phish_domain_registrations, :domain, unique: true
    add_index :phish_domain_registrations, :registrar
    add_index :phish_domain_registrations, :expires_at
    add_index :phish_domain_registrations, :registered_at
    add_index :phish_domain_registrations, :queried_at
    add_index :phish_domain_registrations, :discarded_at
  end
end
