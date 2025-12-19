# frozen_string_literal: true

class CreatePhishCarriers < ActiveRecord::Migration[8.0]
  def change
    create_table :phish_carriers, id: :uuid do |t|
      t.string :name, null: false
      t.string :carrier_type # mobile, voip, landline, toll_free, unknown
      t.string :country_code # ISO 3166-1 alpha-2
      t.jsonb :metadata, default: {}
      t.integer :phone_numbers_count, default: 0

      t.datetime :discarded_at
      t.timestamps

      t.index :name, unique: true
      t.index :carrier_type
      t.index :country_code
      t.index :discarded_at
    end
  end
end
