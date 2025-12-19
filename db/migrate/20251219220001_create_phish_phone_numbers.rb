# frozen_string_literal: true

class CreatePhishPhoneNumbers < ActiveRecord::Migration[8.0]
  def change
    create_table :phish_phone_numbers, id: :uuid do |t|
      t.string :phone_number, null: false # E.164 format (+14155551234)
      t.uuid :verdict_id
      t.uuid :carrier_id
      t.datetime :last_checked_at
      t.datetime :last_seen_at
      t.string :phone_type # mobile, voip, landline, toll_free, unknown
      t.string :country_code # ISO 3166-1 alpha-2

      # Scam classification fields (same as domains/urls)
      t.string :scam_category
      t.string :scam_subcategory
      t.datetime :marked_clean_at
      t.uuid :marked_clean_by_id

      t.datetime :discarded_at
      t.timestamps

      t.index :phone_number, unique: true
      t.index :verdict_id
      t.index :carrier_id
      t.index :last_checked_at
      t.index :last_seen_at
      t.index :phone_type
      t.index :country_code
      t.index :scam_category
      t.index :scam_subcategory
      t.index :marked_clean_at
      t.index :marked_clean_by_id
      t.index :discarded_at
    end

    # safety_assured: This is a new table with no existing data
    safety_assured do
      add_foreign_key :phish_phone_numbers, :verdicts
      add_foreign_key :phish_phone_numbers, :phish_carriers, column: :carrier_id
      add_foreign_key :phish_phone_numbers, :users, column: :marked_clean_by_id
    end
  end
end
