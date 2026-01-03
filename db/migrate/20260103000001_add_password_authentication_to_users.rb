# frozen_string_literal: true

class AddPasswordAuthenticationToUsers < ActiveRecord::Migration[8.1]
  def change
    # Adding nullable columns is safe
    safety_assured do
      change_table :users, bulk: true do |t|
        # Password authentication (bcrypt)
        t.string :password_digest

        # Email confirmation flow
        t.string :confirmation_token
        t.datetime :confirmation_sent_at
        t.datetime :confirmed_at

        # Password reset flow
        t.string :password_reset_token
        t.datetime :password_reset_sent_at
        t.datetime :password_reset_expires_at
      end
    end

    # Safe to add non-concurrently since columns are new and empty
    safety_assured do
      add_index :users, :confirmation_token, unique: true
      add_index :users, :password_reset_token, unique: true
    end
  end
end
