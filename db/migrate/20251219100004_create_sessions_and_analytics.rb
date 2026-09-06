# frozen_string_literal: true

class CreateSessionsAndAnalytics < ActiveRecord::Migration[8.1]
  def change
    # Rails session store (for web sessions)
    create_table :sessions, id: :uuid do |t|
      t.string :session_id, null: false
      t.text :data

      t.timestamps
    end

    add_index :sessions, :session_id, unique: true
    add_index :sessions, :updated_at

    # Ahoy visits
    create_table :ahoy_visits, id: :uuid do |t|
      t.string :visit_token
      t.string :visitor_token
      t.uuid :user_id

      # Network
      t.string :ip
      t.text :user_agent
      t.text :referrer
      t.string :referring_domain
      t.text :landing_page

      # Browser/Device
      t.string :browser
      t.string :os
      t.string :device_type

      # Location
      t.string :country
      t.string :region
      t.string :city
      t.float :latitude
      t.float :longitude

      # UTM params
      t.string :utm_source
      t.string :utm_medium
      t.string :utm_term
      t.string :utm_content
      t.string :utm_campaign

      # App info
      t.string :app_version
      t.string :os_version
      t.string :platform

      t.datetime :started_at
    end

    add_index :ahoy_visits, :visit_token, unique: true
    add_index :ahoy_visits, [ :visitor_token, :started_at ]
    add_index :ahoy_visits, :user_id

    # Ahoy events
    create_table :ahoy_events, id: :uuid do |t|
      t.uuid :visit_id
      t.uuid :user_id
      t.string :name
      t.jsonb :properties
      t.datetime :time
    end

    add_index :ahoy_events, [ :name, :time ]
    add_index :ahoy_events, :properties, using: :gin, opclass: :jsonb_path_ops
    add_index :ahoy_events, :user_id
    add_index :ahoy_events, :visit_id

    # Ahoy messages (email tracking)
    create_table :ahoy_messages, id: :uuid do |t|
      t.string :user_type
      t.uuid :user_id
      t.text :to_ciphertext     # Encrypted email address
      t.string :to_bidx         # Blind index for search
      t.string :mailer
      t.text :subject
      t.datetime :sent_at
      t.string :campaign
    end

    add_index :ahoy_messages, [ :user_type, :user_id ]
    add_index :ahoy_messages, :to_bidx
    add_index :ahoy_messages, :campaign

    # Ahoy clicks (link tracking)
    create_table :ahoy_clicks, id: :uuid do |t|
      t.string :campaign
      t.string :token
    end

    add_index :ahoy_clicks, :campaign
  end
end
