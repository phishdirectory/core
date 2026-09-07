# frozen_string_literal: true

# Magic link, password reset and email confirmation tokens were stored in
# plaintext. Read access to the users table was therefore account takeover for
# every user with a link outstanding: copy the token, visit the URL, be them.
#
# These are bearer tokens we generate and then compare against. We never need
# to read one back, so a digest is the right shape, exactly as UserApiKey
# already does. Encryption would also work but needlessly keeps the value
# recoverable.
#
# Existing tokens are digested rather than dropped, so links already sitting in
# someone's inbox keep working.
class DigestUserAuthTokens < ActiveRecord::Migration[8.1]
  TOKENS = %w[magic_link_token password_reset_token confirmation_token].freeze

  def up
    TOKENS.each { |token| add_column :users, "#{token}_digest", :string }

    safety_assured do
      say_with_time "digesting outstanding auth tokens" do
        execute <<~SQL.squish
          UPDATE users SET
            magic_link_token_digest =
              CASE WHEN magic_link_token IS NOT NULL
                   THEN encode(digest(magic_link_token, 'sha256'), 'hex') END,
            password_reset_token_digest =
              CASE WHEN password_reset_token IS NOT NULL
                   THEN encode(digest(password_reset_token, 'sha256'), 'hex') END,
            confirmation_token_digest =
              CASE WHEN confirmation_token IS NOT NULL
                   THEN encode(digest(confirmation_token, 'sha256'), 'hex') END
        SQL
      end

      # users is small enough that building these inside the transaction costs
      # nothing, and it keeps the tokens indexed at every point.
      TOKENS.each do |token|
        add_index :users, "#{token}_digest", unique: true
        remove_column :users, token
      end
    end
  end

  def down
    safety_assured do
      TOKENS.each do |token|
        add_column :users, token, :string
        add_index :users, token, unique: true
        remove_index :users, "#{token}_digest"
        remove_column :users, "#{token}_digest"
      end
    end
  end
end
