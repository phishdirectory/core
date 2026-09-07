# frozen_string_literal: true

# Service API keys were stored in plaintext, unlike user API keys which have
# always been digested. Any database dump, backup, read replica or Blazer
# query yielded live, fully usable service credentials, and the admin UI
# rendered them in full on the key list forever.
#
# Digest the existing keys so they keep working, keep the last four characters
# so a key can still be recognised, then drop the plaintext.
#
# hash_key goes with it: it has been generated on every key since the table
# was created and is used for nothing but being displayed.
#
# Deploy note: this removes columns the previous release still reads. Run it
# after the new code is live, or accept a brief window during a rolling
# deploy where old instances raise on Service::Key.
class DigestServiceKeys < ActiveRecord::Migration[8.1]
  def up
    add_column :service_keys, :key_digest, :string
    add_column :service_keys, :key_hint, :string

    # A single UPDATE over a table with one row per issued service key.
    safety_assured do
      say_with_time "digesting existing service keys" do
        execute <<~SQL.squish
          UPDATE service_keys
          SET key_digest = encode(digest(api_key, 'sha256'), 'hex'),
              key_hint   = right(api_key, 4)
          WHERE api_key IS NOT NULL
        SQL
      end
    end

    # service_keys holds one row per issued service credential, so the full
    # table scan NOT NULL requires is negligible here.
    safety_assured do
      change_column_null :service_keys, :key_digest, false
      # Same reasoning: too few rows for a non-concurrent build to matter, and
      # keeping it in this transaction means the column is never unindexed.
      add_index :service_keys, :key_digest, unique: true
    end

    safety_assured do
      remove_column :service_keys, :api_key
      remove_column :service_keys, :hash_key
    end
  end

  def down
    add_column :service_keys, :api_key, :string
    add_column :service_keys, :hash_key, :string

    # The plaintext cannot be recovered from a digest. Existing keys are
    # reissued rather than restored.
    safety_assured do
      say_with_time "reissuing service keys (previous values are unrecoverable)" do
        execute <<~SQL.squish
          UPDATE service_keys
          SET api_key  = encode(gen_random_bytes(24), 'hex'),
              hash_key = encode(gen_random_bytes(32), 'hex')
        SQL
      end
    end

    safety_assured do
      change_column_null :service_keys, :api_key, false
      change_column_null :service_keys, :hash_key, false
    end
    safety_assured { add_index :service_keys, :api_key, unique: true }

    remove_index :service_keys, :key_digest
    remove_column :service_keys, :key_digest
    remove_column :service_keys, :key_hint
  end
end
