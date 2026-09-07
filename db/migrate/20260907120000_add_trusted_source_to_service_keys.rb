# frozen_string_literal: true

# Marks a service key as belonging to a trusted source.
#
# A trusted source maintains its own curated list and pushes verdicts to us,
# rather than asking us for one. Api::V1::Source::EntriesController writes those
# submissions straight to the database, so the flag gates a write path and not
# just a read scope. It lives on the key, not on the service, so a partner can
# hold a normal read key and a separate ingestion key.
#
# No index: service_keys holds a handful of rows per service, and every lookup
# already goes through the unique key_digest index.
class AddTrustedSourceToServiceKeys < ActiveRecord::Migration[8.1]
  def change
    add_column :service_keys, :trusted_source, :boolean, default: false, null: false
  end
end
