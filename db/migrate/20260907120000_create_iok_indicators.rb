# frozen_string_literal: true

# IOK ("Indicators of Kit") rules from phish-report/IOK.
#
# Each row is one Sigma-style rule that matches against the content of a
# fetched page. The parsed `detection` block is stored as JSON so the matcher
# can be rebuilt without re-reading the upstream YAML, and `content_digest`
# lets the sync job skip rows whose upstream file has not changed.
class CreateIokIndicators < ActiveRecord::Migration[8.1]
  def change
    create_table :iok_indicators, id: :uuid, default: -> { "gen_random_uuid()" } do |t|
      t.string   :slug, null: false
      t.string   :title, null: false
      t.text     :description
      t.string   :level
      t.jsonb    :reference_urls, default: [], null: false
      t.jsonb    :tags, default: [], null: false
      t.jsonb    :detection, default: {}, null: false
      t.string   :source_url
      t.string   :content_digest, null: false
      # "upstream" for a rule from the archive, "local" for one checked into
      # db/iok/local. The sync job's retire step is scoped to one source, so
      # without this the upstream pass would discard every local rule.
      #
      # Deliberately unindexed: a few hundred rows over three values is a
      # sequential scan whichever way it is written.
      t.string   :source, default: "upstream", null: false
      t.boolean  :enabled, default: true, null: false
      t.datetime :synced_at
      t.datetime :discarded_at

      t.timestamps
    end

    add_index :iok_indicators, :slug,
              unique: true,
              where: "discarded_at IS NULL",
              name: "index_iok_indicators_on_slug_kept"
    add_index :iok_indicators, :discarded_at
    add_index :iok_indicators, :enabled
    add_index :iok_indicators, :tags, using: :gin
  end
end
