# frozen_string_literal: true

class ApplicationRecord < ActiveRecord::Base
  primary_abstract_class

  # Find an existing record by its natural key, or create it.
  #
  # Rails' own create_or_find_by! is the wrong tool for any model that also
  # declares `validates ..., uniqueness: true`. It attempts the INSERT first
  # and rescues ActiveRecord::RecordNotUnique from the database, but the
  # uniqueness validation raises ActiveRecord::RecordInvalid before the INSERT
  # is ever issued. The rescue never fires, so every lookup of a record that
  # already exists fails instead of returning it.
  #
  # Find first, create if absent, and fall back to a second find only when the
  # failure really was a concurrent writer getting there first. A genuine
  # validation failure (bad format, missing field) still raises.
  def self.find_or_create_by_natural_key!(attributes)
    find_by(attributes) || create!(attributes)
  rescue ActiveRecord::RecordInvalid, ActiveRecord::RecordNotUnique
    find_by(attributes) || raise
  end
end
