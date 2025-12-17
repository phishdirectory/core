# frozen_string_literal: true

# SoftDeletable: Provides soft delete functionality using Discard
#
# Instead of permanently deleting records, marks them as "discarded"
# with a timestamp. Records can be recovered if needed.
#
# Usage:
#   class PhishDomain < ApplicationRecord
#     include SoftDeletable
#   end
#
# Then in your model:
#   domain.discard         # Soft delete
#   domain.undiscard       # Restore
#   domain.discarded?      # Check if soft deleted
#   domain.kept?           # Check if not soft deleted
#
# Scopes:
#   PhishDomain.kept       # Only non-deleted records (default)
#   PhishDomain.discarded  # Only soft-deleted records
#   PhishDomain.with_discarded  # All records including deleted
#
# Note: Requires a `discarded_at` timestamp column in the table
# Migration: add_column :table_name, :discarded_at, :datetime
#            add_index :table_name, :discarded_at

module SoftDeletable
  extend ActiveSupport::Concern

  included do
    include Discard::Model

    # Default scope excludes discarded records
    default_scope -> { kept }
  end

  # Permanently delete the record (bypass soft delete)
  def destroy_permanently!
    self.class.unscoped { destroy! }
  end

  # Alias for more intuitive API
  def soft_delete
    discard
  end

  def soft_delete!
    discard!
  end

  def restore
    undiscard
  end

  def restore!
    undiscard!
  end

  class_methods do
    # Find a discarded record by ID
    def find_discarded(id)
      with_discarded.discarded.find(id)
    end

    # Restore a discarded record by ID
    def restore_record(id)
      find_discarded(id).undiscard
    end

    # Permanently delete all discarded records older than duration
    def purge_discarded(older_than: 30.days)
      with_discarded
        .discarded
        .where("discarded_at < ?", older_than.ago)
        .destroy_all
    end
  end
end
