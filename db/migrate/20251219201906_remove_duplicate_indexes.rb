class RemoveDuplicateIndexes < ActiveRecord::Migration[8.1]
  # These indexes are covered by composite indexes and are redundant.
  # Removing them improves write performance.

  def up
    remove_index :api_requests, name: :index_api_requests_on_authenticatable, if_exists: true
    remove_index :report_submissions, name: :index_report_submissions_on_case_id, if_exists: true
    remove_index :scam_classifications, name: :index_scam_classifications_on_user_id, if_exists: true
    remove_index :scam_skips, name: :index_scam_skips_on_user_id, if_exists: true
    remove_index :user_sessions, name: :index_user_sessions_on_user_id, if_exists: true
    remove_index :verdicts, name: :index_verdicts_on_scam_category, if_exists: true
  end

  def down
    add_index :api_requests, [:authenticatable_type, :authenticatable_id], name: :index_api_requests_on_authenticatable, if_not_exists: true
    add_index :report_submissions, :case_id, name: :index_report_submissions_on_case_id, if_not_exists: true
    add_index :scam_classifications, :user_id, name: :index_scam_classifications_on_user_id, if_not_exists: true
    add_index :scam_skips, :user_id, name: :index_scam_skips_on_user_id, if_not_exists: true
    add_index :user_sessions, :user_id, name: :index_user_sessions_on_user_id, if_not_exists: true
    add_index :verdicts, :scam_category, name: :index_verdicts_on_scam_category, if_not_exists: true
  end
end
