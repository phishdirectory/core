class RemoveUnneededIndexes < ActiveRecord::Migration[8.1]
  def change
    remove_index :friendly_id_slugs, name: "index_friendly_id_slugs_on_slug_and_sluggable_type", column: [:slug, :sluggable_type]
    remove_index :user_api_keys, name: "index_user_api_keys_on_user_id", column: :user_id
  end
end
