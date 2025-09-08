# == Schema Information
#
# Table name: user_api_keys
#
#  id           :bigint           not null, primary key
#  active       :boolean          default(TRUE), not null
#  expires_at   :datetime
#  key_digest   :string           not null
#  last_used_at :datetime
#  name         :string           not null
#  created_at   :datetime         not null
#  updated_at   :datetime         not null
#  user_id      :bigint           not null
#
# Indexes
#
#  index_user_api_keys_on_expires_at          (expires_at)
#  index_user_api_keys_on_key_digest          (key_digest) UNIQUE
#  index_user_api_keys_on_user_id             (user_id)
#  index_user_api_keys_on_user_id_and_active  (user_id,active)
#
# Foreign Keys
#
#  fk_rails_...  (user_id => users.id)
#
require 'rails_helper'

RSpec.describe UserApiKey, type: :model do
  pending "add some examples to (or delete) #{__FILE__}"
end
