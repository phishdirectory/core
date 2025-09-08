# frozen_string_literal: true
#
module Api
module Entities
  class User < Base
    expose :id, documentation: { type: "Integer", desc: "User database ID" }
    expose :pd_id, documentation: { type: "String", desc: "Phish Directory unique ID", example: "PDU1ABC2DEF" }
    expose :email, documentation: { type: "String", desc: "User email address" }
    expose :first_name, documentation: { type: "String", desc: "User first name" }
    expose :last_name, documentation: { type: "String", desc: "User last name" }
    expose :full_name, documentation: { type: "String", desc: "User full name" }
    expose :username, documentation: { type: "String", desc: "Unique username" }
    expose :email_verified, documentation: { type: "Boolean", desc: "Whether email is verified" }
    expose :access_level, documentation: { type: "String", desc: "User access level", values: %w[user trusted admin superadmin owner] }
    expose :staff, documentation: { type: "Boolean", desc: "Whether user is staff" }
    expose :status, documentation: { type: "String", desc: "User account status", values: %w[active suspended deactivated] }
    expose :created_at, format_with: :iso8601, documentation: { type: "String", desc: "Account creation timestamp" }
    expose :updated_at, format_with: :iso8601, documentation: { type: "String", desc: "Last update timestamp" }
    expose :profile_photo_url, documentation: { type: "String", desc: "Profile photo URL", allow_blank: true }

    private

    def profile_photo_url
      object.has_profile_photo? ? object.public_avatar_url : nil
    end
  end
end
end
