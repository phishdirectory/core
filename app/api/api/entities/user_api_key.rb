# frozen_string_literal: true

module Api
  module Entities
    class UserApiKey < Base
      expose :id, documentation: { type: "Integer", desc: "API key database ID" }
      expose :name, documentation: { type: "String", desc: "API key name/description" }
      expose :last_used_at, format_with: :iso8601, documentation: { type: "String", desc: "Last usage timestamp", allow_blank: true }
      expose :expires_at, format_with: :iso8601, documentation: { type: "String", desc: "Expiration timestamp", allow_blank: true }
      expose :active, documentation: { type: "Boolean", desc: "Whether API key is active" }
      expose :created_at, format_with: :iso8601, documentation: { type: "String", desc: "Creation timestamp" }

      # Only expose the raw key when it's just been created
      expose :key, if: lambda { |instance, options| options[:show_key] == true },
                   documentation: { type: "String", desc: "API key (only shown at creation)", example: "pd_aBcD..." }

      private

      def key
        object.raw_key
      end


    end
  end
end
