module Api
  module Entities
    # The `ApiError` Entity inherits from Grape::Entity rather than our custom
    # Base class because its response structure is fairly different compared to
    # successful (200) responses.
    class ApiError < Grape::Entity
      expose :message, documentation: {
        type: String
      }

      def self.entity_name
        "Error Response"
      end

    end
  end
end
