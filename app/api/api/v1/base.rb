# frozen_string_literal: true

module API
  module V1
    class Base < Grape::API
      version 'v1', using: :path

      # Mount individual resource APIs
      mount API::V1::Health
      mount API::V1::Auth
      mount API::V1::Users
      mount API::V1::ApiKeys
    end
  end
end