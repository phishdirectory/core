# frozen_string_literal: true

GrapeSwaggerRails.options.url      = "/api/v1/swagger_doc"
GrapeSwaggerRails.options.app_url  = Rails.env.production? ? "https://phish.directory" : "http://localhost:3000"
GrapeSwaggerRails.options.app_name = "Phish Directory API"
