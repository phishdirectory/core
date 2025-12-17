# frozen_string_literal: true

Rswag::Ui.configure do |c|
  # List the Swagger endpoints that you want to be documented through the
  # swagger-ui. The first parameter is the path (absolute or relative to the UI
  # host) to the corresponding endpoint and the second is a title that will be
  # displayed in the document selector.
  c.openapi_endpoint "/api-docs/v1/swagger.yaml", "phish.directory API V1"

  # Custom path for Swagger UI assets (since we mount at /docs/api)
  c.config_object["urls.primaryName"] = "phish.directory API V1"
end
