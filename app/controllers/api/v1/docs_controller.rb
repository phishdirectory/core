# frozen_string_literal: true

module Api
  module V1
    class DocsController < BaseController
      skip_before_action :authenticate_api_request!
      skip_before_action :check_rate_limit

      def index
        api_spec = {
          openapi: "3.0.3",
          info: {
            title: "Phish Directory Core API",
            description: "API for Phish Directory authentication and user management",
            version: "1.0.0",
            contact: {
              name: "API Support",
              email: "support@phish.directory"
            }
          },
          servers: [
            {
              url: "#{request.base_url}/api/v1",
              description: "Current environment"
            }
          ],
          security: [
            {
              ApiKeyAuth: []
            }
          ],
          components: {
            securitySchemes: {
              ApiKeyAuth: {
                type: "apiKey",
                in: "header",
                name: "X-API-Key"
              }
            },
            schemas: schemas,
            responses: responses
          },
          paths: paths
        }

        render_success(api_spec)
      end

      private

      def schemas
        {
          User: {
            type: "object",
            properties: {
              id: { type: "integer", example: 1 },
              pd_id: { type: "string", example: "PDU1ABC2DEF" },
              email: { type: "string", format: "email", example: "user@example.com" },
              first_name: { type: "string", example: "John" },
              last_name: { type: "string", example: "Doe" },
              full_name: { type: "string", example: "John Doe" },
              username: { type: "string", example: "johndoe" },
              email_verified: { type: "boolean", example: true },
              access_level: { type: "string", enum: ["user", "trusted", "admin", "superadmin", "owner"] },
              staff: { type: "boolean", example: false },
              status: { type: "string", enum: ["active", "suspended", "deactivated"] },
              created_at: { type: "string", format: "date-time" },
              updated_at: { type: "string", format: "date-time" }
            }
          },
          Error: {
            type: "object",
            properties: {
              success: { type: "boolean", example: false },
              error: {
                type: "object",
                properties: {
                  message: { type: "string", example: "Validation failed" },
                  details: {
                    type: "array",
                    items: { type: "string" },
                    example: ["Email can't be blank"]
                  }
                }
              }
            }
          },
          Success: {
            type: "object",
            properties: {
              success: { type: "boolean", example: true },
              data: { type: "object" }
            }
          }
        }
      end

      def responses
        {
          NotFound: {
            description: "Resource not found",
            content: {
              "application/json" => {
                schema: { "$ref" => "#/components/schemas/Error" }
              }
            }
          },
          Unauthorized: {
            description: "Authentication required",
            content: {
              "application/json" => {
                schema: { "$ref" => "#/components/schemas/Error" }
              }
            }
          },
          ValidationError: {
            description: "Validation failed",
            content: {
              "application/json" => {
                schema: { "$ref" => "#/components/schemas/Error" }
              }
            }
          }
        }
      end

      def paths
        {
          "/health" => {
            get: {
              tags: ["System"],
              summary: "Health check",
              description: "Check API health status",
              security: [],
              responses: {
                "200" => {
                  description: "System is healthy",
                  content: {
                    "application/json" => {
                      schema: { "$ref" => "#/components/schemas/Success" }
                    }
                  }
                }
              }
            }
          },
          "/auth/authenticate" => {
            post: {
              tags: ["Authentication"],
              summary: "Authenticate user",
              description: "Authenticate with email (sends magic link) or magic link token",
              security: [],
              requestBody: {
                required: true,
                content: {
                  "application/json" => {
                    schema: {
                      type: "object",
                      oneOf: [
                        {
                          properties: {
                            email: { type: "string", format: "email" }
                          },
                          required: ["email"]
                        },
                        {
                          properties: {
                            magic_link_token: { type: "string" }
                          },
                          required: ["magic_link_token"]
                        }
                      ]
                    }
                  }
                }
              },
              responses: {
                "200" => {
                  description: "Authentication successful or magic link sent",
                  content: {
                    "application/json" => {
                      schema: { "$ref" => "#/components/schemas/Success" }
                    }
                  }
                },
                "400" => { "$ref" => "#/components/responses/ValidationError" },
                "401" => { "$ref" => "#/components/responses/Unauthorized" }
              }
            }
          },
          "/users/{id}" => {
            get: {
              tags: ["Users"],
              summary: "Get user by ID",
              description: "Retrieve user information by PD ID",
              parameters: [
                {
                  name: "id",
                  in: "path",
                  required: true,
                  schema: { type: "string" },
                  example: "PDU1ABC2DEF"
                }
              ],
              responses: {
                "200" => {
                  description: "User information",
                  content: {
                    "application/json" => {
                      schema: {
                        allOf: [
                          { "$ref" => "#/components/schemas/Success" },
                          {
                            properties: {
                              data: { "$ref" => "#/components/schemas/User" }
                            }
                          }
                        ]
                      }
                    }
                  }
                },
                "404" => { "$ref" => "#/components/responses/NotFound" },
                "401" => { "$ref" => "#/components/responses/Unauthorized" }
              }
            }
          },
          "/users" => {
            post: {
              tags: ["Users"],
              summary: "Create user",
              description: "Create a new user account",
              requestBody: {
                required: true,
                content: {
                  "application/json" => {
                    schema: {
                      type: "object",
                      properties: {
                        user: {
                          type: "object",
                          properties: {
                            first_name: { type: "string", example: "John" },
                            last_name: { type: "string", example: "Doe" },
                            email: { type: "string", format: "email", example: "john@example.com" }
                          },
                          required: ["first_name", "last_name", "email"]
                        }
                      }
                    }
                  }
                }
              },
              responses: {
                "201" => {
                  description: "User created successfully",
                  content: {
                    "application/json" => {
                      schema: {
                        allOf: [
                          { "$ref" => "#/components/schemas/Success" },
                          {
                            properties: {
                              data: {
                                type: "object",
                                properties: {
                                  message: { type: "string" },
                                  user: { "$ref" => "#/components/schemas/User" }
                                }
                              }
                            }
                          }
                        ]
                      }
                    }
                  }
                },
                "422" => { "$ref" => "#/components/responses/ValidationError" },
                "401" => { "$ref" => "#/components/responses/Unauthorized" }
              }
            }
          }
        }
      end
    end
  end
end