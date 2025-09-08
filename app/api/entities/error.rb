# frozen_string_literal: true

module Entities
  class Error < Base
    expose :success, documentation: { type: "Boolean", desc: "Always false for errors", default: false }
    expose :error do
      expose :message, documentation: { type: "String", desc: "Error message" }
      expose :details, documentation: { type: "Array[String]", desc: "Detailed error information", is_array: true }
    end
  end
end