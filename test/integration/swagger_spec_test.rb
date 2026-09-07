# frozen_string_literal: true

require "test_helper"
require "yaml"

# The OpenAPI spec is hand written, so it drifts silently: for a long time it
# described ten endpoints while the application served thirty, and the four
# result schemas had fallen behind their serializers. These tests fail the build
# instead, so a new endpoint cannot ship undocumented.
class SwaggerSpecTest < ActiveSupport::TestCase
  SPEC_PATH = Rails.root.join("swagger/v1/swagger.yaml")
  VERBS = %w[get post put patch delete].freeze

  # Documented as an operation but deliberately not one, so the sync check must
  # not read it as a verb.
  PATH_LEVEL_KEYS = %w[parameters summary description servers].freeze

  def spec
    @spec ||= YAML.safe_load_file(SPEC_PATH, aliases: true)
  end

  # Every routed [path, verb] under /api/v1, with Rails' :id rewritten to the
  # OpenAPI {id} form.
  def routed_operations
    Rails.application.routes.routes.filter_map do |route|
      path = route.path.spec.to_s.sub(/\(\.:format\)\z/, "")
      next unless path.start_with?("/api/v1/")

      verb = route.verb.to_s.downcase
      next if verb.blank?

      [ path.delete_prefix("/api/v1").gsub(/:([a-z_]+)/) { "{#{$1}}" }, verb ]
    end.to_set
  end

  def documented_operations
    spec["paths"].flat_map do |path, operations|
      operations.keys.select { |key| VERBS.include?(key) }.map { |verb| [ path, verb ] }
    end.to_set
  end

  # ===========================================
  # The spec is well formed
  # ===========================================

  test "the spec parses" do
    assert spec.is_a?(Hash)
    assert_equal "3.0.3", spec["openapi"]
  end

  test "every $ref resolves" do
    refs = []
    walk = lambda do |node|
      case node
      when Hash then node.each { |key, value| key == "$ref" ? refs << value : walk.call(value) }
      when Array then node.each { |value| walk.call(value) }
      end
    end
    walk.call(spec)

    broken = refs.uniq.reject do |ref|
      ref.delete_prefix("#/").split("/").reduce(spec) { |node, seg| node.is_a?(Hash) ? node[seg] : nil }
    end

    assert_empty broken, "these $refs point at nothing: #{broken.join(", ")}"
  end

  test "every tag an operation uses is declared" do
    declared = spec["tags"].map { |tag| tag["name"] }.to_set
    used = spec["paths"].values.flat_map do |operations|
      operations.filter_map { |verb, op| op["tags"] if VERBS.include?(verb) }
    end.flatten.to_set

    assert_empty (used - declared).to_a, "undeclared tags"
    assert_empty (declared - used).to_a, "declared tags that nothing uses"
  end

  test "a path only holds operations and the keys OpenAPI allows beside them" do
    spec["paths"].each do |path, operations|
      unexpected = operations.keys - VERBS - PATH_LEVEL_KEYS
      assert_empty unexpected, "#{path} holds unexpected keys: #{unexpected.join(", ")}"
    end
  end

  # ===========================================
  # The spec matches the application
  # ===========================================

  test "every API endpoint the application serves is documented" do
    missing = (routed_operations - documented_operations).to_a.sort

    assert_empty missing,
                 "these endpoints are routed but absent from swagger/v1/swagger.yaml: " \
                 "#{missing.map { |path, verb| "#{verb.upcase} #{path}" }.join(", ")}"
  end

  test "every documented endpoint is one the application actually serves" do
    fictional = (documented_operations - routed_operations).to_a.sort

    assert_empty fictional,
                 "these endpoints are documented but not routed: " \
                 "#{fictional.map { |path, verb| "#{verb.upcase} #{path}" }.join(", ")}"
  end

  test "every operation carries a unique operationId" do
    ids = spec["paths"].values.flat_map do |operations|
      operations.filter_map { |verb, op| op["operationId"] if VERBS.include?(verb) }
    end

    assert_equal documented_operations.size, ids.size, "every operation needs an operationId"
    assert_equal ids.uniq.size, ids.size, "operationIds must be unique: #{(ids - ids.uniq).uniq.join(", ")}"
  end

  # ===========================================
  # The schemas match the serializers
  # ===========================================

  test "the verdict enums list every classification a record can carry" do
    %w[DomainResult UrlResult PhoneResult EmailResult].each do |schema|
      documented = spec.dig("components", "schemas", schema, "properties", "verdict", "enum")

      assert_equal Verdict::CLASSIFICATIONS.sort, documented.sort,
                   "#{schema} verdict enum has drifted from Verdict::CLASSIFICATIONS"
    end
  end

  test "trusted sources may only be offered the classifications the service accepts" do
    documented = spec.dig("components", "schemas", "SourceEntry", "properties", "classification", "enum")

    assert_equal TrustedSourceUpsertService::CLASSIFICATIONS.sort, documented.sort
  end

  test "the documented webhook events match the model" do
    documented = spec.dig(
      "components", "schemas", "Webhook", "properties", "events", "items", "enum"
    )

    assert_equal Service::Webhook::EVENTS.sort, documented.sort
  end

  test "the documented access levels match the model" do
    documented = spec.dig("components", "schemas", "User", "properties", "access_level", "enum")

    assert_equal User::ACCESS_LEVELS.sort, documented.sort
  end

  test "the trusted source entry cap matches the service" do
    %w[domains urls emails phone_numbers].each do |type|
      documented = spec.dig(
        "paths", "/source/#{type}", "post", "requestBody",
        "content", "application/json", "schema", "properties", type, "maxItems"
      )

      assert_equal TrustedSourceUpsertService::MAX_ENTRIES, documented,
                   "/source/#{type} documents the wrong entry cap"
    end
  end
end
