# frozen_string_literal: true

require "test_helper"

class Iok::ConditionTest < ActiveSupport::TestCase
  # Stands in for a compiled rule: the condition only asks which selections
  # exist and which of them matched.
  class Context
    def initialize(results)
      @results = results
    end

    def names
      @results.keys
    end

    def matched?(name)
      @results.fetch(name, false)
    end
  end

  def evaluate(source, results)
    Iok::Condition.new(source).matches?(Context.new(results))
  end

  # ===========================================
  # Boolean operators
  # ===========================================

  test "a bare identifier is the selection's own result" do
    assert evaluate("selection", "selection" => true)
    assert_not evaluate("selection", "selection" => false)
  end

  test "and requires every operand" do
    assert evaluate("a and b and c", "a" => true, "b" => true, "c" => true)
    assert_not evaluate("a and b and c", "a" => true, "b" => false, "c" => true)
  end

  test "or requires one operand" do
    assert evaluate("a or b", "a" => false, "b" => true)
    assert_not evaluate("a or b", "a" => false, "b" => false)
  end

  test "not negates" do
    assert evaluate("a and not b", "a" => true, "b" => false)
    assert_not evaluate("a and not b", "a" => true, "b" => true)
  end

  test "and binds tighter than or" do
    # Read as (a and b) or c, so c alone is enough.
    assert evaluate("a and b or c", "a" => false, "b" => false, "c" => true)
    assert_not evaluate("a and b or c", "a" => true, "b" => false, "c" => false)
  end

  test "parentheses override precedence" do
    assert_not evaluate("a and (b or c)", "a" => true, "b" => false, "c" => false)
    assert evaluate("a and (b or c)", "a" => true, "b" => false, "c" => true)
  end

  test "not applies to a parenthesised group" do
    # From originaltrial-token.yml upstream.
    results = { "originTrialToken" => true, "officialDomain" => false, "officialSubdomain" => false }
    assert evaluate("originTrialToken and not (officialDomain or officialSubdomain)", results)

    results["officialDomain"] = true
    assert_not evaluate("originTrialToken and not (officialDomain or officialSubdomain)", results)
  end

  test "nested parentheses evaluate correctly" do
    source = "jsFile and favicon and ((discordBackground and fakeCaptchaButton) or (linkAccountButton))"

    assert evaluate(
      source,
      "jsFile" => true, "favicon" => true,
      "discordBackground" => false, "fakeCaptchaButton" => false, "linkAccountButton" => true
    )
    assert_not evaluate(
      source,
      "jsFile" => true, "favicon" => true,
      "discordBackground" => true, "fakeCaptchaButton" => false, "linkAccountButton" => false
    )
  end

  # ===========================================
  # Quantifiers
  # ===========================================

  test "all of them requires every selection" do
    assert evaluate("all of them", "a" => true, "b" => true)
    assert_not evaluate("all of them", "a" => true, "b" => false)
  end

  test "1 of them requires any selection" do
    assert evaluate("1 of them", "a" => false, "b" => true)
    assert_not evaluate("1 of them", "a" => false, "b" => false)
  end

  test "any of them behaves like 1 of them" do
    assert evaluate("any of them", "a" => false, "b" => true)
    assert_not evaluate("any of them", "a" => false, "b" => false)
  end

  test "a numeric quantifier is a minimum" do
    assert evaluate("2 of them", "a" => true, "b" => true, "c" => false)
    assert_not evaluate("3 of them", "a" => true, "b" => true, "c" => false)
  end

  test "1 of a glob only considers matching selection names" do
    # From upstream: `notfoundPageFragments and (1 of php*)`.
    results = { "notfoundPageFragments" => true, "phpMyAdmin" => false, "phpInfo" => true }
    assert evaluate("notfoundPageFragments and (1 of php*)", results)

    results["phpInfo"] = false
    assert_not evaluate("notfoundPageFragments and (1 of php*)", results)
  end

  test "all of a glob only considers matching selection names" do
    assert evaluate("all of php*", "phpOne" => true, "phpTwo" => true, "other" => false)
    assert_not evaluate("all of php*", "phpOne" => true, "phpTwo" => false, "other" => true)
  end

  test "quantifier words are still usable as selection names" do
    # `all` is only a keyword when `of` follows it.
    assert evaluate("all and any", "all" => true, "any" => true)
    assert_not evaluate("all and any", "all" => true, "any" => false)
  end

  # ===========================================
  # Lists and parsing failures
  # ===========================================

  test "a list of conditions is an or" do
    assert evaluate([ "a", "b" ], "a" => false, "b" => true)
    assert_not evaluate([ "a", "b" ], "a" => false, "b" => false)
  end

  test "referenced_names lists identifiers but not glob targets" do
    condition = Iok::Condition.new("a and not b and (1 of php*)")

    assert_equal %w[a b], condition.referenced_names.sort
  end

  test "an unbalanced parenthesis is rejected" do
    assert_raises(Iok::Condition::ParseError) { Iok::Condition.new("(a and b") }
  end

  test "a trailing operator is rejected" do
    assert_raises(Iok::Condition::ParseError) { Iok::Condition.new("a and") }
  end

  test "a dangling operand is rejected" do
    assert_raises(Iok::Condition::ParseError) { Iok::Condition.new("a b") }
  end

  test "an empty condition is rejected" do
    assert_raises(Iok::Condition::ParseError) { Iok::Condition.new("   ") }
    assert_raises(Iok::Condition::ParseError) { Iok::Condition.new([]) }
  end

  test "a non-string condition is rejected" do
    assert_raises(Iok::Condition::ParseError) { Iok::Condition.new({ "a" => 1 }) }
  end

  test "an unknown selection name is false rather than an error" do
    assert_not evaluate("missing", "a" => true)
  end
end
