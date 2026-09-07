# frozen_string_literal: true

require "test_helper"

class Iok::RuleTest < ActiveSupport::TestCase
  def rule(detection, slug: "test-rule", title: "Test rule")
    Iok::Rule.new(slug: slug, title: title, detection: detection)
  end

  def matches?(detection, snapshot)
    rule(detection).matches?(snapshot)
  end

  # ===========================================
  # Comparators
  # ===========================================

  test "contains matches a substring of the field" do
    detection = { "sel" => { "html|contains" => "phishing-kit" }, "condition" => "sel" }

    assert matches?(detection, "html" => "<p>phishing-kit</p>")
    assert_not matches?(detection, "html" => "<p>something else</p>")
  end

  test "startswith and endswith anchor the comparison" do
    detection = {
      "start" => { "hostname|startswith" => "login." },
      "finish" => { "hostname|endswith" => ".example.com" },
      "condition" => "start and finish"
    }

    assert matches?(detection, "hostname" => "login.corp.example.com")
    assert_not matches?(detection, "hostname" => "corp.example.com")
  end

  test "re matches a regular expression" do
    detection = { "sel" => { "html|re" => 'data-content="([0-9]{2,3}).+"' }, "condition" => "sel" }

    assert matches?(detection, "html" => '<div data-content="123 more">')
    assert_not matches?(detection, "html" => '<div data-content="1">')
  end

  test "a matcher with no modifier is an exact comparison" do
    detection = { "sel" => { "hostname" => "example.com" }, "condition" => "sel" }

    assert matches?(detection, "hostname" => "example.com")
    assert_not matches?(detection, "hostname" => "www.example.com")
  end

  # IOK builds its evaluator with evaluator.CaseSensitive, but sigma-go's
  # case-sensitive comparator table has no entry for the default comparison, so
  # only the explicit comparators are case sensitive.
  test "contains is case sensitive but an exact comparison is not" do
    contains = { "sel" => { "html|contains" => "LoginForm" }, "condition" => "sel" }
    assert_not matches?(contains, "html" => "<div>loginform</div>")

    exact = { "sel" => { "hostname" => "Example.COM" }, "condition" => "sel" }
    assert matches?(exact, "hostname" => "example.com")
  end

  # ===========================================
  # Value lists and the all modifier
  # ===========================================

  test "a list of values matches when any one matches" do
    detection = { "sel" => { "html|contains" => [ "absent", "present" ] }, "condition" => "sel" }

    assert matches?(detection, "html" => "present")
  end

  test "the all modifier requires every value to match" do
    detection = {
      "sel" => { "html|contains|all" => [ "first", "second" ] },
      "condition" => "sel"
    }

    assert matches?(detection, "html" => "first and second")
    assert_not matches?(detection, "html" => "first only")
  end

  test "several field matchers in one selection are combined with and" do
    detection = {
      "sel" => { "html|contains" => "kit", "title|contains" => "Sign in" },
      "condition" => "sel"
    }

    assert matches?(detection, "html" => "kit", "title" => [ "Sign in" ])
    assert_not matches?(detection, "html" => "kit", "title" => [ "Home" ])
  end

  test "a selection given as a list of mappings is an or" do
    detection = {
      "sel" => [
        { "html|contains" => "first-kit" },
        { "html|contains" => "second-kit" }
      ],
      "condition" => "sel"
    }

    assert matches?(detection, "html" => "second-kit")
    assert_not matches?(detection, "html" => "third-kit")
  end

  # ===========================================
  # Multi-valued fields
  # ===========================================

  test "a list-valued field matches when any of its values matches" do
    detection = { "sel" => { "requests|contains" => "cryptocoins.css" }, "condition" => "sel" }
    snapshot = {
      "requests" => [ "https://evil.test/app.js", "https://evil.test/css/cryptocoins.css" ]
    }

    assert matches?(detection, snapshot)
  end

  test "the all modifier can be satisfied across different values of one field" do
    detection = {
      "sel" => { "requests|endswith|all" => [ "/a.js", "/b.js" ] },
      "condition" => "sel"
    }

    assert matches?(detection, "requests" => [ "https://evil.test/a.js", "https://evil.test/b.js" ])
    assert_not matches?(detection, "requests" => [ "https://evil.test/a.js" ])
  end

  test "an absent field never matches" do
    detection = { "sel" => { "cookies|startswith" => "PHPSESSID=" }, "condition" => "sel" }

    assert_not matches?(detection, "html" => "anything")
  end

  # ===========================================
  # A real rule from the corpus
  # ===========================================

  test "evaluates a rule taken from the upstream corpus" do
    # indicators/apple-icloud-467ab986.yml
    detection = {
      "stylesheet" => { "html|contains" => 'href="assets/layout/apple.css"' },
      "titleClassStyle" => { "html|contains" => ".Estilo2" },
      "imageAjaxLoader" => { "html|contains" => 'src="assets/img/ajax-loader.gif"' },
      "condition" => "stylesheet and titleClassStyle and imageAjaxLoader"
    }

    page = <<~HTML
      <link rel="stylesheet" href="assets/layout/apple.css">
      <style>.Estilo2 { color: red }</style>
      <img src="assets/img/ajax-loader.gif">
    HTML

    assert matches?(detection, "html" => page)
    assert_not matches?(detection, "html" => page.sub(".Estilo2", ".Something"))
  end

  test "accepts a page snapshot as well as a hash" do
    snapshot = Iok::PageSnapshot.new(
      url: "https://evil.test/",
      fields: { "html" => [ "<p>kit</p>" ] }
    )
    detection = { "sel" => { "html|contains" => "kit" }, "condition" => "sel" }

    assert rule(detection).matches?(snapshot)
  end

  # ===========================================
  # Compile-time validation
  # ===========================================

  test "rejects an unknown field" do
    error = assert_raises(Iok::Rule::InvalidRule) do
      rule({ "sel" => { "body|contains" => "x" }, "condition" => "sel" })
    end

    assert_match(/unknown field/, error.message)
  end

  test "rejects an unknown modifier" do
    assert_raises(Iok::Rule::InvalidRule) do
      rule({ "sel" => { "html|base64offset" => "x" }, "condition" => "sel" })
    end
  end

  test "rejects a condition naming a selection that does not exist" do
    error = assert_raises(Iok::Rule::InvalidRule) do
      rule({ "sel" => { "html|contains" => "x" }, "condition" => "sel and missing" })
    end

    assert_match(/unknown selection/, error.message)
  end

  test "rejects a detection block with no condition" do
    assert_raises(Iok::Rule::InvalidRule) do
      rule({ "sel" => { "html|contains" => "x" } })
    end
  end

  test "rejects a detection block with no selections" do
    assert_raises(Iok::Rule::InvalidRule) { rule({ "condition" => "sel" }) }
  end

  test "rejects an unparseable condition" do
    assert_raises(Iok::Rule::InvalidRule) do
      rule({ "sel" => { "html|contains" => "x" }, "condition" => "sel and" })
    end
  end

  test "rejects an invalid regular expression" do
    assert_raises(Iok::Rule::InvalidRule) do
      rule({ "sel" => { "html|re" => "[unclosed" }, "condition" => "sel" })
    end
  end

  test "rejects a non-scalar value" do
    assert_raises(Iok::Rule::InvalidRule) do
      rule({ "sel" => { "html|contains" => [ { "nested" => true } ] }, "condition" => "sel" })
    end
  end

  # Page bodies arrive in whatever encoding the site served. Comparing a
  # UTF-8 rule value against invalid bytes raises rather than returning false,
  # which would otherwise abort the whole check.
  test "invalid byte sequences in the page do not raise" do
    detection = { "sel" => { "html|contains" => "kit" }, "condition" => "sel" }
    broken = (+"caf\xE9 kit").force_encoding(Encoding::UTF_8)

    assert_nothing_raised { matches?(detection, "html" => broken) }
  end
end
