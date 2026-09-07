# frozen_string_literal: true

require "test_helper"

# The taxonomy used to be an invented "XARF v4" of snake_case categories and
# types that appears in no published schema. Schema 3 is the newest abusix
# publishes, and it is a ReportClass plus a ReportType.
class Xarf::CategoryMapperTest < ActiveSupport::TestCase
  test "every class in the taxonomy is one the schema defines" do
    assert_equal %w[Content Activity Vulnerability], Xarf::CategoryMapper::REPORT_CLASSES
  end

  test "phishing maps onto the content class" do
    assert_equal(
      { report_class: "Content", report_type: "Phishing" },
      Xarf::CategoryMapper.to_xarf("phishing")
    )
  end

  test "an unconfirmed site is still reported, with the class the schema has" do
    mapping = Xarf::CategoryMapper.to_xarf("suspicious")

    assert_equal "Content", mapping[:report_class]
    assert_equal "Phishing", mapping[:report_type]
  end

  test "clean, unknown and protected domains are never reported" do
    %w[clean unknown protected].each do |classification|
      assert_nil Xarf::CategoryMapper.to_xarf(classification)
      assert_not Xarf::CategoryMapper.reportable?(classification)
    end
  end

  test "an incoming report maps back onto a classification" do
    assert_equal "phishing", Xarf::CategoryMapper.from_xarf("Content", "Phishing")
    assert_equal "phishing", Xarf::CategoryMapper.from_xarf("Content", "Malware")
    assert_equal "suspicious", Xarf::CategoryMapper.from_xarf("Activity", "Spam")
  end

  test "a type outside what this directory classifies maps to nothing" do
    assert_nil Xarf::CategoryMapper.from_xarf("Content", "Copyright")
  end

  test "the invented v4 vocabulary is rejected" do
    assert_not Xarf::CategoryMapper.valid_report_class?("content")
    assert_not Xarf::CategoryMapper.valid_report_type?("suspicious_registration")
    assert_not Xarf::CategoryMapper.valid_report_type?("brand_infringement")
    assert_nil Xarf::CategoryMapper.from_xarf("content", "phishing")
  end

  test "a type is checked against the class it was sent under" do
    assert Xarf::CategoryMapper.type_in_class?("Content", "Phishing")
    assert_not Xarf::CategoryMapper.type_in_class?("Vulnerability", "Phishing")
  end

  test "Malware is valid under both the classes the schema allows it in" do
    assert Xarf::CategoryMapper.type_in_class?("Content", "Malware")
    assert Xarf::CategoryMapper.type_in_class?("Activity", "Malware")
  end

  test "severity uses the closed enum the schema defines" do
    assert_equal "high", Xarf::CategoryMapper.severity_for_confidence(0.95)
    assert_equal "medium", Xarf::CategoryMapper.severity_for_confidence(0.7)
    assert_equal "low", Xarf::CategoryMapper.severity_for_confidence(0.2)
    assert_equal "low", Xarf::CategoryMapper.severity_for_confidence(nil)
  end

  test "a verdict maps with its confidence carried through" do
    verdict = Verdict.create!(classification: "phishing", confidence_score: 0.91)
    mapping = Xarf::CategoryMapper.map_verdict(verdict)

    assert mapping[:reportable]
    assert_equal "Phishing", mapping[:report_type]
    assert_in_delta 0.91, mapping[:confidence]
  end

  test "a missing verdict is not reportable" do
    assert_not Xarf::CategoryMapper.map_verdict(nil)[:reportable]
  end
end
