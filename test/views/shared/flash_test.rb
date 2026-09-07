# frozen_string_literal: true

require "test_helper"

# Each layout used to inline its own flash block and none handled :success,
# which the classification controller sets on its two most important actions.
class SharedFlashTest < ActionView::TestCase
  def render_flash(**messages)
    flash.clear
    messages.each { |key, value| flash[key] = value }
    render partial: "shared/flash"
    rendered
  end

  test "renders a success message" do
    assert_match(/Classification submitted/, render_flash(success: "Classification submitted"))
  end

  test "renders a notice message" do
    assert_match(/Saved your changes/, render_flash(notice: "Saved your changes"))
  end

  test "renders an alert message" do
    assert_match(/Something went wrong/, render_flash(alert: "Something went wrong"))
  end

  test "renders an error message" do
    assert_match(/Could not save/, render_flash(error: "Could not save"))
  end

  test "renders several messages at once" do
    output = render_flash(success: "Saved", alert: "But check this")

    assert_match(/Saved/, output)
    assert_match(/But check this/, output)
  end

  test "success and alert are styled differently" do
    assert_match(/text-success/, render_flash(success: "Done"))
    assert_match(/text-danger/, render_flash(alert: "Broken"))
  end

  test "renders nothing when there is no message" do
    assert_equal "", render_flash.strip
  end

  test "blank messages are ignored" do
    assert_equal "", render_flash(notice: "").strip
  end

  # The API key reveal is data the page renders itself, not a message.
  test "the one-time api key is never rendered as a message" do
    output = render_flash(api_key: "pdat_secret_value")

    assert_no_match(/pdat_secret_value/, output)
  end

  test "the notice is suppressed while a key is being revealed" do
    output = render_flash(api_key: "pdat_x", notice: "API key created")

    assert_no_match(/API key created/, output)
  end

  test "is announced to assistive technology" do
    assert_match(/role="status"/, render_flash(notice: "Saved"))
    assert_match(/aria-live="polite"/, render_flash(notice: "Saved"))
  end
end
