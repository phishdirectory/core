# frozen_string_literal: true

require "test_helper"

class WebhookAddressPolicyTest < ActiveSupport::TestCase
  test "allows ordinary public hosts" do
    assert_not WebhookAddressPolicy.obviously_internal?("https://hooks.example.com/notify")
    assert_not WebhookAddressPolicy.obviously_internal?("https://8.8.8.8/notify")
  end

  test "blocks loopback by name and by address" do
    assert WebhookAddressPolicy.obviously_internal?("http://localhost:3000/hook")
    assert WebhookAddressPolicy.obviously_internal?("http://127.0.0.1/hook")
    assert WebhookAddressPolicy.obviously_internal?("http://[::1]/hook")
  end

  test "blocks the cloud metadata endpoint" do
    assert WebhookAddressPolicy.obviously_internal?("http://169.254.169.254/latest/meta-data/"),
           "the link local range is how instance credentials get stolen"
    assert WebhookAddressPolicy.obviously_internal?("http://metadata.google.internal/")
  end

  test "blocks private ranges" do
    %w[
      http://10.0.0.5/hook
      http://172.16.4.4/hook
      http://192.168.1.10/hook
      http://100.64.0.1/hook
    ].each do |url|
      assert WebhookAddressPolicy.obviously_internal?(url), "#{url} should be blocked"
    end
  end

  test "blocks internal-looking hostnames" do
    assert WebhookAddressPolicy.obviously_internal?("http://api.internal/hook")
    assert WebhookAddressPolicy.obviously_internal?("http://printer.local/hook")
  end

  test "blocks a url with no host at all" do
    assert WebhookAddressPolicy.obviously_internal?("not a url")
    assert WebhookAddressPolicy.obviously_internal?("")
  end

  test "blocked_ip? recognises each blocked range" do
    assert WebhookAddressPolicy.blocked_ip?(IPAddr.new("169.254.169.254"))
    assert_not WebhookAddressPolicy.blocked_ip?(IPAddr.new("93.184.216.34"))
  end
end
