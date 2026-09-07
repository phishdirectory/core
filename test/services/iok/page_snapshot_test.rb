# frozen_string_literal: true

require "test_helper"

class Iok::PageSnapshotTest < ActiveSupport::TestCase
  PAGE = <<~HTML
    <html>
      <head>
        <title> Sign in </title>
        <link rel="stylesheet" href="/assets/layout/apple.css">
        <style>.Estilo2 { color: red }</style>
        <script src="/assets/kit.js"></script>
        <script>var exfil = "send.php";</script>
      </head>
      <body>
        <img src="assets/img/ajax-loader.gif">
        <svg><title>icon</title></svg>
      </body>
    </html>
  HTML

  def stub_page(body: PAGE, headers: {})
    stub_request(:get, "https://evil.test/")
      .to_return(status: 200, body: body, headers: { "Content-Type" => "text/html" }.merge(headers))
  end

  def capture(url = "https://evil.test/", fetch_assets: false)
    Iok::PageSnapshot.capture(url, fetch_assets: fetch_assets)
  end

  # ===========================================
  # Field extraction
  # ===========================================

  test "captures the served html as both html and dom" do
    stub_page

    snapshot = capture

    assert_equal [ PAGE ], snapshot.values_for("html")
    assert_equal snapshot.values_for("html"), snapshot.values_for("dom")
  end

  test "captures the hostname" do
    stub_page

    assert_equal [ "evil.test" ], capture.values_for("hostname")
  end

  test "captures the page title and ignores an svg title" do
    stub_page

    assert_equal [ "Sign in" ], capture.values_for("title")
  end

  test "captures inline script and style but not linked ones" do
    stub_page

    snapshot = capture

    assert_equal [ 'var exfil = "send.php";' ], snapshot.values_for("js")
    assert_equal [ ".Estilo2 { color: red }" ], snapshot.values_for("css")
  end

  test "captures subresource urls resolved against the page" do
    stub_page

    requests = capture.values_for("requests")

    assert_includes requests, "https://evil.test/"
    assert_includes requests, "https://evil.test/assets/layout/apple.css"
    assert_includes requests, "https://evil.test/assets/kit.js"
    assert_includes requests, "https://evil.test/assets/img/ajax-loader.gif"
  end

  test "captures headers in sigma's Name: value form" do
    stub_page(headers: { "Server" => "nginx" })

    assert_includes capture.values_for("headers"), "Server: nginx"
  end

  test "captures cookies as name=value pairs" do
    stub_page(headers: { "Set-Cookie" => "PHPSESSID=abc123; Path=/; HttpOnly" })

    assert_equal [ "PHPSESSID=abc123" ], capture.values_for("cookies")
  end

  # Net::HTTP folds repeated Set-Cookie headers into one comma-joined string,
  # and an Expires attribute contains a comma of its own.
  test "splits folded cookie headers without splitting inside an expires date" do
    stub_page(headers: { "Set-Cookie" => "a=1; Expires=Wed, 09 Jun 2021 10:18:14 GMT, b=2; Path=/" })

    assert_equal [ "a=1", "b=2" ], capture.values_for("cookies")
  end

  # ===========================================
  # Fetching linked assets
  # ===========================================

  test "fetches linked scripts and stylesheets when asked" do
    stub_page
    stub_request(:get, "https://evil.test/assets/kit.js").to_return(status: 200, body: "steal()")
    stub_request(:get, "https://evil.test/assets/layout/apple.css")
      .to_return(status: 200, body: ".kit {}")

    snapshot = capture(fetch_assets: true)

    assert_includes snapshot.values_for("js"), "steal()"
    assert_includes snapshot.values_for("css"), ".kit {}"
  end

  test "an asset that fails to load does not fail the snapshot" do
    stub_page
    stub_request(:get, "https://evil.test/assets/kit.js").to_timeout
    stub_request(:get, "https://evil.test/assets/layout/apple.css").to_return(status: 404, body: "")

    snapshot = capture(fetch_assets: true)

    assert_equal [ 'var exfil = "send.php";' ], snapshot.values_for("js")
  end

  test "stops after the asset limit" do
    links = Array.new(20) { |i| "<script src=\"/#{i}.js\"></script>" }.join
    stub_page(body: "<html><body>#{links}</body></html>")
    stub_request(:get, %r{\Ahttps://evil\.test/\d+\.js\z}).to_return(status: 200, body: "x")

    capture(fetch_assets: true)

    assert_requested(:get, %r{\Ahttps://evil\.test/\d+\.js\z},
                     times: Iok::PageSnapshot::MAX_ASSETS)
  end

  # ===========================================
  # Redirects
  # ===========================================

  test "follows redirects and reports the final url" do
    stub_request(:get, "https://evil.test/")
      .to_return(status: 302, headers: { "Location" => "/login" })
    stub_request(:get, "https://evil.test/login")
      .to_return(status: 200, body: "<title>Login</title>")

    snapshot = capture

    assert_equal "https://evil.test/login", snapshot.url
    assert_equal [ "Login" ], snapshot.values_for("title")
  end

  test "gives up after too many redirects" do
    stub_request(:get, %r{\Ahttps://evil\.test/})
      .to_return(status: 302, headers: { "Location" => "https://evil.test/next" })

    assert_raises(Iok::PageSnapshot::FetchError) { capture }
  end

  # ===========================================
  # Failures and address policy
  # ===========================================

  test "refuses to fetch an internal address" do
    error = assert_raises(Iok::PageSnapshot::BlockedAddress) { capture("http://127.0.0.1/") }

    assert_match(/internal address/, error.message)
  end

  test "refuses the cloud metadata endpoint" do
    assert_raises(Iok::PageSnapshot::BlockedAddress) { capture("http://169.254.169.254/latest/") }
  end

  test "refuses a non-http scheme" do
    assert_raises(Iok::PageSnapshot::FetchError) { capture("file:///etc/passwd") }
  end

  test "wraps a connection failure" do
    stub_request(:get, "https://evil.test/").to_timeout

    assert_raises(Iok::PageSnapshot::FetchError) { capture }
  end

  # A 404 or a 500 page can itself carry a kit fingerprint, so the status is
  # not treated as an error.
  test "keeps the body of an error response" do
    stub_page(body: "<title>Not found</title>")
    stub_request(:get, "https://evil.test/").to_return(status: 404, body: "<title>Not found</title>")

    assert_equal [ "Not found" ], capture.values_for("title")
  end

  test "normalises a page served in another encoding" do
    body = (+"<title>caf\xE9</title>").force_encoding(Encoding::ASCII_8BIT)
    stub_page(body: body)

    assert_nothing_raised { capture.values_for("html").first.include?("title") }
  end
end
