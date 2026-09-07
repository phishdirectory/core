# frozen_string_literal: true

require "test_helper"

# The SAML IdP never worked. The controller replaced saml_idp's
# validate_saml_request with a presence check, and saml_idp's default
# saml_request is a stub whose issuer is nil, so the request was never decoded
# and every authentication ended at "Unknown or disabled service provider".
# Behind that, encode_saml_response passed keyword arguments to a method taking
# nine positional ones, and the view base64 encoded an already encoded response.
#
# None of it had test coverage, so all of it is covered here.
class SamlIdpTest < ActionDispatch::IntegrationTest
  ACS_URL = "https://sp.example.com/saml/consume"
  ENTITY_ID = "https://sp.example.com/metadata"

  setup do
    Flipper.enable(:saml_idp_enabled)
    @user = create_test_user(email: "saml-user@example.com", first_name: "Sam", last_name: "Ell")
    @service_provider = create_service_provider
  end

  teardown do
    Flipper.disable(:saml_idp_enabled)
  end

  # ===========================================
  # Feature flag and metadata
  # ===========================================

  test "every endpoint is closed when the feature flag is off" do
    Flipper.disable(:saml_idp_enabled)

    get saml_auth_path(SAMLRequest: encoded_authn_request)

    assert_response :service_unavailable
  end

  test "metadata is served as signed XML" do
    get saml_metadata_path

    assert_response :success
    assert_equal "application/samlmetadata+xml", response.media_type
    assert_includes response.body, "EntityDescriptor"
  end

  # ===========================================
  # Request decoding
  # ===========================================

  test "a request with no SAMLRequest is a client error" do
    get saml_auth_path

    assert_response :bad_request
    assert_equal "Missing SAML request", response.body
  end

  test "a SAMLRequest that is not valid base64 XML is a client error" do
    get saml_auth_path(SAMLRequest: Base64.strict_encode64("this is not xml"))

    assert_response :bad_request
    assert_equal "Invalid SAML request", response.body
  end

  test "a LogoutRequest sent to the auth endpoint is rejected" do
    get saml_auth_path(SAMLRequest: encoded_logout_request)

    assert_response :bad_request
  end

  # ===========================================
  # Service provider resolution
  # ===========================================

  test "an unknown issuer is refused" do
    get saml_auth_path(SAMLRequest: encoded_authn_request(issuer: "https://stranger.example.com/metadata"))

    assert_response :forbidden
    assert_equal "Unknown or disabled service provider", response.body
  end

  test "a disabled service provider is refused" do
    @service_provider.update!(enabled: false)

    get saml_auth_path(SAMLRequest: encoded_authn_request)

    assert_response :forbidden
    assert_equal "Unknown or disabled service provider", response.body
  end

  test "a discarded service provider is refused" do
    @service_provider.discard!

    get saml_auth_path(SAMLRequest: encoded_authn_request)

    assert_response :forbidden
  end

  # ===========================================
  # The assertion itself
  # ===========================================

  test "a signed in user gets a SAML response" do
    sign_in(@user)

    get saml_auth_path(SAMLRequest: encoded_authn_request)

    assert_response :success
    assert_not_nil saml_response_value, "the form should carry a SAMLResponse"
  end

  test "the SAML response is base64 encoded exactly once" do
    sign_in(@user)

    get saml_auth_path(SAMLRequest: encoded_authn_request)

    # The view used to wrap an already encoded response, so one decode returned
    # more base64 rather than XML.
    decoded = Base64.decode64(saml_response_value)

    assert_includes decoded, "<samlp:Response", "one decode should yield the response XML"
  end

  test "the assertion carries the audience, destination and name ID" do
    sign_in(@user)

    get saml_auth_path(SAMLRequest: encoded_authn_request)
    doc = saml_response_document

    assert_equal ACS_URL, doc.root["Destination"]
    assert_equal ENTITY_ID, text_at(doc, "//saml:Audience")
    assert_equal @user.email, text_at(doc, "//saml:NameID")
  end

  test "the name ID format follows the service provider configuration" do
    sign_in(@user)

    get saml_auth_path(SAMLRequest: encoded_authn_request)
    doc = saml_response_document
    name_id = doc.at_xpath("//saml:NameID", saml: assertion_namespace)

    assert_equal Saml::ServiceProvider::NAME_ID_FORMATS[:email], name_id["Format"]
  end

  test "a persistent name ID format sends the pd_id instead of the email" do
    @service_provider.update!(name_id_format: Saml::ServiceProvider::NAME_ID_FORMATS[:persistent])
    sign_in(@user)

    get saml_auth_path(SAMLRequest: encoded_authn_request)
    doc = saml_response_document
    name_id = doc.at_xpath("//saml:NameID", saml: assertion_namespace)

    assert_equal @user.pd_id, name_id.content
    assert_equal Saml::ServiceProvider::NAME_ID_FORMATS[:persistent], name_id["Format"]
  end

  test "user attributes are asserted with their values" do
    sign_in(@user)

    get saml_auth_path(SAMLRequest: encoded_authn_request)

    assert_equal @user.email, asserted_attribute("email")
    assert_equal @user.pd_id, asserted_attribute("pd_id")
    assert_equal "Sam", asserted_attribute("first_name")
    assert_equal "Ell", asserted_attribute("last_name")
  end

  test "the response refers back to the request it answers" do
    sign_in(@user)
    request_id = "_#{SecureRandom.uuid}"

    get saml_auth_path(SAMLRequest: encoded_authn_request(id: request_id))
    doc = saml_response_document

    assert_equal request_id, doc.root["InResponseTo"]
  end

  test "the assertion is signed when the service provider asks for it" do
    sign_in(@user)

    get saml_auth_path(SAMLRequest: encoded_authn_request)
    doc = saml_response_document

    assert_not_nil doc.at_xpath("//ds:Signature", ds: "http://www.w3.org/2000/09/xmldsig#"),
                   "sign_assertions defaults to true, so the response should be signed"
  end

  test "a successful authentication is recorded" do
    sign_in(@user)

    assert_difference -> { @service_provider.authentications.count }, 1 do
      get saml_auth_path(SAMLRequest: encoded_authn_request)
    end

    authentication = @service_provider.authentications.order(:created_at).last

    assert_equal "success", authentication.status
    assert_equal @user, authentication.user
  end

  # ===========================================
  # Sign in round trip
  # ===========================================

  test "a signed out user is sent to log in and the request survives the trip" do
    get saml_auth_path(SAMLRequest: encoded_authn_request, RelayState: "back-to-here")

    assert_redirected_to login_path
    assert_equal "back-to-here", session[:saml_request_params]["RelayState"]
  end

  test "signing in returns the user to the SAML flow and issues the assertion" do
    saml_request = encoded_authn_request

    get saml_auth_path(SAMLRequest: saml_request, RelayState: "back-to-here")

    assert_redirected_to login_path

    # AuthController redirects to session[:return_to]. The old code stored the
    # path under saml_return_to, which nothing reads, so the flow was abandoned
    # and the user landed on the dashboard instead.
    sign_in(@user)

    assert_response :success
    assert_not_nil saml_response_value, "the assertion should be issued after signing in"
    assert_equal @user.email, text_at(saml_response_document, "//saml:NameID")
  end

  test "the relay state comes back on the form after signing in" do
    sign_in(@user)

    get saml_auth_path(SAMLRequest: encoded_authn_request, RelayState: "back-to-here")

    assert_response :success
    assert_select "input[name=RelayState][value=back-to-here]"
  end

  # ===========================================
  # Request signatures
  # ===========================================

  test "an unsigned request is accepted when the provider does not require signing" do
    sign_in(@user)

    get saml_auth_path(SAMLRequest: encoded_authn_request)

    assert_response :success
  end

  test "an unsigned request is refused when the provider requires signing" do
    @service_provider.update!(want_authn_requests_signed: true, certificate: sp_certificate.to_pem)
    sign_in(@user)

    get saml_auth_path(SAMLRequest: encoded_authn_request)

    assert_response :forbidden
    assert_equal "Invalid SAML request", response.body
  end

  test "a correctly signed request is accepted when the provider requires signing" do
    @service_provider.update!(want_authn_requests_signed: true, certificate: sp_certificate.to_pem)
    sign_in(@user)

    get saml_auth_path(**signed_request_params)

    assert_response :success
    assert_not_nil saml_response_value
  end

  test "a request signed by the wrong key is refused" do
    @service_provider.update!(want_authn_requests_signed: true, certificate: sp_certificate.to_pem)
    sign_in(@user)

    params = signed_request_params(key: OpenSSL::PKey::RSA.new(2048))

    get saml_auth_path(**params)

    assert_response :forbidden
  end

  test "a rejected request is recorded as a failure" do
    @service_provider.update!(want_authn_requests_signed: true, certificate: sp_certificate.to_pem)
    sign_in(@user)

    assert_difference -> { @service_provider.authentications.count }, 1 do
      get saml_auth_path(SAMLRequest: encoded_authn_request)
    end

    assert_equal "failure", @service_provider.authentications.order(:created_at).last.status
  end

  private

  # ===========================================
  # Service provider and keys
  # ===========================================

  def create_service_provider
    Saml::ServiceProvider.create!(
      name: "Example SP",
      entity_id: ENTITY_ID,
      assertion_consumer_service_url: ACS_URL,
      name_id_format: Saml::ServiceProvider::NAME_ID_FORMATS[:email]
    )
  end

  # One key pair per process keeps these tests off the RSA generation path for
  # every single example.
  def self.sp_key
    @sp_key ||= OpenSSL::PKey::RSA.new(2048)
  end

  def self.sp_certificate
    @sp_certificate ||= begin
      certificate = OpenSSL::X509::Certificate.new
      certificate.version = 2
      certificate.serial = 1
      certificate.subject = OpenSSL::X509::Name.parse("/CN=sp.example.com")
      certificate.issuer = certificate.subject
      certificate.public_key = sp_key.public_key
      certificate.not_before = Time.now - 60
      certificate.not_after = Time.now + 3600
      certificate.sign(sp_key, OpenSSL::Digest.new("SHA256"))
      certificate
    end
  end

  def sp_key = self.class.sp_key
  def sp_certificate = self.class.sp_certificate

  # ===========================================
  # Building requests
  # ===========================================

  def authn_request_xml(issuer: ENTITY_ID, acs_url: ACS_URL, id: "_#{SecureRandom.uuid}")
    <<~XML
      <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                          xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                          ID="#{id}"
                          Version="2.0"
                          IssueInstant="#{Time.now.utc.iso8601}"
                          Destination="http://www.example.com/saml/auth"
                          AssertionConsumerServiceURL="#{acs_url}"
                          ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
        <saml:Issuer>#{issuer}</saml:Issuer>
      </samlp:AuthnRequest>
    XML
  end

  def logout_request_xml(issuer: ENTITY_ID)
    <<~XML
      <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                           xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                           ID="_#{SecureRandom.uuid}"
                           Version="2.0"
                           IssueInstant="#{Time.now.utc.iso8601}">
        <saml:Issuer>#{issuer}</saml:Issuer>
        <saml:NameID>saml-user@example.com</saml:NameID>
      </samlp:LogoutRequest>
    XML
  end

  def encoded_authn_request(**options) = deflate_and_encode(authn_request_xml(**options))
  def encoded_logout_request(**options) = deflate_and_encode(logout_request_xml(**options))

  # Redirect binding uses raw deflate, with no zlib header.
  def deflate_and_encode(xml)
    stream = Zlib::Deflate.new(Zlib::BEST_COMPRESSION, -Zlib::MAX_WBITS)
    deflated = stream.deflate(xml, Zlib::FINISH)
    stream.close
    Base64.strict_encode64(deflated)
  end

  # The redirect binding signs the query string itself, in this exact order,
  # rather than signing the XML.
  def signed_request_params(key: sp_key, relay_state: nil)
    saml_request = encoded_authn_request
    sig_alg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

    signed_string = +"SAMLRequest=#{CGI.escape(saml_request)}"
    signed_string << "&RelayState=#{CGI.escape(relay_state)}" if relay_state
    signed_string << "&SigAlg=#{CGI.escape(sig_alg)}"

    signature = key.sign(OpenSSL::Digest.new("SHA256"), signed_string)

    params = { SAMLRequest: saml_request, SigAlg: sig_alg, Signature: Base64.strict_encode64(signature) }
    params[:RelayState] = relay_state if relay_state
    params
  end

  # ===========================================
  # Reading responses
  # ===========================================

  def assertion_namespace = "urn:oasis:names:tc:SAML:2.0:assertion"

  def saml_response_value
    field = Nokogiri::HTML(response.body).at_css("input[name=SAMLResponse]")
    field && field["value"]
  end

  def saml_response_document
    Nokogiri::XML(Base64.decode64(saml_response_value))
  end

  def text_at(doc, xpath)
    doc.at_xpath(xpath, saml: assertion_namespace)&.content
  end

  def asserted_attribute(friendly_name)
    doc = saml_response_document
    attribute = doc.at_xpath("//saml:Attribute[@FriendlyName='#{friendly_name}']", saml: assertion_namespace)
    attribute&.at_xpath("saml:AttributeValue", saml: assertion_namespace)&.content
  end
end
