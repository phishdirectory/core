# frozen_string_literal: true

# Disable CRL checking - OpenSSL 3.x enables this by default but CRL endpoints
# can be unreachable. Certificates are still verified for validity.
#
# This patches Net::HTTP to not use the default SSL context flags that include
# CRL checking.

require "net/http"
require "openssl"

module Net
  class HTTP
    # Store original method
    alias_method :original_use_ssl=, :use_ssl=

    def use_ssl=(flag)
      self.original_use_ssl = flag
      if flag
        # Ensure we don't check CRLs
        self.verify_mode = OpenSSL::SSL::VERIFY_PEER
        # Create a custom cert store without CRL checking
        store = OpenSSL::X509::Store.new
        store.set_default_paths
        self.cert_store = store
      end
    end
  end
end
