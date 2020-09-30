require "base64"
require "jwt"

module JWT
  module Multisig
    def self.generate_jwt(payload, private_keychain, algorithms)
      proxy_exception JWT::Error do
        { payload:    base64_encode(payload.to_json),
          signatures: private_keychain.map do |id, value|
            generate_jws(payload, id, value, algorithms[id])
          end
        }
      end
    end

    def self.generate_jws(payload, key_id, key_value, algorithm)
      proxy_exception JWT::Error do
        jwt = JWT.encode(payload, key_value, algorithm).split(".")
        { protected: jwt[0],
          header:    { kid: key_id },
          signature: jwt[1] }
      end
    end

    #
    # Masks all caught exceptions as different exception class.
    # @param exception_class [Class]
    def self.proxy_exception(exception_class)
      yield
    rescue e
      exception_class === e ? raise(e) : raise(exception_class.new(e.inspect))
    end

    #
    # Encodes string in Base64 format (URL-safe).
    #
    # @param string [String]
    # @return [String]
    def self.base64_encode(string : String): String
      Base64.encode(string).tr("+/", "-_").gsub(/[\n=]/, "")
    end

    #
    # Decodes string from Base64 format (URL-safe).
    #
    # @param string [String]
    # @return [String]
    def self.base64_decode(string : String): String
      string += "=" * (4 - string.size.modulo(4))
      Base64.decode_string(string.tr("-_", "+/"))
    end

  end
end
