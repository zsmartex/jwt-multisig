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

    def self.verify_jwt(jwt, public_keychain)
      proxy_exception JWT::DecodeError do
        keychain           = public_keychain
        serialized_payload = base64_decode(jwt["payload"].to_s)
        payload            = JSON.parse(serialized_payload)
        verified           = [] of String | Symbol
        unverified         = [] of String | Symbol

        jwt["signatures"].as_a.each do |jws|
          key_id = jws["header"]["kid"].to_s
          puts keychain, key_id
          if keychain.has_key?(key_id)
            verify_jws(jws, payload, public_keychain)
            verified << key_id
          else
            unverified << key_id
          end
        end
        { payload:    payload,
          verified:   verified.uniq,
          unverified: unverified.uniq }
      end
    end

    def self.verify_jws(jws, payload, public_keychain)
      proxy_exception JWT::DecodeError do
        encoded_header     = jws["protected"].to_s
        serialized_header  = base64_decode(encoded_header)
        serialized_payload = payload.to_json
        encoded_payload    = base64_encode(serialized_payload)
        signature          = jws["signature"].to_s
        public_key         = public_keychain[jws["header"]["kid"].to_s]
        jwt                = [encoded_header, encoded_payload, signature].join(".")
        algorithm          = JSON.parse(serialized_header)["alg"].to_s
        JWT.decode(jwt, public_key, JWT::Algorithm::RS256).first
      end
    end

    def self.generate_jws(payload, key_id, key_value, algorithm)
      proxy_exception JWT::Error do
        jwt = JWT.encode(payload, key_value, algorithm).split(".")
        { protected: jwt[0],
          header:    { kid: key_id },
          signature: jwt[2] }
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
