# frozen_string_literal: true

require 'net/http'
require 'omniauth'

module OmniAuth
  module Strategies
    # Handles authenticating with OmniAuth given a request with a JWT identity
    # token from the "Sign in with Apple" process. Intended to be used by a
    # mobile app to get a session in Rails.
    #
    # NOTE: this is taken partially from these two projects:
    # - https://github.com/MasteryConnect/omniauth-apple-id-token
    # - https://github.com/nhosoya/omniauth-apple
    class AppleIdToken
      JWKS_URL = 'https://appleid.apple.com/auth/keys'
      ISS = 'https://appleid.apple.com'
      ALGORITHMS = ['RS256'].freeze
      VERIFY = true
      VERIFY_ISS = true
      VERIFY_IAT = true
      VERIFY_AUD = true

      class ClaimInvalid < StandardError; end

      include OmniAuth::Strategy

      BASE_SCOPES = %w[name email].freeze
      RESPONSE_TYPES = %w[token id_token].freeze

      option :name, 'apple_id_token'
      option :expiry, 3600 # 1 hour
      option :uid_claim, 'email'
      option :client_id, nil # Required for request_phase e.g. redirect to auth page
      option :aud_claim, nil
      option :required_claims, %w[email]
      option :info_map, 'name' => 'name', 'email' => 'email'
      option(
        :client_options,
        site: 'https://appleid.apple.com',
        authorize_url: '/auth/authorize',
        token_url: '/auth/token'
      )
      option(
        :authorize_params,
        response_mode: 'form_post',
        scope: 'email name'
      )

      def authorize_params
        super.merge(nonce: new_nonce)
      end

      def new_nonce
        session['omniauth.nonce'] = SecureRandom.urlsafe_base64(16)
      end

      def decoded
        unless @decoded
          begin
            id_token = request.params['id_token']
            @decoded = decode_payload(jwt: id_token)
          rescue StandardError => e
            raise ClaimInvalid, e.message
          end
        end

        (options.required_claims || []).each do |field|
          raise ClaimInvalid, "Missing required '#{field}' claim." unless @decoded.key?(field.to_s)
        end

        @decoded
      end

      def callback_phase
        super
      rescue ClaimInvalid => e
        fail! :claim_invalid, e
      end

      uid do
        decoded[options.uid_claim]
      end

      extra do
        { raw_info: decoded }
      end

      info do
        options.info_map.inject({}) do |h,(k,v)|
          h[k.to_s] = decoded[v.to_s]
          h
        end
      end

      private

      def jwks
        uri = URI.parse(JWKS_URL)
        response = Net::HTTP.get_response(uri)
        JSON.parse(response.body, symbolize_names: true)
      end

      def decode_payload(jwt:)
        payload, _header = ::JWT.decode(
          jwt,
          nil, # key
          VERIFY,
          verify_iss: VERIFY_ISS,
          iss: ISS,
          verify_iat: VERIFY_IAT,
          verify_aud: VERIFY_AUD,
          aud: options.aud_claim,
          algorithms: ALGORITHMS,
          jwks: jwks
        )

        payload
      end

      def uid_lookup
        @uid_lookup ||= options.uid_claim.new(request)
      end

    end

  end
end
