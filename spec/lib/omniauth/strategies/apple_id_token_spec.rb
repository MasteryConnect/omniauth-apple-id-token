require 'spec_helper'
require 'multi_json'
require 'jwt'

class TestLookup
  def initialize(request)
    @request = request
  end

  def uid(decoded)
    'foo'
  end
end

describe OmniAuth::Strategies::AppleIdToken do
  let(:rsa_private){ OpenSSL::PKey::RSA.generate 512 }
  let(:rsa_public){ rsa_private.public_key }
  let(:cert) do
    cert = OpenSSL::X509::Certificate.new
    cert.public_key = rsa_public
    cert
  end
  let(:aud_claim) { 'test_audience_claim' }
  let(:client_id) { 'test_client_id' }
  let(:response_json) { MultiJson.load(last_response.body) }
  let(:args) {
    [
      {
        cert: cert,
        aud_claim: aud_claim,
        client_id: client_id
      }
    ]
  }

  let(:app){
    the_args = args
    Rack::Builder.new do |b|
      b.use Rack::Session::Cookie, secret: 'sekrit'
      b.use OmniAuth::Strategies::AppleIdToken, *the_args
      b.run lambda { |env| [200, {}, [(env['omniauth.auth'] || {}).to_json]] }
    end
  }

  context 'request phase' do
    # FIXME: this needs to be adapted from the original Google example to work with Apple
    xit 'should redirect to the configured login url' do
      get '/auth/apple_id_token'
      expect(last_response.status).to eq(302)
      expect(last_response.headers['Location'].gsub(/&state=[0-9a-z]*/, '')).to eq('https://accounts.google.com/o/oauth2/auth?scope=profile%20email%20openid&access_type=offline&include_granted_scopes=true&redirect_uri=http%3A%2F%2Fexample.org%2Fauth%2Fappleidtoken%2Fcallback&response_type=token%20id_token&client_id=test_client_id') # Removed state random field
    end
  end

  context 'callback phase' do
    # FIXME: this needs to be adapted from the original Google example to work with Apple
    xit 'should decode the response' do
      encoded = JWT.encode({name: 'Bob', email: 'bob@example.com', 'iss': 'https://appleid.apple.com', aud: aud_claim}, rsa_private, 'RS256')
      get '/auth/apple_id_token/callback?id_token=' + encoded
      expect(response_json["info"]["email"]).to eq("bob@example.com")
    end

    it 'should not work without required fields' do
      encoded = JWT.encode({name: 'bob'}, 'imasecret')
      get '/auth/apple_id_token/callback?id_token=' + encoded
      expect(last_response.status).to eq(302)
    end

    # FIXME: this needs to be adapted from the original Google example to work with Apple
    xit 'should assign the uid' do
      encoded = JWT.encode({name: 'Bob', email: 'bob@example.com', 'iss': 'https://appleid.apple.com', aud: aud_claim}, rsa_private, 'RS256')
      get '/auth/apple_id_token/callback?id_token=' + encoded
      expect(response_json["uid"]).to eq('bob@example.com')
    end
  end
end
