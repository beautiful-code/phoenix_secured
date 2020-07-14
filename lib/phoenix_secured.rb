require "phoenix_secured/version"

module PhoenixSecured
  class Error < StandardError; end
  # Your code goes here...
end

require 'jwt'

# Spanning all controller action calls
ActionController::API.class_eval do

  before_action :authenticate_request!

  private

  def authenticate_request!
    payload, header = auth_token
    header
    @requested_user = {
      email: payload['https://sassbox.com/email'],
      first_name: payload['https://sassbox.com/first_name'],
      last_name: payload['https://sassbox.com/last_name']
    }
  rescue JWT::VerificationError, JWT::DecodeError
    render json: { errors: ['Not Authenticated'] }, status: :unauthorized
  end

  def http_token
    request.headers['Authorization'].split(' ').last if request.headers['Authorization'].present?
  end

  def auth_token
    JsonWebToken.verify(http_token)
  end


  class JsonWebToken
    def self.verify(token)
      @jwks_hash ||= jwks_hash
      JWT.decode(token, nil,
                 true, # Verify the signature of this token
                 algorithm: 'RS256',
                 iss: 'https://bc-org-chart.auth0.com/',
                 verify_iss: true,
                 aud: 'https://api.bc-reference.com',
                 verify_aud: true) do |header|
        @jwks_hash[header['kid']]
      end
    end

    def self.jwks_hash
      jwks_raw = Net::HTTP.get URI('https://bc-org-chart.auth0.com/.well-known/jwks.json')
      jwks_keys = Array(JSON.parse(jwks_raw)['keys'])
      Hash[
        jwks_keys
        .map do |k|
          [
            k['kid'],
            OpenSSL::X509::Certificate.new(
              Base64.decode64(k['x5c'].first)
            ).public_key
          ]
        end
      ]
    end
  end

end
