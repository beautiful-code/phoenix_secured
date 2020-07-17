require "phoenix_secured/version"

module PhoenixSecured
  class Error < StandardError; end
  # Your code goes here...
end

require 'jwt'

# Spanning all controller action calls
ActionController::API.class_eval do

  before_action :authenticate_request!
  before_action :set_org, :validate_user_permissions, except: [:org_init]

  private

  # Migrated from Secured concern
  def authenticate_request!
    payload, header = JsonWebToken.verify(http_token)
    header if false # Commeent this line
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

  # Migrated from OrgService concern
  def set_org
    @org_id = request.headers["X-WWW-ORG-ID"]
  end

  def validate_user_permissions
    permissions = get_current_user_permissions
    if permissions["status"] && permissions["status"] != 200
      render json: permissions
    else
      @requested_user[:role] = permissions["role"]
    end
  end

  def get_current_user_permissions
    path = "orgs/#{@org_id}/validate_user"
    OrgServiceClient.request(path: path, query_hash: { email: @requested_user[:email] })
  end



  class OrgServiceClient
    def self.request(path:, query_hash:)
      conn = Faraday.new do |c|
        c.use OpenCensus::Trace::Integrations::FaradayMiddleware
        c.adapter Faraday.default_adapter
      end

      query_hash[:app_name] = PHOENIX_APP_NAME
      response = conn.get "#{ENV['ORG_SERVICE_BASE_API']}/#{path}?#{query_hash.to_query}"

      if response.status == 200
        JSON.parse(response.body)
      elsif response.status === 403
        { status: 403, message: "User doesn't have enough access!" }
      else
        nil
      end
    end

    def self.post_request(path:, body_hash:)
      conn = Faraday.new do |c|
        c.use OpenCensus::Trace::Integrations::FaradayMiddleware
        c.adapter Faraday.default_adapter
      end

      body_hash[:app_name] = PHOENIX_APP_NAME
      response = conn.post "#{ENV['ORG_SERVICE_BASE_API']}/#{path}?#{body_hash.to_query}"

      if response.status == 200
        JSON.parse(response.body)
      else
        {status: response.status}
      end
    end
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

      # Faraday and OpenCensus middleware will be made available by the encompassing Rails App
      conn = Faraday.new do |c|
        c.use OpenCensus::Trace::Integrations::FaradayMiddleware
        c.adapter Faraday.default_adapter
      end
      response = conn.get "https://bc-org-chart.auth0.com/.well-known/jwks.json"

      jwks_keys = Array(JSON.parse(response.body)['keys'])
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
