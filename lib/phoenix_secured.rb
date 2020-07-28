require "phoenix_secured/version"

module PhoenixSecured
  class Error < StandardError; end

  # Your code goes here...
end

require "jwt"

# Spanning all controller action calls
ActionController::API.class_eval do
  before_action :authenticate_request!
  before_action :set_group_id, :validate_user_permissions, except: [:app_init, :create_group]

  private

  # Migrated from Secured concern
  def authenticate_request!
    payload, header = JsonWebToken.verify(http_token)
    header if false # Commeent this line
    @requested_user = {
      email: payload["https://sassbox.com/email"],
      first_name: payload["https://sassbox.com/first_name"],
      last_name: payload["https://sassbox.com/last_name"],
    }
  rescue JWT::VerificationError, JWT::DecodeError
    render json: { errors: ["Not Authenticated"] }, status: :unauthorized
  end

  def http_token
    request.headers["Authorization"].split(" ").last if request.headers["Authorization"].present?
  end

  # GroupBaseService concern (formerly known as OrgService)
  def set_group_id
    @group_id = request.headers["X-WWW-GROUP-ID"]
  end

  def validate_user_permissions
    permissions = get_current_user_permissions
    if permissions[:status] != 200
      render json: permissions
    else
      @requested_user[:role] = permissions[:body]["role"]
    end
  end

  def get_current_user_permissions
    path = "/groups/#{@group_id}/validate_user"
    GroupBaseServiceClient.request(path: path, query_hash: { user_email: @requested_user[:email] })
  end

  class GroupBaseServiceClient
    def self.request(path:, query_hash:)
      response = self.conn.get "#{ENV["GROUP_BASE_SERVICE_BASE_API"]}/#{PHOENIX_APP_ID}/#{path}?#{query_hash.to_query}"
      { body: JSON.parse(response.body), status: response.status }
    end

    def self.post_request(path:, body_hash:)
      response = self.conn.post "#{ENV["GROUP_BASE_SERVICE_BASE_API"]}/#{PHOENIX_APP_ID}/#{path}?#{body_hash.to_query}"
      { body: JSON.parse(response.body), status: response.status }
    end

    def self.put_request(path:, body_hash:)
      response = conn.put "#{ENV["GROUP_BASE_SERVICE_BASE_API"]}/#{PHOENIX_APP_ID}/#{path}?#{body_hash.to_query}"
      { body: JSON.parse(response.body), status: response.status }
    end

    private

    def self.conn
      Faraday.new do |c|
        c.use OpenCensus::Trace::Integrations::FaradayMiddleware
        c.adapter Faraday.default_adapter
      end
    end
  end

  class JsonWebToken
    def self.verify(token)
      @jwks_hash ||= jwks_hash
      JWT.decode(token, nil,
                 true, # Verify the signature of this token
                 algorithm: "RS256",
                 iss: "https://bc-org-chart.auth0.com/",
                 verify_iss: true,
                 aud: "https://api.bc-reference.com",
                 verify_aud: true) do |header|
        @jwks_hash[header["kid"]]
      end
    end

    def self.jwks_hash

      # Faraday and OpenCensus middleware will be made available by the encompassing Rails App
      conn = Faraday.new do |c|
        c.use OpenCensus::Trace::Integrations::FaradayMiddleware
        c.adapter Faraday.default_adapter
      end
      response = conn.get "https://bc-org-chart.auth0.com/.well-known/jwks.json"

      jwks_keys = Array(JSON.parse(response.body)["keys"])
      Hash[
        jwks_keys
          .map do |k|
          [
            k["kid"],
            OpenSSL::X509::Certificate.new(
              Base64.decode64(k["x5c"].first)
            ).public_key,
          ]
        end
      ]
    end
  end
end
