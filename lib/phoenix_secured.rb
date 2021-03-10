require "phoenix_secured/version"
require "jwt"
require 'net/http'

module PhoenixSecured
  class Error < StandardError; end

  # Your code goes here...
end


class FirebaseIDTokenVerifier
  VALID_JWT_PUBLIC_KEYS_RESPONSE_CACHE_KEY = "firebase_jwt_public_keys_cache_key"
  JWT_ALGORITHM = 'RS256'

  def initialize(firebase_project_id)
    @firebase_project_id = firebase_project_id
  end

  def decode(id_token)
    decoded_token, error = FirebaseIDTokenVerifier.decode_jwt_token(id_token, @firebase_project_id, nil)
    raise error if error.present?

    payload = decoded_token[0]
    headers = decoded_token[1]

    # validate
    alg = headers['alg']
    if alg != JWT_ALGORITHM
      raise "Invalid access token 'alg' header (#{alg}). Must be '#{JWT_ALGORITHM}'."
    end

    valid_public_keys = FirebaseIDTokenVerifier.retrieve_and_cache_jwt_valid_public_keys
    kid = headers['kid']

    unless valid_public_keys.keys.include?(kid)
      raise "Invalid access token 'kid' header, do not correspond to valid public keys."
    else
      public_key = OpenSSL::X509::Certificate.new(valid_public_keys[kid]).public_key
    end

    sub = payload['sub']
    unless sub.present?
      raise "Invalid access token. 'Subject' (sub) must be a non-empty string."
    end

    # validate signature
    # More info: https://github.com/jwt/ruby-jwt/issues/216
    # for this we need to decode one more time, but now with cert public key
    decoded_token, error = FirebaseIDTokenVerifier.decode_jwt_token(id_token, @firebase_project_id, public_key)
    raise error if decoded_token.nil?

    decoded_token
  end

  def self.retrieve_and_cache_jwt_valid_public_keys
    valid_public_keys = Rails.cache.read(VALID_JWT_PUBLIC_KEYS_RESPONSE_CACHE_KEY)
    if valid_public_keys.nil?
      uri = URI("https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com")
      https = Net::HTTP.new(uri.host, uri.port)
      https.use_ssl = true
      req = Net::HTTP::Get.new(uri.path)
      response = https.request(req)
      if response.code != '200'
        raise "Something went wrong: can't obtain valid JWT public keys from Google."
      end
      valid_public_keys = JSON.parse(response.body)

      cc = response["cache-control"] # format example: Cache-Control: public, max-age=24442, must-revalidate, no-transform
      max_age = cc[/max-age=(\d+?),/m, 1] # get something between 'max-age=' and ','

      Rails.cache.write(VALID_JWT_PUBLIC_KEYS_RESPONSE_CACHE_KEY, valid_public_keys, expires_in: max_age.to_i)
    end

    valid_public_keys
  end

  def self.decode_jwt_token(firebase_jwt_token, firebase_project_id, public_key)
    # Validation rules: https://firebase.google.com/docs/auth/admin/verify-id-tokens#verify_id_tokens_using_a_third-party_jwt_library
    custom_options = {
      verify_iat: true,
      verify_aud: true,
      aud: firebase_project_id,
      verify_iss: true,
      iss: "https://securetoken.google.com/"+firebase_project_id
    }

    if public_key.present?
      custom_options[:algorithm] = JWT_ALGORITHM
    end

    begin
      decoded_token = JWT.decode(firebase_jwt_token, public_key, public_key.present?, custom_options)
    rescue JWT::ExpiredSignature
      return nil, "Invalid access token. 'Expiration time' (exp) must be in the future."
    rescue JWT::InvalidIatError
      return nil, "Invalid access token. 'Issued-at time' (iat) must be in the past."
    rescue JWT::InvalidAudError
      return nil, "Invalid access token. 'Audience' (aud) must be your Firebase project ID, the unique identifier for your Firebase project."
    rescue JWT::InvalidIssuerError
      return nil, "Invalid access token. 'Issuer' (iss) Must be 'https://securetoken.google.com/<projectId>', where <projectId> is your Firebase project ID."
    rescue JWT::VerificationError
      return nil, "Invalid access token. Signature verification failed."
    end

    return decoded_token, nil
  end
end

# Spanning all controller action calls
ActionController::API.class_eval do
  before_action :authenticate_request!
  before_action :set_group_id, :validate_user_permissions, except: [:app_init, :create_group]

  private

  def authenticate_request!
    begin
      verifier = FirebaseIDTokenVerifier.new(ENV["FIREBASE_PROJECT_ID"])
      decoded_token = verifier.decode(id_token)

      payload = decoded_token[0]
      if Time.now.to_i - 60 <= payload["auth_time"]
        UserInfoServiceClient.post_request(path: "user_info/details", body_hash: {
            user_info: {
              user_id: payload["email"],
              first_name: payload["name"] || "",
              last_name: "",
              profile_pic_url: payload["picture"] || ""
            }
          }
        )
      end
      @requested_user = {
        email: payload["email"],
        name: payload["name"],
        picture: payload["picture"],
        uid: payload["sub"],
      }
    rescue Exception => e
      render json: { message: e }, status: :unauthorized
    end
  end

  def id_token
    request.headers["Authorization"].split(" ").last if request.headers["Authorization"].present?
  end

  # GroupBaseService concern (formerly known as OrgService)
  def set_group_id
    @group_id = request.headers["X-WWW-GROUP-ID"]
  end

  def validate_user_permissions
    permissions = get_current_user_permissions
    if permissions[:status] != 200
      render json: permissions, status: 403
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
      response = self.conn.put "#{ENV["GROUP_BASE_SERVICE_BASE_API"]}/#{PHOENIX_APP_ID}/#{path}?#{body_hash.to_query}"
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

  class UserInfoServiceClient
    def self.request(path:, query_hash:)
      response = self.conn.get "#{ENV["USER_INFO_SERVICE_BASE_API"]}/#{path}?#{query_hash.to_query}"
      { body: JSON.parse(response.body), status: response.status }
    end

    def self.post_request(path:, body_hash:)
      response = self.conn.post "#{ENV["USER_INFO_SERVICE_BASE_API"]}/#{path}?#{body_hash.to_query}"
      { body: response.body, status: response.status }
    end

    private

    def self.conn
      Faraday.new do |c|
        c.use OpenCensus::Trace::Integrations::FaradayMiddleware
        c.adapter Faraday.default_adapter
      end
    end
  end
end
