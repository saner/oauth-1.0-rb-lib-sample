require 'net/http'
require 'uri'

require 'oauth_lib'


class OAuthClient
  def initialize(conf)
    @conf = conf
  end

  def make_oauth_request(uri, method, auth_header, client_secret, request_secret)

    # get header signature
    oauth_signature = OAuthLib::create_signature(client_secret, request_secret, "HMAC-SHA1", uri, method, auth_header)
    auth_header[:oauth_signature] = oauth_signature
    puts oauth_signature


    uri = URI.parse(uri)
    http = Net::HTTP.new(uri.host, uri.port)

    req = case method.upcase
            when 'GET' then Net::HTTP::Get.new(uri.path + "?#{uri.query}")
            when 'POST' then Net::HTTP::Post.new(uri.path + "?#{uri.query}")
          end

    # set header
    header = OAuthLib::auth_header auth_header
    puts header
    req["Authorization"] = header

    http.request(req)
  end

  def get_request_token()
    auth_header = {
      :oauth_consumer_key => @conf[:client_token][:key],
      :oauth_nonce => OAuthLib::new_nonce(),
      :oauth_signature_method => "HMAC-SHA1",
      :oauth_timestamp => OAuthLib::new_timestamp(),
      :oauth_callback => "oob",
      :oauth_version => "1.0",
    }
    make_oauth_request(@conf[:request_uri], "POST", auth_header, @conf[:client_token][:secret], "")
  end

  def get_access_token(request_token)
    auth_header = {
      :oauth_consumer_key => @conf[:client_token][:key],
      :oauth_nonce => OAuthLib::new_nonce(),
      :oauth_signature_method => "HMAC-SHA1",
      :oauth_timestamp => OAuthLib::new_timestamp(),
      :oauth_callback => "oob",
      :oauth_version => "1.0",
      :oauth_token => request_token[:key],
    }
    make_oauth_request(@conf[:access_uri], "POST", auth_header, @conf[:client_token][:secret], request_token[:secret])
  end

  def authenticated_call(access_token, call_endpoint)
    auth_header = {
      :oauth_consumer_key => @conf[:client_token][:key],
      :oauth_nonce => OAuthLib::new_nonce(),
      :oauth_signature_method => "HMAC-SHA1",
      :oauth_timestamp => OAuthLib::new_timestamp(),
      :oauth_callback => "oob",
      :oauth_version => "1.0",
      :oauth_token => access_token[:key],
    }
    make_oauth_request(call_endpoint, "POST", auth_header, @conf[:client_token][:secret], access_token[:secret])
  end


end

example_conf = {
  :request_uri => "http://term.ie/oauth/example/request_token.php",
  :authorize_uri => "",
  :access_uri => "http://term.ie/oauth/example/access_token.php",
  :client_token => {
    :key => "key",
    :secret => "secret"
  }
}

google_conf = {
  :request_uri => "https://www.google.com/accounts/OAuthGetRequestToken",
  :authorize_uri => "https://www.google.com/accounts/OAuthAuthorizeToken",
  :access_uri => "https://www.google.com/accounts/OAuthGetAccessToken",
  :client_token => {
    :key => "",
    :secret => ""
  }
}

# puts OAuthClient.new.make_oauth_request "http://www.google.com/cos", "GET", ""

oauth = OAuthClient.new(example_conf)

resp_str = oauth.get_request_token
resp = Hash[ resp_str.body.split("&").map { |s| ps = s.split("="); [ps[0].to_sym, ps[1]] } ]
puts resp

req_token = { :key => resp[:oauth_token], :secret => resp[:oauth_token_secret] }
puts req_token
resp_str = oauth.get_access_token req_token

resp = Hash[ resp_str.body.split("&").map { |s| ps = s.split("="); [ps[0].to_sym, ps[1]] } ]
access_token = { :key => resp[:oauth_token], :secret => resp[:oauth_token_secret] }
puts access_token

#puts OAuthClient.new.authenticated_call example_conf, access_token, "http://term.ie/oauth/example/echo_api.php"

# not working with example uri
# puts OAuthClient.new.authenticated_call example_conf, access_token, "http://term.ie/oauth/example/echo_api.php?method=foo&bar=baz"

