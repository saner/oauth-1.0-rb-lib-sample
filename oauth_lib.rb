require 'net/http'
require 'base64'
require 'openssl'
require 'uuid'


module OAuthLib

  def self.new_nonce
    #UUID.new.generate
    "4572616e48616d6d65724c61686176"
  end


  def self.new_timestamp
    Time.now.utc.to_i
  end

  def self.create_signature(client_secret, token_secret, sign_method, uri, http_method, head_params)

    # get params from request uri
    uri_params = get_uri_params uri

    # combine all params
    params = {}
    params.merge! head_params
    params.merge! uri_params

    # encoding params
    params_concats = encode_params params

    # normalize uri, ex strip query params
    uri_norm = normalize_uri uri

    # combine base string
    base_str = signature_base_string http_method, uri_norm, params_concats
    puts base_str

    # sign base string
    key = "#{client_secret}&#{token_secret}"
    sign_signature(key, base_str).gsub("\n","")
  end

  def self.auth_header(params)
    "OAuth " + params.map do |k,v| 
      [ (encode_str k.to_s), (encode_str v.to_s) ]
    end.map { |k,v| "#{k}=\"#{v}\"" }.join(',')
  end

  def self.unreserved_characters 
    ('0'..'9').to_a + ('a'..'z').to_a + ('A'..'Z').to_a + ['-', '_', '.', '~']
  end

  def self.encode_params(params)
    params_encoded = params.map { |k,v| [ (encode_str k.to_s), (encode_str v.to_s) ] }

    params_encoded_sorted = Hash[ params_encoded.sort ]

    params_encoded_sorted.map { |k,v| k + "=" + v }.join('&')
  end


  def self.encode_str(str)
    str.each_char.collect do |c|
      if unreserved_characters.include? c
        c
      else
        '%' + c.unpack('U')[0].to_s(16).upcase
      end
    end.join('')
  end



  def self.sign_signature(key, str)
    Base64::encode64(OpenSSL::HMAC.digest('sha1', key, str))
  end


  def self.signature_base_string(method, uri, enc_params)
    method.upcase + "&" + (encode_str (normalize_uri uri)) + "&" + (encode_str enc_params)
    "#{method.upcase}&#{encode_str (normalize_uri uri)}&#{encode_str enc_params}"
  end


  def self.normalize_uri(uri)
    u = URI(uri)

    if (u.scheme == 'http' && u.port == 80) || (u.scheme == 'https' && u.port == 443)
      "#{u.scheme}://#{u.host}#{u.path}"
    else
      "#{u.scheme}://#{u.host}:#{u.port}#{u.path}"
    end
  end


  def self.get_uri_params(uri)
    params_str = URI(uri).query || ""

    Hash[
        params_str.split("&").map do |p| 
          vars = p.split("=")
          [ vars[0].to_sym , vars[1] ]
        end
    ]
  end

end

=begin
    oauth_parameters = {
        "oauth_consumer_key" => "dpf43f3p2l4k3l03",
        "oauth_token" => "nnch734d00sl2jdk",
        "oauth_nonce" => "kllo9940pd9333jh", 
        "oauth_timestamp" => "1191242096",
        "oauth_signature_method" => "HMAC-SHA1", 
        "oauth_version" => "1.0"
      }

    request_parameters = {
        "size" => "original", 
        "file" => "vacation.jpg"
      }
=end

# puts OAuthLib.create_signature("kd94hf93k423kf44", "pfkkdhi9sl3r4s00", "HMAC-SHA1", "http://photos.example.net/photos?size=original&file=vacation.jpg", oauth_parameters)
