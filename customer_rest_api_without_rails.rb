#!/usr/bin/env ruby

require 'rubygems'
require 'json'
require 'restclient'

class CloudService

        class << self

	        attr_accessor :token

                def get( path, decode=true )
                        begin 
                                resource = RestClient::Resource.new( create_uri( URI.encode( path ) ), auth_headers )
                        rescue RestClient::Exception => e
                                #Rails.logger.error e
                                return nil
                        end                        
                        resource.get do |response, request, result, &block|
                                case response.code
                                when 200..207
					puts "Rails.logger.info response.body"
                                        #Rails.logger.info response.body
                                        return decode_response( response.body ) if decode
                                        return response.body
                                when 401
					puts "Rails.logger.info CloudService::GET - token expired, re-upping now"
                                        #Rails.logger.info "CloudService::GET - token expired, re-upping now"
                                        CloudService.token = nil
                                        return get( path )
                                else
                                        #Rails.logger.error "CloudService::GET Error - #{response.body}"
					puts "Rails.logger.error CloudService::GET Error - #{response.body}"
                                end                                
                                return nil
                        end
                end

                def delete( path )
                        begin 
                                resource = RestClient::Resource.new( create_uri( path ), auth_headers )
                        rescue RestClient::Exception => e
                                #Rails.logger.error e
				puts "Rails.logger.error e"
                                return false
                        end                        
                        resource.delete do |response, request, result, &block|
                                case response.code
                                when 200..207
                                        return true
                                when 401
					puts "Rails.logger.info CloudService::DELETE - token expired, re-upping now" 						#Rails.logger.info "CloudService::DELETE - token expired, re-upping now"
                                        CloudService.token = nil
                                        return delete( path )
                                else
					puts "Rails.logger.error CloudService::DELETE Error - #{response.body}"
                                        #Rails.logger.error "CloudService::DELETE Error - #{response.body}"
                                end                                
                                return false
                        end
                end

                def patch( path, params )
                        begin 
                                resource = RestClient::Resource.new( create_uri( path ), auth_headers )
                        rescue RestClient::Exception => e
                                #Rails.logger.error e
				puts "Rails.logger.error e"
                                return e.response
                        end                        
                        resource.patch( params.to_json ) do |response, request, result, &block|
                                case response.code
                                when 200..207
                                when 401
					puts "Rails.logger.info CloudService::PATCH - token expired, re-upping now"
                                        #Rails.logger.info "CloudService::PATCH - token expired, re-upping now"
                                        CloudService.token = nil
                                        patch( path, params )
                                else
					puts "Rails.logger.error CloudService::PATCH Error - #{response.body}"
                                        #Rails.logger.error "CloudService::PATCH Error - #{response.body}"
                                end                                
                                return response
                        end
                end

                def post( path, model, params )
                        begin 
                                resource = RestClient::Resource.new( create_uri( path ), auth_headers )
                        rescue RestClient::Exception => e
				puts "Rails.logger.error e"                                
				#Rails.logger.error e
                                #return e.response
				return nil
                        end                
                        resource.post( params.to_json ) do |response, request, result, &block|
                                case response.code
                                when 200..207
                                        model.update_attributes( cloud_path: response.headers[ :location ] )
                                when 401
					puts "Rails.logger.info CloudService::POST - token expired, re-upping now"
                                        #Rails.logger.info "CloudService::POST - token expired, re-upping now"
                                        CloudService.token = nil
                                        post( path, model, params )
                                else
					puts "CloudService::POST Error - #{response.body}"
                                        #Rails.logger.error "CloudService::POST Error - #{response.body}"
                                end

                                return response
                        end
                end

                def access_token
                        local_token = CloudService.token
                        return local_token.access_token if local_token && local_token.valid?
			resource = create_resource( token_uri, token_headers )
                        resource.post( {} ) do |response, request, result, &block|
                                case response.code
                                when 200..207                        
                                        json = decode_response( response );                                        
                                        CloudService.token = Token.new( json )
                                        return CloudService.token.access_token
                                else
					puts "CloudService::access_token Error - #{response.body}"
                                        #Rails.logger.error "CloudService::access_token Error - #{response.body}"
                                        return response.return!
                                end                                
                        end
                end

                def create_resource( uri, headers )
                        return RestClient::Resource.new( uri, headers )
                end

                def success?( rsp )
                        return ( 200..207 ).include?( rsp.code )
                end

                def create_uri( suffix )
                        return "https://api-staging.tallac.com"
                end

                def decode_response( rsp )
                        return ActiveSupport::JSON.parse( rsp )#, symbolize_names: true )
                end

                def token_params
                        return { grant_type: 'client_credentials' }
                end

                def token_uri
                        return create_uri( '/api/oauth/token?grant_type=client_credentials' )
                end

                def auth_headers
                        return { :headers => 
                                        { :authorization => "Bearer #{access_token}",
                                          :accept        => 'application/json',
                                          :content_type  => 'application/json'  } }
                end

                def token_headers
                        return { :headers => 
                                        { :authorization => "Basic #{CLOUD_SERVICE_CONFIG['credentials']}" } }
                end
        end
end
	                

url = ' https://api-staging.tallac.com/api/oauth/token'

model = nil

params = {
        :id => 'tallac',
        :secret => 'tallac'
}

resp = Cloudservice::post(url,model,params)

resp_text = resp.body

