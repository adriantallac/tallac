#!/usr/bin/env ruby
require 'base64'
require 'date'
require 'restclient'
require 'json'
 
USERNAME="100973193437466374449"
PASSWORD="tallac123"
 
class Token
 
	attr_reader :access_token, :expiration
 
	def initialize( params ) 
		@access_token = params[ :access_token ]
	end
 
	def valid?
		return false
	end
 
	def expired?
		return true
	end
 
end
 
class CloudService
 
    class << self
 
		attr_accessor :token
 
		def get( path, decode=true )
			puts "Making GET request to: #{path}"
			begin 
				resource = RestClient::Resource.new( create_uri( URI.encode( path ) ), auth_headers )
			rescue RestClient::Exception => e
				puts e.to_s
				return nil
			end			
			resource.get do |response, request, result, &block|
				case response.code
				when 200..207
					puts response.body
					return decode_response( response.body ) if decode
					return response.body
				when 401
					puts "CloudService::GET - token expired, re-upping now"
					CloudService.token = nil
					return get( path )
				else
					puts "CloudService::GET Error - #{response.body}"
				end				
				return nil
			end
		end
 
		def delete( path )
			begin 
				resource = RestClient::Resource.new( create_uri( path ), auth_headers )
			rescue RestClient::Exception => e
				puts e
				return false
			end			
			resource.delete do |response, request, result, &block|
				case response.code
				when 200..207
					return true
				when 401
					puts "CloudService::DELETE - token expired, re-upping now"
					CloudService.token = nil
					return delete( path )
				else
					puts "CloudService::DELETE Error - #{response.body}"
				end				
				return false
			end
		end
 
		def patch( path, params )
			begin 
				resource = RestClient::Resource.new( create_uri( path ), auth_headers )
			rescue RestClient::Exception => e
				puts e
				return e.response
			end			
			resource.patch( params.to_json ) do |response, request, result, &block|
				case response.code
				when 200..207
				when 401
					puts "CloudService::PATCH - token expired, re-upping now"
					CloudService.token = nil
					patch( path, params )
				else
					puts "CloudService::PATCH Error - #{response.body}"
				end				
				return response
			end
		end
 
		def post( path, model, params )
			begin 
				resource = RestClient::Resource.new( create_uri( path ), auth_headers )
			rescue RestClient::Exception => e
				puts e
				return e.response
			end		
			resource.post( params.to_json ) do |response, request, result, &block|
				case response.code
				when 200..207
					model.update_attributes( cloud_path: response.headers[ :location ] )
				when 401
					puts "CloudService::POST - token expired, re-upping now"
					CloudService.token = nil
					post( path, model, params )
				else
					puts.error "CloudService::POST Error - #{response.body}"
				end
 
				return response
			end
		end
 
		def access_token
			local_token = CloudService.token			
			return local_token.access_token if local_token && local_token.valid?
			resource = create_resource( token_uri, token_headers )						
			puts "Getting token from: #{token_uri}"
			resource.post( {} ) do |response, request, result, &block|
				puts "Status: #{response.code}"
				case response.code
				when 200..207			
					json = decode_response( response );					
					CloudService.token = Token.new( json )
					return CloudService.token.access_token
				else
					puts "CloudService::access_token Error - #{response.body}"
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
			return "https://api-staging.tallac.com#{suffix}"
		end
 
		def decode_response( rsp )
			return JSON.parse( rsp, symbolize_names: true )
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
					{ :authorization => "Basic #{encoded_auth}" } }
		end
 
		def encoded_auth
			return Base64.encode64( "#{USERNAME}:#{PASSWORD}" ).chomp
		end
	end
end
 
def main
	puts "================================================================================================================== "	
	puts "---------------------------------------------ACCESS GROUP--------------------------------------------------------- "	
	puts "================================================================================================================== "	
	CloudService.get( '/api/access-group/1018244782635993037010', false )
	puts "================================================================================================================== "	
	CloudService.post( '/api/access-group/1018244782635993037010/0', false )	
	puts "================================================================================================================== "
	CloudService.get( '/api/access-group/1018244782635993037010/log?start_time=1&end_time=2', false )
	puts "================================================================================================================== "
	CloudService.get( '/api/access-group/1018244782635993037010/statistics?start_time=1&end_time=2', false )
	puts "================================================================================================================== "	
	puts "---------------------------------------------CUSTOMER------------------------------------------------------------- "	
	puts "================================================================================================================== "
	CloudService.get( '/api/customer/1018244782635993037010', false )
	puts "================================================================================================================== "
	CloudService.get( '/api/access-point', false )
	puts "================================================================================================================== "	
	puts "---------------------------------------------HEALTH CHECK--------------------------------------------------------- "	
	puts "================================================================================================================== "
	CloudService.get( '/api/health-check', false )

end
 
main
