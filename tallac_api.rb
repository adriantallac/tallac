require 'restclient'

class CloudService
	
	# attr_accessor defines two new methods for us <instance_name>.toekn, <instance_name>.token=
	attr_accessor : token

	
	                def post( path, model, params )
                        begin 
                                resource = RestClient::Resource.new( create_uri( path ), auth_headers )
                        rescue RestClient::Exception => e
                                Rails.logger.error e
                                return e.response
                        end                
                        resource.post( params.to_json ) do |response, request, result, &block|
                                case response.code
                                when 200..207
                                        model.update_attributes( cloud_path: response.headers[ :location ] )
                                when 401
                                        Rails.logger.info "CloudService::POST - token expired, re-upping now"
                                        CloudService.token = nil
                                        post( path, model, params )
                                else
                                        Rails.logger.error "CloudService::POST Error - #{response.body}"
                                end

                                return response
                        end
                end

                def access_token
                        local_token = CloudService.token
                        return local_token.access_token if local_token && local_token.valid?
                        resource = create_resource( token_uri,token_headers )                                                                                        
                        resource.post( {} ) do |response, request, result, &block|
                                case response.code
                                when 200..207                        
                                        json = decode_response( response );                                        
                                        CloudService.token = Token.new( json )
                                        return CloudService.token.access_token
                                else
                                        Rails.logger.error "CloudService::access_token Error - #{response.body}"
                                        return response.return!
                                end                                
                        end
                end

