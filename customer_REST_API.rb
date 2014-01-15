require "cloud_service"

url = ' https://api-staging.tallac.com/api/oauth/token'
# uri = URI.parse(uri)

model = nil

params = {
	id => tallac
	secret => tallac
}

#resp = Net::HTTP.post_form(url,params)

resp = Cloudservice.post(url,model,params)

resp_text = resp.body




