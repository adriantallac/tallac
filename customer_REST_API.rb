require "cloud_service"

url = 'http://www.api.tallac.com/oauth/token'
# uri = URI.parse(uri)

model = nil

params = {
	customer id => mpd@tallac.com
	customer secret = runs77@slap
}

#resp = Net::HTTP.post_form(url,params)

resp = Cloudservice.post(url,model,params)

resp_text = resp.body




