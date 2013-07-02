gem 'test-unit'
require 'base64'
require 'cgi'
require 'test/unit'
require 'securerandom'
require 'rest_client'
require 'digest/sha1'
require 'json'

class Base < Test::Unit::TestCase

	def setup
		@baseurl = "http://127.0.0.1:3377"
		@pid = spawn("bin/imqsauth -c !TESTCONFIG1 run")
	end

	def teardown
		Process.kill("KILL", @pid)
	end

	def get(path, headers = {})
		return RestClient.get(@baseurl + path, headers) { |response, request, result| response }
	end

	def post(path, body, headers = {})
		return RestClient.post(@baseurl + path, body, headers) { |response, request, result| response }
	end

	def doany(verb, path, body, headers, responseCode, responseBody = nil)
		r = nil
		if verb == "POST"
			r = RestClient.post(@baseurl + path, body, headers) { |response, request, result| response }
		elsif verb == "GET"
			r = RestClient.get(@baseurl + path, headers) { |response, request, result| response }
		else
			raise "unknown verb #{verb}"
		end

		print(">>  #{path}  =>  #{r.code} #{r.body[0,100]} (#{r.class})\n")
		assert_equal(r.code.to_i, responseCode.to_i)
		if responseBody != nil
			if responseBody.class == Hash
				assert(json_eq(r.body, responseBody))
			else
				assert_equal(r.body, responseBody)
			end
		end
	end

	def doget(path, headers, responseCode, responseBody = nil)
		doany("GET", path, nil, headers, responseCode, responseBody)
	end

	def dopost(path, body, headers, responseCode, responseBody = nil)
		doany("POST", path, body, headers, responseCode, responseBody)
	end

	def basicauth(identity, password)
		return {:Authorization => "Basic " + Base64.encode64("#{identity}:#{password}")}
	end

	def json_eq(a,b)
		return false if a == nil || b == nil
		a_str = a.instance_of?(String) ? a : JSON.generate(a)
		b_str = b.instance_of?(String) ? b : JSON.generate(b)
		a_obj = JSON.parse(a_str)
		b_obj = JSON.parse(b_str)
		a_str_2 = JSON.generate(a_obj)
		b_str_2 = JSON.generate(b_obj)
		if hash_eq(a_obj, b_obj)
			return true
		else
			print( "\n#{a_str_2}\n != \n#{b_str_2}\n" )
			return false
		end
	end

	def hash_eq_internal(a,b)
		return false if a.class != Hash or b.class != Hash
		a.each { |ak,av| 
			bv = b[ak]
			return "#{av} != #{bv} (nil diff)" if (av == nil) != (bv == nil)
			next if av == nil
			return "#{av} vs #{bv}: #{av.class} != #{bv.class}" if av.class != bv.class
			if av.class == Hash
				t = hash_eq_internal(av, bv)
				return t if t != ""
			end
			return "#{av} != #{bv} (value diff)" if a != b
		}
		return ""
	end

	def hash_eq(a,b)
		diff = hash_eq_internal(a,b)
		if diff != ""
			print( "\nhash_eq failed:\n#{diff}\n")
			return false
		end
		return true
	end

end

class Hello < Base

	def experiment
		r = get("/check")
		print("#{r.code}\n")
		print("#{r.body}\n")
		print("#{r.headers}\n")
		print("#{r.description}\n")
		print("--#{r.net_http_res.message}--\n")
	end

	def test_login
		doget("/login", basicauth("joe","123"), 400, "API must be accessed using an HTTP POST method")
		dopost("/login", nil, basicauth("joe","123"), 200, "")
		login_and_check("POST", "/login")
	end

	def test_check
		dopost("/check", nil, basicauth("joe","123"), 400, "API must be accessed using an HTTP GET method")
		doget("/check", basicauth("joe","123"), 200, {:Identity => "joe", :Roles => ["2"]})
		login_and_check("GET", "/check")
	end

	def login_and_check(verb, path)
		doany(verb, path, nil, basicauth("joe","111"), 403, "Invalid password")
		doany(verb, path, nil, basicauth("jjj","123"), 403, "Identity authorization not found")
	end

end
