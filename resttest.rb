gem 'test-unit'
require 'base64'
require 'cgi'
require 'test/unit'
require 'securerandom'
require 'rest_client'
require 'digest/sha1'
require 'json'

class RestBase < Test::Unit::TestCase

	def get(path, headers = {})
		return RestClient.get(@baseurl + path, headers) { |response, request, result| response }
	end

	def post(path, body, headers = {})
		return RestClient.post(@baseurl + path, body, headers) { |response, request, result| response }
	end

	def doany(verb, path, body, headers = {}, responseCode = nil, responseBody = nil)
		r = nil
		if verb == "POST"
			r = RestClient.post(@baseurl + path, body, headers) { |response, request, result| response }
		elsif verb == "PUT"
			r = RestClient.put(@baseurl + path, body, headers) { |response, request, result| response }
		elsif verb == "GET"
			r = RestClient.get(@baseurl + path, headers) { |response, request, result| response }
		else
			raise "RestBase: unknown verb #{verb}"
		end

		print(">>  #{path}  =>  #{r.code} #{r.body[0,300]} (#{r.class})\n")
		if block_given?
			yield(r)
		else
			assert_equal(responseCode.to_i, r.code.to_i)
			if responseBody != nil
				if responseBody.class == Hash
					assert(json_eq(r.body, responseBody))
				else
					assert_equal(responseBody.downcase, r.body.downcase)
				end
			end
		end
	end

	def doget(path, headers = {}, responseCode = nil, responseBody = nil)
		if block_given?
			doany("GET", path, nil, headers) { |r| yield(r) }
		else
			doany("GET", path, nil, headers, responseCode, responseBody)
		end
	end

	def dopost(path, body, headers = {}, responseCode = nil, responseBody = nil)
		if block_given?
			doany("POST", path, body, headers) { |r| yield(r) }
		else
			doany("POST", path, body, headers, responseCode, responseBody)
		end
	end

	def doput(path, body, headers = {}, responseCode = nil, responseBody = nil)
		if block_given?
			doany("PUT", path, body, headers) { |r| yield(r) }
		else
			doany("PUT", path, body, headers, responseCode, responseBody)
		end
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

	def array_eq(a,b)
		return false if a.class != Array or b.class != Array
		return false if a.length != b.length
		a.each_with_index { |av,i|
			return false if a[i] != b[i]
		}
		return true
	end

	def array_eq_any_order(a,b)
		return false if a.class != Array or b.class != Array
		return false if a.length != b.length
		b_visited = Array.new(b.length, false)
		a.each { |a_value|
			b_index = b.index(a_value)
			return false if b_index == nil || b_visited[b_index]
			b_visited[b_index] = true
		}
		return true
	end

	def hash_eq(a,b)
		diff = hash_eq_internal(a,b)
		if diff != ""
			print( "\nhash_eq failed:\n#{diff}\n")
			return false
		end
		return true
	end

	def dumpany(verb, path, body, headers = {})
		doany(verb, path, body, headers) { |r|
			print("Summary: #{r.description}")
			print("Body:    #{r.body}\n")
			print("Headers: #{r.headers}\n")
		}
	end

end

class AuthBase < RestBase
	
	def setup
		@baseurl = "http://127.0.0.1:3377"
		@pid = spawn("bin/imqsauth -c=!TESTCONFIG1 -nosvc run")
	end

	def teardown
		Process.kill("KILL", @pid)
	end

	def basicauth_joe
		return basicauth("joe", "JOE")
	end

	def basicauth_jack
		return basicauth("jack", "JACK")
	end

	def basicauth_admin
		return basicauth("admin", "ADMIN")
	end

	def basicauth_admin_disabled
		return basicauth("admin_disabled", "ADMIN_DISABLED")
	end

	def session_cookie(session)
		return {:Cookie => "session=#{session}"}
	end

end

class Authorization < AuthBase

	def experiment
		r = get("/check")
		print("#{r.code}\n")
		print("#{r.body}\n")
		print("#{r.headers}\n")
		print("#{r.description}\n")
		print("--#{r.net_http_res.message}--\n")
	end

	def login_and_check(verb, path)
		doany(verb, path, nil, {:Authorization => "Basic invalid_auth"}, 400, "http basic authorization must be base64(identity:password)")
		doany(verb, path, nil, basicauth("joe","JoE"), 403, "Invalid password")
		doany(verb, path, nil, basicauth("jjj","JOE"), 403, "Identity authorization not found")
	end

	def test_login
		doget("/login", basicauth_joe, 400, "API must be accessed using an HTTP POST method")
		dopost("/login", nil, basicauth_joe, 200, {:Identity => "joe", :Roles => ["2"]})
		dopost("/login", nil, {}, 400, "http basic authorization must be base64(identity:password)")
		login_and_check("POST", "/login")
	end

	def test_check
		dopost("/check", nil, basicauth_joe, 400, "API must be accessed using an HTTP GET method")
		doget("/check", basicauth_joe, 200, {:Identity => "joe", :Roles => ["2"]})
		doget("/check", {}, 401, "No authorization information")
		login_and_check("GET", "/check")
	end

	def test_set_password()
		# Cannot change somebody else's password if you're not admin
		dopost("/set_password?identity=sam&password=123", nil, basicauth_joe, 403, "You are not an administrator")

		# Change joe's password, while acting as joe
		dopost("/set_password?identity=joe&password=123", nil, basicauth_joe, 200, "Password changed")
		doget("/check", basicauth_joe, 403, "Invalid password")
		dopost("/set_password?identity=joe&password=JOE", nil, basicauth("joe", "123"), 200, "Password changed")
		doget("/check", basicauth_joe, 200, {:Identity => "joe", :Roles => ["2"]})

		# Change joe's password, while acting as administrator
		dopost("/set_password?identity=joe&password=123", nil, basicauth_admin, 200, "Password changed")
		doget("/check", basicauth_joe, 403, "Invalid password")
		dopost("/set_password?identity=joe&password=JOE", nil, basicauth_admin, 200, "Password changed")
		doget("/check", basicauth_joe, 200, {:Identity => "joe", :Roles => ["2"]})
	end

	def test_rename_as_user()
		session = post("/login", nil, basicauth_joe).cookies["session"]
		longmsg_base = "'rename_user' must be accompanied by http basic authentication of the user that is being renamed (this confirms that you know your own password). alternatively, if you have admin rights, you can rename any user."
		longmsg_nobasic = longmsg_base + " error: no authorization information"
		longmsg_wronguser = longmsg_base + " authenticated with 'jack', but tried to rename user 'joe'"
		dopost("/rename_user?old=joe&new=jack", nil, session_cookie(session), 403, longmsg_nobasic)
		dopost("/rename_user?old=joe&new=jack", nil, basicauth_joe, 400, "Identity already exists")
		dopost("/rename_user?old=joe&new=joe", nil, basicauth_joe, 200, "Renamed 'joe' to 'joe'")
		dopost("/rename_user?old=joe&new=jack", nil, basicauth_jack, 403, longmsg_wronguser)
		dopost("/rename_user?old=joe&new=sarah", nil, basicauth_joe, 200, "Renamed 'joe' to 'sarah'")
	end

	def test_rename_as_admin()
		dopost("/rename_user?old=joe&new=jack", nil, basicauth_admin, 400, "Identity already exists")
		dopost("/rename_user?old=joe&new=sarah", nil, basicauth_admin, 200, "Renamed 'joe' to 'sarah'")
		dopost("/rename_user?old=sarah&new=sarah@abc.com", nil, basicauth_admin, 200, "Renamed 'sarah' to 'sarah@abc.com'")
	end
end

class AdminTasks < AuthBase

	def verify_role_groups(identity, groups)
		doget("/users", basicauth_admin, 200) { |r|
			users = JSON.parse(r.body.downcase)
			assert(users[identity.downcase])
			assert(array_eq_any_order(users[identity.downcase]["groups"], groups))
		}
		#dumpany("GET", "/users", nil, basicauth_admin)
	end

	def test_top_filter_admin_rights
		admin_commands =
		%w(
			PUT  create_user
			POST set_user_groups
		)
		(0 .. admin_commands.length - 1).step(2) { |i|
			verb = admin_commands[i]
			action = admin_commands[i + 1]
			doany(verb, "/#{action}", nil, basicauth_joe, 403, "You are not an administrator")
			doany(verb, "/#{action}", nil, basicauth_admin_disabled, 403, "Account disabled")
		}
	end

	def test_create_user_and_set_groups
		doput("/create_user?identity=sam&password=SAM", nil, basicauth_admin, 200, "Created identity 'sam'")
		# Although we have created the identity in the Authenticator, we have not yet created a permit
		# in the PermitDB. That is why a call to /check on "sam" will fail.
		doget("/check", basicauth("sam", "SAM"), 403, "Identity permit not found")
		
		# Enumerating the list of users MUST include "sam", despite the fact that he
		# has no permit defined. Were this not the case, then the admin GUI could get stuck
		# in a state where it has created an identity, but it cannot set its permit, or
		# that identity gets "lost" because it is invisible to certain parts of the system
		verify_role_groups("sam", [])
		
		# This is an unfortunate consequence of authaus not caring how you bring together your PermitDB and Authentication system.
		# You can create permits for users that do not exist in the authentication system. This kind of abuse could only be performed
		# by an administrator.
		dopost("/set_user_groups?identity=nobody&groups=enabled", nil, basicauth_admin, 200, "'nobody' groups set to (enabled)")

		dopost("/set_user_groups?groups=enabled", nil, basicauth_admin, 403, "Identity is empty")

		dopost("/set_user_groups?identity=sam&groups=NOT_A_GROUP", nil, basicauth_admin, 403, "Invalid groups: Group does not exist")

		# Assign 'enabled' group to 'sam'
		dopost("/set_user_groups?identity=sam&groups=enabled", nil, basicauth_admin, 200, "'sam' groups set to (enabled)")
		
		verify_role_groups("sam", ["enabled"])

		# Assign no groups to 'sam'
		dopost("/set_user_groups?identity=sam&groups=", nil, basicauth_admin, 200, "'sam' groups set to ()")

		verify_role_groups("sam", [])

		# Check case-insensitivity
		verify_role_groups("Sam", [])
		dopost("/set_user_groups?identity=saM&groups=enabled", nil, basicauth_admin, 200, "'sam' groups set to (enabled)")
		verify_role_groups("sAm", ["enabled"])
	end

	def test_list_users_noadmin
		doget("/users", basicauth_joe, 200);
	end

	def test_list_groups_noadmin
		doget("/groups", basicauth_joe, 200);
	end	

	def test_list_groups
		doget("/groups", basicauth_admin, 200) { |r|
			groups_list = JSON.parse(r.body)
			groups_by_name = {}
			groups_list.each { |g| groups_by_name[g["Name"]] = g }
			admin = groups_by_name["admin"]
			enabled = groups_by_name["enabled"]
			assert(admin != nil && admin["Roles"].length == 1)
			assert(enabled != nil && enabled["Roles"].length == 1)
		}
	end

	def test_create_group_neg
		#negative test, non-admin usage
		doput("/create_group?groupname=testgroup", nil, basicauth_joe, 403, "you are not an administrator")
	end

	def test_create_group
		doput("/create_group?groupname=testgroup", nil, basicauth_admin, 200, "")
		doget("/groups", basicauth_admin, 200) { |r|
			groups_list = JSON.parse(r.body)
			groups_by_name = {}
			groups_list.each { |g| groups_by_name[g["Name"]] = g }
			testgroup = groups_by_name["testgroup"]
			assert(testgroup != nil && testgroup["Roles"].length == 0)
		}
	end

	def test_set_group_roles_neg
		doput("/set_group_roles?groupname=testgroup&roles=1,2", nil, basicauth_joe, 403, "you are not an administrator")
		doput("/set_group_roles?groupname=testgroup1&roles=1,2", nil, basicauth_admin, 404, "group 'testgroup1' not found: group does not exist")
	end

	def test_set_group_roles
		doput("/create_group?groupname=testgroup", nil, basicauth_admin, 200, "")
		doput("/set_group_roles?groupname=testgroup&roles=1,2", nil, basicauth_admin, 200, "")

		doget("/groups", basicauth_admin, 200) { |r|
			groups_list = JSON.parse(r.body)
			groups_by_name = {}
			groups_list.each { |g| groups_by_name[g["Name"]] = g }
			testgroup = groups_by_name["testgroup"]
			assert(testgroup != nil && testgroup["Roles"].length == 2)
		}
	end

end
