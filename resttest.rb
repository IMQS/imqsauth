gem "test-unit"
require "base64"
require "cgi"
require "test/unit"
require "securerandom"
require "rest_client"
require "digest/sha1"
require "json"

class RestBase < Test::Unit::TestCase
  def get(path, headers = {})
    RestClient.get(@baseurl + path, headers) { |response, _request, _result| response }
  end

  def post(path, body, headers = {})
    RestClient.post(@baseurl + path, body, headers) { |response, _request, _result| response }
  end

  def doany(verb, path, body, headers = {}, responseCode = nil, responseBody = nil)
    r = nil
    if verb == "POST"
      r = RestClient.post(@baseurl + path, body, headers) { |response, _request, _result| response }
    elsif verb == "PUT"
      r = RestClient.put(@baseurl + path, body, headers) { |response, _request, _result| response }
    elsif verb == "GET"
      r = RestClient.get(@baseurl + path, headers) { |response, _request, _result| response }
    else
      raise "RestBase: unknown verb #{verb}"
    end

    print(">>  #{path}  =>  #{r.code} #{r.body[0, 300]} (#{r.class})\n")
    if block_given?
      yield(r)
    else
      assert_equal(responseCode.to_i, r.code.to_i)
      unless responseBody.nil?
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
    { Authorization: "Basic " + Base64.encode64("#{identity}:#{password}") }
  end

  def json_eq(a, b)
    return false if a.nil? || b.nil?
    a_str = a.instance_of?(String) ? a : JSON.generate(a)
    b_str = b.instance_of?(String) ? b : JSON.generate(b)
    a_obj = JSON.parse(a_str)
    b_obj = JSON.parse(b_str)
    a_str_2 = JSON.generate(a_obj)
    b_str_2 = JSON.generate(b_obj)
    if hash_eq(a_obj, b_obj)
      return true
    else
      print("\n#{a_str_2}\n != \n#{b_str_2}\n")
      return false
    end
  end

  def hash_eq_internal(a, b)
    return false if a.class != Hash || b.class != Hash
    a.each do |ak, av|
      bv = b[ak]
      return "#{av} != #{bv} (nil diff)" if av.nil? != bv.nil?
      next if av.nil?
      return "#{av} vs #{bv}: #{av.class} != #{bv.class}" if av.class != bv.class
      if av.class == Hash
        t = hash_eq_internal(av, bv)
        return t if t != ""
      end
      return "#{av} != #{bv} (value diff)" if a != b
    end
    ""
  end

  def array_eq(a, b)
    return false if a.class != Array || b.class != Array
    return false if a.length != b.length
    a.each_with_index do |_av, i|
      return false if a[i] != b[i]
    end
    true
  end

  def array_eq_any_order(a, b)
    return false if a.class != Array || b.class != Array
    return false if a.length != b.length
    b_visited = Array.new(b.length, false)
    a.each do |a_value|
      b_index = b.index(a_value)
      return false if b_index.nil? || b_visited[b_index]
      b_visited[b_index] = true
    end
    true
  end

  def hash_eq(a, b)
    diff = hash_eq_internal(a, b)
    if diff != ""
      print("\nhash_eq failed:\n#{diff}\n")
      return false
    end
    true
  end

  def dumpany(verb, path, body, headers = {})
    doany(verb, path, body, headers) do |r|
      print("Summary: #{r.description}")
      print("Body:    #{r.body}\n")
      print("Headers: #{r.headers}\n")
    end
  end

  def getUserId(email)
    doany("GET", "/userobjects", nil, basicauth("admin", "ADMIN")) do |r|
      obj = JSON.parse(r.body)
      obj.each do |user|
        unless user.nil?
          return user["UserId"] if user["Email"] == email
         end
      end
    end
  end

  def getUser(userid)
    doany("GET", "/userobjects", nil, basicauth("admin", "ADMIN")) do |r|
      obj = JSON.parse(r.body)
      obj.each do |user|
        unless user.nil?
          return user if user["UserId"] == userid
         end
      end
    end
  end
end

class AuthBase < RestBase
  def setup
    @baseurl = "http://127.0.0.1:3377"
    @pid = spawn("bin/imqsauth -c=!TESTCONFIG1 -nosvc run")

    # Load user ids
    doany("GET", "/userobjects", nil, basicauth("admin", "ADMIN")) do |r|
      obj = JSON.parse(r.body)
      obj.each do |user|
        unless user.nil?
          @joe_user_id = user["UserId"] if user["Email"] == "joe"
          @jack_user_id = user["UserId"] if user["Email"] == "jack"
          @admin_user_id = user["UserId"] if user["Email"] == "admin"
          if user["Email"] == "admin_disabled"
            @admin_disabled_user_id = user["UserId"]
          end
        end
      end
      @unknown_user_id = 999
    end
  end

  def teardown
    Process.kill("KILL", @pid)
  end

  def basicauth_joe
    basicauth("joe", "JOE")
  end

  def basicauth_jack
    basicauth("jack", "JACK")
  end

  def basicauth_admin
    basicauth("admin", "ADMIN")
  end

  def basicauth_admin_disabled
    basicauth("admin_disabled", "ADMIN_DISABLED")
  end

  def session_cookie(session)
    { Cookie: "session=#{session}" }
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
    doany(verb, path, nil, { Authorization: "Basic invalid_auth" }, 400, "http basic authorization must be base64(identity:password)")
    doany(verb, path, nil, basicauth("joe", "JoE"), 403, "Invalid password")
    doany(verb, path, nil, basicauth("jjj", "JOE"), 403, "Identity authorization not found")
  end

  def test_login
    doget("/login", basicauth_joe, 400, "API must be accessed using an HTTP POST method")
    dopost("/login", nil, basicauth_joe, 200, UserId: @joe_user_id, Identity: "joe", Email: "", Username: "", Roles: ["2"])
    dopost("/login", nil, {}, 400, "http basic authorization must be base64(identity:password)")
    login_and_check("POST", "/login")
  end

  def test_check
    dopost("/check", nil, basicauth_joe, 400, "API must be accessed using an HTTP GET method")
    doget("/check", basicauth_joe, 200, UserId: @joe_user_id, Identity: "joe", Email: "", Username: "", Roles: ["2"])
    doget("/check", {}, 401, "No authorization information")
    login_and_check("GET", "/check")
  end

  def test_set_password
    # Cannot change somebody else's password if you're not admin
    dopost("/set_password?userid=#{@jack_user_id}&password=123", nil, basicauth_joe, 403, "You are not an administrator")

    # Change joe's password, while acting as joe
    dopost("/set_password?userid=#{@joe_user_id}&password=123", nil, basicauth_joe, 200, "Password changed")
    doget("/check", basicauth_joe, 403, "Invalid password")
    dopost("/set_password?userid=#{@joe_user_id}&password=JOE", nil, basicauth("joe", "123"), 200, "Password changed")
    doget("/check", basicauth_joe, 200, UserId: @joe_user_id, Identity: "joe", Email: "", Username: "", Roles: ["2"])

    # Change joe's password, while acting as administrator
    dopost("/set_password?userid=#{@joe_user_id}&password=123", nil, basicauth_admin, 200, "Password changed")
    doget("/check", basicauth_joe, 403, "Invalid password")
    dopost("/set_password?userid=#{@joe_user_id}&password=JOE", nil, basicauth_admin, 200, "Password changed")
    doget("/check", basicauth_joe, 200, UserId: @joe_user_id, Identity: "joe", Email: "", Username: "", Roles: ["2"])
  end

  def test_rename_as_user
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

  def test_rename_as_admin
    dopost("/rename_user?old=joe&new=jack", nil, basicauth_admin, 400, "Identity already exists")
    dopost("/rename_user?old=joe&new=sarah", nil, basicauth_admin, 200, "Renamed 'joe' to 'sarah'")
    dopost("/rename_user?old=sarah&new=sarah@abc.com", nil, basicauth_admin, 200, "Renamed 'sarah' to 'sarah@abc.com'")
  end

  def test_update_users
    dopost("/update_user?userid=#{@joe_user_id}&email=email&username=username&firstname=firstname&lastname=lastname&mobilenumber=mobilenumber&authusertype=DEFAULT", nil, basicauth_joe, 403, "You are not an administrator")
    dopost("/update_user?userid=#{@unknown_user_id}&email=email&username=username&firstname=firstname&lastname=lastname&mobilenumber=mobilenumber&authusertype=DEFAULT", nil, basicauth_admin, 403, "Identity authorization not found")
    dopost("/update_user?userid=#{@joe_user_id}&email=joeEmail&username=joeUsername&firstname=joeFirstname&lastname=joeLastname&mobilenumber=084&authusertype=DEFAULT", nil, basicauth_admin, 200, "updated user: '1'")
    joeUser = getUser(@joe_user_id)
    assert(joeUser["Email"] == "joeEmail")
    assert(joeUser["Username"] == "joeUsername")
    assert(joeUser["Name"] == "joeFirstname")
    assert(joeUser["Surname"] == "joeLastname")
    assert(joeUser["Mobile"] == "084")
    assert(joeUser["AuthUserType"] == 0)
    dopost("/update_user?userid=#{@joe_user_id}&email=joeEmailUpdated&username=joeUsernameUpdated&firstname=joeFirstnameUpdated&lastname=joeLastnameUpdated&mobilenumber=084674&authusertype=LDAP", nil, basicauth_admin, 200, "updated user: '1'")
    joeUser = getUser(@joe_user_id)
    assert(joeUser["Email"] == "joeEmailUpdated")
    assert(joeUser["Username"] == "joeUsernameUpdated")
    assert(joeUser["Name"] == "joeFirstnameUpdated")
    assert(joeUser["Surname"] == "joeLastnameUpdated")
    assert(joeUser["Mobile"] == "084674")
    assert(joeUser["AuthUserType"] == 1)
    dopost("/update_user?userid=#{@joe_user_id}&email=joeEmailUpdated&username=joeUsernameUpdated&firstname=joeFirstnameUpdated&lastname=joeLastnameUpdated&mobilenumber=084674&authusertype=InvalidAuthUserType", nil, basicauth_admin, 400, "Invalid AuthUserType: 'InvalidAuthUserType'")
  end

  def test_archive_users
    dopost("/archive_user?userid=#{@joe_user_id}", nil, basicauth_joe, 403, "You are not an administrator")
    dopost("/archive_user?userid=#{@unknown_user_id}", nil, basicauth_admin, 403, "Identity authorization not found")
    dopost("/archive_user?userid=#{@joe_user_id}", nil, basicauth_admin, 200, "Archived user: '1'")
  end
end

class AdminTasks < AuthBase
  def verify_role_groups_userobject_endpoint(identity, groups)
    doget("/userobjects", basicauth_admin, 200) do |r|
      users = JSON.parse(r.body.downcase)
      users.each do |user|
        unless user.nil?
          if user["Email"] == identity
            assert(user["Email"] == identity.downcase)
            assert(array_eq_any_order(user["UserId"]["groups"], groups))
            break
           end
        end
      end
    end
    # dumpany("GET", "/users", nil, basicauth_admin)
  end

  def search_in_users(user_key, users)
    users.each do |user|
      return user if user["email"] == user_key
    end
    false
  end

  def verify_role_groups_user_endpoint(identity, groups)
    doget("/users", basicauth_admin, 200) do |r|
      users = JSON.parse(r.body.downcase)
      assert(search_in_users(identity.downcase, users))
      assert(array_eq_any_order(search_in_users(identity.downcase, users)["groups"], groups))
    end
    # dumpany("GET", "/users", nil, basicauth_admin)
  end

  def verify_number_of_users_with_permission(permission, num)
    doget("/userobjects?permission=#{permission}", basicauth_admin, 200) do |r|
      users = JSON.parse(r.body.downcase)
      assert_equal(users.length, num)
    end
  end

  def test_top_filter_admin_rights
    admin_commands =
      %w(
        PUT create_user
        POST set_user_groups
      )
    (0..admin_commands.length - 1).step(2) do |i|
      verb = admin_commands[i]
      action = admin_commands[i + 1]
      doany(verb, "/#{action}", nil, basicauth_joe, 403, "You are not an administrator")
      doany(verb, "/#{action}", nil, basicauth_admin_disabled, 403, "Account disabled")
    end
  end

  def test_create_user_and_set_groups
    doput("/create_user?email=sam&password=SAM", nil, basicauth_admin, 200, "Created identity 'sam'")
    # Although we have created the identity in the Authenticator, we have not yet created a permit
    # in the PermitDB. That is why a call to /check on "sam" will fail.
    doget("/check", basicauth("sam", "SAM"), 403, "Identity permit not found")

    # Enumerating the list of users MUST include "sam", despite the fact that he
    # has no permit defined. Were this not the case, then the admin GUI could get stuck
    # in a state where it has created an identity, but it cannot set its permit, or
    # that identity gets "lost" because it is invisible to certain parts of the system
    verify_role_groups_userobject_endpoint("sam", [])
    verify_role_groups_user_endpoint("sam", [])

    # This is an unfortunate consequence of authaus not caring how you bring together your PermitDB and Authentication system.
    # You can create permits for users that do not exist in the authentication system. This kind of abuse could only be performed
    # by an administrator.
    dopost("/set_user_groups?userid=#{@unknown_user_id}&groups=enabled", nil, basicauth_admin, 200, "'#{@unknown_user_id}' groups set to (enabled)")

    dopost("/set_user_groups?groups=enabled", nil, basicauth_admin, 403, "No userid specified")

    sam_user_id = getUserId("sam")
    dopost("/set_user_groups?userid=#{sam_user_id}&groups=NOT_A_GROUP", nil, basicauth_admin, 403, "Invalid groups: Group does not exist")

    # Assign 'enabled' group to 'sam'
    dopost("/set_user_groups?userid=#{sam_user_id}&groups=enabled", nil, basicauth_admin, 200, "'#{sam_user_id}' groups set to (enabled)")

    verify_role_groups_userobject_endpoint("sam", ["enabled"])
    verify_role_groups_user_endpoint("sam", ["enabled"])

    # Assign no groups to 'sam'
    dopost("/set_user_groups?userid=#{sam_user_id}&groups=", nil, basicauth_admin, 200, "'#{sam_user_id}' groups set to ()")

    verify_role_groups_userobject_endpoint("sam", [])
    verify_role_groups_user_endpoint("sam", [])
  end

  def test_get_users_with_permission
    doput("/create_user?email=bilbo&password=BILBO", nil, basicauth_admin, 200, "Created identity 'bilbo'")

    # create 'fellowship' group with permission 999 (which isn't used in any other test)
    doput("/create_group?groupname=fellowship", nil, basicauth_admin, 200, "")
    doput("/set_group_roles?groupname=fellowship&roles=1,999", nil, basicauth_admin, 200, "")
    bilbo_user_id = getUserId("bilbo")
    
    # Assign 'fellowship' group to 'bilbo'
    dopost("/set_user_groups?userid=#{bilbo_user_id}&groups=fellowship", nil, basicauth_admin, 200, "'#{bilbo_user_id}' groups set to (fellowship)")
    verify_number_of_users_with_permission(999, 1)

    # Assign no groups to 'bilbo'
    dopost("/set_user_groups?userid=#{bilbo_user_id}&groups=", nil, basicauth_admin, 200, "'#{bilbo_user_id}' groups set to ()")
    verify_number_of_users_with_permission(999, 0)
  end

  def test_list_users_noadmin
    doget("/users", basicauth_joe, 200)
    doget("/userobjects", basicauth_admin, 200)
  end

  def test_list_groups_noadmin
    doget("/groups", basicauth_joe, 200)
  end

  def test_list_groups
    doget("/groups", basicauth_admin, 200) do |r|
      groups_list = JSON.parse(r.body)
      groups_by_name = {}
      groups_list.each { |g| groups_by_name[g["Name"]] = g }
      admin = groups_by_name["admin"]
      enabled = groups_by_name["enabled"]
      assert(!admin.nil? && admin["Roles"].length == 1)
      assert(!enabled.nil? && enabled["Roles"].length == 1)
    end
  end

  def test_create_group_neg
    # negative test, non-admin usage
    doput("/create_group?groupname=testgroup", nil, basicauth_joe, 403, "you are not an administrator")
  end

  def test_create_group
    doput("/create_group?groupname=testgroup", nil, basicauth_admin, 200, "")
    doget("/groups", basicauth_admin, 200) do |r|
      groups_list = JSON.parse(r.body)
      groups_by_name = {}
      groups_list.each { |g| groups_by_name[g["Name"]] = g }
      testgroup = groups_by_name["testgroup"]
      assert(!testgroup.nil? && testgroup["Roles"].length == 0)
    end
  end

  def test_set_group_roles_neg
    doput("/set_group_roles?groupname=testgroup&roles=1,2", nil, basicauth_joe, 403, "you are not an administrator")
    doput("/set_group_roles?groupname=testgroup1&roles=1,2", nil, basicauth_admin, 404, "group 'testgroup1' not found: group does not exist")
  end

  def test_set_group_roles
    doput("/create_group?groupname=testgroup", nil, basicauth_admin, 200, "")
    doput("/set_group_roles?groupname=testgroup&roles=1,2", nil, basicauth_admin, 200, "")

    doget("/groups", basicauth_admin, 200) do |r|
      groups_list = JSON.parse(r.body)
      groups_by_name = {}
      groups_list.each { |g| groups_by_name[g["Name"]] = g }
      testgroup = groups_by_name["testgroup"]
      assert(!testgroup.nil? && testgroup["Roles"].length == 2)
    end
  end
end
