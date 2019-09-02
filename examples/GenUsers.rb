require 'random_word_generator'

out_file = File.new("users.csv", "w+")

out_file.puts("name,surname,email,mobile,telephone,remarks,groups,password")

for i in 1..99
	temp = RandomWordGenerator.word
	out_file.write(temp + ",")											# name
	out_file.write(temp + ",")											# surname
	out_file.write(temp + RandomWordGenerator.word + "@filler.co.za,")	# email
	out_file.write(",")													# mobile
	out_file.write("0,")												# telephone
	out_file.write("Good,")												# remarks
	out_file.write("enabled,")											# groups
	out_file.write(temp + "\n")											# password
end

temp = RandomWordGenerator.word
out_file.write(temp + ",")												# name
out_file.write(temp + ",")												# surname
out_file.write(temp + RandomWordGenerator.word + "@filler.co.za,")		# email
out_file.write(",")														# mobile
out_file.write("0,")													# telephone
out_file.write("Good,")													# remarks
out_file.write("enabled,")												# groups
out_file.write(temp)													# password

out_file.close()
