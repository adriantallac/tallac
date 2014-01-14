class Greeter
	def init(name="world")
		@name = name
	end
	
	def say_hi
		puts "Hello #{@name}"
	end

	def say_bye
		puts "Bye #{@name}"
	end
	
end

if __FILE__ == $0
	g = Greeter.new()
	g.say_hi
	g.say_bye
end

