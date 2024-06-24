from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from time import sleep

import sys
import string
import random


def address_to_string(address):
	ip, port = address
	print(ip)
	return ':'.join([ip, str(port)])


class ServerProtocol(DatagramProtocol):

	def __init__(self):
		self.active_sessions = {} # session objects
		self.registered_clients = {} # client objects
		self.next_player_id = 0 # next player id will be this attribute value



	#########################
	# Helper functions #
	#########################


	# checks if a username is valid
	def check_username(self, username):
		if len(username) > 20:
			return 1
		for user_id in self.registered_clients:
			user = self.registered_clients[user_id]
			if username == user.username:
				return 2
		# valid username
		return 0
	

	# check if user exists
	def user_is_registered(self, user_id):
		return user_id in self.registered_clients.keys()


	# check if session exists
	def session_is_active(self, session):
		return session in self.active_sessions.keys()


	# checks if a user is already in a server
	def user_already_in_session(self, user_id):
		user = self.registered_clients[user_id]
		if user.session_id==None:
			return False
		return True


	# check if user is in that session
	def user_is_in_session(self, s_id, user_id):
		session = self.active_sessions[s_id]
		for user in session.registered_clients:
			if user.name == user_id:
				return True
		return False


	# get user session
	def get_user_session_id(self, user_id):
		if self.user_already_in_session(user_id):
			return self.registered_clients[user_id].session_id
		return None

	# check if user is session server
	def user_is_server(self, s_id, user_id):
		session = self.active_sessions[s_id]
		session_server = session.registered_clients[0]

		if session_server.name == user_id:
			return True
		return False


	# generates an id for a new registered user
	def generate_user_id(self):
		self.next_player_id = self.next_player_id + 1
		return self.next_player_id - 1 


	# generates random id for new session
	def generate_random_id(self):
		N = 8
		return ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))


	# removes a user from registered clients list
	def remove_user(self, user):
		try:
			del user
		except KeyError:
			print("Player doesn't exist")


	# removes a session from active sessions list
	def remove_session(self, s_id):
		# users leave session

		print("removing session, " + str(len(self.active_sessions[s_id].registered_clients)))
		session = self.active_sessions[s_id]
		for user in session.registered_clients:
			user.session_id = None
			print("removing " + user.name)
			#self.user_leave_session(user)

		# quit session from list
		session.registered_clients.clear()
		
		self.active_sessions.pop(s_id)

		# remove session
		try:
			del session
		except KeyError:
			print("Tried to terminate non-existing session")


	def user_leave_session(self, user):
		session = self.active_sessions[user.session_id]
		user.leave_session()

		# remove user from sessio	
		session.registered_clients.remove(user)


	# register a client in the server
	def register_client2(self, c_username, c_id, c_ip, c_port):
		# check if id is already used
		if self.user_is_registered(c_id): 
			print("Client %s is already registered." % [c_id])
			return False
		else:
			# create new client object and add it to registered clients list
			new_client = Client(c_username, c_id, c_ip, c_port)
			self.registered_clients[c_id] = new_client
			print("Client registered correctly!")
			return True


	# register a client in the server
	def register_client3(self, c_username, c_id, c_ip, c_port, p_ip, p_port, peer_port):
		# check if id is already used
		if self.user_is_registered(c_id): 
			print("Client %s is already registered." % [c_id])
			return False
		else:
			# create new client object and add it to registered clients list
			new_client = Client(c_username, c_id, c_ip, c_port, p_ip, p_port, peer_port)
			self.registered_clients[c_id] = new_client
			print("Client registered correctly!")
			return True


	# create a new session
	def create_session2(self, s_id, players, private, teams):
		# check is session exsit already?
		if s_id in self.active_sessions.keys():
			print("session with that id already created")

		# create session and add it to the list
		self.active_sessions[s_id] = Session(s_id, players, self, private, teams)


	def add_user_to_session(self, user_id, session_id):
		user = self.registered_clients[user_id]
		session = self.active_sessions[session_id]

		print("user added to session")

		user.session_id = session_id
		session.registered_clients.append(user)


	# start exhchanging info between clients and server
	def exchange_info(self, c_session):
		if not c_session in self.active_sessions:
			return
		self.active_sessions[c_session].exchange_peer_info()


	# print session and players
	def print_sessions_and_players(self):
		for session_id in self.active_sessions:
			session = self.active_sessions[session_id]
			print("Session: " + session_id)

			for player in session.registered_clients:
				print("Client: " + player.name)


	# datagram received by server
	def datagramReceived(self, datagram, address):
		"""Handle incoming datagram messages."""

		# print message
		print("Message received:")
		print(datagram)
		print("\n")

		data_string = datagram.decode("utf-8")
		msg_type = data_string[:2]

		########################################################
		# MESSAGES USED BY GAME TO MANAGE PLAYERS AND SESSIONS #
		########################################################
		
		# register client in the server || message format: [rp:username:private_ip:private_port:public_port]
		if msg_type == "rp":
			# get message information
			split = data_string.split(":")
			username = split[1]	
			#private_ip = split[2]
			#private_port = split[3]
			#public_port = split[4]

			c_ip, c_port = address

			# check if username is valid (length...)
			valid_code = self.check_username(username)

			if valid_code==1:
				self.transport.write(bytes('er:'+"Username must have less than 20 characters!","utf-8"), address)			
				return 
			
			elif valid_code==2:
				self.transport.write(bytes('er:'+"That username is actually used!","utf-8"), address)	
				return

			# generate an id for this user
			c_id = self.generate_user_id()
			
			# print user information
			print("Client will be registered, username: " + username + ", id: " + str(c_id) + ", ip: " + c_ip + ", port: " + str(c_port))

			# register client
			if not self.register_client2(username, str(c_id), c_ip, c_port):#, private_ip, private_port, public_port): # server internal error at registering
				self.transport.write(bytes('e2:'+"server internal error at registering user","utf-8"), address)
				return

			# send user id || message format: [ok:user_id]
			self.transport.write(bytes('ok:'+str(c_id),"utf-8"), address)
			
		# register information || message format: [user_id:private_ip:private_port:public_port]
		elif msg_type == "ri":
			split = data_string.split(":")
			user_id = split[1]
			private_ip = split[2]
			private_port = split[3]
			public_port = split[4]

			user = self.registered_clients[user_id]
			user.add_information(private_ip, private_port, public_port)

			# send user id || message format: [ok:user_id]
			self.transport.write(bytes('ok:',"utf-8"), address)

		# create session || message format: [cr:teams:players:private]
		elif msg_type == "cs":
			# split data from datagram
			split = data_string.split(":")
			player_id = split[1] #string
			teams = split[2]   # boolean
			players = split[3] # int
			private = split[4] # boolean

			# user doesn't exists
			if not self.user_is_registered(player_id):
				self.transport.write(bytes('er:'+"User doesn't exists", "utf-8"), address)
				return 

			# player already created a session (probably ok message lost)
			if self.registered_clients[player_id].session_id != None:
				# player is already in a session, get session id and send to player
				s_id = self.get_user_session_id(player_id)
				self.transport.write(bytes('ok:'+s_id,"utf-8"), address)
			
			# create session
			else:
				# generate random id for the session			
				s_id = self.generate_random_id()

				# print session id
				print("Session with id: " + s_id + "created")

				# add session to session list
				self.create_session2(s_id, players, private, teams)

				# add player to the session 
				self.add_user_to_session(player_id, s_id)

				print("sending " + s_id)
				# send ok message to client || message format [ok:session_id]
				self.transport.write(bytes('ok:'+s_id,"utf-8"), address)


		# client asked to find session with specified properties || message format: [fs:user_id:teams:players]
		elif msg_type == "fs":
			#split datagram information
			split = data_string.split(":")
			user_id = split[1]
			teams = split[2]
			players = split[3]

			# user doesn't exists
			if not self.user_is_registered(user_id):
				self.transport.write(bytes('er:'+"User doesn't exists", "utf-8"), address)
				return 

			player = self.registered_clients[user_id]


			# player is already in a session (probably packet lost)
			s_id = self.get_user_session_id(user_id) # already in session
			print("s_id = " + str(s_id))
			if not s_id == None:
				session = self.active_sessions[s_id]
				self.transport.write(bytes('ok:' + session.id + ":" + session.teams+":"+session.private+":"+session.client_max+":"+str(len(session.registered_clients)), "utf-8"), address)
				return

			else: # player not in session
				session_finded = False
				# look for a session that has that properties and it's public
				for session_id in self.active_sessions:
					# get session with id session_id
					session = self.active_sessions[session_id]
					print("session info(teams:" + session.teams + " players: " + session.client_max + " type: " + session.private + ")")

					# check if session is public
					if session.private=="false": # public
						# check session properties
						if session.client_max == players and session.teams == teams and len(session.registered_clients) < int(session.client_max): # check that session has place to add the user
							# send new player to all players in the room
							'''for s_player in session.registered_clients:
								p_address = (s_player.ip, s_player.port)
								print(p_address)
						
								self.transport.write(bytes('np:'+player.username+":"+str(len(session.registered_clients)+1), "utf-8"), p_address) # send how much players are in session to detect errors

							# send session information to user || message format: [ok:session_id:teams:private:player_count:actual_player_count]
							self.transport.write(bytes('ok:' + session.id + ":" + session.teams+":"+session.private+":"+session.client_max+":"+str(len(session.registered_clients)), "utf-8"), address)

							# send info about other players to user
							for i in range(0, len(session.registered_clients)):
								session_player = session.registered_clients[i]
								self.transport.write(bytes('sp:' + str(i) + ":" + session_player.username, "utf-8"), address)
							'''
							# add client to session
							#session.register_client_at_session(player)
							self.add_user_to_session(user_id, session.id)
							session_finded = True

							# print session users
							self.print_sessions_and_players()
							print("clients registered at session: " + str(len(session.registered_clients)))

							# send reponse to user || message format: [ok:session_id:teams:private:player_count:actual_player_count]
							self.transport.write(bytes('ok:' + session.id + ":" + session.teams+":"+session.private+":"+session.client_max+":"+str(len(session.registered_clients)), "utf-8"), address)
							
				# no session with thoes properties
				if not session_finded:
					self.transport.write(bytes("er:Doesn't exist any session with that properties!", "utf-8"), address)
	

		# ask for session users usernames || message format: [su:player_id]
		elif msg_type == "su":
			split = data_string.split(":")
			user_id = split[1]

			# check if player keeps in a session (maybe it has been deleted)
			if self.registered_clients[user_id].session_id == None:
				self.transport.write(bytes('err:'+"User not in a session (maybe removed?)", "utf-8"), address)
				return

			# get session object
			session = self.active_sessions[self.registered_clients[user_id].session_id]

			username_list = []
			# send session users usernames
			for i in range(0, len(session.registered_clients)):
				username_list.append(session.registered_clients[i].username)
			
			message = ":".join(username_list)

			# send
			self.transport.write(bytes('ok:' + str(len(session.registered_clients)) + ":" + message, "utf-8"), address)


		# find session using session code || message format: [fc:user_id:session_code]	
		elif msg_type == "fc":
			#split information
			split = data_string.split(":")
			user_id = split[1]
			s_id = split[2]

			# user doesn't exists
			if not self.user_is_registered(user_id):
				self.transport.write(bytes('er:'+"User doesn't exists", "utf-8"), address)
				return 

			# check if user is already in a session
			player = self.registered_clients[user_id]
			if player.session_id != None:
				session = self.active_sessions[player.session_id]
				self.transport.write(bytes('ok:'+session.teams+":"+session.private+":"+session.client_max+":"+str(len(session.registered_clients)) + ":" + player.session_id, "utf-8"), address)
				return


			# session doesn't exists
			if not self.session_is_active(s_id):
				self.transport.write(bytes('er:'+"Session doesn't exists", "utf-8"), address)
				return
			
			# session is full
			print("Max_clients = " + str(self.active_sessions[s_id].client_max) + ", registered_clients = " + str(len(self.active_sessions[s_id].registered_clients)))
			if int(self.active_sessions[s_id].client_max) <= len(self.active_sessions[s_id].registered_clients):
				self.transport.write(bytes('er:'+"Session is full!", "utf-8"), address)
				return 
			

			# get session and client objects
			session = self.active_sessions[s_id]
			player = self.registered_clients[user_id]

			# add client to session
			session.register_client_at_session(player)

			# print session users
			self.print_sessions_and_players()
		
			print("clients registered at session: " + str(len(session.registered_clients)))

			# send reponse to user
			self.transport.write(bytes('ok:'+session.teams+":"+session.private+":"+session.client_max+":"+str(len(session.registered_clients)) + ":" + player.session_id, "utf-8"), address)


		# an user leaves a session || message format: [ls:user_id]
		elif msg_type == "ls":
			split = data_string.split(":")
			user_id = split[1]

			# user doesn't exists
			if not self.user_is_registered(user_id):
				self.transport.write(bytes('er:'+"User doesn't exists", "utf-8"), address)
				return 

			# user not in a session
			user = self.registered_clients[user_id]
			s_id = user.session_id
			if user.session_id == None:
				self.transport.write(bytes('er:'+"User not in a session", "utf-8"), address)
				return

			# user can't leave session when game is starting
			session = self.active_sessions[user.session_id]
			print("Client max: " + str(session.client_max) + ", registered clients: " + str(len(session.registered_clients)))
			if len(session.registered_clients) == int(session.client_max):
				print("session is full")
				self.transport.write(bytes('er:'+"Session is full, you can't leave it now!", "utf-8"), address)
				return	
			
			# leave session
			self.user_leave_session(user)

			self.transport.write(bytes('ok:'+s_id, "utf-8"), address)


		# session server removes session || message format: [rs:user_id]
		elif msg_type == "rs":
			split = data_string.split(":")
			user_id = split[1] # session server
			print(user_id)

			# user doesn't exists
			if not self.user_is_registered(user_id):
				self.transport.write(bytes('er:'+"User doesn't exists", "utf-8"), address)
				return 

			# user not in a session
			session_server = self.registered_clients[user_id]
			s_id = session_server.session_id
			if session_server.session_id == None:
				self.transport.write(bytes('er:'+"User not in a session", "utf-8"), address)
				return

			# user not session admin
			if self.active_sessions[s_id].registered_clients[0].name != user_id:
				self.transport.write(bytes('er:'+"Only session admin can remove this session", "utf-8"), address)
				return

			# user can't remove session when game is starting
			'''session = self.active_sessions[session_server.session_id]
			print("Client max: " + str(session.client_max) + ", registered clients: " + str(len(session.registered_clients)))
			if len(session.registered_clients) == int(session.client_max):
				print("session is full")
				self.transport.write(bytes('er:'+"Session is full, you can't leave it now!", "utf-8"), address)
				return	'''
			

			# remove session
			session = self.active_sessions[s_id]

			# drop session
			self.remove_session(s_id)

			# send ok message
			self.transport.write(bytes('ok:', "utf-8"), address)
			

		# user exited game || message format: [eg:user_id]
		elif msg_type == "eg":
			split = data_string.split(":")
			user_id = split[1]

			# user doesn't exists
			if not self.user_is_registered(user_id):
				self.transport.write(bytes('er:'+"Server internal error, user doesn't exists", "utf-8"), address)
				return

			# remove user from clients list
			user = self.registered_clients[user_id]
			self.registered_clients.pop(user_id)

			if user.session_id == None:
				self.transport.write(bytes('ok:'+"User not in a session", "utf-8"), address)
				return

			# delete user from session
			if user.session_id != None:
				session = self.active_sessions[user.session_id]
				session_id = session.id

				# if is session admin remove session too
				if session.registered_clients[0].name == user.name:
					self.active_sessions.pop(session_id)

					# remove session from all users
					for user in session.registered_clients:
						user_id = user.name
						user.session_id = None
						session.registered_clients.remove(user)

					try:
						del session
					except KeyError:
						print("Session doesn't exist")

					self.remove_user(user)
					self.transport.write(bytes('ok:'+"User and session removed", "utf-8"), address)

				else:
					session.registered_clients.remove(user)
					self.remove_user(user)
					self.transport.write(bytes('ok:'+"User removed", "utf-8"), address)
					return	
				




		# session server invites an user to session || message format: []
		elif msg_type == "iu":
			pass

		
		# session server drops an user from session || message format: []
		elif msg_type == "du":
			pass


		# client send sg message, so send server ip and port (public and private information) || message format: [sg:session_code:user_id]
		elif msg_type == "sg":
			split = data_string.split(":")
			s_id = split[1]
			user_id = split[2]


			# user doesn't exists
			if not self.user_is_registered(user_id):
				self.transport.write(bytes('er:'+"Server internal error, user doesn't exists", "utf-8"), address)
				return 

			# session doesn't exists
			if not self.session_is_active(s_id):
				self.transport.write(bytes('er:'+"Server internal error, session doesn't exists", "utf-8"), address)
				return
			
			# collect infomration to send
			session = self.active_sessions[s_id]
			session_server = session.registered_clients[0]

			session_server_ip = session_server.ip
			session_server_port = session_server.port

			session_public_ip = session_server.ip
			session_public_port = session_server.peer_port

			session_private_server_ip = session_server.private_ip
			session_private_server_port = session_server.private_port

			user = self.registered_clients[user_id]
			user_port = user.port

			# send message || message format: [ok:server_peer_ip:server_peer_port:server_private_ip:server_private_port]
			self.transport.write(bytes('ok:' + session_public_ip + ":" + str(session_public_port)+ ":" + session_private_server_ip + ":" + str(session_private_server_port), "utf-8"), address)


		# session server (client) sends this to know the port in which wait other players messages || message format: [gp:session_code]
		elif msg_type == "gp":
			split = data_string.split(":")
			s_id = split[1]

			# session doesn't exists
			if not self.session_is_active(s_id):
				self.transport.write(bytes('er:'+"Server internal error, session doesn't exists", "utf-8"), address)
				return

			# collect information to send
			session = self.active_sessions[s_id]

			server = session.registered_clients[0]

			server_port = server.port


			# send all clients ip and ports
			ip_port_list = []

			# send session users usernames
			for i in range(0, len(session.registered_clients)):
				ip_port_list.append(session.registered_clients[i].ip + "-" + str(session.registered_clients[i].peer_port) + "-" + session.registered_clients[i].private_ip + "-" + str(session.registered_clients[i].private_port))
			
			message = ":".join(ip_port_list)


			# send message || message format: [ok:server_port]
			self.transport.write(bytes('ok:'+message, "utf-8"), address)

		elif msg_type == "hello":
				split = data_string.split(":")
				print("hello")
				print(address)


		# TESTING MESSAGES
		
		# send how much users are registered in server
		elif msg_type == "tu":
			split = data_string.split(":")
			
			players = len(self.registered_clients)
			print(players)
			message = str(len(self.registered_clients))
			self.transport.write(bytes('ok:'+message, "utf-8"), address)


		# send sessions registered in server
		elif msg_type == "ts":
			message = str(len(self.active_sessions))
			self.transport.write(bytes('ok:'+message, "utf-8"), address)


		# send users registered in session
		elif msg_type == "us":
			split = data_string.split(":")
			s_id = split[1]

			session = self.active_sessions[s_id]
			
			message = str(len(session.registered_clients))

			self.transport.write(bytes('ok:' + message, "utf-8"), address)

		# clear session and user list
		elif msg_type == "cl":
			self.active_sessions.clear()
			self.registered_clients.clear()

			self.transport.write(bytes('ok:', "utf-8"), address)


class Session:

	def __init__(self, session_id, max_clients, server, private, teams):
		self.id = session_id
		self.client_max = max_clients
		self.server = server
		self.registered_clients = [] # player objects
		#new attributes
		self.private = private
		self.teams = teams


	def register_client_at_session(self, client):
		client.session_id = self.id
		self.registered_clients.append(client)


	def client_registered(self, client):
		if client in self.registered_clients: return
		# print("Client %c registered for Session %s" % client.name, self.id)
		self.registered_clients.append(client)
		if len(self.registered_clients) == int(self.client_max):
			sleep(5)
			print("waited for OK message to send, sending out info to peers")
			self.exchange_peer_info()


	def exchange_peer_info_session(self):
		print("waited for OK message to send, sending out info to peers")
		self.exchange_peer_info()


	def exchange_peer_info(self):
		for addressed_client in self.registered_clients:
			address_list = []
			for client in self.registered_clients:
				if not client.name == addressed_client.name:
					address_list.append(client.name + ":" + address_to_string((client.ip, client.port)))
			address_string = ",".join(address_list)
			print(address_string)
			message = bytes( "peers:" + address_string, "utf-8")
			self.server.transport.write(message, (addressed_client.ip, addressed_client.port))

		print("Peer info has been sent")


class Client:

	def confirmation_received(self):
		self.received_peer_info = True

	#called when users registers
	def __init__(self, c_username, c_name, c_ip, c_port):#, private_ip, private_port, peer_port):
		self.username = c_username
		self.name = c_name
		self.session_id = None
		self.ip = c_ip
		self.port = c_port

		self.received_peer_info = False	

		# peer socket in client
		self.peer_port = None#peer_port

		# local net socket
		self.private_ip = None#private_ip
		self.private_port = None#private_port
		
	def add_ip_and_port(self, c_ip, c_port):
		self.ip = c_ip
		self.port = c_port
	
	def add_information(self, c_private_ip, c_private_port, c_peer_port):
		# peer socket in client
		self.peer_port = c_peer_port#peer_port

		# local net socket
		self.private_ip = c_private_ip#private_ip
		self.private_port = c_private_port#private_port

	def set_session(self, s_id):
		self.session_id = s_id

	def leave_session(self):
		print(self.name + " leaving session")
		self.session_id = None


if __name__ == '__main__':
	if len(sys.argv) < 2:
		print("Usage: ./server.py PORT")
		sys.exit(1)

	port = int(sys.argv[1])
	reactor.listenUDP(port, ServerProtocol())
	reactor.listenTCP(port, ServerProtocol())
	print('Listening on *:%d' % (port))
	reactor.run()
