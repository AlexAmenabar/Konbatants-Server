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
	def user_is_registered(self, username):
		return username in self.registered_clients


	# check if session exists
	def session_is_active(self, session):
		return session in self.active_sessions


	# checks if a user is already in a server
	def user_already_in_session(self, user_id):
		user = self.registered_clients[user_id]
		if user==None:
			return False
		return True


	# check if user is in that session
	def user_is_in_session(self, s_id, user_id):
		user = self.registered_clients[user_id]

		if not user.session_id == None:
			return user.session_id == s_id
		return False


	# get user session
	def get_user_session_id(self, user_id):
		if self.user_already_in_session(user_id):
			return self.registered_clients[user_id].session_id
		return None


	# generates an id for a new registered user
	def generate_user_id(self):
		self.next_player_id = self.next_player_id + 1
		return self.next_player_id - 1 


	# generates random id for new session
	def generate_random_id(self):
		N = 8
		return ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))


	# removes a user from registered clients list
	def remove_user(self, user_id):
		try:
			del self.registered_clients[user_id]
		except KeyError:
			print("Player doesn't exist")


	# removes a session from active sessions list
	def remove_session(self, s_id):
		try:
			del self.active_sessions[s_id]
		except KeyError:
			print("Tried to terminate non-existing session")

	
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
		
		# register client in the server || message format: [rp:username]
		if msg_type == "rp":
			# get message information
			split = data_string.split(":")
			username = split[1]		
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
			if not self.register_client2(username, str(c_id), c_ip, c_port): # server internal error at registering
				self.transport.write(bytes('e2:'+"server internal error at registering user","utf-8"), address)
				return

			# send user id || message format: [ok:user_id]
			self.transport.write(bytes('ok:'+str(c_id),"utf-8"), address)
			

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
				self.transport.write(bytes('er:'+"Server internal error: user doesn't exists", "utf-8"), p_address)
				return 

			# player already created a session (probably ok message lost)
			if self.registered_clients[player_id].session_id != None:
				# player is already in a session
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

				# send ok message to client || message format [ok:session_id]
				self.transport.write(bytes('ok:'+s_id,"utf-8"), address)


		# client asked to find session with specified properties || message format: [fs:user_id:teams:players]
		elif msg_type == "fs":
			#split datagram information
			split = data_string.split(":")
			user_id = split[1]
			player = self.registered_clients[user_id]
			teams = split[2]
			players = split[3]

			s_id = self.get_user_session_id(user_id)

			# user doesn't exists
			if not self.user_is_registered(user_id):
				self.transport.write(bytes('er:'+"Server internal error: user doesn't exists", "utf-8"), p_address)
				return 

			# player is already in a session (probably packet lost)
			if not s_id == None:
				self.transport.write(bytes('ok:'+":" + s_id, "utf-8"), address)

			# player not in session
			else:
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
							for s_player in session.registered_clients:
								p_address = (s_player.ip, s_player.port)
								print(p_address)
						
								self.transport.write(bytes('np:'+player.name+":"+str(len(session.registered_clients)+1), "utf-8"), p_address) # send how much players are in session to detect errors

							# send session information to user || message format: [ok:session_id:teams:private:player_count:actual_player_count]
							self.transport.write(bytes('ok:' + session.id + ":" + session.teams+":"+session.private+":"+session.client_max+":"+str(len(session.registered_clients)), "utf-8"), address)

							# send info about other players to user
							for i in range(0, len(session.registered_clients)):
								session_player = session.registered_clients[i]
								self.transport.write(bytes('sp:' + str(i) + ":" + session_player.username, "utf-8"), address)

							# add client to session
							session.register_client_at_session(player)
							session_finded = True

							# print session users
							self.print_sessions_and_players()
							print("clients registered at session: " + str(len(session.registered_clients)))

							# send reponse to user || message format: [ok:session_id:teams:private:player_count:actual_player_count]
							self.transport.write(bytes('ok:'+":" + session.id + ":" + session.teams+":"+session.private+":"+session.client_max+":"+str(len(session.registered_clients)), "utf-8"), address)

							
				# no session with thoes properties
				if not session_finded:
					self.transport.write(bytes("er:Doesn't exist any session with that properties!", "utf-8"), address)
	

		# ask one user information (one package lost at sending session users) || message format: [su:session_id:index]
		elif msg_type == "su":
			split = data_string.split(":")
			session_id = split[1]
			index = int(split[2])

			session = self.active_sessions[session_id]
			user = session.registered_clients[index]

			self.transport.write(bytes('sp:' + str(i) + ":" + session_player.username, "utf-8"), address)


		# find session using session code || message format: [fc:user_id:session_code]	
		elif msg_type == "fc":
			#split information
			split = data_string.split(":")
			usr_id = split[1]
			s_id = split[2]

			# user doesn't exists
			if not self.user_is_registered(user_id):
				self.transport.write(bytes('er:'+"Server internal error: user doesn't exists", "utf-8"), p_address)
				return 

			# session doesn't exists
			if not self.session_is_active(s_id):
				self.transport.write(bytes('er:'+"Server internal error: session doesn't exists", "utf-8"), p_address)
				return
			
			# session is full
			if self.active_sessions[s_id].max_clients <= len(self.active_sessions[s_id].registered_clients):
				self.transport.write(bytes('er:'+"Session is full!", "utf-8"), p_address)
				return 
			

			# get session and client objects
			session = self.active_sessions[s_id]
			player = self.registered_clients[usr_id]

			# send new player to all players in the room
			for s_player in session.registered_clients:
				p_address = (s_player.ip, s_player.port)				
				self.transport.write(bytes('np:'+player.name, "utf-8"), p_address)

			# add client to session
			session.register_client_at_session(player)

			# print session users
			self.print_sessions_and_players()
		
			print("clients registered at session: " + str(len(session.registered_clients)))

			# send reponse to user
			self.transport.write(bytes('ok:'+session.teams+":"+session.private+":"+session.client_max+":"+str(len(session.registered_clients)), "utf-8"), address)


		# client send sg message, so send server ip and port || message format: [sg:session_code:user_id]
		elif msg_type == "sg":
			split = data_string.split(":")
			s_id = split[1]
			user_id = split[2]


			# user doesn't exists
			if not self.user_is_registered(user_id):
				self.transport.write(bytes('er:'+"Server internal error: user doesn't exists", "utf-8"), p_address)
				return 

			# session doesn't exists
			if not self.session_is_active(s_id):
				self.transport.write(bytes('er:'+"Server internal error: session doesn't exists", "utf-8"), p_address)
				return
			
			# collect infomration to send
			session = self.active_sessions[s_id]
			session_server = session.registered_clients[0]

			session_server_ip = session_server.ip
			session_server_port = session_server.port

			user = self.registered_clients[user_id]
			user_port = user.port

			# send message || message format: [ok:server_port]
			self.transport.write(bytes('ok:'+session_server_ip+":"+str(session_server_port)+":"+str(user_port), "utf-8"), address)


		# server (client) sends this to know the port in which wait other players messages || message format: [gp:session_code]
		elif msg_type == "gp":
			split = data_string.split(":")
			s_id = split[1]

			# session doesn't exists
			if not self.session_is_active(s_id):
				self.transport.write(bytes('er:'+"Server internal error: session doesn't exists", "utf-8"), p_address)
				return

			# collect information to send
			session = self.active_sessions[s_id]

			server = session.registered_clients[0]

			server_port = server.port

			# send message || message format: [ok:server_port]
			self.transport.write(bytes('ok:'+str(server_port), "utf-8"), address)


		# an user leaves a session || message format: [ls:session_id:user_id]
		elif msg_type == "ls":
			split = data_string.split(":")
			s_id = split[1]
			user_id = split[2]

			# user doesn't exists
			if not self.user_is_registered(user_id):
				self.transport.write(bytes('er:'+"Server internal error: user doesn't exists", "utf-8"), p_address)
				return 

			# session doesn't exists
			if not self.session_is_active(s_id):
				self.transport.write(bytes('er:'+"Server internal error: session doesn't exists", "utf-8"), p_address)
				return

			# user not in that session
			if not self.user_is_in_session(s_id, user_id):
				self.transport.write(bytes('er:'+"Server internal error: user doesn't exist in that session", "utf-8"), p_address)
				return		

			# leave session
			session = self.active_sessions[s_id]
			
			if len(session.registered_clients) < session.max_clients: # if session is full player can't leave
				user = self.registered_clients[user_id]
				user.leave_session()

				# remove user from server
				session.registered_clients.remove(user)
				self.transport.write(bytes('ls:'+s_id, "utf-8"), p_address)

				# inform members of the session
				for session_user in session.registered_clients:
					p_address = (session_user.ip, session_user.port)
					print(p_address)
					self.transport.write(bytes('ls:'+session_user.name, "utf-8"), p_address)
			
			else:
				self.transport.write(bytes('er:'+"Can't leave session beacuse it's full", "utf-8"), p_address)

		# session server removes session || message format: [rs:session_id:user_id]
		elif msg_type == "rs":
			split = data_string.split(":")
			s_id = split[1]
			user_id = split[2]


		# user exited game || message format: [eg:user_id]
		elif msg_type == "eg":
			split = data_string.split(":")
			user_id = split[1]


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
	def __init__(self, c_username, c_name, c_ip, c_port):
		self.username = c_username
		self.name = c_name
		self.session_id = None
		self.ip = c_ip
		self.port = c_port
		self.received_peer_info = False	
		
	def add_ip_and_port(self, c_ip, c_port):
		self.ip = c_ip
		self.port = c_port
		
	def set_session(self, s_id):
		self.session_id = s_id

	def leave_session(self, s_id):
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
