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
		self.active_sessions = {} #session objects
		self.registered_clients = {} #client objects
		self.next_player_id = 0 # next player id will be this attribute value

	def name_is_registered(self, name):
		return name in self.registered_clients

	def create_session(self, s_id, client_list):
		if s_id in self.active_sessions:
			print("Tried to create existing session")
			return

		self.active_sessions[s_id] = Session(s_id, client_list, self)

	#this is the create_session that is used by me
	def create_session2(self, s_id, players, private, teams):
		#check is session exsit already?

		#create session and add it to the list
		self.active_sessions[s_id] = Session(s_id, players, self, private, teams)


	def remove_session(self, s_id):
		try:
			del self.active_sessions[s_id]
		except KeyError:
			print("Tried to terminate non-existing session")

	
	def register_client(self, c_name, c_session, c_ip, c_port):
		if self.name_is_registered(c_name):
			print("Client %s is already registered." % [c_name])
			return
		if not c_session in self.active_sessions:
			print("Client registered for non-existing session")
		else:
			new_client = Client(c_name, c_session, c_ip, c_port)
			self.registered_clients[c_name] = new_client
			self.active_sessions[c_session].client_registered(new_client)
	

	#new register
	def register_client2(self, c_username, c_id, c_ip, c_port):
		if self.name_is_registered(c_id): # check if id is already used
			print("Client %s is already registered." % [c_name])
			return 1
		else:
			new_client = Client(c_username, c_id, c_ip, c_port)
			print("Client registered in server list " + c_id)
			print(type(c_id))
			self.registered_clients[c_id] = new_client
			print("Client registered correctly!")


	def exchange_info(self, c_session):
		if not c_session in self.active_sessions:
			return
		self.active_sessions[c_session].exchange_peer_info()


	def client_checkout(self, name):
		for client_name in self.registered_clients:
			print(client_name)
		try:
			del self.registered_clients[name]
		except KeyError:
			print("Tried to checkout unregistered client")

	def datagramReceived(self, datagram, address):
		"""Handle incoming datagram messages."""
		print(datagram)
		data_string = datagram.decode("utf-8")
		msg_type = data_string[:2]

		#holepuncher calls this when start_traversal is called by is_server parameter in true, 
		#but now have to be changed
		if msg_type == "rs":
			# register session
			'''c_ip, c_port = address
			self.transport.write(bytes('ok:'+str(c_port),"utf-8"), address)
			split = data_string.split(":")
			session = split[1]
			max_clients = split[2]
			self.create_session(session, max_clients)'''

			split = data_string.split(":")
			s_id = split[1]

			#get the session
			session = self.active_sessions[s_id]

			c_ip, c_port = address
			
			#refresh server client ip and port
			session_server = session.registered_clients[0] #server is in first position
			session_server.ip = c_ip
			session_server.port = c_port
			
			self.transport.write(bytes('ok:'+str(c_port),"utf-8"), address)

		#this is called when start_traversal is called by a client that it is not the server, but in my version
		#all clients are already registered, so change
		elif msg_type == "rc":
			# register client
			'''split = data_string.split(":")
			c_name = split[1]
			c_session = split[2]
			c_ip, c_port = address
			self.transport.write(bytes('ok:'+str(c_port),"utf-8"), address)
			self.register_client(c_name, c_session, c_ip, c_port)'''
			
			split = data_string.split(":")
			c_ip, c_port = address
			c_name = split[1]
			c_session = split[2]

			#refresh client ip and port
			client = self.registered_clients[c_name]
			client.ip = c_ip
			client.port = c_port

			print("client starting traversal with, id: " + str(c_name) + ", ip: " + c_ip + ", port: " + str(c_port))


			#user is already registered 
			self.transport.write(bytes('ok:'+str(c_port),"utf-8"), address)

			session = self.active_sessions[c_session]
			session.exchange_peer_info_session()


		elif msg_type == "ep":
			# exchange peers
			split = data_string.split(":")
			c_session = split[1]
			self.exchange_info(c_session)

		elif msg_type == "cc":
			# checkout client
			split = data_string.split(":")
			c_name = split[1]
			self.client_checkout(c_name)
			
		
		
		
		#ADDED BY ME
		#MESSAGE FORMAT: rp:usrName
		elif msg_type == "rp":
			split = data_string.split(":")
			username = split[1]		
			c_ip, c_port = address

			valid = 1
						
			#check username is valid (length...)
			
			#TODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTODOTOODOTODTOOORDOOTODOTODO
			
			#generate id for this user
			c_id = self.generate_user_id() #HAU HOBETO BEGIRATU BEHAR DA; METODO HOBEAK EGON DAITEZKE IDENTIFIKADOREA SORTZEKO
			
			#response
			if(valid==1):	#username is valid	
				#add user to user list
				print("client will be registered, username: " + username + ", id: " + str(c_id) + ", ip: " + c_ip + ", port: " + str(c_port))

				res = self.register_client2(username, str(c_id), c_ip, c_port)
				if(res == 1):
					self.transport.write(bytes('e2:'+"server error","utf-8"), address)

				#send user new id
				self.transport.write(bytes('ok:'+str(c_id),"utf-8"), address)
				
			else:		#username is not valid
				self.transport.write(bytes('e1:'+username,"utf-8"), address)
		
			#new_client = Client(username, str(user_id))
		
		#create session: cr:teams:players:private
		elif msg_type == "cs":
			print(data_string)
			split = data_string.split(":")
			player_id = split[1] #string
			teams = split[2]   # boolean
			players = split[3] # int
			private = split[4] # boolean

			#generate random id for the session			
			s_id = self.generate_random_id()

			print("Session with id: " + s_id + "created")

			#add session to session list
			self.create_session2(s_id, players, private, teams)

			#add player to the session
			session = self.active_sessions[s_id]
			player = self.registered_clients[player_id]
			session.registered_clients.append(player)


			#print all session and players for each session
			#self.print_sessions_and_players()
			#generate an id for the session
			#client = 

			#OK message + session id
			self.transport.write(bytes('ok:'+s_id,"utf-8"), address)


		#find session	
		elif msg_type == "fs":
			split = data_string.split(":")
			
			
		#enter session
		elif msg_type == "es":
			split = data_string.split(":")
			
			
		#find session by code	
		elif msg_type == "fc":
			split = data_string.split(":")
			usr_id = split[1]
			s_id = split[2]

			print("Adding player to " + s_id + " session")

			#check if user exists


			#check if session exists


			#Add user to session
			session = self.active_sessions[s_id]

			player = self.registered_clients[usr_id]

			print(address)
			

			#send new player to all players in the room
			for s_player in session.registered_clients:
				p_address = (s_player.ip, s_player.port)
				print(p_address)
				self.transport.write(bytes('np:'+player.name, "utf-8"), p_address)


			# add client to session
			session.register_client_at_session(player)

			# print session users
			self.print_sessions_and_players()
		

			# send reponse to user
			self.transport.write(bytes('ok:'+session.teams+":"+session.private+":"+session.client_max+":"+str(len(session.registered_clients)), "utf-8"), address)


			
	
	
	def generate_user_id(self):
		self.next_player_id = self.next_player_id + 1
		return self.next_player_id - 1 

	#for generating session ids
	def generate_random_id(self):
		N = 8
		return ''.join(random.choices(string.ascii_uppercase + string.digits, k=N))


	def print_sessions_and_players(self):
		for session_id in self.active_sessions:
			session = self.active_sessions[session_id]
			print("Session: " + session_id)

			for player in session.registered_clients:
				print("Client: " + player.name)


class Session:

	def __init__(self, session_id, max_clients, server, private, teams):
		self.id = session_id
		self.client_max = max_clients
		self.server = server
		self.registered_clients = []
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
		#if client in self.registered_clients: return
		# print("Client %c registered for Session %s" % client.name, self.id)
		#self.registered_clients.append(client) already registered
		
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

		print("Peer info has been sent. Terminating Session")
		for client in self.registered_clients:
			print(type(client.name))
			print(client.name)
			#self.server.client_checkout(client.name)
		#self.server.remove_session(self.id)


class Client:

	def confirmation_received(self):
		self.received_peer_info = True

	#called when users registers
	def __init__(self, c_usrname, c_name, c_ip, c_port):
		self.usrname = c_usrname
		self.name = c_name
		self.session_id = None
		self.ip = None
		self.ip = c_ip
		self.port = None
		self.port = c_port
		self.received_peer_info = False		
		
	def add_ip_and_port(self, c_ip, c_port):
		self.ip = c_ip
		self.port = c_port
		
	def add_to_session(self, c_session):
		self.ip = c_ip
	
	'''
	def __init__(self, c_name, c_session, c_ip, c_port):
		self.name = c_name
		self.session_id = c_session
		self.ip = c_ip
		self.port = c_port
		self.received_peer_info = False'''

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print("Usage: ./server.py PORT")
		sys.exit(1)

	port = int(sys.argv[1])
	reactor.listenUDP(port, ServerProtocol())
	reactor.listenTCP(port, ServerProtocol())
	print('Listening on *:%d' % (port))
	reactor.run()
