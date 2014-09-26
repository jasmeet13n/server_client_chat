ECEN602 HW1 Programming Assignment
----------------------------------

Team Number: 28
Member 1 # Singh, Jasmeet (UIN: 523005618)
Member 2 # Zhang, Jiahao  (UIN: 723005723)
---------------------------------------

Description/Comments:
--------------------

Functions implemented:
1) JOIN
2) SEND
3) FWD
4) ACK
5) NAK
6) IDLE
7) ONLINE
8) OFFLINE

Both Client and Server handle all attributes viz. USERNAME, MESSAGE, COUNT, REASON
Any number of attributes can be sent in one packet if total length of packet is less than 512 bytes.

Client:
1) Client takes user arguments and connects to the socket with given server IP address and PORT number.
2) We made two structures (sbcp_att as attribute and sbcp_msg as message) to realize the SBCP format which is required. We also made 4 functions for encoding and decoding raw messages to SBCP-format string.
2) Client connects to the server using the CONNECT system call.
3) Client then loops infinitely and SELECT function is used to multiplex between STDIN and server socket.
4) After joining the chat user receives ACK or NAK depending upon the server decision.
5) Client decodes any SBCP message (FWD/IDLE/ONLINE/OFFLINE/ACK/NAK) it receives from server and prints it on screen.
6) Any incoming message is first sent to the process function, which first converts the received string to a SBCP structure using string_to_sbcp function.
7) In the string_to_sbcp function, it takes individual attributes and decodes them using string_to_attribute function.
8) Once everything is decoded the process function takes the required action like printing on the screen or exiting if NAK is received.
9) If user enters a new message, clients first creates a message attribute (attribute_to_string function), packs it into a SBCP packet (sbcp_to_string function) and sends it to the server using the SEND system call.

Server:
1) Server takes the user arguments, creates a socket and binds it to the IP address and PORT number entered by the user. The maximum clients are also set from the user input.
2) All the structures and functions for encoding decoding packets present in the client are also present in the server.
3) One more structure userinfo is used to store username, status and IP address of client.
4) A C++ map is used to map Socket File Descriptor to the userinfo structure.
5) The server starts listening using the LISTEN system call.
6) The server is implemented using the SELECT method.
7) Whenever a server receives a new connection it puts the client socket descriptor into the read_fds set and whenever an connection is closed from the client side, the server removes the client socket descriptor from the read_fds set. The read_fds set tells the select method to look for reads on these sockets.
8) When a JOIN request comes, the function get_ACK_packet is called, which takes user count and all usernames from the userinfo map and puts them into attributes. All these attributes are packet into a single SBCP message with ACK type and sent back to the client. All other clients are notified by sending the ONLINE message with username attribute.
9) If the MAX_CLIENT is reached or client sends a duplicate username NAK is sent back to user.
10) If the server receives 0 bytes it sends OFFLINE message to all other clients. It then removes the details of the user from the userinfo map, closes the socket and removes the socket from the read_fds set.
11) If the server receives IDLE or SEND type packet. It adds the username attribute to the packet and sends to all other users.


Unix command for starting server:
------------------------------------------
./server SERVER_IP SERVER_PORT MAX_CLIENTS

Unix command for starting client:
------------------------------------------
./client USERNAME SERVER_IP SERVER_PORT
