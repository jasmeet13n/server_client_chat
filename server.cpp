#include<sys/types.h>
#include<sys/socket.h>
#include<netdb.h>
#include<unistd.h>
#include<fcntl.h>

#include<arpa/inet.h>
#include<netinet/in.h>

#include<stdio.h>
#include<string.h>
#include<stdlib.h>

#include<iostream>
#include<string>
#include<map>

#define VERSION 3

#define JOIN 2
#define SEND 4
#define FWD 3

#define ACK 7
#define NAK 5
#define ONLINE 8
#define OFFLINE 6
#define IDLE 9

#define A_USERNAME 2
#define A_MESSAGE 4
#define A_REASON 1
#define A_COUNT 3

// Thanks BEEJ.US for tutorial on how to use SELECT and pack and unpack functions
// Some parts of the code have been taken from BEEJ.US

using namespace std;

struct userinfo{					// user info structure
	string username;
	int status;
	int ip;
};

unsigned short int client_count;	// global variable to store client count
map<int, struct userinfo> users;	// map to store client info
int MAXCLIENTS;
int BACKLOG;

uint8_t get_msg_type(char *packet){	// extract 7 bit type of message from packet
	uint8_t type;
	type = (unsigned char)packet[1];
	type &= 0x7F;
	return type;
}

unsigned short int getlength(unsigned short int len)
{	//make a 4-bytes-wide payload.
	unsigned short int rem = len%4;
	return len + (4-rem)%4;
}

void packi16 (char *buf, unsigned short int i)
{   //change the host order to network byte order (16bit)
	i = htons(i);
	memcpy(buf,&i,2);
}
void packi32(char *buf, unsigned long i)
{	//change the host order to network byte order (32bit)
	i = htonl(i);
	memcpy(buf,&i,4);
}
unsigned short int unpacki16(char *buf)
{	//change  network byte order to the host order (16bit)
	unsigned short int i;
	memcpy(&i,buf,2);
	i = ntohs(i);
	return i;
}
unsigned long unpacki32(char *buf)
{	//change  network byte order to the host order (32bit)
	unsigned long i;
	memcpy(&i,buf,2);
	i = ntohl(i);
	return i;
}

//Attribute structure, 2 byte type, 2 byte length
struct sbcp_att{
	uint16_t type;
	uint16_t length;
	char *payload;
};

// SBCP message structure,
struct sbcp_msg{
	uint16_t vrsn;								//last 8 bits of version
	uint8_t type;								// the first bit of vrsn and 7 bits type
	uint16_t length;							// 2 bytes length
	unsigned short int num_att;					// this is to record the number of attributes present while decoding
	struct sbcp_att **att_arr;					// a double pointer array to store n attributes
};

char *attribute_to_string(unsigned short int type, char *data){
	//make raw data into an attribute-like string.(store the attribute in a string).
	//Work like an encoder
	unsigned short int len_data;
	if(type == A_COUNT)
		len_data = 3;
	else
		len_data = strlen(data);
	if(data[len_data-1]=='\n')
		data[len_data-1]='\0';
	unsigned short int len = getlength(len_data);
	char *output;
	output = (char *)malloc((len+4)*sizeof(char));
	packi16(output,type);						// encode type
	packi16(output+2,len+4);					// encode length
	memcpy(output+4,data,len_data);				// encode payload
	memset(output+4+len_data,'\0',len-len_data);	// make remainder bits \0
	return output;
}

struct sbcp_att * string_to_attribute(char *packet){
	//extract attribute information from the encoded string came out of the wire
	//work like an decoder
	struct sbcp_att *output;
	output = (struct sbcp_att *)malloc(sizeof(struct sbcp_att));
	output->type = unpacki16(packet);			// decode the type, change the network byte order to host byte order
	output->length = unpacki16(packet+2);		//decode the length from the next 2 bytes of the packet
	output->payload = (char *)malloc(((output->length)-3)*sizeof(char));	// decode the payload
	memcpy(output->payload,packet+4,(output->length));
	output->payload[(output->length)-4] = '\0';
	return output;
}

char *sbcp_to_string(uint16_t vrsn, uint8_t type, unsigned short int num_att, char **att_arr){
	//make encoded attribute strings into a message-string
	//work like an encoder
	unsigned short int total_len=4;
	int i;
	for(i=0; i<num_att; i++){					// get the total length of attributes
		total_len += unpacki16(att_arr[i]+2);
	}
	char *packet = (char *)malloc(total_len*(sizeof(char)));
	uint8_t bit = vrsn & 1;
	uint8_t vrsn_1 = (vrsn>>1);					// setting the VRSN

	type = type | (bit << 7);					// set type and remove the first bit
	packet[0] = vrsn_1;
	packet[1] = type;							// put type and version on the packet
	packi16(packet+2,total_len);				// encode length

	unsigned short int tmp = 4;
	unsigned short int cur_len;
	for(i=0; i<num_att; i++){
		cur_len = unpacki16(att_arr[i]+2);
		memcpy(packet+tmp,att_arr[i],cur_len);	// read every attribute and copy it to packet string
		tmp+=cur_len;
	}
	return packet;
}

struct sbcp_msg * string_to_sbcp(char *packet){
	//extract the message information from a received string
	//work like a decoder
	struct sbcp_msg * output = (struct sbcp_msg *)malloc(sizeof(struct sbcp_msg));

	uint16_t bits = unpacki16(packet);
	output->vrsn = (bits & 0xFF80) >> 7;		// decode version
	output->type = (unsigned char)packet[1];	// decode type
	output->type &= 0x7F;						// making 8th bit of type as 0, as it is a 7 bit field
	output->length = unpacki16(packet+2);		// decode length
	unsigned short int cur_len, tmp = 4, num_att=0;
	while(tmp != output->length){
		cur_len = unpacki16(packet+tmp+2);
		tmp+=cur_len;
		num_att++;								// count the number of attributes
	}

	output->att_arr = (struct sbcp_att **)malloc(num_att*(sizeof(struct sbcp_att *)));	// allocate memory of all attributes
	tmp = 4;
	int i;
	for(i=0; i<num_att; i++){
		cur_len = unpacki16(packet+tmp+2);		// decode each attribute and copy it to our message structure
		output->att_arr[i] = string_to_attribute(packet+tmp);
		tmp+=cur_len;
	}
	output->num_att = num_att;					// set the number of attributes in the structure
	return output;
}

char *get_ACK_packet(char *packet, int c_sockfd){
	char *output;
	char **att_arr;
	char *msg = (char *)malloc(512*sizeof(char));

	if(client_count >= MAXCLIENTS+1){
		att_arr = (char **)malloc(1*sizeof(char *));
		string message = "CHAT FULL";
		msg = strcpy(msg,message.c_str());
		att_arr[0] = attribute_to_string(A_REASON,msg);
		output = sbcp_to_string(VERSION,NAK,1,att_arr);
		free(msg);
		return output;
		//return NAK message : Reason MAX CLIENTS reached
	}
	else{
		att_arr = (char **)malloc((client_count)*sizeof(char *));
		char tmp[3];
		packi16(tmp,client_count);
		tmp[2] = '\0';
		att_arr[0] = attribute_to_string(A_COUNT,tmp);					// pack COUNT attribute to be sent in ACK
		int i=1;
		map<int,struct userinfo>::iterator it;
		char * tmp2 = (char * )malloc(1024*sizeof(char));

		struct sbcp_att *att;
		att = string_to_attribute(packet+4);
		struct userinfo uinfo;
		string uname(att->payload);

		int dup_uname = 0;
		for(it= users.begin(); it!=users.end(),i<client_count; it++){
			if(it->second.status!=-1){
				tmp2 = strcpy(tmp2, it->second.username.c_str());
				if( uname.compare(it->second.username) == 0){
					dup_uname = 1;
					break;
				}
				att_arr[i] = attribute_to_string(A_USERNAME,tmp2);		// pack all USERNAME attributes to be sent in ACK
				memset(tmp2,'\0',1024);
				i++;	
			}
		}
		free(tmp2);
		if(dup_uname == 1){
			string message = "DUPLICATE USERNAME";
			msg = strcpy(msg,message.c_str());
			free(att_arr[0]);
			att_arr[0] = attribute_to_string(A_REASON,msg);
			output = sbcp_to_string(VERSION,NAK,1,att_arr);
			free(msg);
			return output;
			//return NAK message : Reason Duplicate Username
		}
		else{
			uinfo.username = uname;
			uinfo.status = 1;
			uinfo.ip = 999;
			users[c_sockfd] = uinfo;
			output = sbcp_to_string(VERSION,ACK,client_count,att_arr);
			return output;
			//return ACK message
		}
	}
}

char *process(char *packet,int c_sockfd,int flag_offline){
	char *output;
	char **att_arr;
	char * message = (char * )malloc(120*sizeof(char));
	if(flag_offline == 1){
		message = strcpy(message, users[c_sockfd].username.c_str());
		att_arr = (char **)malloc(1*sizeof(char *));
		att_arr[0] = attribute_to_string(A_USERNAME,message);
		output = sbcp_to_string(VERSION,OFFLINE,1,att_arr);
		free(message);
		map<int, struct userinfo>::iterator it = users.find(c_sockfd);
		if(it!=users.end())
			users.erase(c_sockfd);
		return output;
		//return OFFLINE message
	}

	uint8_t type = get_msg_type(packet);
	cout << "Received message type " << (int)type << " from " << users[c_sockfd].username << endl;

	if(type == JOIN || type == ONLINE){
		att_arr = (char **)malloc(1*sizeof(char *));
		message = strcpy(message, users[c_sockfd].username.c_str());
		att_arr[0] = attribute_to_string(A_USERNAME,message);
		output = sbcp_to_string(VERSION,ONLINE,1,att_arr);
		free(message);
		return output;
		//return ONLINE message
	}
	else if(type == SEND){
		att_arr = (char **)malloc(2*sizeof(char *));
		uint16_t msg_len = unpacki16(packet+4+2);
		att_arr[0] = (char *)malloc(msg_len*sizeof(char));
		memcpy(att_arr[0],packet+4,msg_len);
		message = strcpy(message, users[c_sockfd].username.c_str());
		att_arr[1] = attribute_to_string(A_USERNAME,message);
		output = sbcp_to_string(VERSION,FWD,2,att_arr);
		free(message);
		return output;
		//return FWD message
	}
	else if(type == IDLE){
		att_arr = (char **)malloc(1*sizeof(char *));
		message = strcpy(message, users[c_sockfd].username.c_str());
		att_arr[0] = attribute_to_string(A_USERNAME,message);
		output = sbcp_to_string(VERSION,IDLE,1,att_arr);
		free(message);
		return output;
		//return IDLE message
	}
	return NULL;
}

int main(int argc, char *argv[]){
	int error;

	if(argc!=4){						// if user arguments are not equal to 4 then give an error
		fprintf(stderr,"usage: server ip port max_clients\n");
		return 1;
	}

	MAXCLIENTS = atoi(argv[3]);
	BACKLOG = MAXCLIENTS;				// setting the BACKLOG same as MAX CLIENTS to be handled

	struct addrinfo hints;
	struct addrinfo *servinfo, *p;
	//char ipstr[INET_ADDRSTRLEN];		//INET6_ADDRSTRLEN for IPv6

	//Getting my address
	memset(&hints,0,sizeof(hints));		// initializing the hints structure to be given to getaddrinfo
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	//hints.ai_flags = AI_PASSIVE;

	if((error = getaddrinfo(argv[1], argv[2], &hints, &servinfo)) != 0){	// get the address info for given IP and PORT number
		fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(error));
		exit(1);
	}

	int sockfd;
	for(p=servinfo; p!=NULL; p=p->ai_next){
		if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol))== -1){	// create the server socket
			perror("server: socket");
			continue;
		}
		if((error = bind(sockfd, p->ai_addr, p->ai_addrlen))== -1){		// bind the server to the IP address and port
			perror("server: bind");
			continue;
		}
		break;
	}
	if(p==NULL){
		fprintf(stderr, "my sock fd: failed to bind\n");
		return 2;
	}
	printf("Listening\n");												
	if( (error = listen(sockfd, BACKLOG)) == -1){		// server starts listening with BACKLOG equal to the MAXCLIENTS
		perror("server: listen");
	}

	freeaddrinfo(servinfo);

	// Initializing the required variables
	char buf[1024];
	int num_bytes;
	unsigned short int len;

	fd_set master;
	fd_set read_fds;
	FD_ZERO(&master);
	FD_ZERO(&read_fds);

	FD_SET(sockfd,&master);
	int fdmax = sockfd;
	int c_sockfd;
	int i,j;
	int flag_offline = 0;

	struct sockaddr_storage client_addr;
	socklen_t addr_len;

	char *new_packet;
	struct userinfo tmp;
	map<int, struct userinfo>::iterator it;

	client_count = 0;

	while(1){
		read_fds = master;								// select between file descriptors, select changes the read_fds set so always make a copy from master set
		if( (error = select(fdmax+1, &read_fds, NULL, NULL, NULL)==-1)){
			perror("server: select");
			exit(4);
		}
		for(i=0; i<=fdmax; i++){
			if(FD_ISSET(i,&read_fds)){
				if(i==sockfd){
					addr_len = sizeof(client_addr);		// handle new clients here
					if( (c_sockfd = accept(sockfd, (struct sockaddr *)&client_addr,&addr_len)) == -1){
						perror("server: accept");
					}
					else{
						FD_SET(c_sockfd,&master);
						client_count++;					// increase client count
						tmp.username = "Unknown";		// Initially set the username to Unknown untill we decode the packet to get the username
						tmp.status = -1;
						tmp.ip = 999;					// We are not storing client IP addressed (Not Required)
						users[c_sockfd] = tmp;
						if(c_sockfd > fdmax)
							fdmax = c_sockfd;
					}
				}
				else{
					if((num_bytes = recv(i,buf,sizeof(buf),0)) <=0){
						if(num_bytes == 0){				// If received bytes are zero, it means client has disconnected, so remove its allocated resources
							flag_offline = 1;
							cout << users[i].username << " Disconnected" << endl;
						}
						else{
							perror("server: recv");
						}								
						close(i);
						FD_CLR(i,&master);
						client_count--;					// decrease client count
						users[i].status = -1;
					}
					if(num_bytes>0 || flag_offline==1){
						if(flag_offline == 0){
							uint8_t msg_type = get_msg_type(buf);
							if(msg_type == JOIN){		// if client sent JOIN, process the packet to get a ACK or NAK packet in return
								new_packet = get_ACK_packet(buf,c_sockfd);
								msg_type = get_msg_type(new_packet);
								len = unpacki16(new_packet+2);
								if( (error = send(i,new_packet,len,0)) == -1){
									perror("Server: ACK/NAK Send");
								}

							}
							if(msg_type == NAK){		// if NAK has been sent, close the client socket and remove it from the Read File Descriptor set and map of users
								close(i);
								FD_CLR(i,&master);
								users.erase(i);
								client_count--;			// decrease client count if NAK was sent to client because we initially increased temporarily
								continue;
							}
						}
						new_packet = process(buf,i,flag_offline);	// make the new packet to be send to everyone (FWD, ONLINE, OFFLINE, IDLE)
						if(new_packet == NULL){
							perror("Error: Couldn't Process Data");
							exit(0);
						}
						len = unpacki16(new_packet+2);
						flag_offline = 0;

						for(j=0; j<=fdmax; j++){		// FWD message to all other clients except itself and the server
							if(FD_ISSET(j,&master)){
								if(j!=sockfd && j!=i){
									if( (error = send(j,new_packet,len,0) == -1)){
										perror("server: send");
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return 0;
}
