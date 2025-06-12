/*  
    Name: Project  - 2 - Client for a chat server using the IPK25-CHAT protocol
    Author: Eliška Krejčíková (xkrejce00)
    implementation of a chat for TCP protocol 
*/

#ifndef CHAT_H
#define CHAT_H

#include <getopt.h>
#include <iostream>
#include <unistd.h>
#include <string>
#include <cstring>
#include <vector>
#include <regex>
#include <signal.h>

#include <sys/socket.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <fcntl.h>
#include <sys/epoll.h>

// HElPER FUNCTIONS
/**
 * @brief function takes a string and deletes \r\n or/and \n
 */
void delete_new_line_or_carriage(std::string &msg) {
    if(msg.find("\r\n") != std::string::npos) {
        msg.erase(msg.find("\r\n"), 2);
    }
    if(msg.find("\n") != std::string::npos) {
        msg.erase(msg.find("\n"), 1);
    }
}

/**
 * @brief function convert the whole string to capital letters
 */
std::string msg_to_upper(std::string msg) {
    std::string upper_cmd;
    for (auto &c : msg) {
        c = toupper(c);
        upper_cmd.append(1, c);
    }
    return upper_cmd;
}


/**
 * @brief class for parsing command line arguments
 */
class arg_parse {
    public:
        in_addr ip;
        std::string protocol;

        // default values given by the assigment
        uint16_t port = 4567;
        uint16_t timeout = 250;
        uint8_t udp_max_retrans = 3;

        /**
         * @brief main method of this class, uses getopt to parse args
         */
        void parse(int argc, char *argv[]) {
            int c;
            bool protocol_flag = false;
            bool server_flag = false;
            while((c = getopt(argc, argv, "t:s:p:d:r:h")) != -1) {
                switch(c) {
                    case 't':
                        protocol = optarg;
                        if (protocol != "tcp" && protocol != "udp") {
                            std::cerr << "Not udp nor tcp" << std::endl;
                            exit(1);
                        }
                        protocol_flag = true;
                        break;
                    case 's':
                        if (inet_pton(AF_INET, optarg, &ip) != 1) {
                            // its hostname
                            struct addrinfo hints, *res;
                            memset(&hints, 0, sizeof(hints));
                            hints.ai_family = AF_INET;
                            hints.ai_socktype = SOCK_STREAM;
                            if (getaddrinfo(optarg, NULL, &hints, &res) != 0) {
                                std::cerr << "Invalid server address" << std::endl;
                                exit(1);
                            }
                            struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
                            ip = ipv4->sin_addr;
                            freeaddrinfo(res);

                        }
                        server_flag = true;
                        break;
                    case 'p':
                        port = static_cast<uint16_t>(std::stoul(optarg));
                        break;
                    case 'd':
                        timeout = static_cast<uint16_t>(std::stoul(optarg));
                        break;

                    case 'r':
                        udp_max_retrans = static_cast<uint8_t>(std::stoul(optarg));
                        break;
                    case 'h':
                        print_help();
                        exit(0);
                    default:
                        std::cerr << "Unknown option" << std::endl;
                        exit(1);
                }
            }
            // the arguments need to be set
            if (protocol_flag == false && server_flag == false) {
                std::cerr << "Protocol and server IP address are required" << std::endl;
                exit(1);
            }
        }
        void print_help() {
            std::cout << "This program communicates with a server through stdin and stdout." << std::endl;
            std::cout << "How to use:" << std::endl;
            std::cout << "-t  = protocol - either TCP or UDP" << std::endl;
            std::cout << "-s  = ip/hostname of server which will the program communicate with" << std::endl;
            std::cout << "-p  = number of port" << std::endl;
            std::cout << "-d  = timeout for udp in miliseconds" << std::endl;
            std::cout << "-r  = maximum number of packet send in udp when no response found" << std::endl;
            std::cout << "-h  = displays help message" << std::endl;
        }
};


/**
 * @brief class for parsing data collected from stdin and from packets
 *       
 */
class Message {
    public:
        std::string msg;
        std::string cmd;

        int socket;
        int connection;

        // all possible parts of messages
        uint16_t MSG_ID;
        std::string RN = R"(\r\n)";
        std::string USERNAME = R"([A-Za-z0-9_-]{1,20})";
        std::string CHANNEL_ID = R"([A-Za-z0-9_-]{1,20})";
        std::string SECRET = R"([A-Za-z0-9_-]{1,128})";
        std::string DISPLAY_NAME = R"([!-~]{1,20})";

        std::string ID = R"([A-Za-z0-9_-]{1,20})";
        std::string DNAME = R"([!-~]{1,20})";

        std::string SP = R"( )";
        std::string IS = R"( IS )";
        std::string AS = R"( AS )";
        std::string USING = R"( USING )";
        std::string OK_NOK = R"(OK|NOK)";
        std::string FROM = R"(FROM )";

        int REPLY_OK_POS = 12;
        int REPLY_NOK_POS = 13;
        int MSG_FROM_POS = 9;

        
        /**
         * @brief method is called when a malformed message is received
         *        prints out error to stdout, send an error msg to the server
         *        and closes the connection and exits
         */
        void malformed_answer(std::string msg,std::string display_name) {
            // local error, err to server, bye, close connection/socket, exit
            std::cout << "ERROR: " << msg << std::endl;
            delete_new_line_or_carriage(display_name);
            std::string err_msg = "ERR FROM " + display_name + IS + msg + "\r\n";

            send(socket, err_msg.c_str(), err_msg.size(), 0);
            if(connection > 0) {
                close(connection);
            }
            if(socket > 0) {
                close(socket);
            }
            exit(1);
        }

        /**
         * @brief method is called when a message is received from stdin
         *        it parses the message and sets the cmd and msg variables
         */
        void decipher(std::string display_name) {
            fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK); 
            // the max should be content 60000 + tmsg from + dname + is
            char buf[60034];

            // non-blocking reading
            ssize_t count = read(STDIN_FILENO, buf, sizeof(buf));

            if (count > 0) {
                msg = std::string(buf, count);
            }
            // if ctrl+d/eof
            if (count == 0 || msg.find("\x04") != std::string::npos) {
                delete_new_line_or_carriage(display_name);

                std::string bye = "BYE FROM " + display_name + "\r\n";
                send(socket, bye.c_str(), bye.size(), 0);
                close(connection);
                close(socket);
                exit(0);
            }
        
            // only one word -> cmd empty
            // could be a msg of one word
            size_t cmd_end = msg.find(' ');
            if (cmd_end == std::string::npos) {
                cmd = "";
            } else {
               cmd =  msg.substr(0, cmd_end);
            }

            if (cmd[0] == '/') {
                cmd.erase(0, 1);
            } 
            // delete command from the rest of the message
            if (cmd_end != std::string::npos) {
                msg.erase(0, cmd_end + 1);
            }
            // make cmd lowercase so i can compare it later
            std::string lower_cmd;
            for (auto &c : cmd) {
                c = tolower(c);
                lower_cmd.append(1, c);
            }
            cmd = lower_cmd;
        }
        
        /**
         * @brief method for handling the data from the server
         *        check the format and if the data are incorrect calls malformed_answer
         */
        void answer(std::string display_name) {
            // regex stoped working for longer patterns
            std::string upper_msg = msg_to_upper(msg);
            if (cmd == "BYE") {
                std::string bye = FROM + SP + DNAME + RN;
                std::regex bye_regex(bye);
                if(!std::regex_match(upper_msg,bye_regex)) {
                   malformed_answer(msg,display_name);
                }
                return;
            } else if (cmd == "ERR") {
                size_t is_pos = upper_msg.find(IS);
                std::string display = msg.substr(MSG_FROM_POS, is_pos - MSG_FROM_POS);
                if(is_pos == std::string::npos) {
                    malformed_answer(msg, display_name);
                }
                std::string message_content = msg.substr(is_pos + 4, msg.length() - is_pos +4 );

                std::cout << "ERROR FROM " << display << ": " << message_content << std::endl;

            } else if (cmd == "JOIN") {
                std::string join = ID + AS + DNAME + "\r\n";
                std::regex join_regex(join);
                if(!std::regex_match(upper_msg,join_regex)) {
                   malformed_answer(msg,display_name);
                }
                return;

            } else if (cmd == "MSG") {
                size_t is_pos = upper_msg.find(IS);
                if(is_pos == std::string::npos) {
                    malformed_answer(msg,display_name);
                }
                std::string display = msg.substr(MSG_FROM_POS, is_pos - MSG_FROM_POS);
                std::string content = msg.substr(is_pos + 4, msg.length() - is_pos +4 );  
                std::cout << display << ": " << content << std::endl;

            } else if (cmd == "REPLY") {
                if (upper_msg.rfind("REPLY OK IS ", 0) == 0 || upper_msg.rfind("REPLY NOK IS ", 0) == 0) {
                    std::string content = upper_msg.substr(upper_msg.find("IS ") + 3);
                } else {
                    malformed_answer(msg,display_name);
                }
                delete_new_line_or_carriage(msg);

                // if ok - action sucsess
                if (upper_msg.find("REPLY NOK IS ") != std::string::npos) {
                    std::cout << "Action Failure: " << msg.substr(REPLY_NOK_POS, msg.length())<< std::endl;
                }
                else if(upper_msg.find("REPLY OK IS ") != std::string::npos) {
                    std::cout << "Action Success: " << msg.substr(REPLY_OK_POS, msg.length()) << std::endl;
                }

                return;
            } else {
                malformed_answer(msg,display_name);
            }
        }


        /**
         * @brief method used parse message into vector, so the access to individual parts is better latter
         */
        void format_msg(std::vector<std::string>& params) {
            size_t start = 0;
            size_t end = msg.find(SP);
            
            while (end != std::string::npos) {
                params.push_back(msg.substr(start, end - start));
                start = end + SP.length();
                end = msg.find(SP, start);
            }
            params.push_back(msg.substr(start));
        }
        /**
         * @brief method check the format and create a message that will be sent to the server
         */
        int msg_check(std::string display_name) {
            if (cmd == "auth") {
                std::string auth = USERNAME + SP + SECRET + SP + DISPLAY_NAME + "\n";
                std::regex auth_regex(auth);
                if(!std::regex_match(msg,auth_regex)) {
                   std::cout << "ERROR: Invalid auth format" << std::endl;
                   return 1;
                }
                std::vector<std::string> params;
                format_msg(params);
                delete_new_line_or_carriage(params[2]);

                msg = "AUTH " + params[0] + AS + params[2] + USING + params[1] +  "\r\n";
                return 0;

            } else if (cmd == "join") {
                std::string join = CHANNEL_ID + "\n";
                std::regex join_regex(join);

                if(!std::regex_match(msg,join_regex)) {
                   malformed_answer(msg,display_name);
                }
                std::vector<std::string> params;
                format_msg(params);
                delete_new_line_or_carriage(display_name);
                delete_new_line_or_carriage(params[0]);
                // something was still hanging in msg
                msg.clear();

                msg = "JOIN " + params[0] + AS + display_name + "\r\n";
                return 0;

            } else if (cmd == "rename") {
                std::string rename = DISPLAY_NAME + "\n";
                std::regex rename_regex(rename);
                if(!std::regex_match(msg,rename_regex)) {
                   std::cout << "ERROR: Invalid rename format" << std::endl;
                   return 1;
                }
                return 0;
            
            } else {
                if (msg.length() > 60000) {
                    std::cout << "ERROR: Message too long" << std::endl;
                    return 1;
                }
                delete_new_line_or_carriage(msg);
                delete_new_line_or_carriage(display_name);

                if (cmd == "") {
                    if(msg == "/help") {
                        print_help();
                        return 0;
                    }
                    msg = "MSG FROM " + display_name + " IS " + msg + "\r\n";
                } else {
                    msg = "MSG FROM " + display_name + " IS " + cmd + SP + msg + "\r\n";
                }
                return 0;
            }
        }
        
        
        /**
         * @brief method for printing help message
         */
        void print_help() {
            std::cout << "Possible commands:" << std::endl;
            std::cout << "/auth <username> <secret> <display_name> = authenticates the user with the server" << std::endl;
            std::cout << "/join <channel_id> = joins a different channel" << std::endl;
            std::cout << "/rename <new_display_name> = changes user's display name" << std::endl;
            std::cout << "/help = prints this help message" << std::endl;
        }
};


/**
 * @brief class for handling the main logic,
 *       it sets up the socket, handles the epoll and the FSM
 */
class CHAT {
    public:
        in_addr ip;
        uint16_t port;
        uint16_t timeout;
        uint8_t udp_max_retrans;

        static int new_socket;
        static int connection;
        bool tcp;

        std::string display_name;

        enum states {
            IDLE,
            AUTH,
            OPEN,
            JOIN,
            END
        };

        states state = IDLE;
        states next_state = IDLE;

        /**
         * @brief method send bye msg and closes the connection
         */
        void safely_end(int socket, int connection) {
            delete_new_line_or_carriage(display_name);
            std::string bye_msg = "BYE FROM " + display_name + "\r\n";
            send(socket, bye_msg.c_str(), bye_msg.size(), 0);
            if (connection > 0) {
                close(connection);
            }
            if (socket > 0) {
                close(socket);
            }
        }
        

        /**
         * @brief method changes the state of the FSM
         *        it checks the current state and the command received
         *        and decides on the next state
         */
        void change_state(std::string cmd, std::string msg, std::string upper_msg) {
            delete_new_line_or_carriage(msg);
            if(state == IDLE ) {
                if (cmd == "ERR" || cmd == "BYE") {
                    next_state = END;
                } else {
                    // no specified
                    next_state = IDLE;
                    std::cout << "ERROR: " << msg << std::endl;
                }
            } else if (state == AUTH) {
                if (cmd == "REPLY") {
                    if(upper_msg.find("REPLY OK") != std::string::npos) {
                    //     // if ok
                        next_state = OPEN;
                    } else if (upper_msg.find("REPLY NOK") != std::string::npos) {

                        next_state = AUTH;
                    } 
                } else if (cmd == "ERR" || cmd == "BYE" || cmd == "MSG") {
                    next_state = END;
                } else {
                    // no specified
                    std::cout << "ERROR: " << msg << std::endl;

                }
            } else if (state == OPEN) {
                if(cmd == "MSG") {
                    next_state = OPEN;
                    // nok and ok
                } else if (cmd == "ERR" || cmd == "BYE" || cmd == "REPLY") {
                    next_state = END;
                } else {
                    // no specified
                    std::cout << "ERROR: " << msg << std::endl;
                }
            } else if (state == JOIN) {
                if(cmd == "REPLY") {
                    next_state = OPEN;
                } else if (cmd == "MSG") {
                    next_state = JOIN;
                } else if(cmd == "ERR" || cmd == "BYE") {
                    next_state = END;
                } else {
                    // no specified
                    std::cout << "ERROR: " << msg << std::endl;
                }
            }
        }
        
        /**
         * @brief method sets up the socket and calls the start_chat method
         */
        void setup_socket() {
            int new_socket;
            if(tcp == true) {
                new_socket = socket(AF_INET, SOCK_STREAM, 0);
                if (new_socket < 0) {
                    std::cerr << "Couldn't create a socket" << std::endl;
                    exit(1);
                }
                int flags = fcntl(new_socket, F_GETFL, 0);
                fcntl(new_socket, F_SETFL, flags | O_NONBLOCK);


                struct sockaddr_in server_address;
                server_address.sin_family = AF_INET;
                server_address.sin_port = htons(port);
                server_address.sin_addr = ip;

                int connection = connect(new_socket, (struct sockaddr *)&server_address, sizeof(server_address));
                if (connection < 0) {
                    if (errno != EINPROGRESS) {
                        exit(1);
                    }
                
                }
                start_chat(new_socket, connection);
            } 
            
        }
       

        /**
         * @brief method is called when the chat is started
         *       sets up the epoll and handles both stdin and data from server
         *       based on this, it changes the state of the FSM 
         */
        void start_chat(int new_socket, int connection) {
            // read from stdin and send packets used epoll
            int epoll_fd = epoll_create1(0);
            if (epoll_fd == -1) {
                std::cerr << "Couldn't create epoll" << std::endl;
                exit(1);
            }
            struct epoll_event event, events[2];
            event.events = EPOLLIN | EPOLLET;
            event.data.fd = new_socket;

            if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, new_socket, &event) == -1) {
                std::cerr << "Couldn't add socket to epoll" << std::endl;
                exit(1);
            }

            event.events = EPOLLIN;
            event.data.fd = STDIN_FILENO;
            if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, STDIN_FILENO, &event) == -1) {
                std::cerr << "Couldn't add stdin to epoll" << std::endl;
                exit(1);
            }

            // in case msgs were in multiple packets
            std::string recv_buffer;
            while(true) {
        
                if (state != next_state) {
                    state = next_state;
                }
                if (state == END) {
                    safely_end(new_socket, connection);
                    exit(0);
                }
                int descriptor = epoll_wait(epoll_fd, events, 2, -1);
                if (descriptor == -1) {
                    // ctrl +c 
                    if(errno == EINTR) {
                        safely_end(new_socket, connection);
                        exit(0);
                    } else {
                        std::cerr << "Couldn't wait for epoll" << std::endl;
                        exit(1);
                    }
                } else if (descriptor == 0) {
                    // maybe not nesesary
                    continue;
                }
                receiving_data(new_socket, connection, recv_buffer, descriptor, events);

            }
        }
        /**
         * @brief method checks data from server and call receiving_stdin
         */

        void receiving_data(int new_socket, int connection, std::string &recv_buffer, int descriptor, struct epoll_event *events) {
            for (int i = 0; i < descriptor; i++) {
                // for handling data from socket
                if (events[i].data.fd == new_socket) {
                    char buffer[60034];
                    ssize_t bytes_read = recv(new_socket, buffer, sizeof(buffer), 0);
                    if (bytes_read == 0) {
                        std::cerr << "Server closed the connection" << std::endl;
                        close(new_socket);
                        exit(0);
                    } else if (bytes_read < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            continue;
                        } else {
                            std::cerr << "Could not connect to the port" << std::endl;
                            exit(1);
                        }
                    }
                    // answer from server could be split into multiple packets
                    // msg has to be ended with \r\n
                    if(recv_buffer.length() > 60000) {
                        std::cerr << "ERROR: Message too long" << std::endl;
                        // cut the last few
                        recv_buffer.erase(recv_buffer.end() - 500, recv_buffer.end());
                    } else {
                        recv_buffer.append(buffer, bytes_read);
                    }
                    size_t end;
                    while ((end = recv_buffer.find("\r\n")) != std::string::npos) {
                        std::string single_msg = recv_buffer.substr(0, end);
                        recv_buffer.erase(0, end + 2);
            
                        if (!single_msg.empty()) {
                            Message answer;
                            answer.msg = single_msg;
                            answer.cmd = single_msg.substr(0, single_msg.find(' '));

                            std::string upper_cmd;
                            for( auto &c : answer.cmd) {
                                c = toupper(c);
                                upper_cmd.append(1, c);
                            }
                            answer.cmd = upper_cmd;
                            answer.socket = new_socket;
                            answer.connection = connection;
                            answer.answer(display_name);
                            std::string upper_msg = msg_to_upper(answer.msg);
                            change_state(answer.cmd, answer.msg, upper_msg);
                        }
                    }


                } else if (events[i].data.fd == STDIN_FILENO) {
                    receiving_stdin(new_socket, connection);
                }
            }
        }

        /**
         * @brief method is called when data is received from stdin
         *        it parses the message and sets the cmd and msg variables
         */
        void receiving_stdin(int new_socket, int connection) {
            Message msg;
            msg.socket = new_socket;
            msg.connection = connection;
            msg.decipher(display_name);

            if(msg.cmd == "auth") {
                int last_space = msg.msg.find_last_of(" ");
                display_name = msg.msg.substr(last_space + 1, msg.msg.length() - last_space - 1);
            }
            if (msg.cmd == "rename") {
                int space = msg.msg.find(" ");
                display_name = msg.msg.substr(space + 1, msg.msg.length() - space - 1);
            }
            delete_new_line_or_carriage(display_name);
            bool skip = true;
            int error_check = msg.msg_check(display_name);
            if (error_check == 0) {
                std::string upper_msg = msg_to_upper(msg.msg);
                if (upper_msg.starts_with("MSG FROM ")) {
                    msg.cmd = "msg";
                }
                if (msg.cmd != "rename") {
                    skip = change_state_after_cmd(msg.cmd, msg.msg);
                }
                // error or rename - dont send
                if (!skip) {
                    send(new_socket, msg.msg.c_str(), msg.msg.size(), 0);                        

                }
            }
        }
        /**
         * @brief method based on cmd and current state changes the state
         * @return bool value used to decide whether to send packet to server
         */
        bool change_state_after_cmd(std::string cmd,std::string msg) {
            bool return_val = false;
            delete_new_line_or_carriage(msg);
            if (state == IDLE) {
                if(cmd == "auth") {
                    next_state = AUTH;
                } else if(cmd == "bye") {
                    next_state = END;
                } else {
                    // not specified
                    return_val = true;
                    next_state = IDLE;
                    std::cout << "ERROR: " << msg << std::endl;

                }
            } else if (state == AUTH) {
                if(cmd == "auth") {
                    next_state = AUTH;
                } else if(cmd == "bye" || cmd == "err") {
                    next_state = END;
                } 
                else {
                    return_val = true;
                    next_state = AUTH;
                    std::cout << "ERROR: " << msg << std::endl;
                }
            } else if (state == OPEN) {
                if(cmd == "bye" || cmd == "err") {
                    next_state = END;
                } else if(cmd == "join") {
                    next_state = JOIN;
                } else if(cmd == "msg") {
                    next_state = OPEN;
                } else {
                    return_val = true;
                    next_state = OPEN;
                    std::cout << "ERROR: " << msg << std::endl;
                }
            } else if (state == JOIN) {
                if(cmd == "bye") {
                    next_state = END;
                }
                else {
                    return_val = true;
                    next_state = JOIN;
                    std::cout << "ERROR: " << msg << std::endl;
                }
            }
            return return_val;
        }
                 
};


/**
 * @brief signal handler for ctrl+c
 *         sends bye message and closes the connection
 */
void signal_handler(int signum) {
    if (CHAT::new_socket != -1) {
        std::string message = "BYE\r\n";
    
        send(CHAT::new_socket, message.c_str(), message.size(), 0);
        
        close(CHAT::new_socket);
        close(CHAT::connection);
        exit(signum);  
    }
}
// needs to be here for the signal handler
int CHAT::new_socket = -1;
int CHAT::connection = -1;

int main(int argc, char *argv[]) {
    arg_parse args;
    args.parse(argc, argv);  


    // for ctrl+c
    struct sigaction action;
    action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    sigaction(SIGINT, &action, NULL);

    CHAT ipk_chat;
    ipk_chat.ip = args.ip;
    ipk_chat.port = args.port;
    ipk_chat.timeout = args.timeout;
    ipk_chat.udp_max_retrans = args.udp_max_retrans;
    ipk_chat.tcp = args.protocol == "tcp" ? true : false;
    ipk_chat.setup_socket();

}

#endif // CHAT_H