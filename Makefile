CXXFLAGS = -Wall -Wextra -std=c++20
TARGET = ipk25chat-client
SRC = ipk25chat-client.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	g++ $(CXXFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)