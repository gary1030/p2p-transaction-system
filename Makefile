all:
	g++ -pthread -o server server.cpp myqueue.cpp -lssl -lcrypto
	g++ -o client client.cpp -lssl -lcrypto
server: 
	./server
client:
	./client
clear:
	rm client
	rm server

