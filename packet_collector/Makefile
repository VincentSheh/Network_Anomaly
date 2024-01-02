
GO = go
GOBUILD = $(GO) build -v
GOCLEAN = $(GO) clean

SOURCE = main.go
BINARY = nfnetlink-example

.PHONY: build run clean rebuild clean_iptables
build:
	$(GOBUILD) -o $(BINARY) $(SOURCE)

clean_iptables:
	# @if test $$(iptables -t raw -nvL PREROUTING  | grep -c 'NFQUEUE num 1 bypass') -eq 1; then \
	# 	iptables -t raw -D PREROUTING -p tcp --syn -j NFQUEUE --queue-num=1 --queue-bypass; \
	# fi
	# iptables -t raw -D PREROUTING -p tcp -j NFQUEUE --queue-num=1 --queue-bypass
	sudo iptables -F TEST


accept_local:
	iptables -t raw -I PREROUTING -s 192.168.50.0/24 -j ACCEPT
run: clean_iptables
	iptables -t raw -A PREROUTING -p tcp -j NFQUEUE --queue-num=1 --queue-bypass
	./$(BINARY)

clean: clean_iptables
	rm -fv $(BINARY)
	$(GOCLEAN)

rebuild: clean build
