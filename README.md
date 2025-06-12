# Dokumentace projektu 2 – Client for a chat server using the IPK25-CHAT protocol

Author: Eliška Krejčíková  

Login: xkrejce00  

## Teorie
TCP a UDP jsou protokoly běžně používané v každodenní komunikaci. TCP se vyznačuje spolehlivostí přenosu dat. Probíhá mezi jedním serverem a jedním klientem.
Aby se tyto dvě strany mohly spojit, musí dojít k three-way handshake. Jedna strana musí prvně poslat SYN paket, druhá strana musí odpovědět paketem SYN-ACK, a posledním krokem je zaslání ACK paketu, který konečně vytvoří bezpečné spojení. Proto je toto spojení o něco pomalejší, což ale není problém pro UDP.
UDP jenom posílá data. Neřeší, jestli data došla, nenavazuje spojení, ani se nekontroluje pořadí paketů. Proto je mnohem rychlejší, ale zároveň není bezpečné. Data se můžou ztratit, paketu se můžou pomíchat anebo může se některý paket opakovat.



## Implementace 
### Parsování argumentů
Program začíná zpracováním argumentů. Pro tento účel jsem vytvořila třídu arg_parse, která využívá funkci `getopt()` na postupné rozparsování všech argumentů
a uloží si je do atributů. Za předpokladu, že bude zadán argument -s následován doménou, nikoliv IP adresou, je zavolána funkce `getaddrinfo`. Jestli program dostane
neplatnou doménu, program je ukončen. Program je taky ukončen, když nejsou zadány argumenty: -t a -s (výběr protokolu a  IP adresa/domény), bez nichž tento program
nemůže vykonávat svou funkci.

### TCP
Začala jsem vytvoření třídy CHAT, která měla ovládat jak TCP tak i UDP. Poté jsem šla na přípravu sockety a spojení. Využila jsem funkce `socket`, `connect` a `fcntl` na zařízení, aby socket nebyl blokující. Jelikož chci zároveň číst ze stdin a zachytávat pakety přes spojení, využila jsem také funkce `epoll()`. Chytání paketů jsem zařídila funkcí `recv()`. Ukládám si data, dokud nepřijde ukončení zprávy \r\n. Jelikož je možné, že zpráva bude rozdělena do více paketů, dočasně si ukládám data do bufferu. Jakmile mám celý paket, vytvořím si instanci `třídy Message` a zavolám metodu `answer`, která se stará o zpracování dat, která byla získana z socketu. Kontroluje, že zpráva byla správně postavena(odpovídá regulárnímu výrazu). Jestli byl paket správně postaven, vytisknou se data na stdout. Za předpokladu, že nastal problém, na stdout je vypsán error, errová zpráva je také poslána serveru a program je ukončen.
Je-li paket správný, rozhoduje se na základě obdrženého paketu a nýnějšího stavu, do kterého stavu půjde program následovně.
Logika je odeslána na základě FSM popsaného v zadání (https://git.fit.vutbr.cz/NESFIT/IPK-Projects/src/branch/master/Project_2#client-behaviour). 

Čtení ze stdin probíhá obdobně. Ze třídy Message volám metodu `decipher()`, která čte ze stdin a rozdělí zprávu na příkaz a zbytek zprávy. Na základě přikazu se rozhoduji, jakou zprávu poslat a do jakého stavu pokračovat. Zde nastal problém s příkazem join. Dle gramatiky by ve zprávě `/join` something neměla být tečka, ale tento znak byl potřeba na změnu kanálů na referenčím discord serveru. Tak jsem dočasně tu část kódu zakomentovala.

Signál přerušení byl řešen funkcí signactivate a definovanou funkcí `handle_signal()`. Během testování jsem si všimla, že epoll descriptor tento error chytá, takže jsem se zde přidala volání `safely_end`, která se rozloučí se serverem a poté ukončení spojení.

### Call graf
![graph](/diagram.png)

Struktura zdrojového kódu znázorněna pomocí call grafu.
 "Hranatější" položky značí třídy a barevně jsou vyznačeny, které metody jim patří.
Šipky vyjadřují volání metody.


## Testovaní

### Lokální testování

Největší část testování proběhla na mém zařízení. Pomocí `netcat` jsem otevřela port a komunikaci sledovala pomocí `tcpdump`. Po každém testu jsem znovu spustila `netcat` i `tcpdump`. Chování serveru jsem simulovala posíláním příkazů přes netcat.

Všechny záznamy získané nástrojem `tcpdump` byly uloženy do složky `test_logs`, kde číslo testu souboru odpovídá čísle testu zde v readme.

#### Setup
Otevření nového portu 4567 a spuštění programu:
```
nc -4 -l -C -v 127.0.0.1 4567

/ipk25chat-client -t tcp -s localhost
```

#### Test 1 - Autorizace, kladná odpověď od serveru, zpráva, odpověd od serveru, rename a CTRL +C

![t1](/test_logs/img/local_test1.png)

Prvně se klient připojí přikazem /auth. Následně z druhého terminálu s otevřeným netcat server poslal zprávu `REPLY OK`.
Program správně vypsal `Action success: ...`. Pak proběhlo odeslání od klienta, které se objevilo ve správném tvaru v druhém terminálu.
Zpráva od serveru ke klientovi došla také správně.
Následně byl otestován příkaz `rename` z `displey_name` na `my_name`. Správnost projedení byla otestována posláním nového přikazu. V netcat se objevila zpráva 
pod `my_name`, tudíž příkaz proběhl úspěšně.
Nakonec bylo otestováno ukočení příkazem CTRL + C. Serveru se správně objevila zpráva `BYE FROM my_name` a program byl ukončen.

Tomuto testování odpovídá log test1.txt ve složce test_logs.

#### Test 2 - Autorizace a záporná odpověď od serveru
![t2](/test_logs/img/local_test2.png)

V tomto testu pošlu ze serveru zprávu `REPLY NOK`. Program by měl vypsal chybovou hlášku `Action Failed: ... ` a zůstav se stavu AUTH.
Poté zkusím klientovi zaslat zprávu. V tomto stavu nejsou zprávy podporovány a program by měl skončit ve stavu ERR.
Z výsledky je vidět, že klient se správně rozloučil a následně se program ukončil.


#### Test 3 - Úspěšná autorizace, přechod do stavu OPEN, příkaz join a bye od serveru

![t3](/test_logs/img/local_test3.png)
V tomto testu se úspěšně proběhne autorizace a program je ve stavu OPEN. Využije se příkaz `join` a program se dostane do stavu JOIN.
Server odpoví `REPLY OK` a program bude znovu ve stavu OPEN, kde můžu posílát zprávy. Následně je ukončen po přijetí erroru ze serveru. Program správně poslal poslední zprávu BYE serveru a byl ukončen.



#### Test 4 - MSG ve stavu JOIN

![t4](/test_logs/img/local_test4.png)

V tomto testu úspěšně proběhne autorizace a program je ve stavu OPEN. Využije se příkaz `join` a program se dostane do stavu JOIN.
Ve stavu JOIN se nedá posílat zprávy. V tomtu stavu tedy může přijímat program zprávy ze serveru, ale odeslání vlastní zprávy vede k erroru. Program není ukončen a zpráva není poslána. Až server pošle REPLY, klient může znovu posílat zprávy.
Program je ukončen, když server pošle ERR.


#### Test 5 - Obdržení MSG v AUTH stavu

![t5](/test_logs/img/local_test5.png)


Po vykonání příkazu auth, klient čeká, že příjde `REPLY OK` od serveru. Ale pokud přijde `MSG`, program musí jít do stavu END, rozloučit se a ukončit svůj běh.


### Testování na virtuálním stroji s referenčím serverem
Ke každému testu je přiložený obrázek. V levé části je vidět terminál a v pravé výsledné chování na referenčím serveru.
Až na test 2, kde nastal problém si příkazem rename, testy dosáhly požadovaného chování.
#### Test 1 - test připojení, poslání zprávy a změny kanálu
![test1](/test_logs/img/test1.png)

#### Test 2 - zpráva v jiném kanálu, příkaz rename a zpráva pod novým jménem 
![test2](/test_logs/img/test2.png)

Pozn: zde jsem zadávala příkaz /rename dvakrát. Buď jsem omylem dala k příkazu mezeru navíc, nebo byl příkaz ovlivněn nějakou zprávou ze serveru.
#### Test 3 - připojení, zpráva a ukončení pomocí CTRL + C
![test3](/test_logs/img/test3.png)



## Zdroje
### Citace
[1] Linux man pages online. epoll(7) — Linux manual page. Online.[16. března 2025] Dostupné z: https://man7.org/linux/man-pages/man7/epoll.7.html

[2] Stack Overflow. C Socket send and connect. Online. [17.března 2025]. Dostupné z https://stackoverflow.com/questions/43264266/c-socket-send-and-connect:

[3] Dev community. Understanding blocking and non blocking sockets in C programming: A comprehensive guide. Online. [17.března 2025]. Dostupné z: https://dev.to/vivekyadav200988/understanding-blocking-and-non-blocking-sockets-in-c-programming-a-comprehensive-guide-2ien 

[4] OpenAI. ChatGPT. Non-blocking sockets in C++. Online. [17.března 2025]. Dostupné z: https://chatgpt.com/

[5] OpenAI. ChatGPT. Signal handling with sockets. Online. [20.března 2025]. Dostupné z: https://chatgpt.com/

[6] The Open Group publications. Connect. Online. [16.března 2025]. Dostupné z: https://pubs.opengroup.org/onlinepubs/009695399/functions/connect.html

[7] The GNU C Library. 24.3.1 Basic Signal Handling. Online. [20.března 2025].Dostupné z: https://www.gnu.org/software/libc/manual/html_node/Basic-Signal-Handling.html

[8] Medium. Building a multi-client chat server with select and epoll. [17.března 2025] Dostupné z: https://mecha-mind.medium.com/a-non-threaded-chat-server-in-c-53dadab8e8f3 
