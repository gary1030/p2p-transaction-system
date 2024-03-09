# p2p-transaction-system

## Description

這是一套具備安全傳輸的網際網路第三方支付使用者對使用者小額付款系統。此系統包含三大功能：

1. Server 端對 Client 端（使用者）的統一管理，包含帳號管理、好友名單管理、認證以及 Client 帳戶管理等。
2. Client 間即時通訊。
3. Client 與 Server 以及 Client 間的通訊，都可以各自加密，加密的鑰匙（encryption key）由當下通訊的雙方議定。

## Functions

### Multi-threaded Server

1. 提供 Client 端的註冊與登入
2. 提供 Client 目前的帳戶餘額與上線清單（包含使用者名稱、IP address 以及 port number）
3. 接收 Client 端離線的通知

### Client

1. 向 Server 註冊
2. 向 Server 要最新的帳戶餘額、 上線清單
3. 和其它 Client 執行轉帳功能（不經過 Server）
4. 離線前需主動告知 Server

## Starting Server

1. Compile code

```sh
make
```

2. Start Server

```sh
make server
or
./server <server port>
```

3. Start Client

```sh
make client
or
./client <server ip> <server port>
```

