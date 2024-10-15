## Docker-compose LEMP med NodeJS
### Inkluderar
- nginx -> localhost:80
- node (api) -> localhost: 5000
- php   
- mariadb -> mariadb
- phpmyadmin -> localhost:8080
- mongodb -> localhost:27017

### HowTo

#### node-server
Skall köras via port 5000 eller ändra i nginx.conf.
    www/server

Kör i terinalen: 

       $ npm init
       $ npm i express
       $ npm i nodemon

command: 

    npm run dev

#### Klient-node
Ändra först i 

    /config/nginx/nginx.conf

därefteter kod i

    /www/clent

#### Webbroten
    www/html
#### Starta servern (containern) med
    docker compose up -d
#### Stoppa servern (containern) med
    docker compose down
#### Serverns url
    localhost
### MariaDB
    root password: 12345 
    Byt lösen innan första start i docker-compose.yml (MYSQL_ROOT_PASSWORD=12345)
##### phpmyadmin
    localhost:8080
##### Anslut till MariaDB med php

```php
<?php
    // Definierar konstanter med användarinformation.
    define ('DB_USER', 'userName'); // Användare i MariaDB
    define ('DB_PASSWORD', '12345');
    define ('DB_HOST', 'mariadb'); // Viktigt! Inte localhost!
    define ('DB_NAME', 'dbName');   // Databasen som anslutning skall ske till

    // Skapar en anslutning till MariaDB och databasen dbName
    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8';
    $db = new PDO($dsn, DB_USER, DB_PASSWORD);
```

### MongoDB
Anslutning i container

    mongodb://root:12345@mongodb


Anslutning utifrån ex. compass (user: root, password: 12345)

    mongodb://localhost:27017

