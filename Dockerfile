ARG PHP_VERSION="7.3"

FROM composer:2 as vendor

WORKDIR /app

COPY composer.json composer.lock /app/

RUN composer install \
    --ignore-platform-reqs \
    --no-interaction \
    --no-plugins \
    --no-scripts \
    --prefer-dist \
    --no-autoloader

COPY . /app/

RUN composer dump-autoload \
    --no-scripts \
    --optimize \
    --no-interaction \
    --no-plugins \
    --classmap-authoritative

FROM php:${PHP_VERSION}-cli

RUN mv "$PHP_INI_DIR/php.ini-development" "$PHP_INI_DIR/php.ini"

RUN apt-get update -y \
    && apt-get install -y libgmp-dev file \
    && ln -s /usr/include/x86_64-linux-gnu/gmp.h /usr/local/include/ \
    && docker-php-ext-install -j$(nproc) gmp bcmath \
    && rm -rf /var/lib/apt/lists/*

COPY --from=vendor /app/ /app/

WORKDIR /app
