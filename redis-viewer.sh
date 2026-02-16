#!/bin/bash

# Redis Viewer Script for JWT Auth Service
# Usage: ./redis-viewer.sh [command]

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Container name (update if different)
REDIS_CONTAINER="jwt-auth-redis"

show_help() {
    echo -e "${BLUE}JWT Auth Redis Viewer${NC}"
    echo ""
    echo "Usage: ./redis-viewer.sh [command]"
    echo ""
    echo "Commands:"
    echo -e "  ${GREEN}all${NC}           - Show all JWT auth keys"
    echo -e "  ${GREEN}refresh${NC}       - Show all refresh tokens"
    echo -e "  ${GREEN}blacklist${NC}     - Show all blacklisted tokens"
    echo -e "  ${GREEN}keys <pattern>${NC} - Show keys matching pattern"
    echo -e "  ${GREEN}get <key>${NC}     - Get value of a specific key"
    echo -e "  ${GREEN}ttl <key>${NC}     - Show TTL of a specific key"
    echo -e "  ${GREEN}monitor${NC}       - Monitor Redis activity (Ctrl+C to exit)"
    echo -e "  ${GREEN}count${NC}         - Count all keys"
    echo -e "  ${GREEN}flush${NC}         - Flush all JWT auth keys"
    echo -e "  ${GREEN}help${NC}          - Show this help message"
    echo ""
}

show_all_keys() {
    echo -e "${YELLOW}All JWT Auth Keys:${NC}"
    docker exec -it $REDIS_CONTAINER redis-cli KEYS "jwt_auth:*"
}

show_refresh_tokens() {
    echo -e "${YELLOW}Refresh Tokens:${NC}"
    docker exec -it $REDIS_CONTAINER redis-cli KEYS "jwt_auth:refresh:*"
}

show_blacklist() {
    echo -e "${YELLOW}Blacklisted Tokens:${NC}"
    docker exec -it $REDIS_CONTAINER redis-cli KEYS "jwt_auth:blacklist:*"
}

show_keys() {
    if [ -z "$2" ]; then
        echo -e "${RED}Error: Pattern required${NC}"
        echo "Usage: ./redis-viewer.sh keys <pattern>"
        return
    fi
    echo -e "${YELLOW}Keys matching '$2':${NC}"
    docker exec -it $REDIS_CONTAINER redis-cli KEYS "$2"
}

get_key() {
    if [ -z "$2" ]; then
        echo -e "${RED}Error: Key required${NC}"
        echo "Usage: ./redis-viewer.sh get <key>"
        return
    fi
    echo -e "${YELLOW}Value of '$2':${NC}"
    docker exec -it $REDIS_CONTAINER redis-cli GET "$2"
}

show_ttl() {
    if [ -z "$2" ]; then
        echo -e "${RED}Error: Key required${NC}"
        echo "Usage: ./redis-viewer.sh ttl <key>"
        return
    fi
    echo -e "${YELLOW}TTL of '$2':${NC}"
    docker exec -it $REDIS_CONTAINER redis-cli TTL "$2"
}

monitor() {
    echo -e "${YELLOW}Monitoring Redis activity (Press Ctrl+C to exit)...${NC}"
    docker exec -it $REDIS_CONTAINER redis-cli MONITOR
}

count_keys() {
    echo -e "${YELLOW}Key Counts:${NC}"
    echo "Total JWT auth keys: $(docker exec -it $REDIS_CONTAINER redis-cli KEYS 'jwt_auth:*' | wc -l)"
    echo "Refresh tokens: $(docker exec -it $REDIS_CONTAINER redis-cli KEYS 'jwt_auth:refresh:*' | wc -l)"
    echo "Blacklisted tokens: $(docker exec -it $REDIS_CONTAINER redis-cli KEYS 'jwt_auth:blacklist:*' | wc -l)"
}

flush_keys() {
    echo -e "${RED}Warning: This will delete all JWT auth keys!${NC}"
    read -p "Are you sure? (y/n): " confirm
    if [ "$confirm" = "y" ]; then
        echo -e "${YELLOW}Flushing JWT auth keys...${NC}"
        docker exec -it $REDIS_CONTAINER redis-cli KEYS "jwt_auth:*" | while read key; do
            docker exec -it $REDIS_CONTAINER redis-cli DEL "$key"
        done
        echo -e "${GREEN}Done!${NC}"
    else
        echo "Cancelled."
    fi
}

# Main
case "$1" in
    all)
        show_all_keys
        ;;
    refresh)
        show_refresh_tokens
        ;;
    blacklist)
        show_blacklist
        ;;
    keys)
        show_keys "$@"
        ;;
    get)
        get_key "$@"
        ;;
    ttl)
        show_ttl "$@"
        ;;
    monitor)
        monitor
        ;;
    count)
        count_keys
        ;;
    flush)
        flush_keys
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        show_help
        ;;
esac
