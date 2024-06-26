import redis

try:
    # Attempt to connect to Redis
    r = redis.Redis(host='localhost', port=6379, db=0)
    r.ping()  # Check if the connection is successful by sending a ping command
    print("Successfully connected to Redis")
except redis.ConnectionError as e:
    # If connection fails, print an error message with the specific exception
    print("Failed to connect to Redis:", e)
