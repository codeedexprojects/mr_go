import requests

# Define the endpoint URL and credentials
staging_url = "http://ctbsplusapi.dtdc.com/dtdc-staging-api/api/dtdc/authenticate"
production_url = "https://blktracksvc.dtdc.com/dtdc-api/api/dtdc/authenticate"
username = "OF1993_00003_trk"
password = "s39i3IRWwTnWwFN"

# Make the request to the staging environment
response = requests.get(staging_url, params={"username": username, "password": password})

# Check if the request was successful
if response.status_code == 200:
    # Extract the authentication token from the response
    token = response.json().get("token")
    # You can save this token securely for later use, such as in environment variables or a configuration file
    # For example, you can store it in an environment variable
    # import os
    # os.environ["DTDC_AUTH_TOKEN"] = token
    print("Authentication token:", token)
else:
    print("Failed to authenticate. Status code:", response.status_code)
