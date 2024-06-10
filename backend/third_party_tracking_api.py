# third_party_tracking_api.py

import random

def update_tracking_data(tracking_id):
    # Simulate fetching tracking updates from the third-party tracking system
    # In a real-world scenario, this function would make API requests to the third-party system
    
    # Dummy tracking statuses for demonstration
    statuses = ['In transit', 'Out for delivery', 'Delivered', 'Exception']
    
    # Randomly select a status for the given tracking ID
    status = random.choice(statuses)
    
    # Construct a dummy tracking update response
    tracking_update = {
        'tracking_id': tracking_id,
        'status': status,
        # You can include additional information such as location, estimated delivery time, etc.
        # Add any other relevant fields based on your tracking system's response
    }
    
    return tracking_update
