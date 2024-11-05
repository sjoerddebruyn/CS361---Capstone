import random

def id_gen():
    existing_ids = set()
    try:
        with open("users.txt", "r") as file:
            for line in file:
                stored_id = line.strip().split(", ")[0]
                stored_id = stored_id.split(": ")[1]
                existing_ids.add(stored_id)
    except FileNotFoundError:
        pass

    while True:
        unique_id = random.randint(1000, 9999)
        if str(unique_id) not in existing_ids:
            return unique_id
        
    