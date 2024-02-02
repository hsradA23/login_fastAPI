from hashlib import md5

def get_passhash(password):
    return md5(password.encode('utf-8')).hexdigest()
