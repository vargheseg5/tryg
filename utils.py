from datetime import datetime
from uuid import uuid4

def str_to_date(date_str):
    return datetime.strptime(date_str, '%Y-%m-%d').date()

def get_uuid():
    return uuid4().hex