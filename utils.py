from datetime import datetime
from uuid import uuid4

def str_to_date(date_str):
    return datetime.strptime(date_str, '%Y-%m-%d').date()

def date_to_str(date_obj):
    return date_obj.strftime('%Y-%m-%d')

def datetime_to_str(datetime_obj):
    return datetime_obj.strftime('%a, %d %b %Y @ %I:%M:%S %p %Z UTC')

def get_uuid():
    return uuid4().hex