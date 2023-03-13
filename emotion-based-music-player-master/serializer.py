from sqlalchemy.inspection import inspect
import json 
import datetime

class Serializer(object):

    def serialize(self):
        return {c: getattr(self, c) if type(getattr(self, c)) != datetime.datetime else str(getattr(self, c)) for c in inspect(self).attrs.keys()}

    @staticmethod
    def serialize_list(l):
        return [m.serialize() for m in l]
 