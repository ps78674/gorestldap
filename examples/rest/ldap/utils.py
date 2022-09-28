from passlib.hash import ldap_salted_sha1 as ssha
from uuid import uuid5, NAMESPACE_OID


def gen_ssha_hash(raw_password):
    return ssha.hash(raw_password)


def gen_entry_uuid(name):
    return uuid5(NAMESPACE_OID, name)
