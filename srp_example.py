import srp

# Consider enabling RFC5054 compatibility for interoperation with non pysrp SRP-6a implementations
# pysrp.rfc5054_enable()

# The salt and verifier returned from srp.create_salted_verification_key() should be
# stored on the server.
salt, vkey = srp.create_salted_verification_key("testaccount", "testpassword",)


class AuthenticationFailed(Exception):
    pass


# ~~~ Begin Authentication ~~~

usr = srp.Account("testaccount", "testpassword")
uname, A = usr.start_authentication()

# The authentication process can fail at each step from this
# point on. To comply with the SRP protocol, the authentication
# process should be aborted on the first failure.

# Client => Server: account_id, A
svr = srp.Verifier(uname, salt, vkey, A)
s, B = svr.get_challenge()

if s is None or B is None:
    raise AuthenticationFailed()

# Server => Client: s, B
M = usr.process_challenge(s, B)

if M is None:
    raise AuthenticationFailed()

# Client => Server: M
HAMK = svr.verify_session(M)

if HAMK is None:
    raise AuthenticationFailed()

# Server => Client: HAMK
usr.verify_session(HAMK)

# At this point the authentication process is complete.
print(HAMK)
assert usr.authenticated()
assert svr.authenticated()


def create_v(x: bytes, ng_type: int = srp.NG_2048):
    N, g = srp.get_ng(ng_type, None, None)
    v = long_to_bytes(pow(g, gen_x(hash_class, _s, account_id, password), N))

    return v
