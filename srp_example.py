import passman.srp as srp

# Consider enabling RFC5054 compatibility for interoperation with non pysrp SRP-6a implementations
# pysrp.rfc5054_enable()


def auth():
    # The salt and verifier should be
    # stored on the server.
    x = b"\x89\xb0\x7f\x10Wu\xf6\x1a\x9e\xa6\x98\xbf\xa8W\x8cI\x81\x05\x12\xbb\xfd\xab\xf5G\xf2\xa9rxx\xc6e\x87"
    salt = b"12345"

    class AuthenticationFailed(Exception):
        pass

    # ~~~ Begin Authentication ~~~

    usr = srp.User(username="user", x=x)
    uname, A = usr.start_authentication()

    # The authentication process can fail at each step from this
    # point on. To comply with the SRP protocol, the authentication
    # process should be aborted on the first failure.

    # Client => Server: username, A

    vkey = srp.long_to_bytes(
        pow(usr.g, usr.x, usr.N)
    )  # Server retrieves salt and vkey from DB

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


if __name__ == "__main__":
    auth()
