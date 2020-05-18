import srp

# Consider enabling RFC5054 compatibility for interoperation with non pysrp SRP-6a implementations
# pysrp.rfc5054_enable()

# Create verifier from SRP-x
def create_v(x: bytes):
    # RFC 5054 4096-bit SRP Group hardcoded for now
    N = int(
        """
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08\
8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B\
302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9\
A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6\
49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8\
FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D\
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C\
180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D\
04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D\
B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226\
1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC\
E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26\
99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB\
04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2\
233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127\
D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199\
FFFFFFFFFFFFFFFF""",
        16,
    )
    g = 5
    x_val = int.from_bytes(x, "big")
    v = bytes.fromhex(format(pow(g, x_val, N), "x"))
    return v

def auth():
    # The salt and verifier should be
    # stored on the server.
    vkey = create_v("SRP-X value from key derivation".encode())
    salt = "12345"

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