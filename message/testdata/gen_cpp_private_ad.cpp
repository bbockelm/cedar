// gen_cpp_private_ad.cpp -- generates the golden C++ wire vector used by
// TestInteropReadCppPrivateAd (../interop_cpp_test.go). It links against a built
// HTCondor tree and emits the exact bytes real C++ putClassAd() writes for an ad
// carrying a private attribute (a claim id): an AES-GCM-encrypted message that,
// because the peer version is unknown (< 9.9.0 path), wraps the private attribute
// in a SECRET_MARKER ("ZKM") + put_secret -- exactly the shape that desynced the
// Go collector. Regenerate (paths are for a local htcondor build tree):
//
//   FLAGS=$(python3 -c "import json;c=json.load(open('build/compile_commands.json'));\
//     print(next(' '.join(t for t in (e.get('command') or ' '.join(e['arguments'])).split() \
//     if t[:2] in ('-I','-D')) for e in c if e['file'].endswith('classad_oldnew.cpp')))")
//   clang++ -std=c++20 $FLAGS gen_cpp_private_ad.cpp \
//     -Lbuild/src/condor_utils -Lbuild/src/classad -lcondor_utils_25_13_0 -lclassad -o gen_ad
//   DYLD_LIBRARY_PATH=build/release_dir/lib:build/release_dir/lib/condor:\
//     build/_deps/libressl_libs_darwin-src/lib ./gen_ad out.wire
//   base64 < out.wire | tr -d '\n' > cpp_private_ad.wire.b64
//
// The 32-byte AES key is all zeros (see TestInteropReadCppPrivateAd).
#include "condor_common.h"
#include "condor_classad.h"
#include "classad_oldnew.h"
#include "reli_sock.h"
#include "CryptKey.h"
#include <sys/socket.h>
#include <unistd.h>
#include <cstdio>

int main(int argc, char** argv) {
    int fds[2];
    if (socketpair(PF_UNIX, SOCK_STREAM, 0, fds) < 0) { perror("socketpair"); return 1; }

    ReliSock rc;
    rc.assignSocket(fds[0]);

    // Key present but crypto NOT enabled -> triggers the SECRET_MARKER path for
    // private attributes. 32 zero bytes as a fixed test key.
    unsigned char key[32] = {0};
    KeyInfo k(key, 32, CONDOR_AESGCM, 0);
    rc.set_crypto_key(false, &k, nullptr);

    ClassAd ad;
    ad.Assign("Name", "slot1@interop");
    ad.Assign("MyType", "Machine");
    ad.Assign("ClaimId", "interop-secret-claimid-deadbeef");

    rc.encode();
    if (!putClassAd(&rc, ad) || !rc.end_of_message()) { fprintf(stderr, "putClassAd failed\n"); return 1; }
    shutdown(fds[0], SHUT_WR);

    // Drain the other end -> the exact wire bytes.
    unsigned char buf[65536];
    ssize_t total = 0, n;
    FILE* out = fopen(argv[1], "wb");
    while ((n = read(fds[1], buf, sizeof(buf))) > 0) { fwrite(buf, 1, n, out); total += n; }
    fclose(out);
    fprintf(stderr, "wrote %zd wire bytes\n", total);
    return 0;
}
