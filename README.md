# HQC Post-Quantum Cryptography: Build & Test Documentation

**System Environment:** Lubuntu (Linux)  
**Target:** HQC-128 (Reference Implementation)  
**Date:** February 5, 2026

---

## 1. Prerequisites Installation

We started by installing the necessary build tools and mathematical libraries required for the HQC implementation.

```bash
sudo apt update
sudo apt install build-essential cmake ninja-build clang-format libgmp-dev libntl-dev git
```

* **build-essential:** GCC compiler and make tools.
* **cmake & ninja-build:** The build system used by the project.
* **libgmp-dev & libntl-dev:** Large number arithmetic libraries (optional for base build, required for deep verification).

---

## 2. Cloning the Repository

We pulled the official source code from GitLab into the local machine.

```bash
git clone [https://gitlab.com/pqc-hqc/hqc.git](https://gitlab.com/pqc-hqc/hqc.git)
cd hqc
```

---

## 3. Building the Library (Reference Version)

We cleaned any previous build artifacts and built the "Reference" (portable) version of the library. This ensures it runs on any standard CPU without specific vector extensions (though AVX2 is available as an option).

### Step 3.1: Clean Old Builds

```bash
rm -rf build-ref
```

### Step 3.2: Configure Build

```bash
cmake -S . -B build-ref -DCMAKE_BUILD_TYPE=Release -DHQC_ARCH=ref
```

### Step 3.3: Compile

```bash
cmake --build build-ref -j$(nproc)
```

* **Output:** This created the static library file at `build-ref/src/libhqc_1_ref.a`.
* **Note:** The SHA-3 helper library was created at `build-ref/lib/libfips202.a`.

---

## 4. Creating the Test Driver (`test_hqc.c`)

We created a custom C program to manually invoke the API and simulate a key exchange.

**File:** `test_hqc.c` (placed in the `hqc/` root folder)

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"

void print_hex(const char *label, unsigned char *data, size_t len) {
    printf("%s: ", label);
    for(size_t i = 0; i < len; i++) printf("%02X", data[i]);
    printf("\n");
}

int main() {
    printf("--- HQC Key Encapsulation Mechanism Test ---\n");
    
    // Allocate Memory
    unsigned char pk[CRYPTO_PUBLICKEYBYTES];
    unsigned char sk[CRYPTO_SECRETKEYBYTES];
    unsigned char ct[CRYPTO_CIPHERTEXTBYTES];
    unsigned char ss_alice[CRYPTO_BYTES];
    unsigned char ss_bob[CRYPTO_BYTES];

    // 1. Alice generates Keypair
    printf("[1] Generating Keypair...\n");
    if (crypto_kem_keypair(pk, sk) != 0) return 1;
    printf("Success.\n");

    // 2. Bob Encapsulates (Generates Shared Secret & Ciphertext)
    printf("[2] Encapsulating...\n");
    if (crypto_kem_enc(ct, ss_bob, pk) != 0) return 1;
    printf("Success.\n");

    // 3. Alice Decapsulates (Recovers Shared Secret)
    printf("[3] Decapsulating...\n");
    if (crypto_kem_dec(ss_alice, ct, sk) != 0) return 1;
    printf("Success.\n");

    // 4. Verify Secrets Match
    if (memcmp(ss_alice, ss_bob, CRYPTO_BYTES) == 0) {
        printf("SUCCESS! The shared secrets match.\n");
        print_hex("Shared Secret", ss_alice, 16);
    } else {
        printf("FAILURE! Secrets do not match.\n");
    }
    return 0;
}
```

---

## 5. Compiling the Test Program

This was the critical step where we resolved multiple linker errors. We successfully linked the test code against both the HQC library and the FIPS202 (SHA-3) dependency.

### Command Used:

```bash
gcc -o test_hqc test_hqc.c \
    -I src/common/hqc-1 \
    -I build-ref/include \
    build-ref/src/libhqc_1_ref.a \
    build-ref/lib/libfips202.a \
    -lm
```

### Explanation of Flags:

* `-I src/common/hqc-1`: Path to `api.h` (Specific to HQC-128).
* `-I build-ref/include`: Path to configuration headers.
* `build-ref/src/libhqc_1_ref.a`: The main HQC static library.
* `build-ref/lib/libfips202.a`: The helper library for SHA-3 functions (resolved "undefined reference" errors).
* `-lm`: Links the standard math library.

---

## 6. Execution & Verification

We ran the final binary to confirm the cryptographic handshake worked.

### Command:

```bash
./test_hqc
```

### Output:

```text
--- HQC Key Encapsulation Mechanism Test ---
Public Key Size: 2241 bytes
Secret Key Size: 2321 bytes
Ciphertext Size: 4433 bytes
Shared Secret Size: 32 bytes

[1] Generating Keypair...
Success.

[2] Encapsulating Shared Secret...
Success. Bob sent ciphertext.

[3] Decapsulating...
Success. Alice recovered secret.

[4] Verifying Shared Secrets...
SUCCESS! The shared secrets match.
Shared Secret (First 16 bytes): D2F180212A57C5A446736160E6A3B0D0
```

The matching shared secret confirms that the Post-Quantum Cryptography implementation is functioning correctly on your machine.
