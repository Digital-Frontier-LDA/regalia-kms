#define _GNU_SOURCE
#include <dlfcn.h>
#include <expat.h>
#include <stdint.h>
#include <unistd.h>

XML_Bool XML_SetHashSalt16Bytes(XML_Parser parser, const uint8_t entropy[16]) {
    XML_Bool (*real)(XML_Parser, const uint8_t[16]) = dlsym(RTLD_NEXT, "XML_SetHashSalt16Bytes");
    if (!real) _exit(125);
    XML_Bool result = real(parser, entropy);
    if (result) {
        const char message[] = "REGALIA_EXPAT_SALT16_ACCEPTED\n";
        (void)write(2, message, sizeof(message)-1);
    }
    return result;
}

int XML_SetHashSalt(XML_Parser parser, unsigned long salt) {
    int (*real)(XML_Parser, unsigned long) = dlsym(RTLD_NEXT, "XML_SetHashSalt");
    if (!real) _exit(125);
    int result = real(parser, salt);
    if (result) {
        const char message[] = "REGALIA_EXPAT_LEGACY_SALT_ACCEPTED\n";
        (void)write(2, message, sizeof(message)-1);
    }
    return result;
}
