/* Read-only harness for the exact vendor scconf library built into the PAM package.
 * This is native dependency verification, not an alternative authentication stack.
 */
#include <stddef.h>
#include "scconf.h"
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    scconf_context *context = scconf_new(argv[1]);
    if (context == NULL) return 2;
    int parsed = scconf_parse(context);
    scconf_free(context);
    return parsed > 0 ? 0 : 1;
}
