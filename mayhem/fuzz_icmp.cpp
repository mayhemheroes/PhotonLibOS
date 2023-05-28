#include <stdint.h>
#include <stdio.h>

#include <fuzzer/FuzzedDataProvider.h>
#include "estring.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();
    std::string str2 = provider.ConsumeRandomLengthString();

    estring_view esv(str);
    esv.icmp(str2);
    return 0;
}
